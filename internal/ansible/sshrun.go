package ansible

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/AlteredParadox/ansbui/internal/sshpool"
	"golang.org/x/crypto/ssh"
)

// remoteWriteTimeout bounds a single atomic file write to the
// control node. Generous enough that brief network blips or pool
// session-saturation don't fail an otherwise-completed
// bootstrap run on the inventory step (the original
// vaultRunTimeout 30s caused that), but bounded so a wedged
// session can't hang the orchestrator forever.
const remoteWriteTimeout = 5 * time.Minute

// remoteReadTimeout bounds a single confined file read from the
// control node. Reads are interactive (a UI request is waiting on
// them) and the files involved are playbooks and vault YAML, so a
// minute is generous; the point is that the bound exists at all.
const remoteReadTimeout = 1 * time.Minute

// WriteFileInWorkDir is the exported entry point to the confined
// atomic write helper — the bootstrap package calls it to persist a
// modified inventory file. rel is resolved against workDir ON THE
// CONTROL NODE (realpath) and the write is refused if the physical
// target escapes the tree; see confineToWorkDirScript. Returns a
// wrapped error carrying trimmed stderr so callers can surface
// "refusing to write through symlink" and confinement diagnostics.
func WriteFileInWorkDir(ctx context.Context, cli *ssh.Client, workDir, rel, content string) error {
	stderr, err := writeFileAtomicInWorkDir(ctx, cli, workDir, rel, content)
	if err != nil {
		if stderr == "" {
			stderr = err.Error()
		}
		return fmt.Errorf("write %s: %s", rel, stderr)
	}
	return nil
}

// confineToWorkDirScript emits the shell preamble every workDir-
// scoped read/write runs first on the control node: resolve workDir
// and the target to their PHYSICAL paths (realpath follows every
// symlinked component) and refuse when the target leaves the tree.
// On success $TGT holds the resolved absolute path for the command
// that follows.
//
// validateRelPath already rejects `..` and absolute paths lexically,
// but a symlinked intermediate directory (workDir/linkdir → /etc)
// only escapes physically — path.Join can't see it, and the writer's
// final-destination symlink check misses link PARENTS. realpath on
// the control node is the ground truth. The cost is that operator
// setups which deliberately symlink directories out of the workDir
// tree are no longer reachable through the UI; that's the boundary
// working as intended.
//
// realpath -m (target) tolerates a not-yet-existing final component
// so imports can create new files; -e (workDir) requires the root to
// exist. An empty workDir means "the SSH user's home" (the session
// cwd), matching the historical path.Join behaviour.
func confineToWorkDirScript(workDir, rel string) string {
	if workDir == "" {
		workDir = "."
	}
	return `WD=$(realpath -e -- ` + shellQuote(workDir) + `) || { echo "workDir not found on control node" >&2; exit 3; }; ` +
		`TGT=$(realpath -m -- "$WD"/` + shellQuote(rel) + `) || { echo "cannot resolve target path" >&2; exit 3; }; ` +
		`case "$TGT" in "$WD"/*) ;; *) echo "refusing: path resolves outside the configured workDir (symlinked directory?)" >&2; exit 3;; esac`
}

// readFileInWorkDir cats rel (confined to workDir — see
// confineToWorkDirScript) and returns stdout + trimmed stderr.
//
// Bounded by remoteReadTimeout. This path had no deadline of its own
// and its callers (the inline-vault key list, the playbook reader)
// pass the HTTP request's ctx — and the server sets no WriteTimeout,
// deliberately, so nothing else ended the request either. A control
// node that accepted the session and then never finished the `cat`
// held the handler until the client gave up.
func readFileInWorkDir(ctx context.Context, cli *ssh.Client, workDir, rel string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, remoteReadTimeout)
	defer cancel()
	script := confineToWorkDirScript(workDir, rel) + `; cat -- "$TGT"`
	return runRemoteScript(ctx, cli, script, "")
}

// confineParentToWorkDirScript is the WRITE-side confinement: it
// physically resolves rel's parent directory against workDir and
// re-attaches the final component UNRESOLVED. The full-path variant
// (confineToWorkDirScript) would resolve a final symlink too, which
// silently defeated the writer's `[ -L "$TGT" ]` refusal — the check
// ran against the link's target, so an in-tree symlink was followed
// and its target overwritten instead of being refused. With only the
// parents resolved, containment still holds for every directory
// component, and a symlink at the destination itself is caught by
// the writer's refusal, restoring the documented contract.
func confineParentToWorkDirScript(workDir, rel string) string {
	if workDir == "" {
		workDir = "."
	}
	// validateRelPath guarantees rel has no "", ".", ".." segments,
	// so Dir/Base split cleanly ("." parent for top-level files).
	return `WD=$(realpath -e -- ` + shellQuote(workDir) + `) || { echo "workDir not found on control node" >&2; exit 3; }; ` +
		`TGTD=$(realpath -m -- "$WD"/` + shellQuote(path.Dir(rel)) + `) || { echo "cannot resolve target directory" >&2; exit 3; }; ` +
		`case "$TGTD"/ in "$WD"/*) ;; *) echo "refusing: path resolves outside the configured workDir (symlinked directory?)" >&2; exit 3;; esac; ` +
		`TGT="$TGTD"/` + shellQuote(path.Base(rel))
}

// writeFileAtomicInWorkDir overwrites rel (resolved against workDir
// with symlink confinement — see confineToWorkDirScript) with
// `content`, streamed over the session's stdin (so it sidesteps the
// 128 KB MAX_ARG_STRLEN ceiling that any base64-in-argv approach
// would hit). Also creates the file if it doesn't exist — the
// playbook Import flow relies on this to write a new file under the
// workdir.
//
// Hardening (see atomicWriteScriptFor for the script itself):
//   - `set -eo pipefail` so any pipeline failure aborts before chmod/mv.
//   - EXIT trap removes the `*.tmp.$$` if anything goes wrong midway
//     (other than SIGKILL, which bash can't trap).
//   - `[ -L "$TGT" ]` refuses to write when the destination is a
//     symlink. rename(2) wouldn't follow the link at the destination
//     (it would replace the symlink with a regular file), so this is
//     defense-in-depth against an honest-mistake symlink being
//     destroyed and replaced with a regular file. A determined local
//     racer can swap a regular file for a symlink between the check
//     and the rename; accepted residual risk for a single-operator
//     deployment.
//   - mode bits are preserved via stat+chmod for files that already
//     exist; new files get 0644 (matches the umask-default that the
//     previous `>`-based writers would have produced). Owner is not
//     preserved — the new file is owned by the SSH user, which for
//     ansbui's typical setup is the operator who owns the workdir.
//
// Returns trimmed stderr (empty if the run succeeded) plus any
// underlying error from the SSH execution. Callers should wrap the
// error with their own context (e.g. "write playbook %s: %s").
func writeFileAtomicInWorkDir(ctx context.Context, cli *ssh.Client, workDir, rel, content string) (stderr string, err error) {
	// Atomic file writes get their own bound (5 min) so a slow
	// inventory-update step at the end of a long bootstrap
	// run doesn't fail under the 30s vaultRunTimeout that used
	// to apply implicitly via runRemoteScript.
	ctx, cancel := context.WithTimeout(ctx, remoteWriteTimeout)
	defer cancel()
	// Parent-only confinement so the writer's own final-symlink
	// refusal still fires on the real destination — see
	// confineParentToWorkDirScript.
	script := confineParentToWorkDirScript(workDir, rel) + `; ` + atomicWriteScriptFor(`"$TGT"`)
	_, stderr, err = runRemoteScript(ctx, cli, script, content)
	return stderr, err
}

// atomicWriteScript is the bash one-liner form for a literal
// destination path. Kept so the symlink-refusal branch can be
// exercised by integration tests against a local bash without
// standing up a full SSH server. The contract is the same on the
// wire: stdin = file content, exit 2 + stderr message when the
// destination is a symlink, exit 0 + atomic rename otherwise.
func atomicWriteScript(full string) string {
	return atomicWriteScriptFor(shellQuote(full))
}

// atomicWriteScriptFor builds the script body around an already-safe
// shell token for the destination — either a shellQuote'd literal
// path or a double-quoted variable reference like `"$TGT"` set by a
// confinement preamble.
//
// Durability mirrors the local config/history writers: the temp file
// is fsync'd (coreutils `sync FILE` = fsync) before the rename, and
// the parent directory after it, so a control-node power loss can't
// silently revert a write the API already reported as successful.
func atomicWriteScriptFor(q string) string {
	return fmt.Sprintf(
		`set -eo pipefail; trap '[ -n "${TMP:-}" ] && rm -f "$TMP"' EXIT; `+
			`if [ -L %s ]; then echo "refusing to write through symlink" >&2; exit 2; fi; `+
			`if [ -e %s ]; then PERM=$(stat -c '%%a' %s); else PERM=0644; fi; `+
			`D=$(dirname -- %s); `+
			`TMP=%s.tmp.$$; `+
			`cat > "$TMP"; `+
			`chmod "$PERM" "$TMP"; `+
			`sync -- "$TMP"; `+
			`mv "$TMP" %s; `+
			`sync -- "$D"`,
		q, q, q, q, q, q,
	)
}

// runRemoteScript opens a session, optionally feeds stdin, runs the
// supplied script under /usr/bin/env bash -c, and returns stdout +
// trimmed stderr + the underlying error.
//
// Streaming stdin is what makes this useful: shipping large file
// content via argv hits Linux's MAX_ARG_STRLEN (128 KB per element,
// PAGE_SIZE × 32, not configurable). Writing through stdin sidesteps
// that bound entirely — useful for vault encrypt/decrypt and for
// writing files larger than ~95 KB after base64 + JSON envelope.
//
// Callers are expected to bound ctx with their own timeout
// appropriate to the workload (vault: 30s; atomic writes: 5 min).
// runRemoteScript itself doesn't impose a default — using one
// helper across both vault and bootstrap callers led to a
// 30s cap silently applying to a small inventory write at the
// tail of a 30-minute bootstrap run.
// Output goes through sshpool.RunStdin rather than raw bytes.Buffers
// so these helpers obey the same byte caps and the same process-wide
// session semaphore as every other remote query. They previously had
// neither: a control node returning a huge or endless stream could
// grow the heap unbounded, and concurrent vault/file requests could
// each hold a session outside the shared admission control.
func runRemoteScript(ctx context.Context, cli *ssh.Client, script, stdin string) (stdout, stderr string, err error) {
	var in io.Reader
	if stdin != "" {
		// Left nil when empty so the session gets no stdin at all,
		// rather than one that reads EOF immediately.
		in = strings.NewReader(stdin)
	}
	cmd := "/usr/bin/env bash -c " + shellQuote(script)
	stdout, stderr, err = sshpool.RunStdin(ctx, cli, cmd, in)
	return stdout, strings.TrimSpace(stderr), err
}
