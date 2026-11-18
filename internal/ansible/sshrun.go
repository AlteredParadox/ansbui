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
	return resolveExact("WD", `-e -- `+shellQuote(workDir), "workDir not found on control node") + `; ` +
		resolveExact("TGT", `-m -- "$WD"/`+shellQuote(rel), "cannot resolve target path") + `; ` +
		`case "$TGT" in "$WD"/*) ;; *) echo "refusing: path resolves outside the configured workDir (symlinked directory?)" >&2; exit 3;; esac`
}

// resolveExact emits shell that assigns realpath's output to the
// variable name, byte for byte, or prints failMsg and exits 3.
//
// A plain NAME=$(realpath ...) is not byte for byte: command
// substitution strips trailing newlines, and a newline is a legal
// character in a file name. That turned the confinement check into a
// check of a different path from the one realpath resolved. Take a
// link `a` whose target is the name "b" followed by a newline — a name
// that does not exist — beside a second link `b` pointing out of the
// tree. realpath resolves `a` to "<workDir>/b\n" and stops there (-m
// tolerates the missing last component). The substitution dropped the
// newline, the check saw "<workDir>/b" and passed it as in-tree, and
// the command that followed opened `b`: a symlink, and the escape the
// check exists to prevent.
//
// So a sentinel is printed after the path and removed again: the
// substitution then ends in the sentinel, has no trailing newline to
// strip, and what is left after removing realpath's own line ending
// plus the sentinel is the exact physical path. A name that really
// ends in a newline stays that name — nonexistent in the case above,
// so the read or write that follows fails instead of following a
// second link.
func resolveExact(name, realpathArgs, failMsg string) string {
	return name + `=$(realpath ` + realpathArgs + ` && printf .) || { echo "` + failMsg + `" >&2; exit 3; }; ` +
		name + `=${` + name + `%$'\n'.}`
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
	return resolveExact("WD", `-e -- `+shellQuote(workDir), "workDir not found on control node") + `; ` +
		resolveExact("TGTD", `-m -- "$WD"/`+shellQuote(path.Dir(rel)), "cannot resolve target directory") + `; ` +
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
//   - the temp file is created by mktemp: exclusively, under an
//     unpredictable name, mode 0600. It gets the destination's mode
//     only once the content is complete, just before the rename.
//   - EXIT trap removes the temp file if anything goes wrong midway
//     (other than SIGKILL, which bash can't trap).
//   - `[ -L "$TGT" ]` refuses to write when the destination is a
//     symlink. rename(2) wouldn't follow the link at the destination
//     (it would replace the symlink with a regular file), so this is
//     defense-in-depth against an honest-mistake symlink being
//     destroyed and replaced with a regular file. A directory at the
//     destination is refused too, and `mv -T` keeps a directory that
//     appears there later from being moved INTO.
//   - mode bits are preserved via stat+chmod for files that already
//     exist; new files get 0644 (matches the umask-default that the
//     previous `>`-based writers would have produced). Owner is not
//     preserved — the new file is owned by the SSH user, which for
//     ansbui's typical setup is the operator who owns the workdir.
//
// Residual, accepted for a single-operator deployment: every step
// after mktemp names the temp file and the destination by path again.
// Another local user who can WRITE the destination's directory can
// swap either for a symlink between two steps. Closing that needs the
// write, chmod and rename done through one descriptor, which a shell
// script cannot do; the alternative is not to let other users write
// the playbook tree.
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
//
// The temp file. It used to be `<dest>.tmp.$$`, opened with a plain
// `cat >`. Three things were wrong with that, all for another local
// user on the control node:
//
//   - The file was created under the account's umask and only chmod'ed
//     afterwards, so while a 0600 file (vault, group_vars) was being
//     uploaded its NEW content sat in a 0644 file for the length of
//     the upload — and anyone who opened it in that window kept
//     reading after the chmod.
//   - The name is predictable ($$ is a pid) and the open followed
//     symlinks, so a link planted in advance at `<dest>.tmp.<pid>`
//     for a range of upcoming pids sent the operator's content to a
//     file of the planter's choosing, chmod'ed that file, and then
//     renamed the LINK over the destination. No race needed.
//   - The EXIT trap read a variable called TMP before the script had
//     assigned it. A login environment that exports TMP (common: it
//     is a conventional name for the temp directory) made every early
//     exit run `rm -f` on that inherited value.
//
// mktemp creates the file exclusively (O_EXCL: a planted name is an
// error, not something to follow), with a name nobody can plant in
// advance, and `umask 077` makes it 0600 from its first byte. The
// trap variable is assigned before the trap is installed, so nothing
// inherited is ever acted on, and cleared after the rename.
func atomicWriteScriptFor(q string) string {
	return fmt.Sprintf(
		`set -eo pipefail; ANSBUI_TMPF=; trap '[ -n "$ANSBUI_TMPF" ] && rm -f -- "$ANSBUI_TMPF"' EXIT; `+
			`if [ -L %[1]s ]; then echo "refusing to write through symlink" >&2; exit 2; fi; `+
			`if [ -d %[1]s ]; then echo "refusing to replace a directory" >&2; exit 2; fi; `+
			`if [ -e %[1]s ]; then PERM=$(stat -c '%%a' -- %[1]s); else PERM=0644; fi; `+
			`D=$(dirname -- %[1]s); `+
			`umask 077; `+
			`ANSBUI_TMPF=$(mktemp -- %[1]s.tmp.XXXXXXXXXX); `+
			`cat > "$ANSBUI_TMPF"; `+
			`chmod -- "$PERM" "$ANSBUI_TMPF"; `+
			`sync -- "$ANSBUI_TMPF"; `+
			`mv -T -- "$ANSBUI_TMPF" %[1]s; `+
			`ANSBUI_TMPF=; `+
			`sync -- "$D"`,
		q,
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
