package ansible

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// writeFileAtomicViaStdin overwrites the absolute path `full` on the
// remote with `content`, streamed over the session's stdin (so it
// sidesteps the 128 KB MAX_ARG_STRLEN ceiling that any base64-in-argv
// approach would hit).
//
// Hardening:
//   - `set -eo pipefail` so any pipeline failure aborts before chmod/mv.
//   - EXIT trap removes the `*.tmp.$$` if anything goes wrong midway
//     (other than SIGKILL, which bash can't trap).
//   - `[ -L "$FULL" ]` refuses to write when the destination is a
//     symlink. rename(2) wouldn't follow the link at the destination
//     (it would replace the symlink with a regular file), so this is
//     defense-in-depth against an honest-mistake symlink being
//     destroyed and replaced with a regular file. A determined local
//     racer can swap a regular file for a symlink between the check
//     and the rename; accepted residual risk for a single-operator
//     deployment.
//   - mode bits preserved via stat+chmod. Owner is not preserved —
//     the new file is owned by the SSH user; for ansbui's typical
//     setup that's the operator who owns the workdir.
//
// Returns trimmed stderr (empty if the run succeeded) plus any
// underlying error from the SSH execution. Callers should wrap the
// error with their own context (e.g. "write playbook %s: %s").
func writeFileAtomicViaStdin(ctx context.Context, cli *ssh.Client, full, content string) (stderr string, err error) {
	q := shellQuote(full)
	script := fmt.Sprintf(
		`set -eo pipefail; trap '[ -n "${TMP:-}" ] && rm -f "$TMP"' EXIT; `+
			`if [ -L %s ]; then echo "refusing to write through symlink" >&2; exit 2; fi; `+
			`PERM=$(stat -c '%%a' %s); `+
			`TMP=%s.tmp.$$; `+
			`cat > "$TMP"; `+
			`chmod "$PERM" "$TMP"; `+
			`mv "$TMP" %s`,
		q, q, q, q,
	)
	_, stderr, err = runRemoteScript(ctx, cli, script, content)
	return stderr, err
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
// The session is force-closed after vaultRunTimeout to keep a stuck
// remote shell from hanging the request. ctx cancellation also kills
// the session promptly.
func runRemoteScript(ctx context.Context, cli *ssh.Client, script, stdin string) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(ctx, vaultRunTimeout)
	defer cancel()
	sess, err := cli.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	var so, se bytes.Buffer
	sess.Stdout = &so
	sess.Stderr = &se
	if stdin != "" {
		sess.Stdin = bytes.NewBufferString(stdin)
	}
	cmd := "/usr/bin/env bash -c " + shellQuote(script)
	if err := sess.Start(cmd); err != nil {
		return "", "", fmt.Errorf("start command: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case runErr := <-done:
		return so.String(), strings.TrimSpace(se.String()), runErr
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = sess.Close()
			<-done
		}
		return so.String(), strings.TrimSpace(se.String()), ctx.Err()
	}
}
