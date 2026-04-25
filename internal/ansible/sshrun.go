package ansible

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

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
