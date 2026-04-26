package provision

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// targetSession is an SSH connection to a freshly-supplied server.
// Auth is password-only (we typically don't have a key on the box
// yet), and host-key verification is intentionally disabled — the
// whole point of provisioning is the operator's first contact with
// the machine, before any key is on record.
type targetSession struct {
	client       *ssh.Client
	sudoPassword string
}

// dialPasswordTarget opens an SSH connection to host:port, with
// password auth. sudoPassword == "" means the user is root and no
// sudo wrapping is needed; otherwise runRoot will prefix commands
// with `sudo -S` and feed the password on stdin.
func dialPasswordTarget(ctx context.Context, host string, port int, user, password, sudoPassword string) (*targetSession, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // first-contact provisioning — see package doc
		Timeout:         15 * time.Second,
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", addr, err)
	}
	return &targetSession{
		client:       ssh.NewClient(sshConn, chans, reqs),
		sudoPassword: sudoPassword,
	}, nil
}

// Close shuts the underlying SSH client.
func (s *targetSession) Close() error {
	if s.client == nil {
		return nil
	}
	return s.client.Close()
}

// runRoot runs cmd with root privileges and returns stdout +
// trimmed stderr. If the session is non-root and a sudo password
// was supplied, the sudo handshake is decoupled from the inner
// command's stdin so a warm sudo cache can't desync the password
// stream:
//
//   - the operator's sudo password is the first line of stdin,
//     read by the wrapper into a shell variable
//   - that variable is fed into `sudo -S -p '' -v` via printf and
//     a fresh pipe — sudo only reads from this pipe when it
//     actually prompts, so a cache-warm `sudo -nv` no-ops without
//     touching the outer SSH stdin
//   - the wrapper then `exec sudo bash -c '<cmd>'`, replacing
//     itself with sudo. The remaining stdin (everything after
//     line 1) flows through unmolested into the inner command,
//     which can `read -r` its own secrets without contention
//
// Without that decoupling, a warm sudo cache would skip the
// password prompt, leaving `<sudo-pw>\n` in stdin — the inner
// command's `read -r` would then consume the operator's sudo
// password, e.g. as the new ansible user's password. That landed
// the operator's sudo password in /etc/shadow on every target
// box; this rewrite eliminates that path.
func (s *targetSession) runRoot(ctx context.Context, cmd, stdin string) (stdout, stderr string, err error) {
	if s.sudoPassword == "" {
		return s.run(ctx, cmd, stdin)
	}
	wrapper := `set -e; IFS= read -r SUDO_PW; printf '%s\n' "$SUDO_PW" | sudo -S -p '' -v; unset SUDO_PW; exec sudo bash -c ` + shellQuote(cmd)
	return s.run(ctx, wrapper, s.sudoPassword+"\n"+stdin)
}

// run executes cmd with the given stdin. Returns stdout + trimmed
// stderr + the underlying error.
func (s *targetSession) run(ctx context.Context, cmd, stdin string) (string, string, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	var so, se bytes.Buffer
	sess.Stdout = &so
	sess.Stderr = &se
	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}
	if err := sess.Start(cmd); err != nil {
		return "", "", fmt.Errorf("start: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case e := <-done:
		return so.String(), strings.TrimSpace(se.String()), e
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

// shellQuote single-quotes s for safe embedding inside another
// shell command. Mirrors internal/ansible.shellQuote — duplicated
// because the ansible package's helper is unexported and reaching
// in just for this would be uglier.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
