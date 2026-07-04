package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// targetSession is an SSH connection to a freshly-supplied server.
// Auth is password-only (we typically don't have a key on the box
// yet), and host-key verification is intentionally disabled — the
// whole point of bootstrap is the operator's first contact with
// the machine, before any key is on record.
type targetSession struct {
	client        *ssh.Client
	sudoPassword  string
	stopKeepalive func()
}

// dialPasswordTarget opens an SSH connection to host:port, with
// password auth. sudoPassword == "" means the user is root and no
// sudo wrapping is needed; otherwise runRoot will prefix commands
// with `sudo -S` and feed the password on stdin.
func dialPasswordTarget(ctx context.Context, host string, port int, user, password, sudoPassword string) (*targetSession, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // first-contact bootstrap — see package doc
		Timeout:         15 * time.Second,
	}
	return dialTargetWithConfig(ctx, host, port, sudoPassword, cfg)
}

// dialKeyTarget opens an SSH connection to host:port as root using
// the supplied OpenSSH private key bytes. Used by the post-reinstall
// reconnect: reinstall.sh has installed the public counterpart into
// the freshly-installed system's /root/.ssh/authorized_keys, sshd is
// already listening on the requested port, and we need to drive the
// rest of the bootstrap steps (ansible user setup, sshd flip if
// not already on 4242, inventory edit) from this new session.
//
// Host-key verification is still disabled — the reinstall replaces
// the host's keys, so any pin we'd cached pre-reinstall is now
// stale, and there's no safe way to know the new fingerprint
// without an out-of-band channel.
func dialKeyTarget(ctx context.Context, host string, port int, privKey []byte) (*targetSession, error) {
	signer, err := ssh.ParsePrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	cfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // post-reinstall — see comment above
		Timeout:         15 * time.Second,
	}
	return dialTargetWithConfig(ctx, host, port, "", cfg)
}

// dialTargetWithConfig is the shared dial path. Centralising
// keeps dialPasswordTarget and dialKeyTarget bit-identical apart
// from the auth method.
func dialTargetWithConfig(ctx context.Context, host string, port int, sudoPassword string, cfg *ssh.ClientConfig) (*targetSession, error) {
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
	client := ssh.NewClient(sshConn, chans, reqs)
	return &targetSession{
		client:        client,
		sudoPassword:  sudoPassword,
		stopKeepalive: startSSHKeepalive(client),
	}, nil
}

// Keepalive cadence for target sessions. 30s between probes keeps
// NAT/firewall idle timers from expiring during quiet stretches;
// 15s is ample for a reply on any connection that's actually alive.
const (
	sshKeepaliveInterval     = 30 * time.Second
	sshKeepaliveReplyTimeout = 15 * time.Second
)

// startSSHKeepalive pings the SSH connection until the returned
// stop func is called, and force-closes the client when a ping goes
// unanswered. Bootstrap sessions block in sess.Wait() for minutes
// at a time (reinstall.sh prep, apt runs) with no read deadline and
// no job-level timeout — without this, a NAT-dropped connection
// left the whole run hung forever while the heartbeat kept
// printing "still running". Closing the client makes the blocked
// Wait() return an error the orchestrator reports like any other
// step failure.
//
// The stop func is idempotent and safe to call concurrently.
func startSSHKeepalive(client *ssh.Client) func() {
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(sshKeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if !keepaliveAnswered(client, stop) {
					_ = client.Close()
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stop) }) }
}

// keepaliveAnswered sends one keepalive request and reports whether
// the peer replied in time. The send runs in its own goroutine
// because SendRequest on a dead-but-not-closed TCP connection can
// block until the kernel gives up — far longer than we're willing
// to wait. A stop signal counts as answered so session close
// doesn't race a false negative.
func keepaliveAnswered(client *ssh.Client, stop <-chan struct{}) bool {
	done := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(sshKeepaliveReplyTimeout):
		return false
	case <-stop:
		return true
	}
}

// Close shuts the underlying SSH client and its keepalive loop.
func (s *targetSession) Close() error {
	if s.stopKeepalive != nil {
		s.stopKeepalive()
	}
	if s.client == nil {
		return nil
	}
	return s.client.Close()
}

// runRoot runs cmd with root privileges and returns stdout +
// trimmed stderr. If the session is non-root and a sudo password
// was supplied, cmd is wrapped by sudoWrapper — see there for the
// authentication scheme and the two failure modes it defends
// against.
func (s *targetSession) runRoot(ctx context.Context, cmd, stdin string) (stdout, stderr string, err error) {
	if s.sudoPassword == "" {
		return s.run(ctx, cmd, stdin)
	}
	return s.run(ctx, sudoWrapper(cmd), s.sudoPassword+"\n"+stdin)
}

// sudoWrapper wraps cmd so a non-root session can run it as root,
// with the operator's sudo password arriving as the first line of
// stdin. Two constraints shape it:
//
//   - The sudo that authenticates must BE the sudo that runs the
//     command. On default sudoers with no TTY (our ssh exec
//     channel), credential tickets are keyed on the calling
//     process's ppid — an earlier design validated with
//     `sudo -S -v` inside a pipeline and then `exec sudo bash -c`,
//     two invocations with different ppids, so the exec'd sudo
//     never found the cached ticket and died "a terminal is
//     required". The cold path below is a single `sudo -k -S`
//     that reads the password and runs the command itself; ticket
//     keying can't matter.
//
//   - The inner command's stdin must never see the sudo password.
//     The wrapper always consumes line 1 into a variable first. On
//     the cold path it is re-fed to sudo -S through the pipe ahead
//     of the remaining stdin (`-k` guarantees sudo reads exactly
//     that line — without it, a cache warmed between check and run
//     would leave the password line for the inner command, which
//     once landed operators' sudo passwords in /etc/shadow via
//     chpasswd). On the warm/NOPASSWD path (`sudo -n true`
//     succeeds) sudo touches nothing and the remaining stdin flows
//     to the inner command directly; `-n` on the exec'd sudo makes
//     a ticket-keying surprise fail fast instead of hanging on a
//     prompt that can never be answered.
func sudoWrapper(cmd string) string {
	q := shellQuote(cmd)
	return `set -e; IFS= read -r SUDO_PW; ` +
		`if sudo -n true 2>/dev/null; then unset SUDO_PW; exec sudo -n bash -c ` + q + `; fi; ` +
		`{ printf '%s\n' "$SUDO_PW"; unset SUDO_PW; cat; } | sudo -k -S -p '' bash -c ` + q
}

// requireSudo probes the target to confirm `sudo` is on PATH for
// non-root operator accounts. We bypass runRoot's sudo wrapper for
// the probe — wrapping it in sudo would mask the real failure mode
// ("sudo not installed") with a generic SSH-exit error. Returns a
// clear, operator-actionable message when missing so the form
// doesn't silently fail at the first orchestrator step.
//
// Root sessions skip the check entirely — they don't need sudo.
func (s *targetSession) requireSudo(ctx context.Context) error {
	if s.sudoPassword == "" {
		return nil
	}
	if _, _, err := s.run(ctx, "command -v sudo >/dev/null 2>&1", ""); err != nil {
		return fmt.Errorf("the `sudo` binary isn't on the target user's PATH — connect as root for first-time bootstrap so the orchestrator can apt-install sudo, then re-run as the ansible user. (sudoers membership is checked separately by the first elevated command.)")
	}
	return nil
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

// shellQuotePath is shellQuote with leading tilde expansion. The
// shell only expands `~` on UNQUOTED leading tildes, so naive
// quoting of `~/.ssh/ansible_ed25519` produces a literal path and
// `cat` fails with "No such file or directory". We split off the
// tilde and emit `"$HOME/"` (double-quoted so $HOME expands)
// concatenated with the single-quoted suffix — gives the same
// metacharacter safety as shellQuote without breaking tilde paths
// the operator entered in the settings field.
func shellQuotePath(p string) string {
	if p == "~" {
		return `"$HOME"`
	}
	if strings.HasPrefix(p, "~/") {
		return `"$HOME"/` + shellQuote(p[2:])
	}
	return shellQuote(p)
}
