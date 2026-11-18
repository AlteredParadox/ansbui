package bootstrap

import (
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
// yet). Host-key verification is trust-on-first-use by default —
// bootstrap is the operator's first contact with the machine, before
// any key is on record — but every accepted key's fingerprint is
// recorded (hostKeyFP) so the orchestrator can surface it loudly,
// and the operator can pin an expected fingerprint up front via the
// form (Request.HostKeyFingerprint), which turns a mismatch into a
// hard dial failure instead of a silent MITM.
type targetSession struct {
	client        *ssh.Client
	sudoPassword  string
	hostKeyFP     string // SHA256:… fingerprint of the accepted host key
	stopKeepalive func()
}

// fingerprint returns the SHA256 fingerprint of the host key this
// session accepted during its handshake.
func (s *targetSession) fingerprint() string { return s.hostKeyFP }

// normalizeFingerprint canonicalises an operator-entered SHA256 host
// key fingerprint to the exact form ssh.FingerprintSHA256 emits:
// surrounding space trimmed, "SHA256:" prefix ensured, base64 padding
// stripped (OpenSSH prints it unpadded; operators often paste a
// padded variant). Empty input stays empty (no pin).
func normalizeFingerprint(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "SHA256:") {
		s = "SHA256:" + s
	}
	return strings.TrimRight(s, "=")
}

// hostKeyExpectation is what a target dial requires of the host key
// the peer presents. It pairs a pinned/stored fingerprint with a
// human-readable description of its origin, so a mismatch error can
// tell the operator the right remediation. The zero value means "no
// expectation, nothing to record" — accept whatever is presented.
type hostKeyExpectation struct {
	fp  string // normalized SHA256:… fingerprint, "" for none
	src string // e.g. "the operator-pinned fingerprint"

	// accept, when set, is called with the fingerprint of a key that
	// passed the check against fp (or any key at all when fp is
	// empty). It runs inside the key exchange, so an error from it
	// aborts the handshake BEFORE SSH auth: no password is sent to a
	// peer whose acceptance could not be made durable. See
	// hostKeyRecorder for why that ordering matters.
	accept func(fp string) error
}

// recordFingerprintCallback builds the HostKeyCallback for target
// dials. It always writes the presented key's fingerprint into
// *observed. When expect.fp is non-empty (an operator-supplied pin or
// a TOFU-store record, already normalized) it rejects any other key.
// A key that gets past that is handed to expect.accept, whose error
// rejects it too. All of this happens BEFORE any credential is
// transmitted — the callback runs during key exchange, ahead of SSH
// auth. With a zero expectation the callback accepts anything; only
// the post-reinstall dials use that (see tryInstallerDone).
func recordFingerprintCallback(expect hostKeyExpectation, observed *string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		*observed = fp
		if expect.fp != "" && fp != expect.fp {
			return fmt.Errorf("host key mismatch: target presented %s but %s expects %s — if the box was reinstalled or replaced out of band, supply its new fingerprint in the form to update the record; otherwise treat this as a possible MITM and verify via the provider console (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)", fp, expect.src, expect.fp)
		}
		if expect.accept != nil {
			return expect.accept(fp)
		}
		return nil
	}
}

// dialPasswordTarget opens an SSH connection to host:port, with
// password auth. sudoPassword == "" means the user is root and no
// sudo wrapping is needed; otherwise runRoot will prefix commands
// with `sudo -S` and feed the password on stdin. expect, when set,
// pins the host key (see recordFingerprintCallback).
func dialPasswordTarget(ctx context.Context, host string, port int, user, password, sudoPassword string, expect hostKeyExpectation) (*targetSession, error) {
	cfg := &ssh.ClientConfig{
		User:    user,
		Auth:    []ssh.AuthMethod{ssh.Password(password)},
		Timeout: 15 * time.Second,
	}
	return dialTargetWithConfig(ctx, host, port, sudoPassword, expect, cfg)
}

// dialKeyTarget opens an SSH connection to host:port as root using
// the supplied OpenSSH private key bytes. Used by the post-reinstall
// reconnect: reinstall.sh has installed the public counterpart into
// the freshly-installed system's /root/.ssh/authorized_keys, sshd is
// already listening on the requested port, and we need to drive the
// rest of the bootstrap steps (ansible user setup, sshd flip if
// not already on 4242, inventory edit) from this new session.
//
// The reinstall replaces the host's keys, so no pin from before it
// can cover the first post-reinstall dial and expect is empty there
// (TOFU, with a loud warning from the caller). `expect` is a real
// parameter rather than a hard-coded empty value so that every call
// site has to state its choice. Both post-reinstall retry loops pass
// an empty one on every dial, deliberately: they span the handover
// from the installer's ephemeral key to the installed system's, so
// the key seen on an early retry is not the one a later retry should
// see (tryInstallerDone, tryReinstallReady). The control for that
// window is that a strict-mode deployment refuses the whole reinstall
// up front (see requireHostKeyEnv) rather than silently trusting a
// replacement key here.
func dialKeyTarget(ctx context.Context, host string, port int, privKey []byte, expect hostKeyExpectation) (*targetSession, error) {
	signer, err := ssh.ParsePrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	cfg := &ssh.ClientConfig{
		User:    "root",
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(signer)},
		Timeout: 15 * time.Second,
	}
	return dialTargetWithConfig(ctx, host, port, "", expect, cfg)
}

// dialTargetWithConfig is the shared dial path. Centralising
// keeps dialPasswordTarget and dialKeyTarget bit-identical apart
// from the auth method. It owns the HostKeyCallback (recording +
// optional pin — see recordFingerprintCallback) so no dial can
// accidentally ship without at least fingerprint capture.
func dialTargetWithConfig(ctx context.Context, host string, port int, sudoPassword string, expect hostKeyExpectation, cfg *ssh.ClientConfig) (*targetSession, error) {
	var observedFP string
	cfg.HostKeyCallback = recordFingerprintCallback(expect, &observedFP)
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	// cfg.Timeout bounds the TCP connect but NOT the SSH handshake:
	// ssh.NewClientConn on an already-open conn ignores it, so a peer
	// that accepts the socket and never sends a banner would park the
	// bootstrap job forever (no job-level timeout exists). A raw-conn
	// deadline caps the whole handshake — mirrors sshpool.dial — and
	// is cleared afterwards so it doesn't leak onto session I/O.
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(sshConn, chans, reqs)
	return &targetSession{
		client:        client,
		sudoPassword:  sudoPassword,
		hostKeyFP:     observedFP,
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
		// Validate the password against an ISOLATED pipe first — only
		// the password, then EOF. On a wrong password sudo makes exactly
		// one PAM attempt and hits EOF; it cannot read into the payload
		// (the inner command's stdin, e.g. the generated ansible-user
		// password) as retry attempts. `set -e` aborts here on failure,
		// so the run below only executes once the password is known-good
		// — meaning sudo authenticates on its first attempt, consumes
		// exactly the password line, and the rest of stdin flows to the
		// inner command intact.
		`printf '%s\n' "$SUDO_PW" | sudo -k -S -p '' -v; ` +
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

// Bounds for target command execution. The target is the LEAST
// trusted machine ansbui talks to — a fresh box that could be
// stalled, hostile, or mid-compromise — so both the step duration
// and the buffered output must be capped here rather than trusted
// to callers:
//
//   - defaultStepTimeout applies only when the caller's ctx carries
//     no deadline of its own (the job ctx never does). Steps with a
//     real budget (reinstall prep's 15 minutes) keep it. Ten minutes
//     covers the slowest legitimate unbudgeted step — apt update+
//     install with retries on a loaded first boot — while ending a
//     stall well before it monopolises one of the four job slots
//     forever.
//   - output is kept in tail-keeping ring buffers instead of failing
//     on overflow (unlike sshpool.Run): bootstrap steps run for many
//     minutes and their output is only used for diagnostics and
//     tail-parsing, so aborting a 14-minute prep over verbose
//     progress spam would hurt more than bounding what we keep. The
//     tails are what parseReinstallNetInfo and the failure-detail
//     helpers read anyway.
const (
	defaultStepTimeout  = 10 * time.Minute
	targetStdoutMax     = 2 << 20
	targetStderrMax     = 256 << 10
	truncationNoticeFmt = "[output exceeded %d bytes — showing the most recent]\n"
)

// stepContext applies defaultStepTimeout unless ctx already carries
// a deadline. Split out so the policy is unit-testable.
func stepContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, defaultStepTimeout)
}

// tailBuffer keeps the most recent max bytes written to it, dropping
// the oldest on overflow. Not safe for concurrent use — each session
// wires one per stream.
type tailBuffer struct {
	max       int
	buf       []byte
	truncated bool
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if n >= b.max {
		b.buf = append(b.buf[:0], p[n-b.max:]...)
		b.truncated = true
		return n, nil
	}
	if drop := len(b.buf) + n - b.max; drop > 0 {
		b.buf = append(b.buf[:0], b.buf[drop:]...)
		b.truncated = true
	}
	b.buf = append(b.buf, p...)
	return n, nil
}

func (b *tailBuffer) String() string {
	if b.truncated {
		return fmt.Sprintf(truncationNoticeFmt, b.max) + string(b.buf)
	}
	return string(b.buf)
}

// outputWasTruncated reports whether a run() stdout/stderr string
// carries the tailBuffer truncation notice — i.e. the step's output
// exceeded the ring buffer and only the most recent bytes survive.
// Callers that parse positional content out of step output (e.g. the
// reinstall netinfo block, printed early) use this to know the front
// of the transcript is gone.
func outputWasTruncated(s string) bool {
	return strings.HasPrefix(s, "[output exceeded ")
}

// run executes cmd with the given stdin. Returns stdout + trimmed
// stderr + the underlying error. Execution is bounded in time and
// buffered output — see the constants above.
func (s *targetSession) run(ctx context.Context, cmd, stdin string) (string, string, error) {
	ctx, cancel := stepContext(ctx)
	defer cancel()
	sess, err := s.client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	so := &tailBuffer{max: targetStdoutMax}
	se := &tailBuffer{max: targetStderrMax}
	sess.Stdout = so
	sess.Stderr = se
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
		// Wait's own error is deliberately dropped on both receives
		// below: the step reports ctx.Err(), which is the cause; the
		// receive only confirms Wait returned.
		select {
		case <-done: //nolint:errcheck // superseded by ctx.Err()
		case <-time.After(2 * time.Second):
			_ = sess.Close()
			<-done //nolint:errcheck // superseded by ctx.Err()
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
