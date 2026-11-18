// Package sshpool maintains one cached *ssh.Client per configured server
// so we don't pay the TCP + handshake cost on every API request.
//
// Auth is intentionally narrow: SSH agent (if $SSH_AUTH_SOCK is set), or a
// private key file. Password auth is not supported — keys are the correct
// posture for automation, and SonarQube flags password prompts as hotspots.
package sshpool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Pool caches clients keyed by server id.
type Pool struct {
	mu       sync.Mutex
	clients  map[string]*entry
	dialLock map[string]*sync.Mutex
}

type entry struct {
	client *ssh.Client
	cfg    config.Server
}

// New constructs an empty pool.
func New() *Pool {
	return &Pool{
		clients:  make(map[string]*entry),
		dialLock: make(map[string]*sync.Mutex),
	}
}

// Client returns a live ssh.Client for the given server, dialing if
// necessary. Callers must not Close() the returned client — the pool
// owns it.
//
// The map mutex is only held for quick lookups / installs. Dialing
// happens under a per-server mutex so a slow handshake to server A
// does not block callers who need a cached client to server B.
func (p *Pool) Client(ctx context.Context, srv config.Server) (*ssh.Client, error) {
	if cli, ok := p.cached(srv); ok {
		return cli, nil
	}
	dl := p.dialMutexFor(srv.ID)
	dl.Lock()
	defer dl.Unlock()
	// Re-check: another caller may have raced us into the dial section.
	if cli, ok := p.cached(srv); ok {
		return cli, nil
	}
	p.Drop(srv.ID)
	cli, err := dial(ctx, srv)
	if err != nil {
		return nil, err
	}
	p.install(srv, cli)
	return cli, nil
}

func (p *Pool) cached(srv config.Server) (*ssh.Client, bool) {
	p.mu.Lock()
	e, ok := p.clients[srv.ID]
	if !ok || !sameAuth(e.cfg, srv) {
		p.mu.Unlock()
		return nil, false
	}
	cli := e.client
	// pingClient may block on a dead socket; drop the map mutex for
	// the duration so other server ids keep moving.
	p.mu.Unlock()
	if !pingClient(cli) {
		return nil, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Confirm the entry didn't get swapped while we were unlocked.
	cur, ok := p.clients[srv.ID]
	if !ok || cur.client != cli {
		return nil, false
	}
	return cli, true
}

func (p *Pool) install(srv config.Server, cli *ssh.Client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if old, ok := p.clients[srv.ID]; ok {
		_ = old.client.Close()
	}
	p.clients[srv.ID] = &entry{client: cli, cfg: srv}
}

func (p *Pool) dialMutexFor(id string) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()
	if m, ok := p.dialLock[id]; ok {
		return m
	}
	m := &sync.Mutex{}
	p.dialLock[id] = m
	return m
}

// Drop closes and evicts a cached client, e.g. after its auth changes.
func (p *Pool) Drop(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.clients[id]; ok {
		_ = e.client.Close()
		delete(p.clients, id)
	}
}

// Close terminates every cached client. Safe to call on shutdown.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, e := range p.clients {
		_ = e.client.Close()
		delete(p.clients, id)
	}
}

// Bounds for Run. Output is collected in memory per call, and the
// callers are HTTP handlers — an unbounded buffer let one verbose
// remote command (or a hostile control node) grow the heap without
// limit, and no deadline meant a stalled command pinned the handler
// goroutine forever. 8 MiB comfortably covers a large ansible
// inventory JSON; commands with bigger output should stream instead.
const (
	runMaxStdout      = 8 << 20
	runMaxStderr      = 256 << 10
	runDefaultTimeout = 2 * time.Minute
)

// cappedBuffer fails the write (rather than truncating) once the cap
// is hit: partial JSON is useless to every Run caller, and the write
// error aborts the SSH session's copy loop so the remote command is
// torn down instead of continuing to stream into a void.
type cappedBuffer struct {
	name string
	max  int
	buf  bytes.Buffer
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.max {
		return 0, fmt.Errorf("remote %s exceeded %d bytes — aborting", b.name, b.max)
	}
	return b.buf.Write(p)
}

// runSem bounds simultaneous Run invocations process-wide. Each call
// holds an SSH session plus up to ~8.25 MiB of buffers, and the
// callers are the metadata endpoints (inventory, facts, playbooks,
// vault, connection test) — per-call caps alone still let a request
// burst from an allowlisted client multiply into process-exhausting
// aggregate usage. Excess callers queue here (bounded by their own
// ctx / the default deadline) rather than erroring, since metadata
// bursts are typically short page-load fan-outs.
var runSem = make(chan struct{}, 16)

// Run opens a session, runs cmd, and returns stdout/stderr. The run
// is cancelled when ctx ends and always bounded by runDefaultTimeout;
// stdout/stderr are capped (see cappedBuffer) and total concurrency
// is bounded by runSem.
func Run(ctx context.Context, client *ssh.Client, cmd string) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(ctx, runDefaultTimeout)
	defer cancel()
	return RunStdin(ctx, client, cmd, nil)
}

// RunStdin is Run with a stdin stream attached, for commands that
// take input the way the vault helpers pipe a password rather than
// putting it in argv. It applies the same output caps and the same
// process-wide runSem admission as Run.
//
// Unlike Run it imposes NO default deadline: its callers already own
// bounds that differ by an order of magnitude (30s for an
// ansible-vault invocation, 5 minutes for an atomic inventory write),
// and clamping them to runDefaultTimeout would fail long writes. The
// caller is therefore responsible for supplying a ctx with a
// deadline — without one a stalled remote command holds a session and
// a semaphore slot until the client disconnects.
func RunStdin(ctx context.Context, client *ssh.Client, cmd string, stdin io.Reader) (stdout, stderr string, err error) {
	// Checked before the select below, not just inside it: when the
	// context is already done AND a semaphore slot is free, both
	// cases are ready and Go picks one at random, so an abandoned
	// request could still open a session and fire a command at the
	// control node. Testing ctx first makes the abort deterministic.
	if err := ctx.Err(); err != nil {
		return "", "", fmt.Errorf("waiting for an SSH query slot: %w", err)
	}
	select {
	case runSem <- struct{}{}:
		defer func() { <-runSem }()
	case <-ctx.Done():
		return "", "", fmt.Errorf("waiting for an SSH query slot: %w", ctx.Err())
	}
	so := &cappedBuffer{name: "stdout", max: runMaxStdout}
	se := &cappedBuffer{name: "stderr", max: runMaxStderr}
	err = Stream(ctx, client, cmd, stdin, so, se)
	return so.buf.String(), se.buf.String(), err
}

// Stream opens a session and runs cmd, forwarding stdout and stderr to
// the supplied writers line-by-line. If stdin is non-nil it's wired to
// the session's stdin — used for piping vault passwords without putting
// them in argv; pass nil for commands that don't need input. The
// session is aborted if ctx is cancelled.
func Stream(ctx context.Context, client *ssh.Client, cmd string, stdin io.Reader, stdout, stderr io.Writer) error {
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	if stdin != nil {
		sess.Stdin = stdin
	}
	sess.Stdout = stdout
	sess.Stderr = stderr
	if err := sess.Start(cmd); err != nil {
		return fmt.Errorf("start command: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGTERM)
		// If the remote ignores SIGTERM we'd park forever on
		// <-done; force the session shut after a short grace so
		// Wait() returns and we don't leak a goroutine.
		// Wait's own error is deliberately dropped on both receives
		// below: the caller is told the run was cancelled (ctx.Err()),
		// which is the cause; the receive only confirms Wait returned.
		select {
		case <-done: //nolint:errcheck // superseded by ctx.Err()
		case <-time.After(2 * time.Second):
			_ = sess.Close()
			<-done //nolint:errcheck // superseded by ctx.Err()
		}
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func dial(ctx context.Context, srv config.Server) (*ssh.Client, error) {
	// Checked here as well as when a record is saved: a record stored
	// by an older release, or edited into config.json by hand, never
	// went through that check, and the host is about to be written
	// into known_hosts.
	if err := config.ValidateServerHost(srv.Host); err != nil {
		return nil, fmt.Errorf("this connection's host cannot be used: %w — edit the connection", err)
	}
	auth, cleanup, err := buildAuth(srv)
	if err != nil {
		// buildAuth may have registered a cleanup before the
		// failing branch (e.g. agent socket dial succeeded but
		// loadKey failed afterwards in a future code path). Run
		// it now so we don't leak in the error path.
		cleanup()
		return nil, err
	}
	// Auth methods only need their backing resources during
	// ssh.NewClientConn (the handshake). Once that returns we own
	// an authenticated *ssh.Client and the agent socket / etc. is
	// dead weight. cleanup runs after the handshake completes
	// (success or failure).
	defer cleanup()
	cfg := &ssh.ClientConfig{
		User:            srv.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback(srv),
		Timeout:         10 * time.Second,
	}
	addr := net.JoinHostPort(srv.Host, portOrDefault(srv.Port))
	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	// cfg.Timeout bounds the TCP connect but NOT the SSH handshake:
	// ssh.NewClientConn on an already-open conn ignores it, so a peer
	// that accepts the socket and then stalls the banner/kex exchange
	// (a wedged or malicious control node) would block here forever.
	// A raw-conn deadline caps the whole handshake; we clear it after
	// so it doesn't leak onto the live session's reads/writes.
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func portOrDefault(p int) string {
	if p <= 0 {
		return "22"
	}
	return fmt.Sprintf("%d", p)
}

// buildAuth returns the SSH auth methods configured for srv plus a
// cleanup function the caller must run after the handshake completes
// (regardless of outcome). Cleanup closes any socket / file the
// methods opened — currently the unix-domain socket to ssh-agent.
// Without this, every dial leaked one socket connection because
// agent.Client has no Close() and the goroutine sitting on the FD
// outlived the *ssh.Client it served.
func buildAuth(srv config.Server) ([]ssh.AuthMethod, func(), error) {
	var methods []ssh.AuthMethod
	var cleanups []func()
	cleanup := func() {
		for _, c := range cleanups {
			c()
		}
	}
	if srv.KeyPath != "" {
		signer, err := loadKey(srv.KeyPath)
		if err != nil {
			return nil, cleanup, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			cleanups = append(cleanups, func() { _ = conn.Close() })
			methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}
	if len(methods) == 0 {
		return nil, cleanup, errors.New("no SSH auth available: set keyPath or run an ssh-agent")
	}
	return methods, cleanup, nil
}

func loadKey(path string) (ssh.Signer, error) {
	expanded := expandHome(path)
	data, err := os.ReadFile(expanded)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse key %s: %w (encrypted keys aren't supported; add to an ssh-agent instead)", path, err)
	}
	return signer, nil
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// hostKeyCallback returns a verifying callback. The default path is
// strict verification against ~/.ssh/known_hosts with TOFU on the
// first sighting of a host (knownHostsCallback creates the file +
// appends new keys; existing-key mismatches are a hard fail).
//
// If we genuinely can't establish that path — no home dir, can't
// create ~/.ssh, can't initialise the strict callback — we now
// fail closed by returning an error-returning callback. The
// previous behaviour silently degraded to InsecureIgnoreHostKey,
// which made MITM possible without any operator notice.
//
// The escape hatch is a single env var, ANSBUI_INSECURE_SSH=1: an
// operator working in a known-trusted lab who *wants* to skip
// verification can opt in explicitly. It logs once at startup so
// the choice can't be made by accident in a deployment script.
func hostKeyCallback(_ config.Server) ssh.HostKeyCallback {
	if insecureSSHEnabled() {
		return ssh.InsecureIgnoreHostKey() //nolint:gosec // explicit opt-in via env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return failClosedCallback(fmt.Errorf("resolve home dir: %w", err))
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return failClosedCallback(fmt.Errorf("create ~/.ssh: %w", err))
	}
	known := filepath.Join(sshDir, "known_hosts")
	strict, err := knownHostsCallback(known)
	if err != nil {
		return failClosedCallback(fmt.Errorf("init known_hosts callback: %w", err))
	}
	return strict
}

// failClosedCallback is invoked at dial time when host-key
// verification can't be set up. ssh.HostKeyCallback has no error
// channel of its own, so we surface the failure on every dial —
// the operator gets a clear "host key verification not available"
// instead of a silent insecure fallback.
func failClosedCallback(reason error) ssh.HostKeyCallback {
	return func(string, net.Addr, ssh.PublicKey) error {
		return fmt.Errorf("host key verification unavailable: %w (set ANSBUI_INSECURE_SSH=1 to skip verification, NOT recommended)", reason)
	}
}

var insecureSSHWarned sync.Once

func insecureSSHEnabled() bool {
	v := strings.TrimSpace(os.Getenv("ANSBUI_INSECURE_SSH"))
	if v != "1" && !strings.EqualFold(v, "true") {
		return false
	}
	insecureSSHWarned.Do(func() {
		fmt.Fprintln(os.Stderr, "⚠  ANSBUI_INSECURE_SSH is set: SSH host keys will NOT be verified. MITM attacks are undetectable in this mode — unset for any non-lab deployment.")
	})
	return true
}

// pingHealthTimeout bounds a liveness probe. cached() runs pingClient
// while holding the per-server dial mutex, so an unbounded probe on a
// dead-but-open TCP connection (SendRequest blocks until the kernel
// gives up, ~15 min) would stall every other caller for that server
// behind the mutex. A few seconds is ample on a healthy link.
const pingHealthTimeout = 5 * time.Second

func pingClient(c *ssh.Client) bool {
	if c == nil {
		return false
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := c.SendRequest("keepalive@ansbui", true, nil)
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(pingHealthTimeout):
		// Treat a hung probe as dead: the caller drops the cached
		// client and dials fresh. The stuck goroutine drains into the
		// buffered channel and exits when the conn eventually errors.
		return false
	}
}

func sameAuth(a, b config.Server) bool {
	return a.Host == b.Host && a.Port == b.Port && a.User == b.User && a.KeyPath == b.KeyPath
}
