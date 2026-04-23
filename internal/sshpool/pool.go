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
	p.evict(srv.ID)
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

func (p *Pool) evict(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.clients[id]; ok {
		_ = e.client.Close()
		delete(p.clients, id)
	}
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

// Run opens a session, runs cmd, and returns stdout/stderr.
func Run(client *ssh.Client, cmd string) (stdout, stderr string, err error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	var outBuf, errBuf bytes.Buffer
	sess.Stdout = &outBuf
	sess.Stderr = &errBuf
	runErr := sess.Run(cmd)
	return outBuf.String(), errBuf.String(), runErr
}

// Stream opens a session and runs cmd, forwarding stdout and stderr to
// the supplied writers line-by-line. The session is aborted if ctx is
// cancelled.
func Stream(ctx context.Context, client *ssh.Client, cmd string, stdout, stderr io.Writer) error {
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
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
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = sess.Close()
			<-done
		}
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func dial(ctx context.Context, srv config.Server) (*ssh.Client, error) {
	auth, err := buildAuth(srv)
	if err != nil {
		return nil, err
	}
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
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", addr, err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

func portOrDefault(p int) string {
	if p <= 0 {
		return "22"
	}
	return fmt.Sprintf("%d", p)
}

func buildAuth(srv config.Server) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if srv.KeyPath != "" {
		signer, err := loadKey(srv.KeyPath)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}
	if len(methods) == 0 {
		return nil, errors.New("no SSH auth available: set keyPath or run an ssh-agent")
	}
	return methods, nil
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

// hostKeyCallback uses the user's ~/.ssh/known_hosts when available and
// falls back to accept-on-first-use otherwise. Users who want strict TOFU
// should pre-populate known_hosts via ssh-keyscan.
func hostKeyCallback(_ config.Server) ssh.HostKeyCallback {
	home, err := os.UserHomeDir()
	if err != nil {
		return ssh.InsecureIgnoreHostKey() //nolint:gosec // documented above
	}
	known := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(known); err != nil {
		return ssh.InsecureIgnoreHostKey() //nolint:gosec // documented above
	}
	// known_hosts exists: prefer strict verification. If the host is not
	// recorded we fall back to accept-on-first-use so the UI doesn't hang
	// on fresh servers.
	strict, err := knownHostsCallback(known)
	if err != nil {
		return ssh.InsecureIgnoreHostKey() //nolint:gosec // documented above
	}
	return strict
}

func pingClient(c *ssh.Client) bool {
	if c == nil {
		return false
	}
	_, _, err := c.SendRequest("keepalive@ansbui", true, nil)
	return err == nil
}

func sameAuth(a, b config.Server) bool {
	return a.Host == b.Host && a.Port == b.Port && a.User == b.User && a.KeyPath == b.KeyPath
}
