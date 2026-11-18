// ansbui — a single-binary web UI for an Ansible control node.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package sshpool

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Tests for Stream against SSH servers that authenticate and then stop
// answering. Each server behaviour below used to park the caller for
// as long as the peer kept the TCP connection open.

// peerBehaviour selects what the fake server does with a session.
type peerBehaviour int

const (
	// peerIgnoresChannelOpen never confirms or rejects the channel.
	peerIgnoresChannelOpen peerBehaviour = iota
	// peerIgnoresExec confirms the channel and never answers "exec".
	peerIgnoresExec
	// peerRunsForever answers exec, writes one line and then neither
	// exits nor reacts to signals.
	peerRunsForever
	// peerExitsZero answers exec, writes one line and exits 0.
	peerExitsZero
	// peerAnswersExecLate answers exec after lateReply, then behaves
	// like peerRunsForever.
	peerAnswersExecLate
	// peerAcceptsChannelLate confirms the channel after lateReply,
	// then behaves like peerExitsZero.
	peerAcceptsChannelLate
	// peerExitsOnSignal runs until it is sent a signal, then exits.
	peerExitsOnSignal
	// peerEchoesStdinToStderr copies stdin to stderr and exits 0.
	peerEchoesStdinToStderr
)

// lateReply is how long the "late" modes hold their answer.
const lateReply = 400 * time.Millisecond

// fakePeer is an in-process SSH server. It answers global requests
// (so a keepalive health ping passes) in every mode.
type fakePeer struct {
	addr   string
	execs  chan string   // commands that reached an exec request
	closed chan struct{} // one value per session channel the client closed
}

func startFakePeer(t *testing.T, mode peerBehaviour) *fakePeer {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &fakePeer{addr: ln.Addr().String(), execs: make(chan string, 16), closed: make(chan struct{}, 16)}
	var conns sync.Map
	t.Cleanup(func() {
		_ = ln.Close()
		conns.Range(func(k, _ any) bool {
			_ = k.(net.Conn).Close()
			return true
		})
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Store(conn, struct{}{})
			go p.serve(conn, cfg, mode)
		}
	}()
	return p
}

func (p *fakePeer) serve(conn net.Conn, cfg *ssh.ServerConfig, mode peerBehaviour) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer sconn.Close()
	go func() {
		for req := range reqs {
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}()
	var held []ssh.NewChannel // keeps unanswered opens reachable
	for nc := range chans {
		if mode == peerIgnoresChannelOpen {
			held = append(held, nc)
			continue
		}
		go func() {
			if mode == peerAcceptsChannelLate {
				time.Sleep(lateReply)
			}
			ch, chReqs, err := nc.Accept()
			if err != nil {
				return
			}
			p.session(ch, chReqs, mode)
		}()
	}
	_ = held
}

func (p *fakePeer) session(ch ssh.Channel, reqs <-chan *ssh.Request, mode peerBehaviour) {
	exit := func() {
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		_ = ch.Close()
	}
	// The request channel closes when the client closes the session.
	defer func() { p.closed <- struct{}{} }()
	for req := range reqs {
		if req.Type == "signal" && mode == peerExitsOnSignal {
			exit()
			continue
		}
		if req.Type != "exec" {
			// Includes "signal": ignored, like a process that traps TERM.
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		if mode == peerIgnoresExec {
			continue
		}
		if mode == peerAnswersExecLate {
			time.Sleep(lateReply)
		}
		var payload struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &payload)
		p.execs <- payload.Command
		_ = req.Reply(true, nil)
		switch mode {
		case peerEchoesStdinToStderr:
			go func() {
				_, _ = io.Copy(ch.Stderr(), ch)
				exit()
			}()
			continue
		case peerExitsZero, peerAcceptsChannelLate:
			_, _ = ch.Write([]byte("line one\n"))
			exit()
		default:
			_, _ = ch.Write([]byte("line one\n"))
		}
	}
}

// dialPeer connects to addr without host-key verification.
func dialPeer(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // loopback test server
		Timeout:         5 * time.Second,
	}
	cli, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial fake peer: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

// shortenPeerTimeouts makes the fixed peer timeouts test-sized and
// restores them afterwards.
func shortenPeerTimeouts(t *testing.T, open, term, closeAck time.Duration) {
	t.Helper()
	prev := currentPeerLimits.Swap(&peerLimits{sessionOpenTimeout: open, termGrace: term, closeAckTimeout: closeAck})
	t.Cleanup(func() { currentPeerLimits.Store(prev) })
}

// firstWrite closes seen on the first Write, so a test can wait until
// the command's output is flowing — i.e. the exec reply was processed
// and Stream is past its open phase.
type firstWrite struct {
	once sync.Once
	seen chan struct{}
}

func newFirstWrite() *firstWrite { return &firstWrite{seen: make(chan struct{})} }

func (w *firstWrite) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.seen) })
	return len(p), nil
}

func (w *firstWrite) wait(t *testing.T) {
	t.Helper()
	select {
	case <-w.seen:
	case <-time.After(5 * time.Second):
		t.Fatal("no output from the fake peer within 5s")
	}
}

// clientClosed reports whether cli's connection has ended within d.
func clientClosed(cli *ssh.Client, d time.Duration) bool {
	ended := make(chan struct{})
	go func() {
		_ = cli.Wait()
		close(ended)
	}()
	select {
	case <-ended:
		return true
	case <-time.After(d):
		return false
	}
}

// A peer that never answers channel-open must not hold the caller past
// its context, and must not keep a query slot.
func TestRunReturnsWithinContextWhenPeerIgnoresChannelOpen(t *testing.T) {
	shortenPeerTimeouts(t, 2*time.Second, 100*time.Millisecond, 200*time.Millisecond)
	peer := startFakePeer(t, peerIgnoresChannelOpen)
	cli := dialPeer(t, peer.addr)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := Run(ctx, cli, "true")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run error = %v, want context deadline exceeded", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("Run took %s against a 200ms context", took)
	}
	if n := len(runSem); n != 0 {
		t.Fatalf("runSem holds %d slots after Run returned, want 0", n)
	}
	// The connection is closed once the fixed open timeout passes, so
	// the parked channel-open goroutine cannot outlive it.
	if !clientClosed(cli, 5*time.Second) {
		t.Fatal("client still open after sessionOpenTimeout; the abandoned open was never reaped")
	}
}

// Without any caller deadline, the fixed timeout still ends the wait
// and names the peer as the cause.
func TestStreamOpenTimeoutClosesClient(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode peerBehaviour
	}{
		{"channel open unanswered", peerIgnoresChannelOpen},
		{"exec unanswered", peerIgnoresExec},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shortenPeerTimeouts(t, 300*time.Millisecond, 100*time.Millisecond, 200*time.Millisecond)
			peer := startFakePeer(t, tc.mode)
			cli := dialPeer(t, peer.addr)

			var out bytes.Buffer
			errCh := make(chan error, 1)
			go func() { errCh <- Stream(context.Background(), cli, "true", nil, &out, io.Discard) }()
			select {
			case err := <-errCh:
				if err == nil || !strings.Contains(err.Error(), "did not answer a session request") {
					t.Fatalf("Stream error = %v, want the session-request timeout", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Stream did not return after sessionOpenTimeout")
			}
			if !clientClosed(cli, 2*time.Second) {
				t.Fatal("client left open after a session request went unanswered")
			}
		})
	}
}

// A caller that gives up while the exec request is pending must not
// have its buffers written afterwards, and the command must not be
// left running if the peer answers late.
func TestStreamAbandonedDuringExecDoesNotTouchCallerBuffers(t *testing.T) {
	shortenPeerTimeouts(t, time.Second, 100*time.Millisecond, 200*time.Millisecond)
	peer := startFakePeer(t, peerIgnoresExec)
	cli := dialPeer(t, peer.addr)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	out := &cappedBuffer{name: "stdout", max: 1 << 10}
	err := Stream(ctx, cli, "true", strings.NewReader("secret\n"), out, io.Discard)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stream error = %v, want context deadline exceeded", err)
	}
	// Reading the buffer here races any write that slipped past the
	// gate; the race detector is the assertion.
	if got := out.buf.String(); got != "" {
		t.Fatalf("stdout = %q after an abandoned open", got)
	}
	if !clientClosed(cli, 5*time.Second) {
		t.Fatal("client still open after the abandoned exec timed out")
	}
}

// A healthy peer is unaffected: output arrives and the client stays
// usable for the next command.
func TestStreamHealthyPeer(t *testing.T) {
	peer := startFakePeer(t, peerExitsZero)
	cli := dialPeer(t, peer.addr)
	for i := range 3 {
		stdout, _, err := Run(context.Background(), cli, "echo hi")
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if stdout != "line one\n" {
			t.Fatalf("run %d stdout = %q", i, stdout)
		}
	}
	if got := <-peer.execs; got != "echo hi" {
		t.Fatalf("peer saw command %q", got)
	}
	if clientClosed(cli, 200*time.Millisecond) {
		t.Fatal("client closed after healthy runs")
	}
}

// Cancelling a command the peer keeps running closes the channel, and
// the client survives because the peer acknowledged the close.
func TestStreamCancelKeepsClientWhenPeerAcknowledgesClose(t *testing.T) {
	shortenPeerTimeouts(t, 2*time.Second, 100*time.Millisecond, 2*time.Second)
	peer := startFakePeer(t, peerRunsForever)
	cli := dialPeer(t, peer.addr)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	out := newFirstWrite()
	go func() { errCh <- Stream(ctx, cli, "sleep infinity", nil, out, io.Discard) }()
	out.wait(t)
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Stream error = %v, want context canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stream did not return after cancel")
	}
	if clientClosed(cli, 300*time.Millisecond) {
		t.Fatal("client closed although the peer acknowledged the channel close")
	}
}

// freezableRelay forwards TCP between a client and addr until freeze
// is called, after which bytes in both directions are swallowed and
// the connections stay open — a peer that has gone silent without
// closing the socket.
type freezableRelay struct {
	addr   string
	mu     sync.Mutex
	frozen bool
}

func (r *freezableRelay) freeze() {
	r.mu.Lock()
	r.frozen = true
	r.mu.Unlock()
}

func (r *freezableRelay) isFrozen() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.frozen
}

func startFreezableRelay(t *testing.T, target string) *freezableRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	r := &freezableRelay{addr: ln.Addr().String()}
	var conns sync.Map
	t.Cleanup(func() {
		_ = ln.Close()
		conns.Range(func(k, _ any) bool {
			_ = k.(net.Conn).Close()
			return true
		})
	})
	pump := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 && !r.isFrozen() {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go func() {
		for {
			down, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", target)
			if err != nil {
				_ = down.Close()
				continue
			}
			conns.Store(down, struct{}{})
			conns.Store(up, struct{}{})
			go pump(up, down)
			go pump(down, up)
		}
	}()
	return r
}

// A peer that stops answering after the command started cannot hold a
// cancelled caller: with no acknowledgement of the channel close, the
// connection is closed and Stream returns.
func TestStreamCancelClosesClientWhenPeerGoesSilent(t *testing.T) {
	shortenPeerTimeouts(t, 2*time.Second, 100*time.Millisecond, 300*time.Millisecond)
	peer := startFakePeer(t, peerRunsForever)
	relay := startFreezableRelay(t, peer.addr)
	cli := dialPeer(t, relay.addr)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	out := newFirstWrite()
	go func() { errCh <- Stream(ctx, cli, "sleep infinity", nil, out, io.Discard) }()
	out.wait(t)
	relay.freeze()
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Stream error = %v, want context canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stream did not return after cancel against a silent peer")
	}
	if !clientClosed(cli, 2*time.Second) {
		t.Fatal("client left open although the peer never acknowledged the close")
	}
}

// stdin reaches the command and stderr comes back, through the gate.
func TestStreamCarriesStdinAndStderr(t *testing.T) {
	peer := startFakePeer(t, peerEchoesStdinToStderr)
	cli := dialPeer(t, peer.addr)
	stdout, stderr, err := RunStdin(context.Background(), cli, "cat >&2", strings.NewReader("vault-pass\n"))
	if err != nil {
		t.Fatalf("RunStdin: %v", err)
	}
	if stdout != "" || stderr != "vault-pass\n" {
		t.Fatalf("stdout = %q, stderr = %q; want stdin echoed on stderr", stdout, stderr)
	}
}

// Nil writers discard output instead of panicking in the gate.
func TestStreamNilWriters(t *testing.T) {
	peer := startFakePeer(t, peerExitsZero)
	cli := dialPeer(t, peer.addr)
	if err := Stream(context.Background(), cli, "echo hi", nil, nil, nil); err != nil {
		t.Fatalf("Stream with nil writers: %v", err)
	}
}

// A command that exits on SIGTERM ends a cancelled Stream within the
// grace period, with no channel teardown needed.
func TestStreamCancelStopsCommandWithSignal(t *testing.T) {
	shortenPeerTimeouts(t, 2*time.Second, 2*time.Second, 2*time.Second)
	peer := startFakePeer(t, peerExitsOnSignal)
	cli := dialPeer(t, peer.addr)

	ctx, cancel := context.WithCancel(context.Background())
	out := newFirstWrite()
	errCh := make(chan error, 1)
	go func() { errCh <- Stream(ctx, cli, "sleep infinity", nil, out, io.Discard) }()
	out.wait(t)
	start := time.Now()
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Stream error = %v, want context canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stream did not return after cancel")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("Stream took %s to return although the command exited on SIGTERM", took)
	}
	if clientClosed(cli, 200*time.Millisecond) {
		t.Fatal("client closed after a clean signal exit")
	}
}

// The caller gives up while the exec request is pending and the peer
// answers afterwards: the command that started with nobody waiting is
// stopped, and the connection stays usable.
func TestStreamStopsCommandThatStartsAfterCallerLeft(t *testing.T) {
	shortenPeerTimeouts(t, 5*time.Second, 100*time.Millisecond, 2*time.Second)
	peer := startFakePeer(t, peerAnswersExecLate)
	cli := dialPeer(t, peer.addr)

	ctx, cancel := context.WithTimeout(context.Background(), lateReply/4)
	defer cancel()
	out := &cappedBuffer{name: "stdout", max: 1 << 10}
	if err := Stream(ctx, cli, "sleep infinity", nil, out, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stream error = %v, want context deadline exceeded", err)
	}
	select {
	case <-peer.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the late-started command's session was never closed")
	}
	if got := out.buf.String(); got != "" {
		t.Fatalf("stdout = %q; the late command wrote into the caller's buffer", got)
	}
	if clientClosed(cli, 300*time.Millisecond) {
		t.Fatal("client closed although the peer answered within the open timeout")
	}
}

// The caller gives up while the channel is still opening: no command
// is sent at all once the channel arrives.
func TestStreamDoesNotStartCommandAfterCallerLeft(t *testing.T) {
	shortenPeerTimeouts(t, 5*time.Second, 100*time.Millisecond, 2*time.Second)
	peer := startFakePeer(t, peerAcceptsChannelLate)
	cli := dialPeer(t, peer.addr)

	ctx, cancel := context.WithTimeout(context.Background(), lateReply/4)
	defer cancel()
	if err := Stream(ctx, cli, "touch /tmp/should-not-run", nil, io.Discard, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stream error = %v, want context deadline exceeded", err)
	}
	select {
	case <-peer.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the late-opened channel was never closed")
	}
	select {
	case cmd := <-peer.execs:
		t.Fatalf("command %q was sent after the caller had gone", cmd)
	default:
	}
	if clientClosed(cli, 300*time.Millisecond) {
		t.Fatal("client closed although the peer opened the channel within the open timeout")
	}
}
