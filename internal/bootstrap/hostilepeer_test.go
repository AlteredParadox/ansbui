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

package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
	"golang.org/x/crypto/ssh"
)

// Tests for a bootstrap target that authenticates and then misbehaves:
// one that goes quiet on the session channel (which used to hold the
// job, its slot and the per-target lock until the peer hung up, with
// Cancel doing nothing), and one that answers with far more text than
// any os-release holds.

const scriptedTargetPassword = "dummy-password"

// scriptedTarget is an in-process SSH server that completes password
// auth, answers keepalives, and then does what its mode says with
// session channels.
type scriptedTarget struct {
	host string
	port int
}

type targetMode int

const (
	// targetIgnoresChannelOpen never confirms or rejects a channel.
	targetIgnoresChannelOpen targetMode = iota
	// targetAnswersWith replies to every exec with a fixed stdout
	// and exit status 0.
	targetAnswersWith
)

func startScriptedTarget(t *testing.T, mode targetMode, stdout string) *scriptedTarget {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) != scriptedTargetPassword {
				return nil, errors.New("wrong password")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
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
			go serveScriptedTarget(conn, cfg, mode, stdout)
		}
	}()
	return &scriptedTarget{host: "127.0.0.1", port: ln.Addr().(*net.TCPAddr).Port}
}

func serveScriptedTarget(conn net.Conn, cfg *ssh.ServerConfig, mode targetMode, stdout string) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sconn.Close() }()
	go func() {
		for req := range reqs {
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}()
	var held []ssh.NewChannel // unanswered opens stay reachable
	for nc := range chans {
		if mode == targetIgnoresChannelOpen {
			held = append(held, nc)
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = ch.Close() }()
			for r := range creqs {
				if r.Type != "exec" {
					if r.WantReply {
						_ = r.Reply(false, nil)
					}
					continue
				}
				_ = r.Reply(true, nil)
				_, _ = ch.Write([]byte(stdout))
				status := make([]byte, 4)
				binary.BigEndian.PutUint32(status, 0)
				_, _ = ch.SendRequest("exit-status", false, status)
				return
			}
		}()
	}
	_ = held
}

func dialScriptedTarget(t *testing.T, f *scriptedTarget) *targetSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	target, err := dialPasswordTarget(ctx, f.host, f.port, "root", scriptedTargetPassword, "", hostKeyExpectation{})
	if err != nil {
		t.Fatalf("dial scripted target: %v", err)
	}
	t.Cleanup(func() { _ = target.Close() })
	return target
}

// The first command of a bootstrap must return when its context ends,
// even though the target never answers the channel-open.
func TestStepReturnsOnCancelWhenTargetIgnoresChannelOpen(t *testing.T) {
	target := dialScriptedTarget(t, startScriptedTarget(t, targetIgnoresChannelOpen, ""))

	ctx, cancel := context.WithCancel(context.Background())
	var log emitLog
	errCh := make(chan error, 1)
	go func() { errCh <- bootstrapTarget(ctx, target, "ssh-ed25519 AAAA test", log.emit) }()

	// Let the step reach the pending channel-open, then cancel the way
	// POST /api/bootstrap/jobs/{id}/cancel does.
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("bootstrapTarget error = %v, want context canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("bootstrapTarget still running 5s after cancel — the job would keep its slot.\nevents:\n%s", log.String())
	}
	if log.count("fail: read /etc/os-release") != 1 {
		t.Fatalf("want one failure event for the cancelled step, got:\n%s", log.String())
	}
}

// A second job for the same target waits on the per-target lock. It
// must give that wait up when it is cancelled, or every retry takes
// another job slot.
func TestQueuedRunForSameTargetHonoursCancel(t *testing.T) {
	const host = "queued.example.test"
	held := lockTarget(net.JoinHostPort(host, "22"))
	if err := held.Lock(context.Background()); err != nil {
		t.Fatalf("take target lock: %v", err)
	}
	defer held.Unlock()

	req := Request{
		Provider: "hetzner", IP: host, Port: 22,
		Username: "root", Password: "dummy-password", Hostname: host,
	}
	if err := Validate(req); err != nil {
		t.Fatalf("test request is not valid: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var log emitLog
	errCh := make(chan error, 1)
	go func() { errCh <- Run(ctx, nil, config.Server{}, req, "", nil, log.emit) }()
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-errCh:
		t.Fatalf("Run returned (%v) while the target lock was held", err)
	default:
	}
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued Run ignored its Cancel")
	}
	if log.count("fail: cancelled while waiting for another bootstrap of the same target") != 1 {
		t.Fatalf("want one event explaining the cancelled wait, got:\n%s", log.String())
	}
}

func TestCtxLock(t *testing.T) {
	l := newCtxLock()
	if err := l.Lock(context.Background()); err != nil {
		t.Fatalf("first Lock: %v", err)
	}

	// A waiter gives up when its context ends...
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.Lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Lock on a held lock = %v, want deadline exceeded", err)
	}
	// ...and did not acquire, so one Unlock frees the lock.
	l.Unlock()
	if err := l.Lock(context.Background()); err != nil {
		t.Fatalf("Lock after Unlock: %v", err)
	}
	l.Unlock()

	// A context that is already done never acquires a free lock.
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	for range 50 {
		if err := l.Lock(done); !errors.Is(err, context.Canceled) {
			t.Fatalf("Lock with a done context = %v, want canceled", err)
		}
	}
	if err := l.Lock(context.Background()); err != nil {
		t.Fatalf("lock was taken by a cancelled caller: %v", err)
	}
	l.Unlock()
}

// An oversized os-release must not reach job events or the returned
// error at anything like its own size.
func TestOversizedOSReleaseIsClippedInEventsAndError(t *testing.T) {
	const payload = 512 << 10
	// Control bytes included: %q would expand each to four bytes.
	osRelease := "ID=" + strings.Repeat("\x01evil", payload/5) + "\n"
	target := dialScriptedTarget(t, startScriptedTarget(t, targetAnswersWith, osRelease))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var log emitLog
	err := bootstrapTarget(ctx, target, "ssh-ed25519 AAAA test", log.emit)
	if err == nil || !strings.Contains(err.Error(), "unsupported distro") {
		t.Fatalf("bootstrapTarget error = %v, want unsupported distro", err)
	}
	const limit = 512
	if n := len(err.Error()); n > limit {
		t.Fatalf("error is %d bytes for a %d-byte os-release, want at most %d", n, payload, limit)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, line := range log.lines {
		if len(line) > limit {
			t.Fatalf("event is %d bytes, want at most %d: %.80q…", len(line), limit, line)
		}
		if strings.ContainsAny(line, "\x01\r\n") {
			t.Fatalf("event carries control bytes from the target: %.80q…", line)
		}
	}
}

func TestClipOSReleaseValue(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"short value unchanged", "debian", "debian"},
		{"version unchanged", "24.04", "24.04"},
		{"control bytes replaced", "deb\x00ian\r\n\x7f", "deb?ian???"},
		{"long value cut", strings.Repeat("a", 200), strings.Repeat("a", osReleaseValueMax) + "…"},
		{"cut does not split a rune", strings.Repeat("a", osReleaseValueMax-1) + "é", strings.Repeat("a", osReleaseValueMax-1) + "…"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := clipOSReleaseValue(tc.in); got != tc.want {
				t.Fatalf("clipOSReleaseValue(%.30q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	if got := detectDistro("NAME=x\nID=\"" + strings.Repeat("z", 5000) + "\"\n"); len(got) > osReleaseValueMax+len("…") {
		t.Fatalf("detectDistro returned %d bytes", len(got))
	}
	if got := osReleaseField("VERSION_ID="+strings.Repeat("9", 5000), "VERSION_ID"); len(got) > osReleaseValueMax+len("…") {
		t.Fatalf("osReleaseField returned %d bytes", len(got))
	}
}
