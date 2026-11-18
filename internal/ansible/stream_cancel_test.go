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

package ansible

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
	"golang.org/x/crypto/ssh"
)

// TestRunStreamingCancelDoesNotDeadlock reproduces the "close the tab
// mid-run" liveness bug: on ctx cancel the pipe scanners stop reading,
// the ssh session's io.Copy blocks forever in a pipe Write (sess.Close
// only unblocks channel reads), Session.Wait never returns, and
// runStreaming parks — the run is never persisted and the whole
// pipeline leaks. The fake server streams output indefinitely, ignores
// SIGTERM, and never sends an exit status, which is exactly the shape
// of a verbose ansible run whose consumer walked away.
func TestRunStreamingCancelDoesNotDeadlock(t *testing.T) {
	t.Setenv("ANSBUI_INSECURE_SSH", "1")
	addr := startChattySSHServer(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	srv := config.Server{
		ID:      "stream-cancel-test",
		Host:    host,
		Port:    port,
		User:    "test",
		KeyPath: writeTestClientKey(t),
	}
	pool := sshpool.New()
	t.Cleanup(pool.Close)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan Event, 64)
	gotStdout := make(chan struct{})
	go func() {
		var once sync.Once
		for ev := range out {
			if ev.Stream == "stdout" {
				once.Do(func() { close(gotStdout) })
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runStreaming(ctx, pool, srv, "yes-i-am-fake", "yes-i-am-fake", "", out)
		close(out)
	}()

	select {
	case <-gotStdout:
	case err := <-errCh:
		t.Fatalf("runStreaming exited before producing output: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no stdout from fake server within 10s")
	}
	cancel()

	// Stream's cancel path allows a 2s grace for SIGTERM before it
	// force-closes the session; anything well past that is the
	// deadlock this test guards against.
	select {
	case <-errCh:
	case <-time.After(15 * time.Second):
		t.Fatal("runStreaming did not return within 15s of cancel — Stream deadlocked on a blocked pipe write")
	}
}

// startChattySSHServer runs a minimal SSH server that accepts any
// auth, replies success to exec, then writes output lines forever —
// ignoring signals and never sending an exit status. Returns its
// listen address; all resources are torn down via t.Cleanup.
func startChattySSHServer(t *testing.T) string {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveChattyConn(conn, cfg)
		}
	}()
	return ln.Addr().String()
}

func serveChattyConn(conn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go serveChattySession(ch, chReqs)
	}
}

func serveChattySession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "exec":
			_ = req.Reply(true, nil)
			// Stream forever; channel window backpressure
			// throttles us once the client stops reading.
			go func() {
				line := []byte("ok: [fakehost] => chatty output line\n")
				for {
					if _, err := ch.Write(line); err != nil {
						return
					}
				}
			}()
		default:
			// Includes "signal" (SIGTERM): deliberately
			// ignored so the session only ends when the
			// client force-closes it.
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func writeTestClientKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "ansbui-test")
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}
	return path
}
