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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// These tests cover WHEN a bootstrap target's host key becomes a
// durable record, relative to when the password is sent. The decision
// logic (which key is required) is covered in hostkeypolicy_test.go;
// what was untested, and wrong, was the ordering: the record was
// written after authentication and a failed write was only a warning,
// so an unwritable store turned every run into a first contact.

// fakeTarget is an in-process SSH server standing in for a bootstrap
// target. It accepts one password and records every password it is
// offered, which is how a test proves a credential was or was not
// sent.
type fakeTarget struct {
	host string
	port int
	fp   string

	mu        sync.Mutex
	passwords []string
}

func (f *fakeTarget) offered() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.passwords...)
}

func startFakeTarget(t *testing.T, goodPassword string) *fakeTarget {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	f := &fakeTarget{host: "127.0.0.1", port: ln.Addr().(*net.TCPAddr).Port, fp: ssh.FingerprintSHA256(signer.PublicKey())}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			f.mu.Lock()
			f.passwords = append(f.passwords, string(pw))
			f.mu.Unlock()
			if string(pw) != goodPassword {
				return nil, errors.New("wrong password")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeTarget(conn, cfg)
		}
	}()
	return f
}

// serveFakeTarget completes the handshake and answers every exec with
// exit status 0 and no output — enough for the precheck that follows a
// successful dial.
func serveFakeTarget(conn net.Conn, cfg *ssh.ServerConfig) {
	defer func() { _ = conn.Close() }()
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "session only")
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
					_ = r.Reply(false, nil)
					continue
				}
				_ = r.Reply(true, nil)
				status := make([]byte, 4)
				binary.BigEndian.PutUint32(status, 0)
				_, _ = ch.SendRequest("exit-status", false, status)
				return
			}
		}()
	}
}

// emitLog collects a run's events as "type: text" lines.
type emitLog struct {
	mu    sync.Mutex
	lines []string
}

func (e *emitLog) emit(typ, text string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lines = append(e.lines, typ+": "+text)
}

func (e *emitLog) count(substr string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, l := range e.lines {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

func (e *emitLog) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return strings.Join(e.lines, "\n")
}

const firstContactMarker = "first contact — host key accepted on trust"

func precheckCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func rootRequest(f *fakeTarget, password string) Request {
	return Request{IP: f.host, Port: f.port, Username: "root", Password: password}
}

// unwritableStore returns a store that reads as empty and cannot be
// written, without relying on file modes (which root ignores): the
// temp file Put creates is occupied by a directory.
func unwritableStore(t *testing.T) *HostKeyStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hk.json")
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	return NewHostKeyStore(path)
}

// The finding: a first contact whose key cannot be recorded must not
// be sent the password. Before, the write happened after auth and its
// failure was a warning, so the run went ahead and the next one was a
// first contact too.
func TestFirstContactRefusedWhenKeyCannotBeRecorded(t *testing.T) {
	const pw = "dummy-password"
	target := startFakeTarget(t, pw)
	store := unwritableStore(t)
	var log emitLog

	sess, err := connectAndPrecheck(precheckCtx(t), rootRequest(target, pw), store, log.emit)
	if err == nil {
		_ = sess.Close()
		t.Fatalf("connected although the host key could not be recorded; events:\n%s", log.String())
	}
	if got := target.offered(); len(got) != 0 {
		t.Fatalf("the password was sent to a host whose key was never recorded: %d attempt(s)", len(got))
	}
	for _, want := range []string{"refusing to authenticate", target.fp, store.Path(), "no credential was sent"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
	if log.count(firstContactMarker) != 0 {
		t.Errorf("claimed the key was accepted and recorded when it was not:\n%s", log.String())
	}
	if _, ok, _ := store.Get(net.JoinHostPort(target.host, strconv.Itoa(target.port))); ok {
		t.Error("store reports a record that could not have been written")
	}

	// Strict mode refuses the same state earlier still; it must keep
	// doing so (this is the control the audit used as its baseline).
	t.Setenv(requireHostKeyEnv, "1")
	if _, err := connectAndPrecheck(precheckCtx(t), rootRequest(target, pw), store, log.emit); err == nil || !strings.Contains(err.Error(), requireHostKeyEnv) {
		t.Errorf("strict mode did not refuse an unrecorded target: %v", err)
	}
	if got := target.offered(); len(got) != 0 {
		t.Errorf("strict mode sent the password: %d attempt(s)", len(got))
	}
}

// An unreadable store refuses too, and also before auth.
func TestFirstContactRefusedWhenStoreCannotBeRead(t *testing.T) {
	const pw = "dummy-password"
	target := startFakeTarget(t, pw)
	path := filepath.Join(t.TempDir(), "hk.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var log emitLog
	if _, err := connectAndPrecheck(precheckCtx(t), rootRequest(target, pw), NewHostKeyStore(path), log.emit); err == nil {
		t.Fatal("connected with a corrupt host key store")
	}
	if got := target.offered(); len(got) != 0 {
		t.Fatalf("the password was sent with a corrupt store: %d attempt(s)", len(got))
	}
}

// The key is on record from the moment it is accepted, including when
// authentication then fails. The operator is told so on that run, and
// the retry is held to that key: an impostor answering it gets no
// password.
func TestKeyRecordedBeforeAuthAndEnforcedOnRetry(t *testing.T) {
	const pw = "dummy-password"
	target := startFakeTarget(t, pw)
	store := NewHostKeyStore(filepath.Join(t.TempDir(), "hk.json"))
	hostport := net.JoinHostPort(target.host, strconv.Itoa(target.port))

	// Run 1: mistyped password.
	var run1 emitLog
	if _, err := connectAndPrecheck(precheckCtx(t), rootRequest(target, "typo"), store, run1.emit); err == nil {
		t.Fatal("wrong password accepted")
	}
	if got, ok, err := store.Get(hostport); err != nil || !ok || got != target.fp {
		t.Fatalf("after a failed login the store holds %q (ok=%v, err=%v), want the accepted key %q", got, ok, err, target.fp)
	}
	if run1.count(firstContactMarker) != 1 || run1.count(target.fp) == 0 {
		t.Errorf("the run that took the key on trust did not say so:\n%s", run1.String())
	}

	// Run 2: the right password, same host. Verified, not first contact.
	var run2 emitLog
	sess, err := connectAndPrecheck(precheckCtx(t), rootRequest(target, pw), store, run2.emit)
	if err != nil {
		t.Fatalf("retry against the recorded host failed: %v", err)
	}
	_ = sess.Close()
	if run2.count(firstContactMarker) != 0 || run2.count("host key verified against the fingerprint recorded") != 1 {
		t.Errorf("retry was not reported as verified against the record:\n%s", run2.String())
	}

	// Run 3: something else answers for the same address.
	impostor := startFakeTarget(t, pw)
	if err := store.Put(net.JoinHostPort(impostor.host, strconv.Itoa(impostor.port)), target.fp); err != nil {
		t.Fatal(err)
	}
	var run3 emitLog
	_, err = connectAndPrecheck(precheckCtx(t), rootRequest(impostor, pw), store, run3.emit)
	if err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("impostor not rejected as a mismatch: %v", err)
	}
	if got := impostor.offered(); len(got) != 0 {
		t.Fatalf("the password was sent to the impostor: %d attempt(s)", len(got))
	}
	if got, _, _ := store.Get(net.JoinHostPort(impostor.host, strconv.Itoa(impostor.port))); got != target.fp {
		t.Errorf("a rejected key replaced the record: %q", got)
	}
}

// An operator pin for a host with no record (or a stale one) becomes
// the record; a pin the host does not match records nothing.
func TestOperatorPinIsRecorded(t *testing.T) {
	const pw = "dummy-password"
	target := startFakeTarget(t, pw)
	hostport := net.JoinHostPort(target.host, strconv.Itoa(target.port))
	_, staleFP := testHostKey(t)

	t.Run("matching pin replaces a stale record", func(t *testing.T) {
		store := NewHostKeyStore(filepath.Join(t.TempDir(), "hk.json"))
		if err := store.Put(hostport, staleFP); err != nil {
			t.Fatal(err)
		}
		req := rootRequest(target, pw)
		req.HostKeyFingerprint = target.fp
		var log emitLog
		sess, err := connectAndPrecheck(precheckCtx(t), req, store, log.emit)
		if err != nil {
			t.Fatalf("pinned dial failed: %v", err)
		}
		_ = sess.Close()
		if got, _, _ := store.Get(hostport); got != target.fp {
			t.Errorf("record = %q, want the pinned key %q", got, target.fp)
		}
		if log.count(firstContactMarker) != 0 || log.count("operator-pinned") != 1 {
			t.Errorf("a pinned run must report verification, not first contact:\n%s", log.String())
		}
	})

	t.Run("pin that cannot be recorded is refused before auth", func(t *testing.T) {
		before := len(target.offered())
		req := rootRequest(target, pw)
		req.HostKeyFingerprint = target.fp
		var log emitLog
		if _, err := connectAndPrecheck(precheckCtx(t), req, unwritableStore(t), log.emit); err == nil {
			t.Fatal("connected although the pinned key could not be recorded")
		}
		if got := len(target.offered()); got != before {
			t.Errorf("the password was sent: %d new attempt(s)", got-before)
		}
	})

	t.Run("mismatched pin records nothing", func(t *testing.T) {
		before := len(target.offered())
		store := NewHostKeyStore(filepath.Join(t.TempDir(), "hk.json"))
		req := rootRequest(target, pw)
		req.HostKeyFingerprint = staleFP
		var log emitLog
		if _, err := connectAndPrecheck(precheckCtx(t), req, store, log.emit); err == nil {
			t.Fatal("host accepted against a pin it does not match")
		}
		if _, ok, _ := store.Get(hostport); ok {
			t.Error("a key that failed the pin was recorded")
		}
		if got := len(target.offered()); got != before {
			t.Errorf("the password was sent: %d new attempt(s)", got-before)
		}
	})
}

// A host already on record needs no write, so a store that has become
// read-only does not stop bootstraps of hosts it already knows.
func TestKnownHostNeedsNoWrite(t *testing.T) {
	const pw = "dummy-password"
	target := startFakeTarget(t, pw)
	path := filepath.Join(t.TempDir(), "hk.json")
	store := NewHostKeyStore(path)
	if err := store.Put(net.JoinHostPort(target.host, strconv.Itoa(target.port)), target.fp); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".tmp", 0o700); err != nil { // writes now fail
		t.Fatal(err)
	}
	var log emitLog
	sess, err := connectAndPrecheck(precheckCtx(t), rootRequest(target, pw), store, log.emit)
	if err != nil {
		t.Fatalf("known host refused because the store is read-only: %v", err)
	}
	_ = sess.Close()
}

// probeReturning is a hostKeyProbe that reports a fixed result and
// counts its calls.
func probeReturning(fp string, err error, calls *int) hostKeyProbe {
	return func(context.Context, string, int) (string, error) {
		if calls != nil {
			*calls++
		}
		return fp, err
	}
}

// bootstrapTarget moves sshd to targetSSHPort. The record has to move
// with it, or the next run against the new port is a first contact
// with a machine ansbui has already verified. But only when the new
// port really is the same sshd: the record is written on the evidence
// of what that port presents.
func TestHostKeyCarriedToTargetPort(t *testing.T) {
	genuine, genuineFP := testHostKey(t)
	other, otherFP := testHostKey(t)
	const host = "192.0.2.10"
	moved := net.JoinHostPort(host, strconv.Itoa(targetSSHPort))
	unreachable := errors.New("connection refused")
	ctx := context.Background()

	newStore := func(t *testing.T, seed string) *HostKeyStore {
		t.Helper()
		s := NewHostKeyStore(filepath.Join(t.TempDir(), "hk.json"))
		if seed != "" {
			if err := s.Put(moved, seed); err != nil {
				t.Fatal(err)
			}
		}
		return s
	}
	recorded := func(t *testing.T, s *HostKeyStore) string {
		t.Helper()
		fp, _, err := s.Get(moved)
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}

	t.Run("same key on the new port: recorded and enforced there", func(t *testing.T) {
		store := newStore(t, "")
		var log emitLog
		carryHostKeyToTargetPort(ctx, host, 22, genuineFP, store, probeReturning(genuineFP, nil, nil), log.emit)

		expect, err := resolveHostKeyExpectation(Request{}, moved, store)
		if err != nil {
			t.Fatal(err)
		}
		if expect.fp != genuineFP {
			t.Fatalf("expectation for %s = %q, want the key verified on :22 (%q) — a re-run would be a first contact", moved, expect.fp, genuineFP)
		}
		var observed string
		cb := recordFingerprintCallback(expect, &observed)
		if err := cb(moved, nil, other); err == nil {
			t.Error("a different key on the new port was accepted")
		}
		if err := cb(moved, nil, genuine); err != nil {
			t.Errorf("the box's own key was rejected on the new port: %v", err)
		}
		if log.count("ok: host key recorded for "+moved) != 1 {
			t.Errorf("no confirmation event:\n%s", log.String())
		}
		// And strict mode now has what it needs for the new port.
		t.Setenv(requireHostKeyEnv, "1")
		if _, err := resolveHostKeyExpectation(Request{}, moved, store); err != nil {
			t.Errorf("strict mode refuses the moved port: %v", err)
		}
	})

	// The review finding: host:22 and host:4242 need not be the same
	// sshd (sshdPortScript is a no-op when something already listens
	// on the target port; a port-forward can put another machine
	// there). A record for that other listener must survive.
	t.Run("different key on the new port: existing record kept", func(t *testing.T) {
		store := newStore(t, otherFP)
		var log emitLog
		carryHostKeyToTargetPort(ctx, host, 22, genuineFP, store, probeReturning(otherFP, nil, nil), log.emit)
		if got := recorded(t, store); got != otherFP {
			t.Fatalf("the valid record for %s was replaced: %q, want %q", moved, got, otherFP)
		}
		if log.count("presents a different host key") != 1 || log.count(otherFP) == 0 || log.count("ok:") != 0 {
			t.Errorf("conflict not reported:\n%s", log.String())
		}
	})

	t.Run("different key on the new port: nothing recorded", func(t *testing.T) {
		store := newStore(t, "")
		var log emitLog
		carryHostKeyToTargetPort(ctx, host, 22, genuineFP, store, probeReturning(otherFP, nil, nil), log.emit)
		if got := recorded(t, store); got != "" {
			t.Fatalf("recorded %q for a port that presents %q", got, otherFP)
		}
		if log.count("presents a different host key") != 1 {
			t.Errorf("conflict not reported:\n%s", log.String())
		}
	})

	// A box reinstalled out of band and re-bootstrapped with a pinned
	// fingerprint: the old :4242 record is stale, and the port proving
	// it holds the new key is what allows replacing it.
	t.Run("stale record replaced once the port proves the new key", func(t *testing.T) {
		store := newStore(t, otherFP)
		var log emitLog
		carryHostKeyToTargetPort(ctx, host, 22, genuineFP, store, probeReturning(genuineFP, nil, nil), log.emit)
		if got := recorded(t, store); got != genuineFP {
			t.Fatalf("record = %q, want the proven key %q", got, genuineFP)
		}
		if log.count("older record ("+otherFP+") was replaced") != 1 {
			t.Errorf("replacement not reported:\n%s", log.String())
		}
	})

	t.Run("port unreachable, no record yet: recorded on the session's word", func(t *testing.T) {
		store := newStore(t, "")
		var log emitLog
		carryHostKeyToTargetPort(ctx, host, 22, genuineFP, store, probeReturning("", unreachable, nil), log.emit)
		if got := recorded(t, store); got != genuineFP {
			t.Fatalf("record = %q, want %q", got, genuineFP)
		}
		if log.count("could not be reached to confirm") != 1 {
			t.Errorf("unconfirmed write not labelled as such:\n%s", log.String())
		}
	})

	t.Run("port unreachable, different record present: record kept", func(t *testing.T) {
		store := newStore(t, otherFP)
		var log emitLog
		carryHostKeyToTargetPort(ctx, host, 22, genuineFP, store, probeReturning("", unreachable, nil), log.emit)
		if got := recorded(t, store); got != otherFP {
			t.Fatalf("an unverified key replaced the record: %q, want %q", got, otherFP)
		}
		if log.count("is already recorded for "+moved) != 1 || log.count("ok:") != 0 {
			t.Errorf("kept record not reported:\n%s", log.String())
		}
	})

	t.Run("already recorded: no probe, no write, no event", func(t *testing.T) {
		store := newStore(t, genuineFP)
		calls := 0
		var log emitLog
		carryHostKeyToTargetPort(ctx, host, 22, genuineFP, store, probeReturning(otherFP, nil, &calls), log.emit)
		if calls != 0 || log.String() != "" || recorded(t, store) != genuineFP {
			t.Errorf("probe calls=%d, record=%q, events:\n%s", calls, recorded(t, store), log.String())
		}
	})

	t.Run("run that never changed port: nothing to do", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hk.json")
		calls := 0
		var log emitLog
		carryHostKeyToTargetPort(ctx, host, targetSSHPort, genuineFP, NewHostKeyStore(path), probeReturning(genuineFP, nil, &calls), log.emit)
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("store written (stat err %v)", err)
		}
		if calls != 0 || log.String() != "" {
			t.Errorf("probe calls=%d, events:\n%s", calls, log.String())
		}
	})

	t.Run("a failed write is reported, not swallowed", func(t *testing.T) {
		var log emitLog
		carryHostKeyToTargetPort(ctx, host, 22, genuineFP, unwritableStore(t), probeReturning(genuineFP, nil, nil), log.emit)
		if log.count("meta: could not record the host key fingerprint for "+moved) != 1 {
			t.Errorf("failure not reported:\n%s", log.String())
		}
	})

	t.Run("an unreadable store is reported, and not probed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hk.json")
		if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		calls := 0
		var log emitLog
		carryHostKeyToTargetPort(ctx, host, 22, genuineFP, NewHostKeyStore(path), probeReturning(genuineFP, nil, &calls), log.emit)
		if calls != 0 || log.count("meta: could not record the host key fingerprint for "+moved) != 1 {
			t.Errorf("probe calls=%d, events:\n%s", calls, log.String())
		}
	})

	t.Run("nil store is a no-op", func(t *testing.T) {
		calls := 0
		var log emitLog
		carryHostKeyToTargetPort(ctx, host, 22, genuineFP, nil, probeReturning(genuineFP, nil, &calls), log.emit)
		if calls != 0 || log.String() != "" {
			t.Errorf("probe calls=%d, events:\n%s", calls, log.String())
		}
	})
}

// probeHostKey must report the key a listener really presents, and
// must not authenticate: it is pointed at a port that may belong to
// something other than the box being bootstrapped.
func TestProbeHostKey(t *testing.T) {
	target := startFakeTarget(t, "dummy-password")

	fp, err := probeHostKey(precheckCtx(t), target.host, target.port)
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if fp != target.fp {
		t.Errorf("probe returned %q, the listener's key is %q", fp, target.fp)
	}
	if got := target.offered(); len(got) != 0 {
		t.Errorf("the probe attempted authentication: %d password(s) offered", len(got))
	}

	// Nothing listening: an error and no fingerprint.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if fp, err := probeHostKey(precheckCtx(t), "127.0.0.1", closed); err == nil || fp != "" {
		t.Errorf("probe of a closed port returned (%q, %v)", fp, err)
	}

	// A listener that accepts and says nothing: bounded by the context.
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	started := time.Now()
	if fp, err := probeHostKey(ctx, "127.0.0.1", silent.Addr().(*net.TCPAddr).Port); err == nil || fp != "" {
		t.Errorf("probe of a silent listener returned (%q, %v)", fp, err)
	}
	if took := time.Since(started); took > 5*time.Second {
		t.Errorf("probe of a silent listener took %s, want it bounded by the context", took)
	}
}
