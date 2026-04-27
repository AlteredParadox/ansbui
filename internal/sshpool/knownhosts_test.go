package sshpool

import (
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// TestAppendKnownHostRace exercises the TOFU race the
// snapshot-based outer strict callback can't see: two parallel
// first-contact dials to the same host with different keys would
// both observe an empty DB and both append, leaving the file
// with two conflicting entries. appendKnownHost re-loads under
// the mutex; only the first append wins, the second call must
// fail on mismatch.
//
// Burst with N goroutines, M of which carry one key and N-M
// carry another. Exactly one append should land; every losing
// goroutine should get a KeyError. The recorded key may be
// either of the two (whichever raced first).
func TestAppendKnownHostRace(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	keyA := mustEd25519Key(t)
	keyB := mustEd25519Key(t)
	hostname := "racehost.example:22"
	remote := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 22}

	errs := burstAppend(path, hostname, remote, keyA, keyB, 32)
	assertExactlyOneKeyRecorded(t, path, hostname, remote, keyA, keyB)

	winners, mismatches, other := classifyAppendErrors(errs)
	if other != 0 {
		t.Fatalf("unexpected non-KeyError: winners=%d mismatches=%d other=%d errs=%v", winners, mismatches, other, errs)
	}
	if winners == 0 {
		t.Fatalf("no goroutine succeeded: errs=%v", errs)
	}
	if mismatches == 0 {
		t.Fatalf("expected losing key to surface a mismatch KeyError; got winners=%d mismatches=%d", winners, mismatches)
	}
}

// burstAppend launches n goroutines all calling appendKnownHost
// for the same hostname, splitting between keyA (even i) and
// keyB (odd i). They synchronise on a `start` chan so the
// contention window is as tight as possible.
func burstAppend(path, hostname string, remote net.Addr, keyA, keyB ssh.PublicKey, n int) []error {
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		key := keyA
		if i%2 == 1 {
			key = keyB
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = appendKnownHost(path, hostname, remote, key)
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

// assertExactlyOneKeyRecorded fails the test unless the file at
// path contains exactly one of keyA or keyB recorded against
// hostname. The race-fix invariant: only the first append wins.
func assertExactlyOneKeyRecorded(t *testing.T, path, hostname string, remote net.Addr, keyA, keyB ssh.PublicKey) {
	t.Helper()
	cb, err := knownhosts.New(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	var matchA, matchB int
	if err := cb(hostname, remote, keyA); err == nil {
		matchA++
	}
	if err := cb(hostname, remote, keyB); err == nil {
		matchB++
	}
	if matchA+matchB != 1 {
		data, _ := os.ReadFile(path)
		t.Fatalf("expected exactly one of (keyA, keyB) to be recorded, got matchA=%d matchB=%d; file:\n%s", matchA, matchB, data)
	}
}

// classifyAppendErrors buckets the per-goroutine errors into
// the three legal outcomes for the burst: nil (winner), a
// knownhosts.KeyError with Want populated (mismatch loser), or
// anything else (unexpected — should fail the test).
func classifyAppendErrors(errs []error) (winners, mismatches, other int) {
	for _, e := range errs {
		if e == nil {
			winners++
			continue
		}
		var keyErr *knownhosts.KeyError
		if errors.As(e, &keyErr) && len(keyErr.Want) > 0 {
			mismatches++
		} else {
			other++
		}
	}
	return
}

func mustEd25519Key(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	signer, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return signer
}

// TestKnownHostsCallbackTOFU walks the closure returned by
// knownHostsCallback through its three productive states:
//
//  1. empty DB, fresh host → append (TOFU)
//  2. recorded key, same key on next dial → nil
//  3. recorded key, different key on next dial → KeyError (mismatch)
//
// This is the integration glue between strict callback + append
// path that the lower-level appendKnownHost tests don't exercise.
func TestKnownHostsCallbackTOFU(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")

	keyA := mustEd25519Key(t)
	keyB := mustEd25519Key(t)
	hostname := "tofu.example:22"
	remote := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 22}

	// (1) Empty file → first dial appends.
	cb1, err := knownHostsCallback(path)
	if err != nil {
		t.Fatalf("init cb: %v", err)
	}
	if err := cb1(hostname, remote, keyA); err != nil {
		t.Fatalf("first dial should TOFU-accept, got %v", err)
	}

	// (2) Re-load: same host + same key → nil.
	cb2, err := knownHostsCallback(path)
	if err != nil {
		t.Fatalf("init cb2: %v", err)
	}
	if err := cb2(hostname, remote, keyA); err != nil {
		t.Fatalf("repeat dial with same key should accept, got %v", err)
	}

	// (3) Re-load: same host + different key → mismatch (KeyError with Want).
	cb3, err := knownHostsCallback(path)
	if err != nil {
		t.Fatalf("init cb3: %v", err)
	}
	err = cb3(hostname, remote, keyB)
	if err == nil {
		t.Fatalf("dial with rotated key should fail, got nil")
	}
	var keyErr *knownhosts.KeyError
	if !errors.As(err, &keyErr) {
		t.Fatalf("expected *knownhosts.KeyError, got %T (%v)", err, err)
	}
	if len(keyErr.Want) == 0 {
		t.Fatalf("expected Want populated on mismatch, got empty (err=%v)", err)
	}
}
