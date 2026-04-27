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

	const goroutines = 32
	hostname := "racehost.example:22"
	remote := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 22}

	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
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

	// Exactly one key should be recorded. Re-load and verify the
	// file has a single entry.
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

	// Among the goroutines, the ones that carried the recorded
	// key see nil; the ones that carried the other key must see
	// a KeyError with a populated Want.
	winners, mismatches, other := 0, 0, 0
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
