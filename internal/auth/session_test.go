package auth

import (
	"testing"
	"time"
)

func TestSession_CreateValidateDestroy(t *testing.T) {
	t.Parallel()
	s := NewSessionStore()
	tok, err := s.Create()
	if err != nil || tok == "" {
		t.Fatalf("Create: tok=%q err=%v", tok, err)
	}
	if !s.Validate(tok) {
		t.Fatal("fresh token did not validate")
	}
	if s.Validate("") || s.Validate("bogus") {
		t.Fatal("empty/unknown token validated")
	}
	s.Destroy(tok)
	if s.Validate(tok) {
		t.Fatal("destroyed token still validates")
	}
}

func TestSession_IdleExpiry(t *testing.T) {
	t.Parallel()
	now := time.Now()
	s := NewSessionStore()
	s.now = func() time.Time { return now }
	tok, _ := s.Create()

	// Just under the idle timeout with activity keeps it alive and
	// slides the window.
	now = now.Add(idleTimeout - time.Minute)
	if !s.Validate(tok) {
		t.Fatal("session expired early")
	}
	// Another near-idle-timeout gap; since the last Validate slid the
	// window, this is still alive.
	now = now.Add(idleTimeout - time.Minute)
	if !s.Validate(tok) {
		t.Fatal("sliding window did not refresh idle timer")
	}
	// Now let it sit past the idle timeout.
	now = now.Add(idleTimeout + time.Minute)
	if s.Validate(tok) {
		t.Fatal("idle session should have expired")
	}
	if s.Count() != 0 {
		t.Fatalf("expired session not pruned: count=%d", s.Count())
	}
}

func TestSession_AbsoluteLifetime(t *testing.T) {
	t.Parallel()
	now := time.Now()
	s := NewSessionStore()
	s.now = func() time.Time { return now }
	tok, _ := s.Create()

	// Keep it active every hour past the absolute cap; it must still
	// die at absoluteLifetime regardless of activity.
	for elapsed := time.Duration(0); elapsed < absoluteLifetime; elapsed += time.Hour {
		now = now.Add(time.Hour)
		if !s.Validate(tok) {
			t.Fatalf("session died early at %s", elapsed)
		}
	}
	now = now.Add(2 * time.Hour) // now past absoluteLifetime
	if s.Validate(tok) {
		t.Fatal("session outlived the absolute cap")
	}
}

func TestSession_TokensUnique(t *testing.T) {
	t.Parallel()
	s := NewSessionStore()
	seen := make(map[string]bool)
	for range 100 {
		tok, err := s.Create()
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Fatal("duplicate session token")
		}
		seen[tok] = true
	}
}
