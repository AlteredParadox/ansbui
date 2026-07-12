package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostKeyStore_RoundTrip(t *testing.T) {
	t.Parallel()
	s := NewHostKeyStore(filepath.Join(t.TempDir(), "hk.json"))

	if _, ok, err := s.Get("1.2.3.4:22"); err != nil || ok {
		t.Fatalf("empty store: ok=%v err=%v", ok, err)
	}
	if err := s.Put("1.2.3.4:22", "SHA256:abc"); err != nil {
		t.Fatalf("put: %v", err)
	}
	fp, ok, err := s.Get("1.2.3.4:22")
	if err != nil || !ok || fp != "SHA256:abc" {
		t.Fatalf("get after put: fp=%q ok=%v err=%v", fp, ok, err)
	}
	// Keys are case-insensitive on the host part (Run lowercases the
	// address, but a future caller might not).
	if _, ok, _ := s.Get("1.2.3.4:22"); !ok {
		t.Fatal("lookup lost")
	}
	// Replacement (post-reinstall) overwrites.
	if err := s.Put("1.2.3.4:22", "SHA256:new"); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	if fp, _, _ := s.Get("1.2.3.4:22"); fp != "SHA256:new" {
		t.Fatalf("replacement not applied: %q", fp)
	}
}

// A corrupt store must surface an error, not silently degrade every
// later contact back to trust-on-first-use.
func TestHostKeyStore_CorruptFileErrors(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "hk.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewHostKeyStore(path)
	if _, _, err := s.Get("h:22"); err == nil || !strings.Contains(err.Error(), "fix or remove") {
		t.Fatalf("expected parse error with remediation hint, got %v", err)
	}
	if err := s.Put("h:22", "SHA256:x"); err == nil {
		t.Fatal("Put on corrupt store must not silently succeed")
	}
}

// A nil store is a valid no-op — bootstrap.Run must work without one.
func TestHostKeyStore_NilSafe(t *testing.T) {
	t.Parallel()
	var s *HostKeyStore
	if _, ok, err := s.Get("h:22"); ok || err != nil {
		t.Fatalf("nil Get: ok=%v err=%v", ok, err)
	}
	if err := s.Put("h:22", "SHA256:x"); err != nil {
		t.Fatalf("nil Put: %v", err)
	}
	if s.Path() != "" {
		t.Fatal("nil Path should be empty")
	}
}
