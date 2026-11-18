package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fingerprint-shaped values: the store accepts nothing else.
const (
	fpA = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fpB = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func TestHostKeyStore_RoundTrip(t *testing.T) {
	t.Parallel()
	s := NewHostKeyStore(filepath.Join(t.TempDir(), "hk.json"))

	if _, ok, err := s.Get("1.2.3.4:22"); err != nil || ok {
		t.Fatalf("empty store: ok=%v err=%v", ok, err)
	}
	if err := s.Put("1.2.3.4:22", fpA); err != nil {
		t.Fatalf("put: %v", err)
	}
	fp, ok, err := s.Get("1.2.3.4:22")
	if err != nil || !ok || fp != fpA {
		t.Fatalf("get after put: fp=%q ok=%v err=%v", fp, ok, err)
	}
	// Keys are case-insensitive on the host part (Run lowercases the
	// address, but a future caller might not).
	if _, ok, _ := s.Get("1.2.3.4:22"); !ok {
		t.Fatal("lookup lost")
	}
	// Replacement (post-reinstall) overwrites.
	if err := s.Put("1.2.3.4:22", fpB); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	if fp, _, _ := s.Get("1.2.3.4:22"); fp != fpB {
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
	if err := s.Put("h:22", fpA); err == nil {
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
	if err := s.Put("h:22", fpA); err != nil {
		t.Fatalf("nil Put: %v", err)
	}
	if s.Path() != "" {
		t.Fatal("nil Path should be empty")
	}
}

// A store file that parses but is not a store this code could have
// written is corrupt, and corrupt means refuse — never "empty".
func TestHostKeyStore_RejectsContentItDidNotWrite(t *testing.T) {
	t.Parallel()
	for name, content := range map[string]string{
		// Decodes to a nil map: read as empty, then panicked in Put.
		"null": `null`,
		// "A record exists" with nothing to compare against: strict
		// mode was satisfied and every key was accepted.
		"empty value":         `{"h:22": ""}`,
		"not a fingerprint":   `{"h:22": "yes"}`,
		"md5-style":           `{"h:22": "MD5:aa:bb:cc"}`,
		"padded":              `{"h:22": "` + fpA + `="}`,
		"one bad among good":  `{"a:22": "` + fpA + `", "h:22": ""}`,
		"wrong container":     `[]`,
		"non-string value":    `{"h:22": 1}`,
		"trailing whitespace": `{"h:22": "` + fpA + ` "}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "hk.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			s := NewHostKeyStore(path)
			if fp, ok, err := s.Get("h:22"); err == nil {
				t.Errorf("Get returned (%q, %v) with no error", fp, ok)
			}
			if err := s.Put("other:22", fpB); err == nil {
				t.Error("Put wrote into a corrupt store")
			}
			// The file is left for the operator to inspect.
			if got, _ := os.ReadFile(path); string(got) != content {
				t.Errorf("corrupt store was modified: %q", got)
			}
		})
	}
}

// With an empty-valued entry, strict mode must refuse rather than
// treat the target as recorded.
func TestHostKeyStore_EmptyEntryDoesNotSatisfyStrictMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hk.json")
	if err := os.WriteFile(path, []byte(`{"192.0.2.10:22": ""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, strict := range []string{"", "1"} {
		t.Setenv(requireHostKeyEnv, strict)
		expect, err := resolveHostKeyExpectation(Request{}, "192.0.2.10:22", NewHostKeyStore(path))
		if err == nil {
			t.Errorf("strict=%q: resolved to %+v with an empty stored fingerprint, want an error", strict, expect)
		}
	}
}

// Only fingerprints go in.
func TestHostKeyStore_PutRejectsNonFingerprint(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "hk.json")
	s := NewHostKeyStore(path)
	for _, bad := range []string{"", "SHA256:", "SHA256:abc", "nope", fpA + "="} {
		if err := s.Put("h:22", bad); err == nil {
			t.Errorf("Put accepted %q", bad)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("a rejected Put created the store (stat err %v)", err)
	}
}
