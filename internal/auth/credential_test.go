package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredential_SetVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "auth", "credential")
	if err := SetCredential(path, "correct horse battery staple"); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}
	// File is 0600.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", fi.Mode().Perm())
	}

	cred, err := LoadCredential(path)
	if err != nil || cred == nil {
		t.Fatalf("LoadCredential: cred=%v err=%v", cred, err)
	}
	if !cred.Verify("correct horse battery staple") {
		t.Fatal("correct password did not verify")
	}
	if cred.Verify("wrong password") {
		t.Fatal("wrong password verified")
	}
	if cred.Verify("") {
		t.Fatal("empty password verified")
	}
}

func TestSetCredential_RejectsEmpty(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "credential")
	if err := SetCredential(path, "   "); err == nil {
		t.Fatal("expected error for blank password")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("no file should be written for a blank password")
	}
}

// A missing credential file means auth is disabled — (nil, nil), not
// an error.
func TestLoadCredential_MissingIsDisabled(t *testing.T) {
	t.Parallel()
	cred, err := LoadCredential(filepath.Join(t.TempDir(), "nope"))
	if err != nil || cred != nil {
		t.Fatalf("missing file: cred=%v err=%v", cred, err)
	}
}

// A present-but-corrupt file must error, never silently disable auth.
func TestLoadCredential_CorruptErrors(t *testing.T) {
	t.Parallel()
	for _, body := range []string{"", "not-a-hash", "$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA"} {
		path := filepath.Join(t.TempDir(), "credential")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCredential(path); err == nil {
			t.Fatalf("expected error for corrupt credential %q", body)
		}
	}
}

// Distinct passwords get distinct salts → distinct encodings.
func TestHashPassword_SaltedPerCall(t *testing.T) {
	t.Parallel()
	a, err := hashPassword("same")
	if err != nil {
		t.Fatal(err)
	}
	b, err := hashPassword("same")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical — salt not random")
	}
	if !strings.HasPrefix(a, "$argon2id$v=19$") {
		t.Fatalf("unexpected encoding: %q", a)
	}
}
