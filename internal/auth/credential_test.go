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

package auth

import (
	"bytes"
	"encoding/base64"
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

// Out-of-range cost parameters are rejected at load: zero rounds or
// threads panic inside argon2.IDKey at login time, and oversized
// memory/time values would let a corrupt credential exhaust the host
// on every login attempt.
func TestLoadCredential_RejectsMalformedParams(t *testing.T) {
	t.Parallel()
	// Valid salt/hash segments; only the m=,t=,p= block varies.
	const tail = "$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"
	for _, params := range []string{
		"m=65536,t=0,p=4",   // zero rounds → argon2 panic
		"m=65536,t=3,p=0",   // zero threads → argon2 panic
		"m=65536,t=65,p=4",  // rounds above ceiling
		"m=1048577,t=3,p=4", // memory above 1 GiB ceiling
		"m=16,t=3,p=4",      // memory below argon2's 8×threads floor
		"m=65536,t=3,p=65",  // threads above ceiling
		"m=65536,t=-1,p=4",  // negative → Sscanf error
	} {
		path := filepath.Join(t.TempDir(), "credential")
		body := "$argon2id$v=19$" + params + tail
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCredential(path); err == nil {
			t.Fatalf("expected error for params %q", params)
		}
	}
}

// Salt length is bounded: this package writes 16 bytes, and
// anything under 8 or over 64 is corruption, not a credential.
func TestLoadCredential_RejectsBadSaltLength(t *testing.T) {
	t.Parallel()
	const hash = "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g" // 32 bytes
	for name, salt := range map[string]string{
		"empty": "",
		"short": base64.RawStdEncoding.EncodeToString([]byte("tiny")),
		"huge":  base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte("s"), 65)),
	} {
		path := filepath.Join(t.TempDir(), "credential")
		body := "$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$" + hash
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCredential(path); err == nil {
			t.Fatalf("expected error for %s salt", name)
		}
	}
}

// The parameters this package writes are within its own bounds (a
// tautology today, but catches someone raising argonMemory past
// maxArgonMemory without noticing).
func TestParseEncoded_AcceptsOwnOutput(t *testing.T) {
	t.Parallel()
	encoded, err := hashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseEncoded(encoded); err != nil {
		t.Fatalf("parseEncoded of own output: %v", err)
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
