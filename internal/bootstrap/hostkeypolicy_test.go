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
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// These tests cover the host-key decision logic — which key a
// bootstrap target is required to present, and what happens when it
// presents something else. That decision is what stands between the
// operator's SSH/sudo password and an impostor server, and it had no
// test coverage at all: a regression back to warn-only
// trust-on-first-use would have been silent.

// testHostKey returns a freshly generated ed25519 public key and its
// OpenSSH SHA256 fingerprint.
func testHostKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}
	return sshPub, ssh.FingerprintSHA256(sshPub)
}

// TestRecordFingerprintCallbackRejectsMismatch is the core guarantee:
// with an expectation set, a server presenting any other key is
// rejected. The callback runs during key exchange, so returning an
// error here aborts the connection before SSH userauth — i.e. before
// the password is transmitted.
func TestRecordFingerprintCallbackRejectsMismatch(t *testing.T) {
	wanted, wantedFP := testHostKey(t)
	impostor, impostorFP := testHostKey(t)

	t.Run("matching key accepted and recorded", func(t *testing.T) {
		var observed string
		cb := recordFingerprintCallback(hostKeyExpectation{fp: wantedFP, src: "the pin"}, &observed)
		if err := cb("host:22", nil, wanted); err != nil {
			t.Fatalf("matching key rejected: %v", err)
		}
		if observed != wantedFP {
			t.Errorf("observed = %q, want %q", observed, wantedFP)
		}
	})

	t.Run("mismatched key rejected", func(t *testing.T) {
		var observed string
		cb := recordFingerprintCallback(hostKeyExpectation{fp: wantedFP, src: "the operator-pinned fingerprint"}, &observed)
		err := cb("host:22", nil, impostor)
		if err == nil {
			t.Fatal("impostor key accepted — the password would have been sent to it")
		}
		// The error has to name both fingerprints and the source, or
		// the operator can't tell a reinstall from an attack.
		for _, want := range []string{impostorFP, wantedFP, "the operator-pinned fingerprint"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("mismatch error missing %q: %v", want, err)
			}
		}
		// Still recorded, so callers can surface what was actually seen.
		if observed != impostorFP {
			t.Errorf("observed = %q, want %q", observed, impostorFP)
		}
	})

	t.Run("empty expectation accepts anything (TOFU)", func(t *testing.T) {
		var observed string
		cb := recordFingerprintCallback(hostKeyExpectation{}, &observed)
		if err := cb("host:22", nil, impostor); err != nil {
			t.Fatalf("first contact rejected: %v", err)
		}
		if observed != impostorFP {
			t.Errorf("observed = %q, want %q", observed, impostorFP)
		}
	})
}

// TestResolveHostKeyExpectationPrecedence locks in pin-over-store
// ordering. An operator who pastes a fresh fingerprint after an
// out-of-band reinstall must override the stale stored record —
// otherwise the pin silently does nothing and every run fails with a
// mismatch against a dead system.
func TestResolveHostKeyExpectationPrecedence(t *testing.T) {
	_, pinFP := testHostKey(t)
	_, storedFP := testHostKey(t)
	const hostport = "192.0.2.10:22"

	newStore := func(t *testing.T, seed string) *HostKeyStore {
		t.Helper()
		s := NewHostKeyStore(filepath.Join(t.TempDir(), "known_hosts.json"))
		if seed != "" {
			if err := s.Put(hostport, seed); err != nil {
				t.Fatalf("seed store: %v", err)
			}
		}
		return s
	}

	t.Run("pin wins over stored record", func(t *testing.T) {
		got, err := resolveHostKeyExpectation(
			Request{HostKeyFingerprint: pinFP}, hostport, newStore(t, storedFP))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.fp != pinFP {
			t.Errorf("fp = %q, want the pinned %q", got.fp, pinFP)
		}
		if !strings.Contains(got.src, "operator-pinned") {
			t.Errorf("src = %q, want it to name the operator pin", got.src)
		}
	})

	t.Run("stored record used when no pin", func(t *testing.T) {
		got, err := resolveHostKeyExpectation(Request{}, hostport, newStore(t, storedFP))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.fp != storedFP {
			t.Errorf("fp = %q, want the stored %q", got.fp, storedFP)
		}
		if !strings.Contains(got.src, "previous bootstrap") {
			t.Errorf("src = %q, want it to name the store", got.src)
		}
	})

	t.Run("a pin is normalised before use", func(t *testing.T) {
		// Operators paste fingerprints with the prefix omitted or with
		// base64 padding attached; both must resolve to the canonical
		// form the callback compares against.
		bare := strings.TrimPrefix(pinFP, "SHA256:")
		got, err := resolveHostKeyExpectation(
			Request{HostKeyFingerprint: "  " + bare + "==  "}, hostport, newStore(t, ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.fp != pinFP {
			t.Errorf("fp = %q, want normalised %q", got.fp, pinFP)
		}
	})

	t.Run("no pin and no record is TOFU when strict mode is off", func(t *testing.T) {
		got, err := resolveHostKeyExpectation(Request{}, hostport, newStore(t, ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.fp != "" {
			t.Errorf("fp = %q, want empty (first contact)", got.fp)
		}
	})

	t.Run("strict mode refuses an unpinned first contact", func(t *testing.T) {
		t.Setenv(requireHostKeyEnv, "1")
		_, err := resolveHostKeyExpectation(Request{}, hostport, newStore(t, ""))
		if err == nil {
			t.Fatal("strict mode allowed an unauthenticated first contact")
		}
		if !strings.Contains(err.Error(), requireHostKeyEnv) || !strings.Contains(err.Error(), hostport) {
			t.Errorf("refusal should name the env var and the target: %v", err)
		}
	})

	t.Run("strict mode is satisfied by a stored record", func(t *testing.T) {
		t.Setenv(requireHostKeyEnv, "1")
		got, err := resolveHostKeyExpectation(Request{}, hostport, newStore(t, storedFP))
		if err != nil {
			t.Fatalf("strict mode rejected an already-recorded target: %v", err)
		}
		if got.fp != storedFP {
			t.Errorf("fp = %q, want %q", got.fp, storedFP)
		}
	})
}

// TestReinstallHostKeyPolicy covers the strict-mode reinstall
// refusal. A reinstall regenerates the box's host keys, so nothing
// pinned beforehand can cover the reconnect and nothing in band can
// authenticate the replacement — strict mode has to refuse rather
// than silently fall back to trust-on-first-use, which is what it
// did before (hostKeyRequired had a single call site, on the
// first-contact dial only).
func TestReinstallHostKeyPolicy(t *testing.T) {
	enabled := ReinstallOpts{Enabled: true, OS: "debian", Version: "12"}

	t.Run("strict mode refuses a reinstall", func(t *testing.T) {
		t.Setenv(requireHostKeyEnv, "1")
		err := checkReinstallHostKeyPolicy(enabled)
		if err == nil {
			t.Fatal("reinstall allowed under strict host-key mode")
		}
		if !strings.Contains(err.Error(), requireHostKeyEnv) {
			t.Errorf("refusal should name the env var: %v", err)
		}
	})

	t.Run("strict mode allows a non-reinstall bootstrap", func(t *testing.T) {
		t.Setenv(requireHostKeyEnv, "1")
		if err := checkReinstallHostKeyPolicy(ReinstallOpts{}); err != nil {
			t.Fatalf("plain bootstrap refused: %v", err)
		}
	})

	// The escape hatch: strict mode stays on, but the operator can
	// waive verification for one run. The guarantee strict mode
	// actually makes is that nothing is trusted *silently*.
	t.Run("acknowledgement permits a reinstall under strict mode", func(t *testing.T) {
		t.Setenv(requireHostKeyEnv, "1")
		acked := enabled
		acked.AcknowledgeUnverifiableHostKey = true
		if err := checkReinstallHostKeyPolicy(acked); err != nil {
			t.Fatalf("acknowledged reinstall refused: %v", err)
		}
	})

	t.Run("the refusal explains how to proceed", func(t *testing.T) {
		t.Setenv(requireHostKeyEnv, "1")
		err := checkReinstallHostKeyPolicy(enabled)
		if err == nil {
			t.Fatal("expected a refusal")
		}
		if !strings.Contains(err.Error(), "acknowledgement") {
			t.Errorf("refusal should point at the acknowledgement: %v", err)
		}
	})

	// With strict mode off the field is meaningless and must not
	// change anything — the documented default is unchanged TOFU.
	t.Run("acknowledgement is a no-op when strict mode is off", func(t *testing.T) {
		acked := enabled
		acked.AcknowledgeUnverifiableHostKey = true
		if err := checkReinstallHostKeyPolicy(acked); err != nil {
			t.Fatalf("reinstall refused with strict mode off: %v", err)
		}
	})

	t.Run("reinstall allowed when strict mode is off", func(t *testing.T) {
		if err := checkReinstallHostKeyPolicy(enabled); err != nil {
			t.Fatalf("reinstall refused with strict mode off: %v", err)
		}
	})

	// The refusal has to reach the request boundary, so it lands as a
	// 400 before a job slot is taken and — the part that matters —
	// before the target is wiped.
	t.Run("Validate rejects the request under strict mode", func(t *testing.T) {
		t.Setenv(requireHostKeyEnv, "1")
		req := Request{
			Provider: "hetzner", IP: "192.0.2.10", Port: 22,
			Username: "root", Password: "pw",
			Hostname: "box.example.com", VaultPassword: "vp",
			Reinstall: enabled,
		}
		if err := Validate(req); err == nil {
			t.Fatal("Validate accepted a reinstall under strict host-key mode")
		}

		req.Reinstall.AcknowledgeUnverifiableHostKey = true
		if err := Validate(req); err != nil {
			t.Fatalf("Validate rejected an acknowledged reinstall: %v", err)
		}
	})
}

// TestValidateHostKeyFingerprint keeps malformed pins failing at the
// form boundary. A pin that can never match would otherwise surface
// 30 seconds into the run as an indistinguishable "host key
// mismatch", which reads like an attack rather than a typo.
func TestValidateHostKeyFingerprint(t *testing.T) {
	_, valid := testHostKey(t)
	good := []string{
		"", // no pin is always allowed
		valid,
		strings.TrimPrefix(valid, "SHA256:"), // prefix added by normalisation
		"  " + valid + "  ",
	}
	for _, s := range good {
		if err := validateHostKeyFingerprint(s); err != nil {
			t.Errorf("validateHostKeyFingerprint(%q) = %v, want nil", s, err)
		}
	}
	bad := []string{
		"SHA256:tooshort",
		"MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48", // legacy format
		"SHA256:" + strings.Repeat("A", 42),                   // one char short
		"SHA256:" + strings.Repeat("A", 44),                   // one char long
		"SHA256:" + strings.Repeat("!", 43),                   // not base64
		"not a fingerprint at all",
	}
	for _, s := range bad {
		if err := validateHostKeyFingerprint(s); err == nil {
			t.Errorf("validateHostKeyFingerprint(%q) = nil, want an error", s)
		}
	}
}
