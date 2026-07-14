// Package auth provides ansbui's optional single-operator
// authentication: an argon2id password credential stored as a hash
// in the config dir, and an in-memory session store behind the
// login cookie.
//
// Auth is OFF unless a credential file exists — set one with
// `ansbui -set-password`. This keeps existing reverse-proxy
// deployments working across the upgrade; main.go logs a loud
// warning while no credential is configured, mirroring the
// ANSBUI_INSECURE_SSH posture.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters. Tuned for an interactive login on a modest
// control node: 64 MiB / 3 passes is comfortably above OWASP's
// floor while staying well under a second. They're encoded into the
// hash string, so raising them later doesn't invalidate existing
// credentials — a login re-hash path could upgrade in place, but a
// single operator can just re-run -set-password.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// Ceilings for the cost parameters accepted from a stored hash.
// The parameters come from the credential file, so a corrupt or
// hand-edited file could otherwise smuggle values that panic inside
// argon2 (zero rounds/threads) or turn every login attempt into a
// host-exhausting allocation (multi-GiB memory). Generous multiples
// of our own encoding constants above; anything outside is not a
// credential this code ever wrote.
const (
	maxArgonTime    = 64
	maxArgonMemory  = 1 << 20 // KiB (1 GiB)
	maxArgonThreads = 64
)

// Credential is a loaded password hash. The zero value is not
// usable; use LoadCredential or SetCredential.
type Credential struct {
	encoded string // PHC-style $argon2id$... string
}

// hashPassword derives the argon2id encoding for password with a
// fresh random salt.
func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	// PHC string format, matching the de-facto argon2 encoding so the
	// file is recognisable and re-parseable.
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// params carries the decoded cost parameters + salt/hash for Verify.
type params struct {
	memory, time uint32
	threads      uint8
	salt, hash   []byte
}

// validateCosts bounds the cost parameters (see maxArgon* above):
// zero rounds/threads panic inside argon2.IDKey at login time, and
// oversized memory/time are a resource-exhaustion primitive.
// Rejecting here means a corrupt credential fails at startup
// (LoadCredential) with a clear message, not on first login.
func (p params) validateCosts() error {
	if p.time == 0 || p.time > maxArgonTime {
		return fmt.Errorf("argon2 time parameter %d out of range [1, %d]", p.time, maxArgonTime)
	}
	if p.threads == 0 || p.threads > maxArgonThreads {
		return fmt.Errorf("argon2 threads parameter %d out of range [1, %d]", p.threads, maxArgonThreads)
	}
	if p.memory < 8*uint32(p.threads) || p.memory > maxArgonMemory {
		return fmt.Errorf("argon2 memory parameter %d KiB out of range [%d, %d]", p.memory, 8*uint32(p.threads), maxArgonMemory)
	}
	return nil
}

// parseEncoded decodes a PHC argon2id string. Rejects any other
// variant/version so a hand-edited or foreign hash fails loudly
// rather than silently never matching.
func parseEncoded(encoded string) (params, error) {
	var p params
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, errors.New("not an argon2id hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, fmt.Errorf("unsupported argon2 version %q", parts[2])
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return p, fmt.Errorf("malformed argon2 params %q", parts[3])
	}
	if err := p.validateCosts(); err != nil {
		return p, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return p, fmt.Errorf("decode salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return p, fmt.Errorf("decode hash: %w", err)
	}
	// Bound the salt: this code always writes argonSaltLen (16)
	// bytes, but accept a small range so changing that constant
	// later doesn't orphan existing credentials. Below 8 bytes is
	// outside the argon2 RFC's recommendation and means the stored
	// value was never ours; an oversized one is corruption.
	if len(salt) < 8 || len(salt) > 64 {
		return p, fmt.Errorf("unexpected argon2 salt length %d", len(salt))
	}
	// Bound the hash length: it's the argon2 output key length and
	// must round-trip through uint32 in Verify. A pathological
	// hand-edited hash can't drive a huge allocation this way.
	if len(hash) == 0 || len(hash) > 1024 {
		return p, fmt.Errorf("unexpected argon2 hash length %d", len(hash))
	}
	p.salt, p.hash = salt, hash
	return p, nil
}

// Verify reports whether password matches the credential, in
// constant time relative to the stored hash. Uses the cost
// parameters baked into the encoded hash so an older credential
// still verifies after the constants above change.
func (c Credential) Verify(password string) bool {
	p, err := parseEncoded(c.encoded)
	if err != nil {
		return false
	}
	keyLen := uint32(len(p.hash)) //nolint:gosec // G115: parseEncoded bounds len(p.hash) to (0,1024]
	got := argon2.IDKey([]byte(password), p.salt, p.time, p.memory, p.threads, keyLen)
	return subtle.ConstantTimeCompare(got, p.hash) == 1
}

// LoadCredential reads the credential file at path. Returns
// (nil, nil) when the file does not exist — auth is simply disabled
// in that case; any other read/parse error is returned so a
// corrupt or unreadable credential can't silently disable auth on a
// deployment that meant to have it.
func LoadCredential(path string) (*Credential, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read credential %s: %w", path, err)
	}
	encoded := strings.TrimSpace(string(data))
	if encoded == "" {
		return nil, fmt.Errorf("credential file %s is empty — re-run -set-password", path)
	}
	if _, err := parseEncoded(encoded); err != nil {
		return nil, fmt.Errorf("credential file %s is not a valid argon2id hash (%w) — re-run -set-password", path, err)
	}
	return &Credential{encoded: encoded}, nil
}

// SetCredential hashes password and writes it to path atomically
// with 0600 perms (tmp + fsync + rename + dir fsync), creating the
// directory if needed. Used by the -set-password CLI path.
func SetCredential(path, password string) error {
	if strings.TrimSpace(password) == "" {
		return errors.New("password must not be empty")
	}
	encoded, err := hashPassword(password)
	if err != nil {
		return err
	}
	return atomicWrite0600(path, []byte(encoded+"\n"))
}

// atomicWrite0600 writes data durably at 0600 (see the config /
// history writers for the same pattern — kept local so auth has no
// cross-package dependency for a five-line helper).
func atomicWrite0600(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create dir for %s: %w", path, err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open temp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open dir for fsync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	return nil
}
