package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// HostKeyStore persists the SSH host key fingerprints bootstrap has
// accepted, keyed by "host:port". It is ansbui's own known_hosts for
// the bootstrap path: the sshpool (regular control-node connections)
// already uses OpenSSH known_hosts, but bootstrap targets are dialed
// with password auth before any key exists there, and a warn-only
// TOFU gave an on-path attacker the operator's root password on
// every run, not just the first. With the store, only the genuine
// first contact is unauthenticated; every later bootstrap of the
// same host:port must present the recorded key or the dial fails
// before the password is ever transmitted (the host key callback
// runs before SSH auth).
//
// The file is a flat JSON object {"host:port": "SHA256:…"} living
// next to runs.json so it lands in the deployment's writable data
// dir. Writes go through the same tmp+fsync+rename+dir-fsync pattern
// as the config and history writers.
//
// A nil *HostKeyStore is valid and behaves as an empty, non-recording
// store — keeps bootstrap.Run testable without disk state.
type HostKeyStore struct {
	path string
	mu   sync.Mutex
}

// NewHostKeyStore returns a store backed by the JSON file at path.
// The file is created on first Put.
func NewHostKeyStore(path string) *HostKeyStore {
	return &HostKeyStore{path: path}
}

// Path returns the backing file location, for operator-facing
// messages ("remove the entry in … to reset trust").
func (s *HostKeyStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// load reads the whole map. Missing file = empty store; any other
// read/parse failure is returned — treating a corrupt or unreadable
// store as empty would silently downgrade every verification back
// to trust-on-first-use.
func (s *HostKeyStore) load() (map[string]string, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read bootstrap host key store %s: %w", s.path, err)
	}
	m := map[string]string{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse bootstrap host key store %s (fix or remove the file): %w", s.path, err)
	}
	return m, nil
}

// Get returns the recorded fingerprint for hostport.
func (s *HostKeyStore) Get(hostport string) (fp string, ok bool, err error) {
	if s == nil {
		return "", false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return "", false, err
	}
	fp, ok = m[strings.ToLower(hostport)]
	return fp, ok, nil
}

// Put records fp for hostport, replacing any previous entry.
func (s *HostKeyStore) Put(hostport, fp string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.load()
	if err != nil {
		return err
	}
	m[strings.ToLower(hostport)] = fp
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode bootstrap host key store: %w", err)
	}
	return atomicWriteFile(s.path, data)
}

// atomicWriteFile mirrors the config/history writers: tmp file,
// fsync, rename, fsync parent dir — a recorded trust decision must
// not evaporate on power loss.
func atomicWriteFile(path string, data []byte) error {
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

// requireHostKeyEnv is the strict-mode knob: when set to 1/true,
// bootstrap refuses to dial a target that has neither an operator-
// supplied fingerprint nor a stored one — first contact must then be
// explicitly pinned from the provider console. The default remains
// record-and-enforce TOFU because many providers expose no host key
// out of band at all.
const requireHostKeyEnv = "ANSBUI_BOOTSTRAP_REQUIRE_HOSTKEY"

func hostKeyRequired() bool {
	v := strings.TrimSpace(os.Getenv(requireHostKeyEnv))
	return v == "1" || strings.EqualFold(v, "true")
}
