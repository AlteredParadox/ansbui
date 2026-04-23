// Package config persists the user's ansible server connections and app
// preferences (e.g. the Prometheus URL used for live host metrics).
//
// The store is a single JSON file at $XDG_CONFIG_HOME/ansbui/config.json
// (falling back to ~/.config/ansbui/config.json). Access is guarded by a
// mutex so API handlers can read and mutate it concurrently.
//
// The previous "relay" directory is picked up transparently on first
// run so existing users don't lose their connections across the
// rename; see migrateLegacyDir.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Server is a single ansible control node the UI can talk to over SSH.
type Server struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	User      string `json:"user"`
	KeyPath   string `json:"keyPath,omitempty"`
	WorkDir   string `json:"workDir,omitempty"`
	Inventory string `json:"inventory,omitempty"`
	CreatedAt string `json:"createdAt"`
}

// Store is the on-disk config blob.
type Store struct {
	Servers         []Server `json:"servers"`
	ActiveServerID  string   `json:"activeServerId,omitempty"`
	PrometheusURL   string   `json:"prometheusUrl,omitempty"`
	PrometheusLabel string   `json:"prometheusHostLabel,omitempty"`
	// AutoGatherFacts controls whether the host-detail drawer fires a
	// `setup` module call automatically when the drawer opens. When
	// false, the drawer shows a [Gather facts] button instead so the
	// operator opts in per-host.
	AutoGatherFacts bool `json:"autoGatherFacts,omitempty"`
	// GeoIPEnabled controls whether inventory enrichment sends public
	// host IPs to ipinfo.io to populate the Region column. Off by
	// default — IPs leave the local network to a third-party.
	GeoIPEnabled bool `json:"geoIpEnabled,omitempty"`
}

// Manager loads, persists, and mutates the config store.
type Manager struct {
	path  string
	mu    sync.RWMutex
	store Store
}

// New returns a Manager backed by the default config path. It creates the
// file on first use with sensible defaults, and promotes a legacy
// ~/.config/relay directory (pre-rename) if it's present.
func New() (*Manager, error) {
	path, err := defaultPath()
	if err != nil {
		return nil, err
	}
	migrateLegacyDir(filepath.Dir(path))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	m := &Manager{path: path}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

// legacyConfigDirName is the pre-rename directory the app used to
// write to (when the binary was called "relay"). migrateLegacyDir
// promotes it to the new location on first run so existing users
// don't lose their server list / prometheus settings.
const legacyConfigDirName = "relay"

func migrateLegacyDir(newDir string) {
	if _, err := os.Stat(newDir); err == nil {
		return // new dir already exists, nothing to do
	}
	parent := filepath.Dir(newDir)
	legacy := filepath.Join(parent, legacyConfigDirName)
	if _, err := os.Stat(legacy); err != nil {
		return
	}
	_ = os.Rename(legacy, newDir)
}

func defaultPath() (string, error) {
	if p := os.Getenv("ANSBUI_CONFIG"); p != "" {
		return p, nil
	}
	// Back-compat: users who set RELAY_CONFIG before the rename still
	// work without changing their env.
	if p := os.Getenv("RELAY_CONFIG"); p != "" {
		return p, nil
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "ansbui", "config.json"), nil
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		m.store = Store{
			Servers:         []Server{},
			PrometheusLabel: "instance",
		}
		return m.persistLocked()
	}
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, &m.store); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if m.store.PrometheusLabel == "" {
		m.store.PrometheusLabel = "instance"
	}
	return nil
}

func (m *Manager) persistLocked() error {
	data, err := json.MarshalIndent(m.store, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	return atomicWrite(m.path, data)
}

// atomicWrite writes data to a sibling tmp file, fsyncs, then renames
// over the target. Without the fsync, a crash between the rename and
// the writeback can leave a zero-byte file on disk.
func atomicWrite(path string, data []byte) error {
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
	return os.Rename(tmp, path)
}

// Snapshot returns a deep copy of the current store.
func (m *Manager) Snapshot() Store {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneStore(m.store)
}

// Servers returns the configured servers.
func (m *Manager) Servers() []Server {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Server, len(m.store.Servers))
	copy(out, m.store.Servers)
	return out
}

// ServerByID returns the server with the given id, or false.
func (m *Manager) ServerByID(id string) (Server, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.store.Servers {
		if s.ID == id {
			return s, true
		}
	}
	return Server{}, false
}

// ActiveServer returns the active server (the one most recently selected
// by the UI). The boolean is false when no server is selected or when the
// active id points to a deleted entry.
func (m *Manager) ActiveServer() (Server, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.store.ActiveServerID == "" {
		return Server{}, false
	}
	for _, s := range m.store.Servers {
		if s.ID == m.store.ActiveServerID {
			return s, true
		}
	}
	return Server{}, false
}

// UpsertServer adds a new server or updates one with the same id.
func (m *Manager) UpsertServer(in Server) (Server, error) {
	if err := validateServer(in); err != nil {
		return Server{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	in = normaliseServer(in)
	for i, s := range m.store.Servers {
		if s.ID == in.ID {
			in.CreatedAt = s.CreatedAt
			m.store.Servers[i] = in
			if err := m.persistLocked(); err != nil {
				return Server{}, err
			}
			return in, nil
		}
	}
	if in.CreatedAt == "" {
		in.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	m.store.Servers = append(m.store.Servers, in)
	if err := m.persistLocked(); err != nil {
		return Server{}, err
	}
	return in, nil
}

// DeleteServer removes a server by id.
func (m *Manager) DeleteServer(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	filtered := m.store.Servers[:0]
	for _, s := range m.store.Servers {
		if s.ID != id {
			filtered = append(filtered, s)
		}
	}
	m.store.Servers = filtered
	if m.store.ActiveServerID == id {
		m.store.ActiveServerID = ""
	}
	return m.persistLocked()
}

// SetActive marks the given server as active.
func (m *Manager) SetActive(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.store.Servers {
		if s.ID == id {
			m.store.ActiveServerID = id
			return m.persistLocked()
		}
	}
	return fmt.Errorf("unknown server id %q", id)
}

// SetPrometheus updates the Prometheus integration settings. The URL is
// normalised so that entries like "10.0.0.1:9090" (no scheme) and
// trailing-slash variants all persist as a clean http(s):// URL.
func (m *Manager) SetPrometheus(rawURL, label string) error {
	normalised, err := normalisePromURL(rawURL)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store.PrometheusURL = normalised
	if label = strings.TrimSpace(label); label != "" {
		m.store.PrometheusLabel = label
	}
	return m.persistLocked()
}

// normalisePromURL trims whitespace + trailing slashes and prepends
// http:// when no scheme is present. Returns "" for empty input.
// Rejects anything other than http / https so a user can't sneak a
// file:// or javascript: URL through the settings endpoint.
func normalisePromURL(raw string) (string, error) {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	if s == "" {
		return "", nil
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("invalid prometheus URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("prometheus URL scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("prometheus URL is missing a host")
	}
	return s, nil
}

// Prometheus returns the configured Prometheus URL and host label.
func (m *Manager) Prometheus() (url, label string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.store.PrometheusURL, m.store.PrometheusLabel
}

// SetAutoGatherFacts persists the auto-gather toggle.
func (m *Manager) SetAutoGatherFacts(v bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store.AutoGatherFacts = v
	return m.persistLocked()
}

// SetGeoIPEnabled persists the geoip enrichment toggle.
func (m *Manager) SetGeoIPEnabled(v bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store.GeoIPEnabled = v
	return m.persistLocked()
}

func validateServer(s Server) error {
	if strings.TrimSpace(s.Host) == "" {
		return errors.New("host is required")
	}
	if strings.TrimSpace(s.User) == "" {
		return errors.New("user is required")
	}
	if s.Port < 0 || s.Port > 65535 {
		return errors.New("port must be between 0 and 65535")
	}
	return nil
}

func normaliseServer(s Server) Server {
	if s.Port == 0 {
		s.Port = 22
	}
	s.Host = strings.TrimSpace(s.Host)
	s.User = strings.TrimSpace(s.User)
	s.KeyPath = strings.TrimSpace(s.KeyPath)
	s.WorkDir = strings.TrimSpace(s.WorkDir)
	s.Inventory = strings.TrimSpace(s.Inventory)
	if s.ID == "" {
		s.ID = slugify(s.Name, s.Host, s.User)
	}
	if s.Name == "" {
		s.Name = fmt.Sprintf("%s@%s", s.User, s.Host)
	}
	return s
}

func slugify(parts ...string) string {
	var buf strings.Builder
	for _, p := range parts {
		for _, r := range strings.ToLower(p) {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
				buf.WriteRune(r)
			case r == '-', r == '_', r == '.':
				buf.WriteRune('-')
			}
		}
		buf.WriteByte('-')
	}
	out := strings.Trim(buf.String(), "-")
	if out == "" {
		out = fmt.Sprintf("server-%d", time.Now().Unix())
	}
	return out
}

func cloneStore(s Store) Store {
	out := s
	out.Servers = make([]Server, len(s.Servers))
	copy(out.Servers, s.Servers)
	return out
}
