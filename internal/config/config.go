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
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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
	// ControlPrivKeyPath is the path on the active control node to
	// the SSH private key whose public counterpart gets installed
	// into the ansible user's authorized_keys during bootstrap.
	// Used by the post-reinstall reconnect step to dial the freshly-
	// installed target on :4242 with key auth. Empty means use the
	// default (~/.ssh/ansible_ed25519).
	ControlPrivKeyPath string `json:"controlPrivKeyPath,omitempty"`
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
// the writeback can leave a zero-byte file on disk. The directory
// entry itself also needs an fsync after the rename — a power loss
// after the rename's metadata hits the journal but before the dir's
// inode is flushed leaves the new file invisible at boot.
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
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

// fsyncDir flushes a directory's inode so a rename or unlink that
// landed in the journal becomes durable across crashes/power loss.
// On Linux this is a no-arg fsync against the directory's fd; on
// platforms that disallow it we'd need a different shim, but ansbui
// only ships on Linux.
func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir for fsync: %w", err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	return nil
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

// promLabelRE matches the Prometheus label-name grammar — the same
// shape PromQL accepts for `by (...)` group keys. Validating at the
// settings boundary stops a hostile label like `instance) +
// vector(0)` from being spliced into a query expression.
var promLabelRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func validatePromLabel(s string) error {
	if !promLabelRE.MatchString(s) {
		return fmt.Errorf("prometheus label %q must match [a-zA-Z_][a-zA-Z0-9_]*", s)
	}
	return nil
}

// normalisePromURL trims whitespace + trailing slashes and prepends
// http:// when no scheme is present. Returns "" for empty input.
// Rejects anything other than http / https so a user can't sneak a
// file:// or javascript: URL through the settings endpoint.
//
// SSRF guardrails: the metrics fetcher hits whatever URL is stored
// here, server-side, with no per-user auth in front. Allowlist by
// default — denylists miss private services on RFC1918 networks
// and don't address DNS rebinding at fetch time:
//
//   - When ANSBUI_PROM_ALLOWED_HOSTS is set (comma-separated
//     host[:port] entries), only those hosts are accepted. This is
//     the right setting for any deployment behind shared auth.
//   - When unset, only loopback hosts (127.0.0.1, ::1, "localhost")
//     are accepted. Matches the default loopback bind: the typical
//     install scrapes a same-host Prometheus.
//   - Cloud-IMDS hostnames are always rejected (defence in depth
//     even on loopback — should never resolve there, but a
//     misconfigured /etc/hosts could).
//
// We deliberately don't resolve the hostname here. DNS lookup at
// validation time races with the actual fetch (rebinding); a
// thorough fix would inspect the resolved IP inside the
// http.Transport's DialContext. Tracked as a follow-up — the
// allowlist already constrains the surface to a known set of
// hostnames, which is the practically valuable bound.
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
	if err := CheckPromHost(u.Hostname(), u.Host); err != nil {
		return "", err
	}
	return s, nil
}

// promMetadataDeny is the cloud-IMDS denylist. These addresses are
// link-local (169.254.0.0/16) on every IaaS we know of — there is
// no legitimate reason for ansbui to scrape Prometheus over them,
// and reaching them server-side would expose IAM credentials.
var promMetadataDeny = map[string]struct{}{
	"169.254.169.254":          {}, // AWS / GCP / OpenStack / DigitalOcean IMDS
	"169.254.170.2":            {}, // AWS ECS task metadata
	"fd00:ec2::254":            {}, // AWS IMDSv6
	"metadata.google.internal": {},
	"metadata":                 {},
	"169.254.169.254.nip.io":   {}, // common SSRF bypass
}

// CheckPromHost enforces the SSRF allowlist described on
// normalisePromURL. Exported so prom.NewClient can re-check at fetch
// time: a config.json edited by hand (or written by an older binary)
// bypasses the settings endpoint entirely, and write-time-only
// validation would let such a URL reach cloud metadata server-side.
func CheckPromHost(host, hostport string) error {
	hostLower := strings.ToLower(host)
	if _, blocked := promMetadataDeny[hostLower]; blocked {
		return fmt.Errorf("prometheus host %q is on the cloud-metadata denylist", host)
	}
	// 169.254.0.0/16 catches arbitrary link-local addresses that
	// aren't on the explicit denylist (some providers stick IMDS at
	// a non-canonical link-local).
	if ip := net.ParseIP(host); ip != nil && ip.IsLinkLocalUnicast() {
		return fmt.Errorf("prometheus host %q is link-local (169.254.0.0/16) — denied", host)
	}
	allow := strings.TrimSpace(os.Getenv("ANSBUI_PROM_ALLOWED_HOSTS"))
	if allow == "" {
		// Default: loopback only. Operators wanting any other host
		// must set ANSBUI_PROM_ALLOWED_HOSTS — keeps the SSRF
		// surface to either same-host Prom or an explicitly named
		// remote, no surprise pivots into private services.
		if isLoopbackHost(host) {
			return nil
		}
		return fmt.Errorf("prometheus host %q is not loopback; set ANSBUI_PROM_ALLOWED_HOSTS=%s to allow it (allowlist required because ansbui has no built-in auth — see config.go normalisePromURL)", host, hostport)
	}
	for _, entry := range strings.Split(allow, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.EqualFold(entry, host) || strings.EqualFold(entry, hostport) {
			return nil
		}
	}
	return fmt.Errorf("prometheus host %q is not in ANSBUI_PROM_ALLOWED_HOSTS", hostport)
}

// isLoopbackHost recognises the textual forms of localhost: the
// literal "localhost" name and any IP that net.ParseIP marks as
// loopback (127.0.0.0/8 and ::1). Anything else gets routed through
// the allowlist requirement above.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// Prometheus returns the configured Prometheus URL and host label.
func (m *Manager) Prometheus() (url, label string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.store.PrometheusURL, m.store.PrometheusLabel
}

// SettingsUpdate bundles every field the /api/settings endpoint can
// touch in one call. Used by SetSettings to apply all four values
// under a single mutex + a single persist, so a mid-way disk error
// can never leave the on-disk store with prom URL applied but
// (say) GeoIPEnabled still at the old value.
type SettingsUpdate struct {
	PrometheusURL      string
	PrometheusLabel    string
	AutoGatherFacts    bool
	GeoIPEnabled       bool
	ControlPrivKeyPath string
}

// SetSettings applies every field in u atomically. Validation runs
// before any mutation, so a bad Prometheus URL fails the whole call
// and the store stays at its previous state. The single persist at
// the end is the same atomicWrite the individual setters use, so a
// crash inside the rename is still safe.
func (m *Manager) SetSettings(u SettingsUpdate) error {
	normalisedURL, err := normalisePromURL(u.PrometheusURL)
	if err != nil {
		return err
	}
	label := strings.TrimSpace(u.PrometheusLabel)
	if label != "" {
		if err := validatePromLabel(label); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store.PrometheusURL = normalisedURL
	if label != "" {
		m.store.PrometheusLabel = label
	}
	m.store.AutoGatherFacts = u.AutoGatherFacts
	m.store.GeoIPEnabled = u.GeoIPEnabled
	m.store.ControlPrivKeyPath = strings.TrimSpace(u.ControlPrivKeyPath)
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
