package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/AlteredParadox/relay/internal/ansible"
	"github.com/AlteredParadox/relay/internal/config"
	"github.com/AlteredParadox/relay/internal/prom"
)

// dnsCache memoises hostname → []IP lookups so the DNS fallback in
// applyMetrics stays cheap when an inventory has many hosts and
// /api/inventory is polled. Entries are valid for 60s.
type dnsCache struct {
	mu      sync.Mutex
	entries map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	ips    []string
	expiry time.Time
}

var sharedDNS = &dnsCache{entries: map[string]dnsCacheEntry{}}

func (c *dnsCache) lookup(ctx context.Context, host string) []string {
	c.mu.Lock()
	e, ok := c.entries[host]
	c.mu.Unlock()
	if ok && time.Now().Before(e.expiry) {
		return e.ips
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	var ips []string
	if err == nil {
		ips = make([]string, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP.String())
		}
	}
	c.mu.Lock()
	c.entries[host] = dnsCacheEntry{ips: ips, expiry: time.Now().Add(60 * time.Second)}
	c.mu.Unlock()
	return ips
}

func (s *Server) resolveServer(r *http.Request) (config.Server, error) {
	id := r.URL.Query().Get("server")
	if id == "" {
		if srv, ok := s.Config.ActiveServer(); ok {
			return srv, nil
		}
		return config.Server{}, errors.New("no ansible server selected")
	}
	srv, ok := s.Config.ServerByID(id)
	if !ok {
		return config.Server{}, fmt.Errorf("unknown server %q", id)
	}
	return srv, nil
}

func (s *Server) inventory(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	inv, err := ansible.FetchInventory(r.Context(), s.Pool, srv)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if result, ok := s.tryMetrics(r.Context()); ok {
		applyMetrics(r.Context(), &inv, result.Metrics)
	}
	writeJSON(w, http.StatusOK, inv)
}

// metrics returns the raw per-host metric snapshot plus per-probe
// diagnostics. The UI's settings panel uses this to explain why
// Prometheus data may not be showing up, including a cross-reference
// between the live Prometheus hosts and the current inventory.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	url, _ := s.Config.Prometheus()
	if url == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": false,
			"metrics":    map[string]any{},
			"probes":     []any{},
		})
		return
	}
	result, ok := s.tryMetrics(r.Context())
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"configured": true,
			"error":      "prometheus client could not be constructed (check URL / logs)",
			"metrics":    map[string]any{},
			"probes":     []any{},
		})
		return
	}
	diagnosis := map[string]any{
		"configured": true,
		"metrics":    result.Metrics,
		"probes":     result.Probes,
	}
	// Best-effort cross-reference: if we can resolve an active server,
	// compute which inventory hostnames matched a Prom sample and which
	// didn't, and list any Prom hosts that had no inventory entry.
	if srv, err := s.resolveServer(r); err == nil {
		if inv, err := ansible.FetchInventory(r.Context(), s.Pool, srv); err == nil {
			matched, unmatchedInv, unmatchedProm := diffMetrics(r.Context(), inv, result.Metrics)
			diagnosis["matched"] = matched
			diagnosis["unmatchedInventory"] = unmatchedInv
			diagnosis["unmatchedPrometheus"] = unmatchedProm
		}
	}
	writeJSON(w, http.StatusOK, diagnosis)
}

// diffMetrics returns (matched, inventory-only, prometheus-only)
// hostname slices so the UI can show the operator exactly where names
// are diverging. Match order mirrors applyMetrics: inventory name →
// ansible_host → DNS-resolved IPs of the inventory name. The last rule
// covers Tailscale / WireGuard setups where Prometheus stores the
// scrape IP but the inventory uses FQDNs.
func diffMetrics(ctx context.Context, inv ansible.Inventory, metrics map[string]prom.HostMetric) (matched, invOnly, promOnly []string) {
	seen := make(map[string]bool, len(metrics))
	for _, h := range inv.Hosts {
		if key, ok := matchHost(ctx, h, metrics); ok {
			matched = append(matched, h.Name)
			seen[key] = true
			continue
		}
		invOnly = append(invOnly, h.Name)
	}
	for k := range metrics {
		if !seen[k] {
			promOnly = append(promOnly, k)
		}
	}
	return
}

// matchHost returns the metrics map key that matched (so diffMetrics
// can mark it used) and whether a match was found. Lookup order:
//
//  1. inventory host name
//  2. ansible_host (often an IP)
//  3. any IP the host name resolves to via the system resolver — this
//     lets Prometheus label samples with e.g. Tailscale 100.x addresses
//     while the inventory uses FQDNs.
func matchHost(ctx context.Context, h ansible.Host, metrics map[string]prom.HostMetric) (string, bool) {
	if _, ok := metrics[h.Name]; ok {
		return h.Name, true
	}
	if h.IP != "" {
		if _, ok := metrics[h.IP]; ok {
			return h.IP, true
		}
	}
	for _, ip := range sharedDNS.lookup(ctx, h.Name) {
		if _, ok := metrics[ip]; ok {
			return ip, true
		}
	}
	return "", false
}

func (s *Server) tryMetrics(ctx context.Context) (prom.MetricsResult, bool) {
	url, label := s.Config.Prometheus()
	if url == "" {
		return prom.MetricsResult{}, false
	}
	client, err := prom.NewClient(url, label)
	if err != nil {
		log.Printf("prom: bad client config: %v", err)
		return prom.MetricsResult{}, false
	}
	result, err := client.Metrics(ctx)
	if err != nil {
		log.Printf("prom: metrics call failed: %v", err)
		return prom.MetricsResult{}, false
	}
	for _, p := range result.Probes {
		if p.Error != "" {
			log.Printf("prom: probe %q failed: %s", p.Name, p.Error)
		}
	}
	return result, true
}

func applyMetrics(ctx context.Context, inv *ansible.Inventory, metrics map[string]prom.HostMetric) {
	for i := range inv.Hosts {
		h := &inv.Hosts[i]
		key, ok := matchHost(ctx, *h, metrics)
		if !ok {
			continue
		}
		m := metrics[key]
		h.CPU = m.CPU
		h.Mem = m.Mem
		h.Load = m.Load
		if m.Uptime > 0 {
			h.Uptime = m.Uptime
		}
		if m.OS != "" {
			h.OS = m.OS
		}
		if !m.Up {
			h.Status = "err"
		} else if m.CPU > 90 || m.Mem > 90 {
			h.Status = "warn"
		} else {
			h.Status = "ok"
		}
	}
}
