package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/prom"
)

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
		applyMetrics(&inv, result.Metrics)
	}
	if s.Config.Snapshot().GeoIPEnabled {
		s.geoResolver().enrichInventory(r.Context(), &inv)
	}
	applyLastPlay(&inv, s.Runs.LastPlayPerHost())
	writeJSON(w, http.StatusOK, inv)
}

// applyLastPlay decorates each host with its most recent playbook
// and that run's start time, sourced from the recap events recorded
// in runs.json. Hosts that have never been part of a playbook recap
// pass through untouched.
func applyLastPlay(inv *ansible.Inventory, last map[string]ansible.LastPlay) {
	for i := range inv.Hosts {
		if lp, ok := last[inv.Hosts[i].Name]; ok {
			inv.Hosts[i].LastPlaybook = lp.Playbook
			inv.Hosts[i].LastPlaybookAt = lp.At
		}
	}
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
			matched, unmatchedInv, unmatchedProm := diffMetrics(inv, result.Metrics)
			diagnosis["matched"] = matched
			diagnosis["unmatchedInventory"] = unmatchedInv
			diagnosis["unmatchedPrometheus"] = unmatchedProm
		}
	}
	writeJSON(w, http.StatusOK, diagnosis)
}

// diffMetrics returns (matched, inventory-only, prometheus-only)
// hostname slices so the UI can show the operator exactly where names
// are diverging.
func diffMetrics(inv ansible.Inventory, metrics map[string]prom.HostMetric) (matched, invOnly, promOnly []string) {
	seen := make(map[string]bool, len(metrics))
	for _, h := range inv.Hosts {
		if _, ok := metrics[h.Name]; ok {
			matched = append(matched, h.Name)
			seen[h.Name] = true
			continue
		}
		if _, ok := metrics[h.IP]; ok {
			matched = append(matched, h.Name)
			seen[h.IP] = true
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

func (s *Server) tryMetrics(ctx context.Context) (prom.MetricsResult, bool) {
	url, label := s.Config.Prometheus()
	if url == "" {
		return prom.MetricsResult{}, false
	}
	client, err := prom.NewClient(url, label)
	if err != nil {
		log.Printf("prom: bad client config: %s", logSafe(err.Error()))
		return prom.MetricsResult{}, false
	}
	result, err := client.Metrics(ctx)
	if err != nil {
		log.Printf("prom: metrics call failed: %s", logSafe(err.Error()))
		return prom.MetricsResult{}, false
	}
	for _, p := range result.Probes {
		if p.Error != "" {
			log.Printf("prom: probe %q failed: %s", p.Name, logSafe(p.Error))
		}
	}
	return result, true
}

// maxLoggedRemoteText bounds one piece of remote-derived text in a
// log line.
const maxLoggedRemoteText = 512

// logSafe makes text that may have been written by a remote peer safe
// to put in the server log: shortened, with every non-printing
// character (newline, carriage return, other controls, the Unicode
// line separators) written as an escape, so it cannot start a new log
// line. The access logger quotes method and path for the same reason.
// prom.fetch already bounds and quotes what it takes from a response;
// doing it here as well means this log does not depend on every
// caller remembering to.
func logSafe(s string) string {
	if len(s) > maxLoggedRemoteText {
		s = strings.ToValidUTF8(s[:maxLoggedRemoteText], "") + "…"
	}
	var b strings.Builder
	for _, r := range s {
		if strconv.IsPrint(r) {
			b.WriteRune(r)
			continue
		}
		fmt.Fprintf(&b, "\\u%04x", r)
	}
	return b.String()
}

func applyMetrics(inv *ansible.Inventory, metrics map[string]prom.HostMetric) {
	for i := range inv.Hosts {
		h := &inv.Hosts[i]
		m, ok := metrics[h.Name]
		if !ok {
			m, ok = metrics[h.IP]
		}
		if !ok {
			continue
		}
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
