package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/AlteredParadox/relay/internal/ansible"
	"github.com/AlteredParadox/relay/internal/config"
	"github.com/AlteredParadox/relay/internal/prom"
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
	writeJSON(w, http.StatusOK, inv)
}

// metrics returns the raw per-host metric snapshot plus per-probe
// diagnostics. The UI's settings panel uses this to explain why
// Prometheus data may not be showing up.
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
			"error":      "prometheus client could not be constructed (check URL)",
			"metrics":    map[string]any{},
			"probes":     []any{},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": true,
		"metrics":    result.Metrics,
		"probes":     result.Probes,
	})
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
