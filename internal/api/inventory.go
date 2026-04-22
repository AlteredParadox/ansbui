package api

import (
	"context"
	"errors"
	"fmt"
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
	if metrics := s.tryMetrics(r.Context()); metrics != nil {
		applyMetrics(&inv, metrics)
	}
	writeJSON(w, http.StatusOK, inv)
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	metrics := s.tryMetrics(r.Context())
	if metrics == nil {
		writeJSON(w, http.StatusOK, map[string]any{"configured": false, "metrics": map[string]any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "metrics": metrics})
}

func (s *Server) tryMetrics(ctx context.Context) map[string]prom.HostMetric {
	url, label := s.Config.Prometheus()
	if url == "" {
		return nil
	}
	client, err := prom.NewClient(url, label)
	if err != nil {
		return nil
	}
	m, err := client.Metrics(ctx)
	if err != nil {
		return nil
	}
	return m
}

func applyMetrics(inv *ansible.Inventory, metrics map[string]prom.HostMetric) {
	for i := range inv.Hosts {
		h := &inv.Hosts[i]
		m, ok := metrics[h.Name]
		if !ok {
			// fall back to matching on ansible_host / IP
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
