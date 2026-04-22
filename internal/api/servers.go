package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/AlteredParadox/ansbui/internal/config"
)

func (s *Server) listServers(w http.ResponseWriter, _ *http.Request) {
	snap := s.Config.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"servers":        snap.Servers,
		"activeServerId": snap.ActiveServerID,
	})
}

func (s *Server) upsertServer(w http.ResponseWriter, r *http.Request) {
	var srv config.Server
	if err := json.NewDecoder(r.Body).Decode(&srv); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode body: %w", err))
		return
	}
	saved, err := s.Config.UpsertServer(srv)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) deleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	s.Pool.Drop(id)
	if err := s.Config.DeleteServer(id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) activateServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Config.SetActive(id); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"activeServerId": id})
}

func (s *Server) testServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	srv, ok := s.Config.ServerByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("unknown server %q", id))
		return
	}
	ctx := r.Context()
	client, err := s.Pool.Client(ctx, srv)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	sess, err := client.NewSession()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("open session: %v", err),
		})
		return
	}
	defer sess.Close()
	out, err := sess.Output("ansible --version 2>&1 | head -n1")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("probe ansible: %v", err),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"version": string(out),
	})
}

type settingsBody struct {
	PrometheusURL   string `json:"prometheusUrl"`
	PrometheusLabel string `json:"prometheusHostLabel"`
	AutoGatherFacts bool   `json:"autoGatherFacts"`
}

func (s *Server) getSettings(w http.ResponseWriter, _ *http.Request) {
	snap := s.Config.Snapshot()
	writeJSON(w, http.StatusOK, settingsBody{
		PrometheusURL:   snap.PrometheusURL,
		PrometheusLabel: snap.PrometheusLabel,
		AutoGatherFacts: snap.AutoGatherFacts,
	})
}

func (s *Server) setSettings(w http.ResponseWriter, r *http.Request) {
	var body settingsBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode body: %w", err))
		return
	}
	if err := s.Config.SetPrometheus(body.PrometheusURL, body.PrometheusLabel); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.Config.SetAutoGatherFacts(body.AutoGatherFacts); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, body)
}
