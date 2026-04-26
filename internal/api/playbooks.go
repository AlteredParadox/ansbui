package api

import (
	"errors"
	"net/http"

	"github.com/AlteredParadox/ansbui/internal/ansible"
)

func (s *Server) listPlaybooks(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	pbs, err := ansible.ListPlaybooks(r.Context(), s.Pool, srv)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"playbooks": pbs})
}

func (s *Server) getPlaybook(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	name := r.URL.Query().Get("path")
	if name == "" {
		writeError(w, http.StatusBadRequest, errors.New("path query param is required"))
		return
	}
	pb, err := ansible.LoadPlaybook(r.Context(), s.Pool, srv, name)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, pb)
}

func (s *Server) putPlaybook(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var body struct {
		Path string `json:"path"`
		YAML string `json:"yaml"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if err := ansible.SavePlaybook(r.Context(), s.Pool, srv, body.Path, body.YAML); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
