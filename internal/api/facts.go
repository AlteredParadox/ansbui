package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/AlteredParadox/ansbui/internal/ansible"
)

// /api/facts?host=<name> — runs ansible … -m setup --one-line and
// returns the decoded ansible_facts map. Single-host query only; the
// caller's host param is passed through as the ansible target.
func (s *Server) getFacts(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	if host == "" {
		writeError(w, http.StatusBadRequest, errors.New("host query param is required"))
		return
	}
	result, err := ansible.GatherFacts(r.Context(), s.Pool, srv, host)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
