package api

import (
	"fmt"
	"net/http"

	"github.com/AlteredParadox/relay/internal/ansible"
)

func (s *Server) listRuns(w http.ResponseWriter, _ *http.Request) {
	runs := s.Runs.List()
	// Strip the log from list responses — clients fetch it via /api/runs/{id}.
	out := make([]ansible.RunRecord, len(runs))
	for i, r := range runs {
		clone := r
		clone.Log = nil
		out[i] = clone
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": out})
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	run, ok := s.Runs.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("unknown run %q", id))
		return
	}
	writeJSON(w, http.StatusOK, run)
}
