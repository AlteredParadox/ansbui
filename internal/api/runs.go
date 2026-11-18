package api

import (
	"fmt"
	"net/http"
)

func (s *Server) listRuns(w http.ResponseWriter, _ *http.Request) {
	// List carries no logs — clients fetch one via /api/runs/{id}.
	writeJSON(w, http.StatusOK, map[string]any{"runs": s.Runs.List()})
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
