// ansbui — a single-binary web UI for an Ansible control node.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

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
