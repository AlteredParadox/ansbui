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
	if !ansible.ValidHostName(host) {
		writeError(w, http.StatusBadRequest, ansible.ErrFactsHost)
		return
	}
	result, err := ansible.GatherFacts(r.Context(), s.Pool, srv, host)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
