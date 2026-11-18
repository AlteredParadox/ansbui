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
	"net/http"
	"regexp"
)

// sourceBaseURL is where the Corresponding Source is published. AGPL §13
// requires that a network user be offered the source of the version they
// are interacting with — a downstream fork that changes this (and rebuilds)
// makes /source point at ITS source, which is exactly the intent.
const sourceBaseURL = "https://github.com/AlteredParadox/ansbui"

// Legal carries the texts embedded at the repo root (see legal.go there)
// and the build's version stamp.
type Legal struct {
	// License is the project's own license text.
	License []byte
	// ThirdPartyLicenses is the generated notices file for everything
	// linked into or embedded in the binary.
	ThirdPartyLicenses []byte
	// Version is the build stamp: a release tag, or "dev" / empty for an
	// unstamped build.
	Version string
}

// version returns the build version ("dev" for unstamped builds).
func (s *Server) version() string {
	if s.Legal.Version == "" {
		return "dev"
	}
	return s.Legal.Version
}

// pinnable matches a release tag ("v1.2.3") or a bare commit hash, the two
// version strings that name a tree on GitHub. `git describe` output such as
// "v1.2.3-4-gabc1234" or "abc1234-dirty" does not, and must not be pinned.
var pinnable = regexp.MustCompile(`^(v\d+\.\d+\.\d+|[0-9a-f]{7,40})$`)

// sourceURL is the AGPL §13 offer target. A stamped release pins to its
// tag, so the source you are offered is the source that is running; any
// other build can only point at the repository. The version never reaches
// the URL unless it matches pinnable, so the redirect cannot be steered
// anywhere but a tree of sourceBaseURL.
func (s *Server) sourceURL() string {
	if v := s.version(); pinnable.MatchString(v) {
		return sourceBaseURL + "/tree/" + v
	}
	return sourceBaseURL
}

// registerLegalRoutes adds the three routes the AGPL offer consists of.
// They sit outside /api/, so the login (withAuth), the Host allowlist and
// the same-origin check — all scoped to /api/ — do not apply: §13 obliges
// the offer to every network user, and a login wall would defeat it. They
// expose nothing about the deployment: two texts compiled into the binary
// and a redirect to a fixed public repository.
func (s *Server) registerLegalRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /license", s.serveLegalText(func() []byte { return s.Legal.License }, "license text unavailable"))
	mux.HandleFunc("GET /third-party-licenses", s.serveLegalText(func() []byte { return s.Legal.ThirdPartyLicenses }, "third-party notices unavailable"))
	mux.HandleFunc("GET /source", s.handleSource)
}

// serveLegalText serves an embedded text blob as plain UTF-8. The body is
// read through a closure at REQUEST time, so a Server whose Legal field is
// set after Handler() was called still serves it.
func (s *Server) serveLegalText(get func() []byte, missing string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		body := get()
		if len(body) == 0 {
			http.Error(w, missing, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		// Tied to the binary, so it only changes when the build does.
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(body)
	}
}

// handleSource implements the AGPL §13 source offer.
func (s *Server) handleSource(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.sourceURL(), http.StatusFound)
}
