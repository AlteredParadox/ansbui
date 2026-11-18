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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/AlteredParadox/ansbui/internal/config"
)

func legalTestServer(t *testing.T, version string) *Server {
	t.Helper()
	s := authTestServer(t, "correct horse battery staple")
	s.WebRoot = fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>ansbui</title>")}}
	s.Legal = Legal{
		License:            []byte("LICENSE TEXT\n"),
		ThirdPartyLicenses: []byte("NOTICES TEXT\n"),
		Version:            version,
	}
	return s
}

// The AGPL offer has to reach every network user, so the three routes
// answer a request that carries no session, on a server where login is
// enabled and every /api/ route answers 401 to the same request.
func TestLegalRoutesNeedNoLogin(t *testing.T) {
	h := legalTestServer(t, "v1.2.3").Handler()

	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		// A Host no allowlist knows and a foreign Origin: neither guard
		// applies outside /api/.
		r := httptest.NewRequest(http.MethodGet, "http://ansbui.example.net"+path, nil)
		r.Header.Set("Origin", "https://elsewhere.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := get("/api/servers"); w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Fatalf("control: /api/servers without a session = %d, want it refused", w.Code)
	}

	for path, want := range map[string]string{
		"/license":              "LICENSE TEXT\n",
		"/third-party-licenses": "NOTICES TEXT\n",
	} {
		w := get(path)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, w.Code)
			continue
		}
		if got := w.Body.String(); got != want {
			t.Errorf("GET %s body = %q, want %q", path, got, want)
		}
		if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
			t.Errorf("GET %s Content-Type = %q", path, ct)
		}
		// The general response headers still apply.
		if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("GET %s is missing the security headers: %v", path, w.Header())
		}
	}

	w := get("/source")
	if w.Code != http.StatusFound {
		t.Fatalf("GET /source = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != sourceBaseURL+"/tree/v1.2.3" {
		t.Errorf("GET /source Location = %q", loc)
	}
}

// /source pins to the running version only when that version names a tree
// on GitHub. Anything else — and anything that is not a version at all —
// points at the repository, so the redirect cannot be steered.
func TestSourceURL(t *testing.T) {
	for version, want := range map[string]string{
		"v1.2.3":             sourceBaseURL + "/tree/v1.2.3",
		"0123abc":            sourceBaseURL + "/tree/0123abc",
		"":                   sourceBaseURL,
		"dev":                sourceBaseURL,
		"v1.2.3-4-g0123abc":  sourceBaseURL,
		"0123abc-dirty":      sourceBaseURL,
		"v1.2.3/../../evil":  sourceBaseURL,
		"//evil.example":     sourceBaseURL,
		"v1.2.3\nSet-Cookie": sourceBaseURL,
	} {
		s := &Server{Legal: Legal{Version: version}}
		if got := s.sourceURL(); got != want {
			t.Errorf("sourceURL() for version %q = %q, want %q", version, got, want)
		}
	}
}

// A binary built without its texts says so instead of serving an empty
// page that looks like a license.
func TestLegalTextMissing(t *testing.T) {
	h := (&Server{}).Handler()
	for _, path := range []string{"/license", "/third-party-licenses"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusInternalServerError {
			t.Errorf("GET %s with no text embedded = %d, want 500", path, w.Code)
		}
	}
}

func TestVersionDefaultsToDev(t *testing.T) {
	if got := (&Server{}).version(); got != "dev" {
		t.Errorf("version() = %q, want dev", got)
	}
	if got := (&Server{Legal: Legal{Version: "v2.0.0"}}).version(); got != "v2.0.0" {
		t.Errorf("version() = %q, want v2.0.0", got)
	}
}

// Settings carries the build version for the About section of the UI.
func TestSettingsReportTheVersion(t *testing.T) {
	t.Setenv("ANSBUI_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	cfg, err := config.New()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Config: cfg, Legal: Legal{Version: "v3.1.4"}}
	w := httptest.NewRecorder()
	s.getSettings(w, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	var body settingsBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	if body.Version != "v3.1.4" {
		t.Errorf("settings version = %q, want v3.1.4", body.Version)
	}
}
