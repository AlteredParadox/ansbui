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
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestUnknownAPIRouteReturnsJSON404(t *testing.T) {
	s := &Server{
		Addr: selfHost,
		WebRoot: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<!doctype html>")},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/does-not-exist", nil)
	req.Host = selfHost
	// As the SPA sends it: without the marker an unlisted read is
	// refused before routing (see clientMarkerRequired).
	req.Header.Set(clientMarkerHeader, "1")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body=%q", w.Code, http.StatusNotFound, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type = %q, want json", ct)
	}
	if !strings.Contains(w.Body.String(), "unknown API route") {
		t.Fatalf("body did not contain API error: %q", w.Body.String())
	}
}

func TestDecodeJSONBodyMaxBytesReturns413(t *testing.T) {
	h := limitBody(4, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		if !decodeJSONBody(w, r, &body) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"name":"too long"}`))
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%q", w.Code, http.StatusRequestEntityTooLarge, w.Body.String())
	}
}

var _ fs.FS = fstest.MapFS{}
