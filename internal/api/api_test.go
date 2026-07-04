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
