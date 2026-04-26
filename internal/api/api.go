// Package api wires the HTTP routes, owns the global handler
// dependencies, and serves the embedded web bundle.
package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
)

// Server is the HTTP API + static bundle.
type Server struct {
	Config  *config.Manager
	Pool    *sshpool.Pool
	Runs    *ansible.Recorder
	WebRoot fs.FS

	// geo is constructed lazily on first use so apps that never turn
	// on geoip enrichment don't pay the dns-cache + http client cost.
	geoOnce sync.Once
	geo     *geoResolver
}

func (s *Server) geoResolver() *geoResolver {
	s.geoOnce.Do(func() { s.geo = newGeoResolver() })
	return s.geo
}

// Handler returns the http.Handler for the whole app.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/servers", s.listServers)
	mux.HandleFunc("POST /api/servers", limitBody(smallBody, s.upsertServer))
	mux.HandleFunc("DELETE /api/servers/{id}", s.deleteServer)
	mux.HandleFunc("POST /api/servers/{id}/activate", s.activateServer)
	mux.HandleFunc("POST /api/servers/{id}/test", s.testServer)
	mux.HandleFunc("GET /api/settings", s.getSettings)
	mux.HandleFunc("POST /api/settings", limitBody(smallBody, s.setSettings))

	mux.HandleFunc("GET /api/inventory", s.inventory)
	mux.HandleFunc("GET /api/metrics", s.metrics)
	mux.HandleFunc("GET /api/facts", s.getFacts)

	mux.HandleFunc("GET /api/playbooks", s.listPlaybooks)
	mux.HandleFunc("GET /api/playbooks/content", s.getPlaybook)
	mux.HandleFunc("PUT /api/playbooks/content", limitBody(largeBody, s.putPlaybook))

	mux.HandleFunc("GET /api/runs", s.listRuns)
	mux.HandleFunc("GET /api/runs/{id}", s.getRun)

	mux.HandleFunc("GET /api/vault", s.listVault)
	mux.HandleFunc("POST /api/vault/view", limitBody(smallBody, s.viewVault))
	mux.HandleFunc("POST /api/vault/content", limitBody(largeBody, s.writeVault))
	mux.HandleFunc("POST /api/vault/inline/list", limitBody(smallBody, s.listInlineVault))
	mux.HandleFunc("POST /api/vault/inline/decrypt", limitBody(smallBody, s.decryptInlineVault))
	mux.HandleFunc("POST /api/vault/inline/upsert", limitBody(largeBody, s.upsertInlineVault))
	mux.HandleFunc("GET /api/adhoc/stream", s.wsAdhoc)
	mux.HandleFunc("GET /api/playbook/stream", s.wsPlaybook)
	mux.HandleFunc("GET /api/provision/stream", s.wsProvision)

	mux.Handle("/", s.staticHandler())

	return withLogging(mux)
}

// Body size caps for POST / PUT handlers. Control-plane payloads
// (server defs, settings, vault passwords) are tiny; playbook +
// vault-write bodies can reasonably be a few hundred kilobytes.
const (
	smallBody = 64 * 1024
	largeBody = 1 * 1024 * 1024
)

// limitBody wraps an http.HandlerFunc so the request body is capped
// via http.MaxBytesReader. Requests over the cap get 413 before the
// handler sees them.
func limitBody(max int64, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, max)
		h(w, r)
	}
}

func (s *Server) staticHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.WebRoot))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve index.html at "/"; /api/ already handled above. Static
		// files fall through to fileServer.
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(s.WebRoot, p); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				r.URL.Path = "/index.html"
			}
		}
		fileServer.ServeHTTP(w, r)
	})
}

func withLogging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rw, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			log.Printf("%s %s %d %s", r.Method, r.URL.Path, rw.status, time.Since(start))
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Hijack delegates to the underlying ResponseWriter so gorilla/websocket
// can upgrade the connection. Without this the Upgrader fails with
// "response does not implement http.Hijacker" and the WebSocket never
// opens (browser sees a 500 and fires 'error').
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	return h.Hijack()
}

// Flush delegates so SSE / chunked responses keep working. Cheap to add
// alongside Hijack since the same wrapper sits in front of every API
// handler.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// writeJSON sends a JSON response. On encode error it logs — by the time
// we hit it the headers are already out so there's nothing useful to
// return to the client.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}

// writeError returns {error: "..."} with the given status. kept tiny so
// every handler can call it without pulling in an error framework.
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
