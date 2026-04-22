// Package api wires the HTTP routes, owns the global handler
// dependencies, and serves the embedded web bundle.
package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/AlteredParadox/relay/internal/ansible"
	"github.com/AlteredParadox/relay/internal/config"
	"github.com/AlteredParadox/relay/internal/sshpool"
)

// Server is the HTTP API + static bundle.
type Server struct {
	Config   *config.Manager
	Pool     *sshpool.Pool
	Runs     *ansible.Recorder
	WebRoot  fs.FS
}

// Handler returns the http.Handler for the whole app.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/servers", s.listServers)
	mux.HandleFunc("POST /api/servers", s.upsertServer)
	mux.HandleFunc("DELETE /api/servers/{id}", s.deleteServer)
	mux.HandleFunc("POST /api/servers/{id}/activate", s.activateServer)
	mux.HandleFunc("POST /api/servers/{id}/test", s.testServer)
	mux.HandleFunc("GET /api/settings", s.getSettings)
	mux.HandleFunc("POST /api/settings", s.setSettings)

	mux.HandleFunc("GET /api/inventory", s.inventory)
	mux.HandleFunc("GET /api/metrics", s.metrics)

	mux.HandleFunc("GET /api/playbooks", s.listPlaybooks)
	mux.HandleFunc("GET /api/playbooks/content", s.getPlaybook)
	mux.HandleFunc("PUT /api/playbooks/content", s.putPlaybook)

	mux.HandleFunc("GET /api/runs", s.listRuns)
	mux.HandleFunc("GET /api/runs/{id}", s.getRun)
	mux.HandleFunc("GET /api/adhoc/stream", s.wsAdhoc)
	mux.HandleFunc("GET /api/playbook/stream", s.wsPlaybook)

	mux.Handle("/", s.staticHandler())

	return withLogging(mux)
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
