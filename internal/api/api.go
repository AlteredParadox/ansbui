// Package api wires the HTTP routes, owns the global handler
// dependencies, and serves the embedded web bundle.
package api

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/jobs"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
)

// Server is the HTTP API + static bundle.
type Server struct {
	Config  *config.Manager
	Pool    *sshpool.Pool
	Runs    *ansible.Recorder
	Jobs    *jobs.Manager
	WebRoot fs.FS

	// Addr is the -addr flag value the HTTP server binds to. The
	// origin guard uses its hostname part (when it is a DNS name)
	// as an allowed Host header value.
	Addr string

	// geo is constructed lazily on first use so apps that never turn
	// on geoip enrichment don't pay the dns-cache + http client cost.
	geoOnce sync.Once
	geo     *geoResolver

	// staticETags memoises content-hash ETags for embedded web assets.
	// The bundle is baked in at build time and never changes at runtime,
	// so each hash is computed once. Keyed by asset path.
	staticETags sync.Map
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
	mux.HandleFunc("DELETE /api/servers/{id}", limitBody(emptyBody, s.deleteServer))
	mux.HandleFunc("POST /api/servers/{id}/activate", limitBody(emptyBody, s.activateServer))
	mux.HandleFunc("POST /api/servers/{id}/test", limitBody(emptyBody, s.testServer))
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
	mux.HandleFunc("POST /api/bootstrap/start", limitBody(smallBody, s.httpBootstrapStart))
	mux.HandleFunc("GET /api/bootstrap/jobs", s.httpBootstrapList)
	mux.HandleFunc("GET /api/bootstrap/jobs/{id}", s.httpBootstrapGet)
	mux.HandleFunc("GET /api/bootstrap/jobs/{id}/log", s.httpBootstrapLog)
	mux.HandleFunc("POST /api/bootstrap/jobs/{id}/cancel", limitBody(emptyBody, s.httpBootstrapCancel))
	mux.HandleFunc("GET /api/bootstrap/jobs/{id}/stream", s.wsBootstrapStream)

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, fmt.Errorf("unknown API route %s %s", r.Method, r.URL.Path))
	})
	mux.Handle("/", s.staticHandler())

	return withLogging(withOriginGuard(mux, allowedHostnames(s.Addr)))
}

// withOriginGuard rejects HTTP requests whose Origin header is set
// and doesn't match the request's Host. ansbui has no auth —
// anyone reaching the port can already drive ansible-playbook and
// now SSH-bootstrap fresh boxes — so the deployment posture is
// "behind a VPN / on localhost". But CORS quirks let a malicious
// origin fire-and-forget POSTs (and, for the bootstrap read
// endpoints that surface recent target IPs/hostnames, GETs) from
// the operator's browser if they have ansbui open in another tab.
// This guard mirrors the same-origin check the WebSocket upgrader
// enforces.
//
// Two layers, applied independently:
//
//   - Host allowlist (DNS-rebinding defence) on EVERY /api/ request,
//     read or write. Rebinding is primarily a read primitive: after
//     the rebind the attacker's page is same-origin and can GET
//     /api/inventory, /api/vault, /api/settings, /api/servers, etc.,
//     so a write-only Host check would leave the whole read surface
//     exfiltrating. The only tell is the Host header, which still
//     names the attacker's domain (see hostguard.go). Static assets
//     (the SPA shell under "/") are public and stay unguarded so the
//     page still loads; everything sensitive lives under /api/.
//
//   - Origin == Host (CSRF defence) on state-mutating verbs and the
//     run-stream WS upgrades. Browsers omit Origin on same-origin
//     GETs and curl/CLI clients omit it entirely, so we only reject a
//     present-and-wrong Origin — non-browser admin callers keep
//     working. This mirrors the WS upgrader's own CheckOrigin
//     (sameOriginCheck), reused here so the two never drift.
func withOriginGuard(h http.Handler, allowedHosts map[string]struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hostGuardedRequest(r) && !hostAllowed(r.Host, allowedHosts) {
			writeError(w, http.StatusForbidden, fmt.Errorf("request Host %q not recognised (DNS-rebinding guard) — if ansbui is behind a reverse proxy, list its public hostname in %s", r.Host, allowedHostsEnv))
			return
		}
		if originGuardedRequest(r) && !sameOriginCheck(r) {
			writeError(w, http.StatusForbidden, errors.New("cross-origin request rejected"))
			return
		}
		h.ServeHTTP(w, r)
	})
}

// hostGuardedRequest reports whether the DNS-rebinding Host check
// applies: every /api/ request (reads included), regardless of
// method. The static SPA shell served from "/" is deliberately
// excluded — it carries no operator data.
func hostGuardedRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/")
}

// originGuardedRequest reports whether the Origin==Host CSRF check
// applies: all state-mutating verbs plus the run-stream WS upgrades
// (which a rebound page could otherwise open with a matching Origin).
func originGuardedRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	case http.MethodGet, http.MethodHead:
		return strings.HasPrefix(r.URL.Path, "/api/bootstrap/") ||
			r.URL.Path == "/api/adhoc/stream" ||
			r.URL.Path == "/api/playbook/stream"
	default:
		return false
	}
}

// Body size caps for POST / PUT handlers. Control-plane payloads
// (server defs, settings, vault passwords) are tiny; playbook +
// vault-write bodies can reasonably be a few hundred kilobytes.
// emptyBody applies to verbs whose handler ignores the body (e.g.
// POST /activate, DELETE) — capping near-zero stops a malicious
// client from streaming arbitrary bytes onto the goroutine that
// http.Server still has to drain.
const (
	emptyBody = 1024
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve index.html at "/"; /api/ already handled above. Unknown
		// paths (and bare directories) fall back to index.html so client
		// routing survives deep links and refreshes.
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if fi, err := fs.Stat(s.WebRoot, name); err != nil || fi.IsDir() {
			name = "index.html"
		}
		s.serveStaticFile(w, r, name)
	})
}

// serveStaticFile writes an embedded asset with a content-hash ETag and
// Cache-Control: no-cache. The bundle is baked in at build time, so the
// hash is stable for the binary's life but changes whenever the file
// does — browsers revalidate cheaply (304) and always pick up a fresh
// build without a manual hard-refresh. embed.FS reports a zero modtime,
// so before this every response had no validator and stale JS lingered
// in browser caches (which is how a broken Bootstrap.jsx survived a fix).
func (s *Server) serveStaticFile(w http.ResponseWriter, r *http.Request, name string) {
	f, err := s.WebRoot.Open(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()
	rs, ok := f.(io.ReadSeeker)
	if !ok {
		// embed.FS files are seekable; this guards a future FS swap.
		http.Error(w, "asset not seekable", http.StatusInternalServerError)
		return
	}
	if etag := s.staticETag(name); etag != "" {
		w.Header().Set("Etag", etag)
		w.Header().Set("Cache-Control", "no-cache")
	}
	// Zero modtime skips Last-Modified (embed has none); the ETag is the
	// validator. ServeContent matches If-None-Match against the ETag we
	// set and returns 304 when it matches, and infers Content-Type from
	// the name's extension.
	http.ServeContent(w, r, name, time.Time{}, rs)
}

// staticETag returns a strong content-hash ETag for an embedded asset,
// memoised since the bundle never changes at runtime. Empty string if
// the asset can't be read (caller then serves without a validator).
func (s *Server) staticETag(name string) string {
	if v, ok := s.staticETags.Load(name); ok {
		return v.(string)
	}
	data, err := fs.ReadFile(s.WebRoot, name)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	s.staticETags.Store(name, etag)
	return etag
}

func withLogging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(rw, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// %q on Method + Path so a request with embedded
			// CR/LF or control bytes can't forge a second log
			// line — gosec G706 (log injection via taint
			// analysis). r.URL.Path is operator-controlled at
			// the boundary, so quoting is the cheap fix.
			log.Printf("%q %q %d %s", r.Method, r.URL.Path, rw.status, time.Since(start))
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
