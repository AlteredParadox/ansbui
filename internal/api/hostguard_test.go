package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// Shared endpoints for the guard tests: the server's own loopback
// authority and the attacker's rebindable name.
const (
	selfHost = "127.0.0.1:8787"
	evilHost = "evil.example:8787"
)

func TestHostAllowed(t *testing.T) {
	allowed := allowedHostnames("ansbui.internal:8787")
	cases := []struct {
		host string
		want bool
	}{
		{selfHost, true},
		{"127.0.0.1", true},
		{"[::1]:8787", true},
		{"::1", true},
		{"192.168.1.5:8787", true}, // IP literal: not rebindable
		{"localhost:8787", true},
		{"localhost", true},
		{"LOCALHOST:8787", true},
		{"ansbui.localhost:8787", true},
		{"ansbui.internal:8787", true}, // the -addr hostname
		{"ANSBUI.Internal:8787", true},
		{evilHost, false}, // rebindable DNS name
		{"evil.example", false},
		{"localhost.evil.example:8787", false},
		{"", false},
	}
	for _, c := range cases {
		if got := hostAllowed(c.host, allowed); got != c.want {
			t.Errorf("hostAllowed(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestAllowedHostnamesEnv(t *testing.T) {
	t.Setenv(allowedHostsEnv, "Proxy.Example.com, other.example.com ,")
	allowed := allowedHostnames(selfHost) // IP bound host: not added
	for _, h := range []string{"proxy.example.com:443", "other.example.com"} {
		if !hostAllowed(h, allowed) {
			t.Errorf("env-allowed host %q rejected", h)
		}
	}
	if hostAllowed("evil.example.com", allowed) {
		t.Error("unlisted host allowed")
	}
}

// TestOriginGuardDNSRebinding drives the two request shapes a
// rebinding page produces — both are same-origin in the browser's
// eyes, so the Origin check alone passes and only the Host check can
// stop them.
func TestOriginGuardDNSRebinding(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	guard := withOriginGuard(ok, allowedHostnames(selfHost))

	req := func(method, path, host, origin string) int {
		r := httptest.NewRequest(method, path, nil)
		r.Host = host
		r.Header.Set(clientMarkerHeader, "1") // as the SPA sends it
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		guard.ServeHTTP(w, r)
		return w.Code
	}

	// Rebound POST: browser sends Origin, and it MATCHES Host.
	if code := req(http.MethodPost, "/api/bootstrap/start", evilHost, "http://evil.example:8787"); code != http.StatusForbidden {
		t.Errorf("rebound POST passed with %d", code)
	}
	// Rebound same-origin GET: no Origin header at all.
	if code := req(http.MethodGet, "/api/bootstrap/jobs", evilHost, ""); code != http.StatusForbidden {
		t.Errorf("rebound GET passed with %d", code)
	}
	// Rebound WS upgrade paths are Host-guarded too.
	if code := req(http.MethodGet, "/api/adhoc/stream", evilHost, "http://evil.example:8787"); code != http.StatusForbidden {
		t.Errorf("rebound WS upgrade passed with %d", code)
	}

	// Legitimate traffic keeps working.
	if code := req(http.MethodPost, "/api/bootstrap/start", selfHost, "http://127.0.0.1:8787"); code != http.StatusNoContent {
		t.Errorf("loopback POST rejected with %d", code)
	}
	if code := req(http.MethodPost, "/api/settings", "localhost:8787", ""); code != http.StatusNoContent {
		t.Errorf("curl-style POST (no Origin) rejected with %d", code)
	}
	// Plain cross-origin CSRF still caught by the Origin comparison.
	if code := req(http.MethodPost, "/api/settings", selfHost, "http://evil.example"); code != http.StatusForbidden {
		t.Errorf("cross-origin POST passed with %d", code)
	}
	// API reads are Host-guarded too: a rebound page can same-origin-GET
	// /api/inventory (fleet map), /api/vault, /api/settings — so an
	// unrecognised Host must be rejected on reads, not just writes.
	if code := req(http.MethodGet, "/api/inventory", evilHost, ""); code != http.StatusForbidden {
		t.Errorf("rebound API read passed with %d", code)
	}
	// Legit read from the real host still works.
	if code := req(http.MethodGet, "/api/inventory", selfHost, ""); code != http.StatusNoContent {
		t.Errorf("loopback API read rejected with %d", code)
	}
	// The static SPA shell stays public — the page must load even via an
	// unrecognised Host; only /api/ carries operator data.
	if code := req(http.MethodGet, "/", evilHost, ""); code != http.StatusNoContent {
		t.Errorf("static shell GET blocked with %d", code)
	}
}

// TestOriginGuardCoversAPIReads locks in the route-wide CSRF check.
// The guard used to apply only to mutating verbs plus three GET
// paths, so a hostile page the operator visited could fire off
// /api/facts?host=all (an ansible setup run across the whole fleet)
// and every other API read. The responses were always opaque
// cross-origin, but the work still ran.
func TestOriginGuardCoversAPIReads(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	guard := withOriginGuard(ok, allowedHostnames(selfHost))

	req := func(method, path, origin string) int {
		r := httptest.NewRequest(method, path, nil)
		r.Host = selfHost                     // IP literal: passes the Host/rebinding check
		r.Header.Set(clientMarkerHeader, "1") // as the SPA sends it
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		guard.ServeHTTP(w, r)
		return w.Code
	}

	// Every API read is now rejected when a foreign Origin is present,
	// not just the bootstrap/stream paths that were allowlisted before.
	for _, path := range []string{
		"/api/facts?host=all",
		"/api/inventory",
		"/api/metrics",
		"/api/playbooks",
		"/api/playbooks/content?path=site.yml",
		"/api/runs",
		"/api/runs/1",
		"/api/vault",
		"/api/servers",
		"/api/settings",
		"/api/health",
		"/api/bootstrap/jobs",
		"/api/adhoc/stream",
	} {
		if code := req(http.MethodGet, path, "http://evil.example"); code != http.StatusForbidden {
			t.Errorf("cross-origin GET %s passed with %d, want 403", path, code)
		}
	}

	// HEAD is guarded too — same handlers, same side effects.
	if code := req(http.MethodHead, "/api/inventory", "http://evil.example"); code != http.StatusForbidden {
		t.Errorf("cross-origin HEAD passed with %d", code)
	}

	// Legitimate traffic must keep working. Browsers send no Origin at
	// all on same-origin GETs; the SPA's marker header (set by req
	// above) is what admits those.
	if code := req(http.MethodGet, "/api/inventory", ""); code != http.StatusNoContent {
		t.Errorf("same-origin GET (no Origin header) rejected with %d", code)
	}
	if code := req(http.MethodGet, "/api/inventory", "http://127.0.0.1:8787"); code != http.StatusNoContent {
		t.Errorf("same-origin GET (matching Origin) rejected with %d", code)
	}
	// The static SPA shell stays reachable cross-origin so the page loads.
	if code := req(http.MethodGet, "/", "http://evil.example"); code != http.StatusNoContent {
		t.Errorf("static shell blocked with %d", code)
	}
}

// TestAllowedHostsWithPortMatches locks in the port-stripping fix: an
// operator who copies the rejected Host verbatim (host:port, exactly
// what the 403 message echoes) into ANSBUI_ALLOWED_HOSTS must then be
// accepted, even though the request Host also carries the port.
func TestAllowedHostsWithPortMatches(t *testing.T) {
	t.Setenv(allowedHostsEnv, "proxy.example.com:8443")
	allowed := allowedHostnames("0.0.0.0:8443") // IP bind contributes nothing
	if !hostAllowed("proxy.example.com:8443", allowed) {
		t.Error("host:port entry did not match host:port request Host")
	}
	if !hostAllowed("proxy.example.com", allowed) {
		t.Error("host:port entry did not match bare-host request Host")
	}
}

// guardReq is one request through withOriginGuard, described by the
// headers that decide its fate.
type guardReq struct {
	method, path string
	host         string // "" = selfHost
	origin       string
	fetchSite    string // Sec-Fetch-Site
	fwdProto     string // X-Forwarded-Proto
	marker       bool   // clientMarkerHeader present
}

func (g guardReq) code(t *testing.T, allowed map[string]struct{}) int {
	t.Helper()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r := httptest.NewRequest(g.method, g.path, nil)
	r.Host = selfHost
	if g.host != "" {
		r.Host = g.host
	}
	for name, v := range map[string]string{"Origin": g.origin, "Sec-Fetch-Site": g.fetchSite, "X-Forwarded-Proto": g.fwdProto} {
		if v != "" {
			r.Header.Set(name, v)
		}
	}
	if g.marker {
		r.Header.Set(clientMarkerHeader, "1")
	}
	w := httptest.NewRecorder()
	withOriginGuard(ok, allowed).ServeHTTP(w, r)
	return w.Code
}

// TestOriginGuardComparesScheme covers the cross-scheme hole: behind
// a TLS-terminating proxy that forwards the public Host,
// https://host and http://host carry the same Host header, so a
// host-only Origin comparison accepted a plaintext page for the
// deployment's own name. A network attacker can serve that page, and
// from it open the run WebSocket with whatever credential the browser
// attaches across schemes (proxy basic auth, or none).
func TestOriginGuardComparesScheme(t *testing.T) {
	const pub = "ansbui.example.test"
	t.Setenv(allowedHostsEnv, pub)
	allowed := allowedHostnames(selfHost)

	cases := []struct {
		name string
		req  guardReq
		want int
	}{
		{"https page through the proxy",
			guardReq{method: http.MethodPost, path: "/api/settings", host: pub, origin: "https://" + pub, fwdProto: "https"}, http.StatusNoContent},
		{"plaintext page for the same name, POST",
			guardReq{method: http.MethodPost, path: "/api/settings", host: pub, origin: "http://" + pub, fwdProto: "https"}, http.StatusForbidden},
		{"plaintext page for the same name, run WebSocket",
			guardReq{method: http.MethodGet, path: "/api/adhoc/stream", host: pub, origin: "http://" + pub, fwdProto: "https"}, http.StatusForbidden},
		{"https page, proxy did not send X-Forwarded-Proto",
			guardReq{method: http.MethodPost, path: "/api/login", host: pub, origin: "https://" + pub}, http.StatusForbidden},
		{"proxy chain sends a list; the first hop is the browser's",
			guardReq{method: http.MethodPost, path: "/api/settings", host: pub, origin: "https://" + pub, fwdProto: "https, http"}, http.StatusNoContent},
		{"a list whose first hop is plaintext",
			guardReq{method: http.MethodPost, path: "/api/settings", host: pub, origin: "https://" + pub, fwdProto: "http, https"}, http.StatusForbidden},
		{"scheme case does not matter",
			guardReq{method: http.MethodPost, path: "/api/settings", host: pub, origin: "https://" + pub, fwdProto: "HTTPS"}, http.StatusNoContent},
		{"plain-HTTP loopback dev",
			guardReq{method: http.MethodPost, path: "/api/settings", origin: "http://" + selfHost}, http.StatusNoContent},
		{"a scheme that is neither",
			guardReq{method: http.MethodPost, path: "/api/settings", origin: "ftp://" + selfHost}, http.StatusForbidden},
		{"opaque origin (sandboxed frame, data: URL)",
			guardReq{method: http.MethodPost, path: "/api/settings", origin: "null"}, http.StatusForbidden},
	}
	for _, c := range cases {
		if got := c.req.code(t, allowed); got != c.want {
			t.Errorf("%s: status %d, want %d", c.name, got, c.want)
		}
	}

	// The upgrader's CheckOrigin is the same decision.
	r := httptest.NewRequest(http.MethodGet, "/api/adhoc/stream", nil)
	r.Host = pub
	r.Header.Set("Origin", "http://"+pub)
	r.Header.Set("X-Forwarded-Proto", "https")
	if sameOriginCheck(r) {
		t.Error("wsUpgrader.CheckOrigin accepts the plaintext origin of an HTTPS deployment")
	}
	r.Header.Set("Origin", "https://"+pub)
	if !sameOriginCheck(r) {
		t.Error("wsUpgrader.CheckOrigin rejects the deployment's own https origin")
	}
}

// TestOriginGuardMismatchNamesTheProxyFix: the one scheme mismatch a
// legitimate deployment produces must say what to change, because the
// symptom is a UI that loads and then fails every action.
func TestOriginGuardMismatchNamesTheProxyFix(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	r.Host = selfHost
	r.Header.Set("Origin", "https://"+selfHost)
	err := checkSameOrigin(r)
	if err == nil || !strings.Contains(err.Error(), "X-Forwarded-Proto: https") {
		t.Errorf("https page on a plain-http hop: error %v does not name X-Forwarded-Proto", err)
	}
	// The attacker's direction gets no such hint.
	r.Header.Set("Origin", "http://"+selfHost)
	r.Header.Set("X-Forwarded-Proto", "https")
	if err := checkSameOrigin(r); !errors.Is(err, errCrossOrigin) {
		t.Errorf("plaintext page on an https hop: error %v, want the terse refusal", err)
	}
}

// TestOriginGuardFetchMetadata: Sec-Fetch-Site is the browser's own
// statement of where a request came from, present even on the
// requests that carry no Origin (image and script loads, navigations).
func TestOriginGuardFetchMetadata(t *testing.T) {
	allowed := allowedHostnames(selfHost)
	cases := []struct {
		site string
		want int
	}{
		{"same-origin", http.StatusNoContent},
		{"none", http.StatusNoContent}, // typed URL or bookmark
		{"", http.StatusNoContent},     // not a browser on a secure origin
		{"cross-site", http.StatusForbidden},
		{"same-site", http.StatusForbidden}, // sibling subdomain, or another port
		{"something-new", http.StatusForbidden},
	}
	for _, c := range cases {
		// A local read, so the marker rule is not what decides.
		for _, g := range []guardReq{
			{method: http.MethodGet, path: "/api/runs", fetchSite: c.site},
			{method: http.MethodPost, path: "/api/settings", fetchSite: c.site},
			// Even with a matching Origin: both signals must agree.
			{method: http.MethodPost, path: "/api/settings", fetchSite: c.site, origin: "http://" + selfHost},
		} {
			if got := g.code(t, allowed); got != c.want {
				t.Errorf("%s %s with Sec-Fetch-Site %q: status %d, want %d", g.method, g.path, c.site, got, c.want)
			}
		}
	}
	// The static shell is not guarded: the page must load from a link.
	if got := (guardReq{method: http.MethodGet, path: "/", fetchSite: "cross-site"}).code(t, allowed); got != http.StatusNoContent {
		t.Errorf("static shell with Sec-Fetch-Site cross-site: status %d", got)
	}
}

// TestOriginGuardClientMarker covers the request another site's page
// can cause with no header to betray it: an Origin-less GET (an
// <img>, a link, a navigation), from a browser that sends no
// Sec-Fetch-Site because the origin is plain HTTP and not loopback —
// or that sends "none" because the link was opened from another
// application. On the routes that reach the control node, only the
// marker distinguishes the SPA's own call from that.
func TestOriginGuardClientMarker(t *testing.T) {
	allowed := allowedHostnames(selfHost)
	remote := []string{
		"/api/facts?host=all",
		"/api/inventory",
		"/api/metrics",
		"/api/playbooks",
		"/api/playbooks/content?path=site.yml",
		"/api/vault",
		"/api/adhoc/stream",
		"/api/playbook/stream",
		"/api/not-a-route-yet", // unlisted reads are covered by default
	}
	for _, path := range remote {
		for _, site := range []string{"", "none", "same-origin"} {
			if got := (guardReq{method: http.MethodGet, path: path, fetchSite: site}).code(t, allowed); got != http.StatusForbidden {
				t.Errorf("GET %s without the marker (Sec-Fetch-Site %q): status %d, want 403", path, site, got)
			}
		}
		if got := (guardReq{method: http.MethodHead, path: path}).code(t, allowed); got != http.StatusForbidden {
			t.Errorf("HEAD %s without the marker: status %d, want 403", path, got)
		}
		if got := (guardReq{method: http.MethodGet, path: path, marker: true}).code(t, allowed); got != http.StatusNoContent {
			t.Errorf("GET %s with the marker: status %d, want 204", path, got)
		}
	}

	// A browser WebSocket upgrade cannot carry the marker and does not
	// need it: it always carries Origin, which has been checked.
	for _, path := range []string{"/api/adhoc/stream", "/api/playbook/stream"} {
		if got := (guardReq{method: http.MethodGet, path: path, origin: "http://" + selfHost, fetchSite: "same-origin"}).code(t, allowed); got != http.StatusNoContent {
			t.Errorf("same-origin WebSocket upgrade %s: status %d, want 204", path, got)
		}
	}

	// Reads answered from local state stay reachable by a bare curl
	// and by a monitor.
	for _, path := range []string{
		"/api/health",
		"/api/auth/status",
		"/api/servers",
		"/api/settings",
		"/api/runs",
		"/api/runs/1",
		"/api/bootstrap/jobs",
		"/api/bootstrap/jobs/abc",
		"/api/bootstrap/jobs/abc/log",
	} {
		if got := (guardReq{method: http.MethodGet, path: path}).code(t, allowed); got != http.StatusNoContent {
			t.Errorf("local read %s without the marker: status %d, want 204", path, got)
		}
	}
	// Lookalike paths are not local reads.
	for _, path := range []string{"/api/runsX", "/api/healthz", "/api/settings/x", "/api/servers/x"} {
		if got := (guardReq{method: http.MethodGet, path: path}).code(t, allowed); got != http.StatusForbidden {
			t.Errorf("lookalike %s without the marker: status %d, want 403", path, got)
		}
	}

	// Mutating requests never need the marker: a browser always sends
	// Origin on them, and a script without one is not a browser.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if got := (guardReq{method: method, path: "/api/vault/view"}).code(t, allowed); got != http.StatusNoContent {
			t.Errorf("%s without Origin or marker: status %d, want 204", method, got)
		}
	}
}

// TestSecurityHeaders: every response — shell, asset, API, and the
// guard's own refusals — forbids framing and content sniffing; HSTS
// appears only when the browser's hop was HTTPS.
func TestSecurityHeaders(t *testing.T) {
	s := &Server{
		Addr: selfHost,
		WebRoot: fstest.MapFS{
			"index.html":     &fstest.MapFile{Data: []byte("<!doctype html>")},
			"styles/app.css": &fstest.MapFile{Data: []byte("body{}")},
			"data/api.js":    &fstest.MapFile{Data: []byte("void 0;")},
		},
	}
	h := s.Handler()
	get := func(path string, hdr map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = selfHost
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	for _, c := range []struct {
		path string
		hdr  map[string]string
		code int
	}{
		{"/", nil, http.StatusOK},
		{"/deep/link", nil, http.StatusOK},
		{"/styles/app.css", nil, http.StatusOK},
		{"/api/health", nil, http.StatusOK},
		{"/api/inventory", nil, http.StatusForbidden}, // marker missing
		{"/api/health", map[string]string{"Origin": "http://evil.example"}, http.StatusForbidden}, // cross-origin
	} {
		w := get(c.path, c.hdr)
		if w.Code != c.code {
			t.Errorf("GET %s: status %d, want %d", c.path, w.Code, c.code)
		}
		if got := w.Header().Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
			t.Errorf("GET %s: Content-Security-Policy %q lacks frame-ancestors 'none'", c.path, got)
		}
		if got := w.Header().Get("Content-Security-Policy"); got != contentSecurityPolicy {
			t.Errorf("GET %s: Content-Security-Policy %q, want the full policy", c.path, got)
		}
		if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("GET %s: Referrer-Policy %q, want no-referrer", c.path, got)
		}
		if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("GET %s: X-Frame-Options %q, want DENY", c.path, got)
		}
		if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("GET %s: X-Content-Type-Options %q, want nosniff", c.path, got)
		}
		if got := w.Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("GET %s over plain HTTP: Strict-Transport-Security %q, want none", c.path, got)
		}
	}

	// nosniff makes the browser refuse a stylesheet or script whose
	// declared type is wrong, so the declared types have to be right.
	for path, want := range map[string]string{"/styles/app.css": "text/css", "/data/api.js": "javascript", "/": "text/html"} {
		if got := get(path, nil).Header().Get("Content-Type"); !strings.Contains(got, want) {
			t.Errorf("GET %s: Content-Type %q, want it to contain %q", path, got, want)
		}
	}

	// HSTS when the browser's hop was HTTPS, with no includeSubDomains.
	for _, path := range []string{"/", "/api/health"} {
		got := get(path, map[string]string{"X-Forwarded-Proto": "https"}).Header().Get("Strict-Transport-Security")
		if !strings.HasPrefix(got, "max-age=") || strings.Contains(strings.ToLower(got), "includesubdomains") {
			t.Errorf("GET %s over HTTPS: Strict-Transport-Security %q", path, got)
		}
	}
}
