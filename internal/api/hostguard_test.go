package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
