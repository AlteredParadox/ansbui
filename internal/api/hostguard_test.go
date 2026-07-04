package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostAllowed(t *testing.T) {
	allowed := allowedHostnames("ansbui.internal:8787")
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1:8787", true},
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
		{"evil.example:8787", false}, // rebindable DNS name
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
	allowed := allowedHostnames("127.0.0.1:8787") // IP bound host: not added
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
	guard := withOriginGuard(ok, allowedHostnames("127.0.0.1:8787"))

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
	if code := req(http.MethodPost, "/api/bootstrap/start", "evil.example:8787", "http://evil.example:8787"); code != http.StatusForbidden {
		t.Errorf("rebound POST passed with %d", code)
	}
	// Rebound same-origin GET: no Origin header at all.
	if code := req(http.MethodGet, "/api/bootstrap/jobs", "evil.example:8787", ""); code != http.StatusForbidden {
		t.Errorf("rebound GET passed with %d", code)
	}
	// Rebound WS upgrade paths are Host-guarded too.
	if code := req(http.MethodGet, "/api/adhoc/stream", "evil.example:8787", "http://evil.example:8787"); code != http.StatusForbidden {
		t.Errorf("rebound WS upgrade passed with %d", code)
	}

	// Legitimate traffic keeps working.
	if code := req(http.MethodPost, "/api/bootstrap/start", "127.0.0.1:8787", "http://127.0.0.1:8787"); code != http.StatusNoContent {
		t.Errorf("loopback POST rejected with %d", code)
	}
	if code := req(http.MethodPost, "/api/settings", "localhost:8787", ""); code != http.StatusNoContent {
		t.Errorf("curl-style POST (no Origin) rejected with %d", code)
	}
	// Plain cross-origin CSRF still caught by the Origin comparison.
	if code := req(http.MethodPost, "/api/settings", "127.0.0.1:8787", "http://evil.example"); code != http.StatusForbidden {
		t.Errorf("cross-origin POST passed with %d", code)
	}
	// Unguarded reads stay open by design, whatever the Host says.
	if code := req(http.MethodGet, "/api/inventory", "evil.example:8787", ""); code != http.StatusNoContent {
		t.Errorf("unguarded GET rejected with %d", code)
	}
}
