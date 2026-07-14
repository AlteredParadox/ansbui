package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AlteredParadox/ansbui/internal/auth"
)

// authTestServer builds a Server with auth enabled and password set.
func authTestServer(t *testing.T, password string) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential")
	if err := auth.SetCredential(path, password); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}
	cred, err := auth.LoadCredential(path)
	if err != nil || cred == nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	return &Server{Credential: cred, Sessions: auth.NewSessionStore()}
}

func login(t *testing.T, s *Server, password string) *http.Cookie {
	t.Helper()
	body := strings.NewReader(`{"password":` + quote(password) + `}`)
	r := httptest.NewRequest(http.MethodPost, "/api/login", body)
	w := httptest.NewRecorder()
	s.handleLogin(w, r)
	if w.Code != http.StatusOK {
		return nil
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// A guarded endpoint is 401 without a session and passes with one.
func TestAuth_GuardsAndAdmits(t *testing.T) {
	s := authTestServer(t, "hunter2")
	h := s.withAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	// No cookie → 401.
	r := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request = %d, want 401", w.Code)
	}

	// Log in, then reuse the cookie → passes to the inner handler.
	cookie := login(t, s, "hunter2")
	if cookie == nil {
		t.Fatal("login did not set a session cookie")
	}
	if cookie.HttpOnly != true || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie hardening missing: %+v", cookie)
	}
	r = httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTeapot {
		t.Fatalf("authenticated request = %d, want 418", w.Code)
	}
}

// Open endpoints and non-API paths pass without a session.
func TestAuth_OpenPathsBypass(t *testing.T) {
	s := authTestServer(t, "pw")
	h := s.withAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, p := range []string{"/api/login", "/api/logout", "/api/auth/status", "/api/health", "/", "/index.html"} {
		r := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == http.StatusUnauthorized {
			t.Fatalf("open path %s was blocked", p)
		}
	}
}

// Wrong password never sets a cookie; logout invalidates the session.
func TestAuth_WrongPasswordAndLogout(t *testing.T) {
	s := authTestServer(t, "right")
	if c := login(t, s, "wrong"); c != nil {
		t.Fatal("wrong password issued a session cookie")
	}
	cookie := login(t, s, "right")
	if cookie == nil {
		t.Fatal("correct password did not log in")
	}
	if !s.requestAuthenticated(withCookie(cookie)) {
		t.Fatal("session should be valid before logout")
	}
	// Logout destroys it.
	r := withCookie(cookie)
	w := httptest.NewRecorder()
	s.handleLogout(w, r)
	if s.requestAuthenticated(withCookie(cookie)) {
		t.Fatal("session still valid after logout")
	}
}

// With auth disabled (no credential) every request is authenticated.
func TestAuth_DisabledIsPassThrough(t *testing.T) {
	s := &Server{} // no credential, no sessions
	if !s.requestAuthenticated(httptest.NewRequest(http.MethodGet, "/api/servers", nil)) {
		t.Fatal("auth-disabled request should be treated as authenticated")
	}
	w := httptest.NewRecorder()
	s.handleAuthStatus(w, httptest.NewRequest(http.MethodGet, "/api/auth/status", nil))
	var body map[string]bool
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["enabled"] {
		t.Fatalf("auth should report disabled: %v", body)
	}
}

// The failure throttle kicks in after the threshold.
func TestAuth_LoginThrottle(t *testing.T) {
	s := authTestServer(t, "pw")
	for range loginFailureThreshold {
		if c := login(t, s, "nope"); c != nil {
			t.Fatal("bad login should not succeed")
		}
	}
	// Next attempt is throttled → 429 even with the RIGHT password.
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"password":"pw"}`))
	w := httptest.NewRecorder()
	s.handleLogin(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failures, got %d", loginFailureThreshold, w.Code)
	}
}

func withCookie(c *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	r.AddCookie(c)
	return r
}
