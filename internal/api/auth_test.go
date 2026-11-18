package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
	// The login throttle refills by elapsed time, and each attempt
	// here verifies a real argon2 hash — a second or more apiece under
	// the race detector on a busy machine. Read from the wall clock,
	// the throttle tests passed or failed with the machine's load (a
	// token refilled mid-test). A fixed clock makes them say the same
	// thing everywhere.
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return &Server{Credential: cred, Sessions: auth.NewSessionStore(), clock: func() time.Time { return fixed }}
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
	for range loginBurst {
		if c := login(t, s, "nope"); c != nil {
			t.Fatal("bad login should not succeed")
		}
	}
	// Next attempt from the same source is throttled → 429 even with
	// the RIGHT password. (httptest requests share one RemoteAddr.)
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"password":"pw"}`))
	w := httptest.NewRecorder()
	s.handleLogin(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d failures, got %d", loginBurst, w.Code)
	}
}

// The throttle is per source: an attacker extending their own
// backoff forever cannot hold the operator's login at 429.
func TestAuth_LoginThrottleDoesNotLockOutOtherSources(t *testing.T) {
	s := authTestServer(t, "pw")
	attempt := func(remoteAddr, password string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"password":`+quote(password)+`}`))
		r.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		s.handleLogin(w, r)
		return w.Code
	}
	// Attacker fails past the threshold, then keeps hammering (each
	// throttled request must NOT extend anyone else's window).
	for range loginBurst {
		if code := attempt("203.0.113.7:5000", "nope"); code != http.StatusUnauthorized {
			t.Fatalf("attacker failure = %d, want 401", code)
		}
	}
	for range 3 {
		if code := attempt("203.0.113.7:5000", "nope"); code != http.StatusTooManyRequests {
			t.Fatalf("throttled attacker = %d, want 429", code)
		}
	}
	// Operator on a different IP logs straight in.
	if code := attempt("10.0.0.5:6000", "pw"); code != http.StatusOK {
		t.Fatalf("operator login while attacker throttled = %d, want 200", code)
	}
}

// The lockout an IPv6 client could cause: cycling through addresses
// of its own /64 it was never throttled, kept both verification slots
// busy, and the operator — different address, correct password — got
// 429 "already being verified" for as long as it went on. Now the /64
// is one source with one budget and one slot.
func TestAuth_OneSubnetCannotLockOutTheOperator(t *testing.T) {
	s := authTestServer(t, "pw")
	attempt := func(remoteAddr, password string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"password":`+quote(password)+`}`))
		r.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		s.handleLogin(w, r)
		return w.Code
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				// A different address of the same /64 every time.
				code := attempt(fmt.Sprintf("[2001:db8:0:1::%x:%x]:4242", g+1, i+1), "nope")
				mu.Lock()
				codes[code]++
				mu.Unlock()
			}
		}()
	}

	// Let the flood get going, then log in as the operator.
	time.Sleep(200 * time.Millisecond)
	for i := range 3 {
		if code := attempt("198.51.100.9:6000", "pw"); code != http.StatusOK {
			close(stop)
			wg.Wait()
			t.Fatalf("operator login %d during the flood = %d, want 200", i, code)
		}
	}
	close(stop)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if codes[http.StatusOK] != 0 {
		t.Fatalf("a wrong password was accepted: %v", codes)
	}
	// The clock is fixed, so nothing refills: the whole /64 gets one
	// burst of real password checks and everything else is refused
	// without one.
	if got := codes[http.StatusUnauthorized]; got > loginBurst {
		t.Fatalf("%d password checks for one /64, budget is %d (%v)", got, loginBurst, codes)
	}
	if codes[http.StatusTooManyRequests] == 0 {
		t.Fatalf("the flood was never refused: %v", codes)
	}
}

func withCookie(c *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	r.AddCookie(c)
	return r
}
