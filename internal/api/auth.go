package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/AlteredParadox/ansbui/internal/auth"
)

// sessionCookieName is the login cookie. HttpOnly + SameSite=Strict
// (see setSessionCookie) means it never reaches JS and never rides a
// cross-site request, which — together with the existing Origin==Host
// guard — covers CSRF for the mutating endpoints.
const sessionCookieName = "ansbui_session"

// authEnabled reports whether a credential is configured. When false
// the whole auth layer is pass-through (the historical
// behind-a-proxy posture), so upgrading a running deployment doesn't
// suddenly lock the operator out before they set a password.
func (s *Server) authEnabled() bool {
	return s.Credential != nil && s.Sessions != nil
}

// requestAuthenticated reports whether r carries a valid session
// cookie. Always true when auth is disabled.
func (s *Server) requestAuthenticated(r *http.Request) bool {
	if !s.authEnabled() {
		return true
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return s.Sessions.Validate(c.Value)
}

// authOpenPath reports whether a path is reachable without a valid
// session even when auth is enabled: the login/logout/status
// endpoints themselves, and the health check. Everything else under
// /api/ requires a session; static assets (the SPA shell, vendored
// JS/CSS) are served by a different handler and carry no operator
// data, matching the existing origin-guard exemption.
func authOpenPath(path string) bool {
	switch path {
	case "/api/login", "/api/logout", "/api/auth/status", "/api/health":
		return true
	default:
		return false
	}
}

// withAuth guards /api/* behind a valid session when auth is enabled.
// Open endpoints (authOpenPath) and everything outside /api/ pass
// through. A blocked request gets 401 with a JSON body the frontend
// uses to drop to the login screen.
func (s *Server) withAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authEnabled() || !strings.HasPrefix(r.URL.Path, "/api/") || authOpenPath(r.URL.Path) {
			h.ServeHTTP(w, r)
			return
		}
		if !s.requestAuthenticated(r) {
			writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
			return
		}
		h.ServeHTTP(w, r)
	})
}

// loginRequest is the POST /api/login body.
type loginRequest struct {
	Password string `json:"password"`
}

// Login throttle: after loginFailureThreshold consecutive failures,
// each further attempt is delayed to loginBackoff from the last, so a
// brute-force gets ~one guess per interval regardless of how fast the
// attacker fires. argon2 verification is already ~100ms, but this
// bounds the aggregate. Any success resets the counter.
const (
	loginFailureThreshold = 5
	loginBackoff          = 3 * time.Second
)

// checkLoginAllowed reports whether a login attempt may proceed now,
// per the failure throttle. Caller holds no lock.
func (s *Server) checkLoginAllowed() bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if s.loginFailures < loginFailureThreshold {
		return true
	}
	return time.Now().After(s.loginNextOK)
}

// recordLoginResult updates the throttle after an attempt.
func (s *Server) recordLoginResult(ok bool) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if ok {
		s.loginFailures = 0
		return
	}
	s.loginFailures++
	s.loginNextOK = time.Now().Add(loginBackoff)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.authEnabled() {
		// Nothing to log into; report success so a stale login page
		// doesn't wedge, but set no cookie.
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if !s.checkLoginAllowed() {
		writeError(w, http.StatusTooManyRequests, errors.New("too many failed attempts — wait a few seconds and retry"))
		return
	}
	var req loginRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Password == "" || !s.Credential.Verify(req.Password) {
		s.recordLoginResult(false)
		writeError(w, http.StatusUnauthorized, errors.New("invalid password"))
		return
	}
	s.recordLoginResult(true)
	token, err := s.Sessions.Create()
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("could not start session"))
		return
	}
	setSessionCookie(w, r, token)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && s.Sessions != nil {
		s.Sessions.Destroy(c.Value)
	}
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAuthStatus tells the frontend whether auth is on and whether
// this request is already authenticated, so it can choose between the
// login screen and the app on boot. Always reachable.
func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"enabled":       s.authEnabled(),
		"authenticated": s.requestAuthenticated(r),
	})
}

// requestIsHTTPS reports whether the browser's connection to us (or
// to the TLS-terminating proxy in front of us) is HTTPS. Used to set
// the cookie Secure attribute: direct TLS shows up as r.TLS, and a
// reverse proxy signals it via X-Forwarded-Proto. Local plain-HTTP
// dev gets a non-Secure cookie so login still works there.
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(auth.MaxCookieAge / time.Second),
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
