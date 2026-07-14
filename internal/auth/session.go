package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// Session lifetime bounds. idleTimeout expires a session that goes
// untouched; absoluteLifetime caps a continuously-used session so a
// stolen cookie can't live forever. Single-operator control plane —
// generous enough not to annoy, short enough to bound exposure.
const (
	idleTimeout      = 12 * time.Hour
	absoluteLifetime = 7 * 24 * time.Hour
	sessionTokenLen  = 32 // bytes of entropy in the cookie value
)

// MaxCookieAge is the cookie Max-Age the HTTP layer should set —
// the absolute session lifetime. The server-side store is the real
// authority (it also enforces the idle timeout); the cookie age just
// keeps a browser from resending a cookie that can never be valid.
const MaxCookieAge = absoluteLifetime

// SessionStore is an in-memory set of live sessions keyed by an
// opaque random token. Sessions do not survive a restart — that
// logs the single operator out, which is an acceptable trade for
// not persisting bearer-equivalent secrets to disk. Safe for
// concurrent use.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session
	now      func() time.Time // injectable for tests
}

type session struct {
	createdAt  time.Time
	lastSeenAt time.Time
}

// NewSessionStore returns an empty store using the wall clock.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*session),
		now:      time.Now,
	}
}

// Create mints a new session and returns its token. The token is
// the cookie value; it is never logged or persisted.
func (s *SessionStore) Create() (string, error) {
	b := make([]byte, sessionTokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	now := s.now()
	s.mu.Lock()
	s.sessions[token] = &session{createdAt: now, lastSeenAt: now}
	s.mu.Unlock()
	return token, nil
}

// Validate reports whether token names a live session, refreshing
// its idle timer (sliding expiry) on success. Expired sessions are
// dropped as they're encountered. An empty token is never valid.
func (s *SessionStore) Validate(token string) bool {
	if token == "" {
		return false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return false
	}
	if s.expiredLocked(sess, now) {
		delete(s.sessions, token)
		return false
	}
	sess.lastSeenAt = now
	return true
}

// Destroy removes a session (logout). No-op for an unknown token.
func (s *SessionStore) Destroy(token string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// Count returns the number of live (non-expired) sessions, pruning
// any expired ones it passes. Exposed for tests and diagnostics.
func (s *SessionStore) Count() int {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, sess := range s.sessions {
		if s.expiredLocked(sess, now) {
			delete(s.sessions, token)
		}
	}
	return len(s.sessions)
}

func (s *SessionStore) expiredLocked(sess *session, now time.Time) bool {
	return now.Sub(sess.lastSeenAt) > idleTimeout ||
		now.Sub(sess.createdAt) > absoluteLifetime
}
