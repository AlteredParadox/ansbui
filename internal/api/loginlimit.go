package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Login throttling. Two independent bounds, both enforced by
// atomically reserving the attempt BEFORE Argon2 runs (a
// check-then-verify race would let a burst of simultaneous requests
// all pass before the first failure is recorded):
//
//   - A global cap on concurrent verifications. Each argon2id
//     verification costs ~64 MiB and argonThreads worker threads, so
//     an unbounded public login endpoint is a memory/CPU-exhaustion
//     primitive. Excess attempts get 429 immediately.
//
//   - A per-source failure backoff: after loginFailureThreshold
//     consecutive failures from one source IP, that source gets ~one
//     attempt per loginBackoff. Scoping it per source means an
//     attacker extending their own backoff window forever cannot
//     lock the operator (a different IP) out of the login — with the
//     old global counter, one failed request per window kept the
//     real password at 429 indefinitely.
//
// The source is the connection's RemoteAddr IP, never
// X-Forwarded-For (trivially spoofable). Behind a reverse proxy all
// clients share the proxy's IP and this degrades to the old global
// throttle — rate-limit or authenticate at the proxy in that
// posture (DEPLOYMENT.md already requires proxy auth there).
const (
	loginFailureThreshold = 5
	loginBackoff          = 3 * time.Second
	maxConcurrentLogins   = 2
	// maxTrackedLoginSources bounds the failure map so an attacker
	// with many source IPs can't grow it without limit; when full,
	// the longest-idle source is evicted. Eviction only ever
	// forgives a backoff early — it never blocks a fresh client.
	maxTrackedLoginSources = 1024
)

type loginVerdict int

const (
	loginProceed loginVerdict = iota
	loginBusy
	loginThrottled
)

type loginSource struct {
	failures    int
	lastAttempt time.Time
	nextOK      time.Time
}

// loginLimiter is the reservation-based login throttle. The zero
// value is ready to use.
type loginLimiter struct {
	mu      sync.Mutex
	active  int
	sources map[string]*loginSource
}

// begin reserves a verification slot for source, or reports why the
// attempt may not proceed. Every loginProceed MUST be paired with
// exactly one end() call once the verification finishes.
func (l *loginLimiter) begin(source string, now time.Time) loginVerdict {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= maxConcurrentLogins {
		return loginBusy
	}
	src := l.source(source, now)
	if src.failures >= loginFailureThreshold && now.Before(src.nextOK) {
		return loginThrottled
	}
	l.active++
	src.lastAttempt = now
	return loginProceed
}

// end releases the slot reserved by begin and records the attempt's
// outcome against source. Success clears the source's history.
func (l *loginLimiter) end(source string, ok bool, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
	if ok {
		delete(l.sources, source)
		return
	}
	// The entry may have been evicted while the verification ran;
	// source() recreates it in that case.
	src := l.source(source, now)
	src.failures++
	src.lastAttempt = now
	src.nextOK = now.Add(loginBackoff)
}

// source returns the tracked entry for key, creating it (and
// evicting the longest-idle entry if the map is at capacity) as
// needed. Caller holds l.mu.
func (l *loginLimiter) source(key string, now time.Time) *loginSource {
	if l.sources == nil {
		l.sources = make(map[string]*loginSource)
	}
	if s, ok := l.sources[key]; ok {
		return s
	}
	if len(l.sources) >= maxTrackedLoginSources {
		l.evictOldest()
	}
	s := &loginSource{lastAttempt: now}
	l.sources[key] = s
	return s
}

// evictOldest drops the source with the oldest lastAttempt. Linear
// scan; the map is small (≤ maxTrackedLoginSources) and this only
// runs when it is full. Caller holds l.mu.
func (l *loginLimiter) evictOldest() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, s := range l.sources {
		if first || s.lastAttempt.Before(oldest) {
			first = false
			oldestKey, oldest = k, s.lastAttempt
		}
	}
	delete(l.sources, oldestKey)
}

// loginSourceKey identifies the client for per-source throttling:
// the IP half of RemoteAddr, falling back to the raw string when it
// doesn't parse (all such clients then share one bucket).
func loginSourceKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return r.RemoteAddr
	}
	return host
}
