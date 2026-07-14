package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
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
//   - A per-source token bucket: each source starts with loginBurst
//     attempts; a failure consumes one and only the passage of time
//     (one token per loginRefill) restores them. Crucially, recovery
//     is a pure function of the clock — throttled requests consume
//     nothing and failures never push recovery further out — so a
//     client hammering the endpoint cannot extend anyone's lockout,
//     including their own bucket's when it is shared. A successful
//     login clears the source's history.
//
// The source is the connection's RemoteAddr IP by default. When the
// deployment declares its reverse proxies via ANSBUI_TRUSTED_PROXIES
// (see Server.TrustedProxies), a connection from a trusted proxy is
// keyed by the rightmost non-trusted hop of X-Forwarded-For instead
// — the address the innermost trusted proxy saw, which the client
// cannot forge (anything it puts in the header sits further left).
// X-Forwarded-For from an UNTRUSTED peer is never consulted.
//
// Clients genuinely sharing one IP (a NAT, or a proxy without
// ANSBUI_TRUSTED_PROXIES set) share a bucket; an attacker there
// still can't extend the lockout, but does race the operator for
// each refilled token. That residual contention has no in-band fix
// — rate-limit or authenticate at the proxy for that posture.
const (
	loginBurst          = 5
	loginRefill         = 3 * time.Second
	maxConcurrentLogins = 2
	// maxTrackedLoginSources bounds the per-source map so an
	// attacker with many source IPs can't grow it without limit;
	// when full, the longest-idle source is evicted. Eviction only
	// ever forgives a backoff early — it never blocks a fresh
	// client.
	maxTrackedLoginSources = 1024
)

type loginVerdict int

const (
	loginProceed loginVerdict = iota
	loginBusy
	loginThrottled
)

type loginSource struct {
	tokens      int
	lastRefill  time.Time
	lastAttempt time.Time
}

// refill credits tokens earned since lastRefill, capped at
// loginBurst. Integer arithmetic: lastRefill advances by whole
// intervals so partial progress toward the next token is kept.
func (s *loginSource) refill(now time.Time) {
	earned := int(now.Sub(s.lastRefill) / loginRefill)
	if earned <= 0 {
		return
	}
	s.tokens += earned
	if s.tokens >= loginBurst {
		s.tokens = loginBurst
		s.lastRefill = now
		return
	}
	s.lastRefill = s.lastRefill.Add(time.Duration(earned) * loginRefill)
}

// loginLimiter is the reservation-based login throttle. The zero
// value is ready to use.
type loginLimiter struct {
	mu      sync.Mutex
	active  int
	sources map[string]*loginSource
}

// begin reserves a verification slot and a token for source, or
// reports why the attempt may not proceed. Every loginProceed MUST
// be paired with exactly one end() call once the verification
// finishes.
func (l *loginLimiter) begin(source string, now time.Time) loginVerdict {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active >= maxConcurrentLogins {
		return loginBusy
	}
	src := l.source(source, now)
	src.refill(now)
	if src.tokens <= 0 {
		return loginThrottled
	}
	src.tokens--
	src.lastAttempt = now
	l.active++
	return loginProceed
}

// end releases the slot reserved by begin. Success clears the
// source's history (refunding the reserved token); failure keeps it
// spent, so recovery is by refill only.
func (l *loginLimiter) end(source string, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active--
	if ok {
		delete(l.sources, source)
	}
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
	s := &loginSource{tokens: loginBurst, lastRefill: now, lastAttempt: now}
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

// ParseTrustedProxies parses the ANSBUI_TRUSTED_PROXIES value: a
// comma-separated list of IPs or CIDR prefixes naming the reverse
// proxies whose X-Forwarded-For is believed. Empty input is valid
// (no trusted proxies). Called from main at startup so a typo is
// fatal there, not silently ignored.
func ParseTrustedProxies(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, entry := range strings.Split(v, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			p, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, err
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, err
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func ipTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// loginSourceKey identifies the client for per-source throttling.
// Directly-connected clients are keyed by their RemoteAddr IP —
// X-Forwarded-For from an untrusted peer is attacker-controlled and
// never consulted. When the connection comes from a trusted proxy,
// the key is the rightmost X-Forwarded-For hop that is not itself a
// trusted proxy: that value was appended by a proxy we trust, so
// the client can't choose it (forged entries sit further left and
// are never reached). Anything unparseable falls back to the
// proxy's own IP — a shared bucket, never an attacker-chosen key.
func (s *Server) loginSourceKey(r *http.Request) string {
	remote, ok := splitAddrIP(r.RemoteAddr)
	if !ok {
		return r.RemoteAddr
	}
	if len(s.TrustedProxies) == 0 || !ipTrusted(remote, s.TrustedProxies) {
		return remote.String()
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		hop, ok := parseForwardedIP(strings.TrimSpace(hops[i]))
		if !ok {
			return remote.String()
		}
		if !ipTrusted(hop, s.TrustedProxies) {
			return hop.String()
		}
	}
	return remote.String()
}

// splitAddrIP extracts the IP from a host:port RemoteAddr,
// normalised (IPv6 canonical form, 4-in-6 unmapped) so one client
// can't occupy several buckets via alternate spellings.
func splitAddrIP(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// parseForwardedIP parses one X-Forwarded-For hop: a bare IP,
// bracketed IPv6, or ip:port (some proxies append the port).
func parseForwardedIP(hop string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(hop); err == nil {
		return a.Unmap(), true
	}
	if host, _, err := net.SplitHostPort(hop); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return a.Unmap(), true
		}
	}
	return netip.Addr{}, false
}
