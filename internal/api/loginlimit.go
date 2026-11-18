package api

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Login throttling. Three bounds, all enforced by reserving the
// attempt BEFORE Argon2 runs (a check-then-verify race would let a
// burst of simultaneous requests all pass before the first failure is
// recorded):
//
//   - A global cap on concurrent verifications. Each argon2id
//     verification costs ~64 MiB and argonThreads worker threads, so
//     an unbounded public login endpoint is a memory/CPU-exhaustion
//     primitive. An attempt that finds every slot taken waits up to
//     loginSlotWait for one, then gets 429.
//
//   - One attempt in flight per source. Without it a single client
//     could hold every verification slot at once, and the operator —
//     arriving with an untouched bucket and the right password — was
//     told "another login attempt is already being verified" for as
//     long as that client kept sending.
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
// — the address the innermost trusted proxy appended. That holds only
// if the proxy really does append or overwrite the header; one that
// relays the client's header untouched hands the client its choice of
// source (see DEPLOYMENT.md, which gives the nginx directive).
// X-Forwarded-For from an UNTRUSTED peer is never consulted.
//
// An IPv6 source is its /64, not the single address (loginSourceID):
// a /64 is the smallest block an ordinary IPv6 host is given, so with
// exact-address keys one client had 2^64 sources, each with a fresh
// burst and its own in-flight allowance.
//
// What this cannot bound is a client that really does come from many
// networks (a botnet, or one routed IPv6 prefix wider than a /64): it
// has many sources by any definition, each gets its own budget, and
// between them they can keep the verification slots busy. Guessing is
// then limited only by argon2's cost and the global cap. The same
// goes for clients sharing one address (a NAT, or a proxy without
// ANSBUI_TRUSTED_PROXIES), who share a bucket and race the operator
// for each refilled token. Neither has an in-band fix — rate-limit or
// authenticate at the proxy for those postures.
const (
	loginBurst          = 5
	loginRefill         = 3 * time.Second
	maxConcurrentLogins = 2
	// loginSlotWait is how long an attempt waits for a verification
	// slot before giving up. A verification takes a fraction of a
	// second, so a slot normally frees well inside this; the wait is
	// what turns brief contention into a short delay instead of an
	// error.
	loginSlotWait = 3 * time.Second
	// maxTrackedLoginSources bounds the per-source map so an
	// attacker with many source IPs can't grow it without limit;
	// when full, the longest-idle source is evicted, which only ever
	// forgives a backoff early. A source with an attempt waiting or
	// verifying is never evicted: its handler is still alive, and
	// dropping its entry would let the same source start a second
	// attempt and let waiters pile up past this bound. So the bound
	// is also the most attempts that can be waiting at once, and a
	// new source is refused (429) only in the one case where all of
	// them are in flight.
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
	inFlight    bool // an attempt from this source is waiting or verifying
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
	sources map[string]*loginSource
	// slots holds one value per verification in progress. A channel
	// rather than a counter so a full house can be waited on; blocked
	// senders are served in arrival order.
	slots chan struct{}
	// slotWait overrides loginSlotWait in tests.
	slotWait time.Duration
}

// begin reserves a token for source and a verification slot, or
// reports why the attempt may not proceed. It may block for up to
// loginSlotWait (less if ctx ends) when every slot is busy. Every
// loginProceed MUST be paired with exactly one end() call once the
// verification finishes.
func (l *loginLimiter) begin(ctx context.Context, source string, now time.Time) loginVerdict {
	slots, verdict := l.reserve(source, now)
	if verdict != loginProceed {
		return verdict
	}
	// Fast path: no timer when a slot is free.
	select {
	case slots <- struct{}{}:
		return loginProceed
	default:
	}
	wait := l.slotWait
	if wait <= 0 {
		wait = loginSlotWait
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case slots <- struct{}{}:
		return loginProceed
	case <-timer.C:
	case <-ctx.Done():
	}
	l.unreserve(source)
	return loginBusy
}

// reserve takes one token from source and marks it in flight.
func (l *loginLimiter) reserve(source string, now time.Time) (chan struct{}, loginVerdict) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.slots == nil {
		l.slots = make(chan struct{}, maxConcurrentLogins)
	}
	src := l.source(source, now)
	if src == nil {
		return nil, loginBusy // every tracked source has an attempt in flight
	}
	src.refill(now)
	if src.inFlight {
		return nil, loginBusy
	}
	if src.tokens <= 0 {
		return nil, loginThrottled
	}
	src.tokens--
	src.lastAttempt = now
	src.inFlight = true
	return l.slots, loginProceed
}

// unreserve undoes reserve for an attempt that never got a slot: the
// password was not checked, so the token goes back.
func (l *loginLimiter) unreserve(source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if src, ok := l.sources[source]; ok && src.inFlight {
		src.inFlight = false
		if src.tokens < loginBurst {
			src.tokens++
		}
	}
}

// end releases the slot reserved by begin. Success clears the
// source's history (refunding the reserved token); failure keeps it
// spent, so recovery is by refill only.
func (l *loginLimiter) end(source string, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	<-l.slots
	src, tracked := l.sources[source]
	if !tracked {
		// Cannot happen while in-flight sources are never evicted;
		// kept so a future change there cannot turn into a panic.
		return
	}
	src.inFlight = false
	if ok {
		delete(l.sources, source)
	}
}

// source returns the tracked entry for key, creating it (and
// evicting the longest-idle entry if the map is at capacity) as
// needed. It returns nil when the map is full and nothing in it is
// idle. Caller holds l.mu.
func (l *loginLimiter) source(key string, now time.Time) *loginSource {
	if l.sources == nil {
		l.sources = make(map[string]*loginSource)
	}
	if s, ok := l.sources[key]; ok {
		return s
	}
	if len(l.sources) >= maxTrackedLoginSources && !l.evictOldestIdle() {
		return nil
	}
	s := &loginSource{tokens: loginBurst, lastRefill: now, lastAttempt: now}
	l.sources[key] = s
	return s
}

// evictOldestIdle drops the idle source with the oldest lastAttempt
// and reports whether there was one. A source with an attempt in
// flight is never a candidate (see maxTrackedLoginSources). Linear
// scan; the map is small (≤ maxTrackedLoginSources) and this only
// runs when it is full. Caller holds l.mu.
func (l *loginLimiter) evictOldestIdle() bool {
	var oldestKey string
	var oldest time.Time
	found := false
	for k, s := range l.sources {
		if s.inFlight {
			continue
		}
		if !found || s.lastAttempt.Before(oldest) {
			found = true
			oldestKey, oldest = k, s.lastAttempt
		}
	}
	if found {
		delete(l.sources, oldestKey)
	}
	return found
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
		return loginSourceID(remote)
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		hop, ok := parseForwardedIP(strings.TrimSpace(hops[i]))
		if !ok {
			return loginSourceID(remote)
		}
		if !ipTrusted(hop, s.TrustedProxies) {
			return loginSourceID(hop)
		}
	}
	return loginSourceID(remote)
}

// loginSourcePrefixV6 is how much of an IPv6 address identifies a
// login source. A /64 is one subnet: the unit a single host, or a
// single customer line, controls every address of.
const loginSourcePrefixV6 = 64

// loginSourceID is the throttle key for an address: the address
// itself for IPv4, the enclosing /64 for IPv6. Callers pass an
// unmapped address (splitAddrIP and parseForwardedIP both unmap), so
// an IPv4 client written as ::ffff:a.b.c.d keeps its IPv4 key. The
// zone is dropped: it names a local interface, not a different peer.
func loginSourceID(a netip.Addr) string {
	a = a.WithZone("")
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(loginSourcePrefixV6)
	if err != nil {
		return a.String()
	}
	return p.String()
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
