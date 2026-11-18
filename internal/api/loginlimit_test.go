package api

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var bg = context.Background()

// The limiter admits at most maxConcurrentLogins verifications at
// once, and a released slot becomes available again.
func TestLoginLimiter_ConcurrencyBound(t *testing.T) {
	l := loginLimiter{slotWait: 20 * time.Millisecond}
	now := time.Now()
	for i := range maxConcurrentLogins {
		if v := l.begin(bg, fmt.Sprintf("10.0.0.%d", i), now); v != loginProceed {
			t.Fatalf("begin #%d = %v, want proceed", i, v)
		}
	}
	if v := l.begin(bg, "10.0.0.99", now); v != loginBusy {
		t.Fatalf("begin over cap = %v, want busy", v)
	}
	l.end("10.0.0.0", false)
	if v := l.begin(bg, "10.0.0.99", now); v != loginProceed {
		t.Fatalf("begin after release = %v, want proceed", v)
	}
}

// raisePeak lifts peak to cur if cur exceeds it (CAS loop, safe
// under concurrent raisers).
func raisePeak(peak *atomic.Int64, cur int64) {
	for {
		p := peak.Load()
		if cur <= p || peak.CompareAndSwap(p, cur) {
			return
		}
	}
}

// Regression for the check-then-verify race: hammer begin/end from
// many goroutines and assert the number of concurrently admitted
// attempts never exceeds the cap. Run with -race for full value.
func TestLoginLimiter_ConcurrentReservation(t *testing.T) {
	l := loginLimiter{slotWait: time.Millisecond}
	var active, peak atomic.Int64
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			source := fmt.Sprintf("10.1.0.%d", i%8)
			for range 50 {
				if l.begin(bg, source, time.Now()) != loginProceed {
					continue
				}
				raisePeak(&peak, active.Add(1))
				active.Add(-1)
				l.end(source, true)
			}
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > maxConcurrentLogins {
		t.Fatalf("observed %d concurrent admitted attempts, cap is %d", p, maxConcurrentLogins)
	}
}

// One source burning its tokens throttles only itself: the operator
// on a different IP still gets through. Regression for the global
// throttle that let any client hold the login at 429 indefinitely.
func TestLoginLimiter_FailuresScopedPerSource(t *testing.T) {
	var l loginLimiter
	now := time.Now()
	attacker, operator := "203.0.113.7", "10.0.0.5"
	for range loginBurst {
		if v := l.begin(bg, attacker, now); v != loginProceed {
			t.Fatalf("attacker pre-exhaustion begin = %v, want proceed", v)
		}
		l.end(attacker, false)
	}
	if v := l.begin(bg, attacker, now); v != loginThrottled {
		t.Fatalf("attacker post-exhaustion begin = %v, want throttled", v)
	}
	if v := l.begin(bg, operator, now); v != loginProceed {
		t.Fatalf("operator begin while attacker throttled = %v, want proceed", v)
	}
	l.end(operator, true)
}

// Recovery is a pure function of time: hammering a throttled bucket
// neither delays its refill nor spends anything, so an attacker
// cannot extend a lockout — the core of the shared-bucket (reverse
// proxy / NAT) finding. Tokens accrue one per loginRefill and cap
// at loginBurst.
func TestLoginLimiter_LockoutCannotBeExtended(t *testing.T) {
	var l loginLimiter
	now := time.Now()
	const src = "192.0.2.10"
	for range loginBurst {
		if v := l.begin(bg, src, now); v != loginProceed {
			t.Fatal("expected proceed while tokens remain")
		}
		l.end(src, false)
	}
	// Hammer the empty bucket right up to the refill boundary.
	for i := range 50 {
		at := now.Add(time.Duration(i) * (loginRefill - time.Millisecond) / 50)
		if v := l.begin(bg, src, at); v != loginThrottled {
			t.Fatalf("attempt %d before refill = %v, want throttled", i, v)
		}
	}
	// One interval after the last FAILURE-spending attempt, exactly
	// one token exists despite the hammering above.
	if v := l.begin(bg, src, now.Add(loginRefill)); v != loginProceed {
		t.Fatal("expected proceed one refill interval later")
	}
	l.end(src, false)
	if v := l.begin(bg, src, now.Add(loginRefill+time.Millisecond)); v != loginThrottled {
		t.Fatal("second token should not exist yet")
	}
	// Long quiet period refills to the burst cap, not beyond.
	later := now.Add(time.Hour)
	for i := range loginBurst {
		if v := l.begin(bg, src, later); v != loginProceed {
			t.Fatalf("refilled attempt %d = %v, want proceed", i, v)
		}
		l.end(src, false)
	}
	if v := l.begin(bg, src, later); v != loginThrottled {
		t.Fatal("bucket must cap at loginBurst")
	}
}

// A successful login clears the source's history.
func TestLoginLimiter_SuccessResets(t *testing.T) {
	var l loginLimiter
	now := time.Now()
	const src = "192.0.2.20"
	for range loginBurst - 1 {
		if v := l.begin(bg, src, now); v != loginProceed {
			t.Fatal("expected proceed")
		}
		l.end(src, false)
	}
	if v := l.begin(bg, src, now); v != loginProceed {
		t.Fatal("expected proceed for final token")
	}
	l.end(src, true)
	// Fresh bucket again.
	for i := range loginBurst {
		if v := l.begin(bg, src, now); v != loginProceed {
			t.Fatalf("post-success attempt %d = %v, want proceed", i, v)
		}
		l.end(src, false)
	}
}

// The per-source map stays bounded no matter how many distinct
// sources fail, and a brand-new source is never rejected by a full
// map (eviction makes room).
func TestLoginLimiter_SourceMapBounded(t *testing.T) {
	var l loginLimiter
	now := time.Now()
	for i := range maxTrackedLoginSources + 100 {
		source := fmt.Sprintf("198.51.%d.%d", i/256, i%256)
		if v := l.begin(bg, source, now); v != loginProceed {
			t.Fatalf("source #%d begin = %v, want proceed", i, v)
		}
		l.end(source, false)
		now = now.Add(time.Millisecond)
	}
	l.mu.Lock()
	n := len(l.sources)
	l.mu.Unlock()
	if n > maxTrackedLoginSources {
		t.Fatalf("tracked sources = %d, want ≤ %d", n, maxTrackedLoginSources)
	}
}

// Source attribution: RemoteAddr by default; behind a declared
// trusted proxy, the rightmost non-trusted X-Forwarded-For hop.
func TestLoginSourceKey(t *testing.T) {
	trusted, err := ParseTrustedProxies("127.0.0.1, 10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		remoteAddr string
		xff        string
		trusted    bool
		want       string
	}{
		{"direct client", "192.0.2.9:4242", "", false, "192.0.2.9"},
		{"xff from untrusted peer is ignored", "192.0.2.9:4242", "203.0.113.99", true, "192.0.2.9"},
		{"trusted proxy, single hop", "127.0.0.1:5000", "203.0.113.7", true, "203.0.113.7"},
		{"client-forged hop sits left of the real one", "127.0.0.1:5000", "1.2.3.4, 203.0.113.7", true, "203.0.113.7"},
		{"chained trusted proxies are skipped", "127.0.0.1:5000", "203.0.113.7, 10.0.0.3", true, "203.0.113.7"},
		{"all hops trusted falls back to proxy IP", "127.0.0.1:5000", "10.0.0.3", true, "127.0.0.1"},
		{"no xff from trusted proxy falls back", "127.0.0.1:5000", "", true, "127.0.0.1"},
		{"garbage hop falls back to proxy IP", "127.0.0.1:5000", "not-an-ip", true, "127.0.0.1"},
		{"hop with port is accepted", "127.0.0.1:5000", "203.0.113.7:9999", true, "203.0.113.7"},
		{"4-in-6 hop is unmapped", "127.0.0.1:5000", "::ffff:203.0.113.7", true, "203.0.113.7"},
		{"direct IPv6 client is keyed by its /64", "[2001:db8:0:1::abcd]:4242", "", false, "2001:db8:0:1::/64"},
		{"another address in that /64 is the same source", "[2001:db8:0:1:ffff:ffff:ffff:1]:4242", "", false, "2001:db8:0:1::/64"},
		{"the next /64 is a different source", "[2001:db8:0:2::abcd]:4242", "", false, "2001:db8:0:2::/64"},
		{"IPv6 hop from a trusted proxy is keyed by its /64", "127.0.0.1:5000", "2001:db8:0:1::abcd", true, "2001:db8:0:1::/64"},
		{"bracketed IPv6 hop with port", "127.0.0.1:5000", "[2001:db8:0:1::abcd]:9999", true, "2001:db8:0:1::/64"},
		{"IPv6 zone does not make a new source", "[fe80::1%eth0]:4242", "", false, "fe80::/64"},
		{"4-in-6 remote address keeps its IPv4 key", "[::ffff:192.0.2.9]:4242", "", false, "192.0.2.9"},
		{"unparseable remoteaddr uses raw string", "garbage", "", false, "garbage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{}
			if tc.trusted {
				s.TrustedProxies = trusted
			}
			r := httptest.NewRequest("POST", "/api/login", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := s.loginSourceKey(r); got != tc.want {
				t.Fatalf("loginSourceKey = %q, want %q", got, tc.want)
			}
		})
	}
}

// ParseTrustedProxies accepts IPs and CIDRs, rejects garbage.
func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies(" 127.0.0.1, 10.0.0.0/8 , ::1 ")
	if err != nil || len(got) != 3 {
		t.Fatalf("ParseTrustedProxies = %v, %v", got, err)
	}
	if _, err := ParseTrustedProxies("127.0.0.1, nonsense"); err == nil {
		t.Fatal("expected error for a bad entry")
	}
	if got, err := ParseTrustedProxies(""); err != nil || len(got) != 0 {
		t.Fatalf("empty input = %v, %v; want no prefixes, nil error", got, err)
	}
}

func TestLoginSourceID(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.9":                       "192.0.2.9",
		"2001:db8:0:1::abcd":              "2001:db8:0:1::/64",
		"2001:db8:0:1:1:2:3:4":            "2001:db8:0:1::/64",
		"2001:db8::1":                     "2001:db8::/64",
		"::1":                             "::/64",
		"fe80::1%eth0":                    "fe80::/64",
		"2001:db8:ffff:ffff:ffff:ffff::1": "2001:db8:ffff:ffff::/64",
	} {
		if got := loginSourceID(netip.MustParseAddr(in)); got != want {
			t.Errorf("loginSourceID(%s) = %q, want %q", in, got, want)
		}
	}
}

// Every address of one /64 draws on one budget. With exact-address
// keys, 20 addresses of a /64 got 20 fresh bursts.
func TestLoginLimiter_IPv6SubnetSharesOneBudget(t *testing.T) {
	var l loginLimiter
	s := &Server{}
	now := time.Now()
	admitted := 0
	for i := range 20 {
		r := httptest.NewRequest("POST", "/api/login", nil)
		r.RemoteAddr = fmt.Sprintf("[2001:db8:0:1::%x]:4242", i+1)
		key := s.loginSourceKey(r)
		if l.begin(bg, key, now) == loginProceed {
			admitted++
			l.end(key, false)
		}
	}
	if admitted != loginBurst {
		t.Fatalf("%d attempts admitted from 20 addresses of one /64, want %d", admitted, loginBurst)
	}
	l.mu.Lock()
	n := len(l.sources)
	l.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d sources tracked for one /64, want 1", n)
	}
}

// One source holds at most one verification at a time, so it cannot
// take every slot: a second source is admitted while the first is
// still being verified. This is the operator-lockout scenario — the
// operator used to get "already being verified" with the correct
// password for as long as one client kept two attempts in flight.
func TestLoginLimiter_OneSourceCannotHoldEverySlot(t *testing.T) {
	l := loginLimiter{slotWait: 20 * time.Millisecond}
	now := time.Now()
	const attacker, operator = "2001:db8:0:1::/64", "198.51.100.9"
	if v := l.begin(bg, attacker, now); v != loginProceed {
		t.Fatalf("first attacker attempt = %v, want proceed", v)
	}
	for i := range 5 {
		if v := l.begin(bg, attacker, now); v != loginBusy {
			t.Fatalf("attacker attempt %d while one is in flight = %v, want busy", i, v)
		}
	}
	if v := l.begin(bg, operator, now); v != loginProceed {
		t.Fatalf("operator attempt while the attacker's is in flight = %v, want proceed", v)
	}
	l.end(operator, true)
	l.end(attacker, false)
	// The refused attempts cost the attacker nothing beyond the one
	// that ran: loginBurst-1 tokens remain.
	for i := range loginBurst - 1 {
		if v := l.begin(bg, attacker, now); v != loginProceed {
			t.Fatalf("attacker attempt %d after release = %v, want proceed", i, v)
		}
		l.end(attacker, false)
	}
	if v := l.begin(bg, attacker, now); v != loginThrottled {
		t.Fatalf("attacker past its burst = %v, want throttled", v)
	}
}

// With every slot busy, an attempt waits for one instead of failing
// at once.
func TestLoginLimiter_WaitsForASlot(t *testing.T) {
	l := loginLimiter{slotWait: 5 * time.Second}
	now := time.Now()
	for i := range maxConcurrentLogins {
		if v := l.begin(bg, fmt.Sprintf("10.2.0.%d", i), now); v != loginProceed {
			t.Fatalf("begin #%d = %v, want proceed", i, v)
		}
	}
	got := make(chan loginVerdict, 1)
	go func() { got <- l.begin(bg, "198.51.100.9", now) }()
	select {
	case v := <-got:
		t.Fatalf("begin returned %v while every slot was busy; it should wait", v)
	case <-time.After(100 * time.Millisecond):
	}
	l.end("10.2.0.0", false)
	select {
	case v := <-got:
		if v != loginProceed {
			t.Fatalf("waiting attempt = %v after a slot freed, want proceed", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting attempt was not admitted when a slot freed")
	}
	l.end("198.51.100.9", true)
	l.end("10.2.0.1", false)
}

// An attempt that never gets a slot is not a failed password: it
// gives up after the wait (or when the request ends), and its token
// is returned.
func TestLoginLimiter_GivingUpReturnsTheToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		wait time.Duration
		ctx  func() (context.Context, context.CancelFunc)
	}{
		{"wait expires", 30 * time.Millisecond, func() (context.Context, context.CancelFunc) { return context.WithCancel(bg) }},
		{"request cancelled", time.Minute, func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(bg, 30*time.Millisecond)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := loginLimiter{slotWait: tc.wait}
			now := time.Now()
			for i := range maxConcurrentLogins {
				if v := l.begin(bg, fmt.Sprintf("10.3.0.%d", i), now); v != loginProceed {
					t.Fatalf("begin #%d = %v, want proceed", i, v)
				}
			}
			const src = "198.51.100.9"
			for i := range loginBurst * 2 { // more than a burst: nothing is spent
				ctx, cancel := tc.ctx()
				start := time.Now()
				v := l.begin(ctx, src, now)
				cancel()
				if v != loginBusy {
					t.Fatalf("attempt %d with no free slot = %v, want busy", i, v)
				}
				if took := time.Since(start); took > 3*time.Second {
					t.Fatalf("attempt %d took %s to give up", i, took)
				}
			}
			for i := range maxConcurrentLogins {
				l.end(fmt.Sprintf("10.3.0.%d", i), false)
			}
			for i := range loginBurst {
				if v := l.begin(bg, src, now); v != loginProceed {
					t.Fatalf("attempt %d after slots freed = %v, want proceed (tokens were spent while waiting)", i, v)
				}
				l.end(src, false)
			}
		})
	}
}

// When every tracked source has an attempt waiting or verifying,
// nothing can be evicted: a new source is refused instead. Evicting a
// live reservation let the same source start a second attempt, let
// waiters grow past the cap, and let the old attempt's release clear
// the replacement's in-flight mark.
func TestLoginLimiter_FullOfLiveReservationsRefusesNewSources(t *testing.T) {
	var l loginLimiter
	now := time.Now()
	name := func(i int) string { return fmt.Sprintf("198.18.%d.%d", i/256, i%256) }
	// reserve is begin without the wait for a slot: each of these is
	// what a handler parked in begin holds.
	for i := range maxTrackedLoginSources {
		if _, v := l.reserve(name(i), now.Add(time.Duration(i)*time.Millisecond)); v != loginProceed {
			t.Fatalf("reservation #%d = %v, want proceed", i, v)
		}
	}
	tracked := func() int {
		l.mu.Lock()
		defer l.mu.Unlock()
		return len(l.sources)
	}

	// One more source: refused, and it displaced nobody.
	const newcomer = "203.0.113.200"
	for range 3 {
		if _, v := l.reserve(newcomer, now.Add(time.Hour)); v != loginBusy {
			t.Fatalf("new source with the map full of live reservations = %v, want busy", v)
		}
	}
	if n := tracked(); n != maxTrackedLoginSources {
		t.Fatalf("tracked sources = %d, want %d (a live reservation was evicted, or the map grew)", n, maxTrackedLoginSources)
	}
	// The oldest source is still the one with an attempt in flight: a
	// second attempt from it is refused, not started afresh.
	if _, v := l.reserve(name(0), now.Add(time.Hour)); v != loginBusy {
		t.Fatalf("second attempt from the oldest live source = %v, want busy", v)
	}
	// begin reports the same thing, without waiting for a slot it will
	// never be given.
	start := time.Now()
	if v := l.begin(bg, newcomer, now.Add(time.Hour)); v != loginBusy {
		t.Fatalf("begin for a new source with the map full = %v, want busy", v)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("begin took %s to refuse; it must not queue", took)
	}

	// Once one attempt gives up, its entry is idle and can make room.
	l.unreserve(name(7))
	if _, v := l.reserve(newcomer, now.Add(time.Hour)); v != loginProceed {
		t.Fatalf("new source after one reservation was released = %v, want proceed", v)
	}
	l.mu.Lock()
	_, stillThere := l.sources[name(7)]
	other := l.sources[name(8)]
	fresh := l.sources[newcomer]
	l.mu.Unlock()
	if stillThere {
		t.Fatal("the idle source was not the one evicted")
	}
	if other == nil || !other.inFlight {
		t.Fatal("releasing one source changed another's reservation")
	}
	if fresh == nil || !fresh.inFlight || fresh.tokens != loginBurst-1 {
		t.Fatalf("the newcomer's reservation is wrong: %+v", fresh)
	}
	if n := tracked(); n != maxTrackedLoginSources {
		t.Fatalf("tracked sources = %d after one swap, want %d", n, maxTrackedLoginSources)
	}
	// Releasing every older attempt leaves the newcomer's reservation
	// exactly as it was.
	for i := range maxTrackedLoginSources {
		if i != 7 {
			l.unreserve(name(i))
		}
	}
	l.unreserve(name(7)) // already gone: must not touch anything
	l.mu.Lock()
	fresh = l.sources[newcomer]
	l.mu.Unlock()
	if fresh == nil || !fresh.inFlight || fresh.tokens != loginBurst-1 {
		t.Fatalf("an older attempt's release changed the newcomer's reservation: %+v", fresh)
	}
}

// Eviction prefers idle sources, and a release for a source that is
// no longer tracked does not break anything.
func TestLoginLimiter_EvictionAndInFlightSources(t *testing.T) {
	var l loginLimiter
	now := time.Now()
	const verifying = "203.0.113.1"
	if v := l.begin(bg, verifying, now); v != loginProceed {
		t.Fatalf("begin = %v, want proceed", v)
	}
	// Fill the map with newer, idle sources; the in-flight one is the
	// oldest and would be the plain choice for eviction.
	for i := range maxTrackedLoginSources + 10 {
		source := fmt.Sprintf("198.18.%d.%d", i/256, i%256)
		at := now.Add(time.Duration(i+1) * time.Millisecond)
		if v := l.begin(bg, source, at); v != loginProceed {
			t.Fatalf("source #%d begin = %v, want proceed", i, v)
		}
		l.end(source, false)
	}
	l.mu.Lock()
	_, kept := l.sources[verifying]
	n := len(l.sources)
	l.mu.Unlock()
	if !kept {
		t.Fatal("a source with an attempt in flight was evicted while idle ones existed")
	}
	if n > maxTrackedLoginSources {
		t.Fatalf("tracked sources = %d, want ≤ %d", n, maxTrackedLoginSources)
	}
	// Force the other case: drop the entry, then release.
	l.mu.Lock()
	delete(l.sources, verifying)
	l.mu.Unlock()
	l.end(verifying, false)
	if v := l.begin(bg, "198.51.100.9", now); v != loginProceed {
		t.Fatalf("begin after releasing an evicted source = %v, want proceed (slot leaked?)", v)
	}
	l.end("198.51.100.9", true)
}
