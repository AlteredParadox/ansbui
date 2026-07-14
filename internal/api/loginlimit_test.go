package api

import (
	"fmt"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The limiter admits at most maxConcurrentLogins verifications at
// once, and a released slot becomes available again.
func TestLoginLimiter_ConcurrencyBound(t *testing.T) {
	var l loginLimiter
	now := time.Now()
	for i := range maxConcurrentLogins {
		if v := l.begin(fmt.Sprintf("10.0.0.%d", i), now); v != loginProceed {
			t.Fatalf("begin #%d = %v, want proceed", i, v)
		}
	}
	if v := l.begin("10.0.0.99", now); v != loginBusy {
		t.Fatalf("begin over cap = %v, want busy", v)
	}
	l.end("10.0.0.0", false)
	if v := l.begin("10.0.0.99", now); v != loginProceed {
		t.Fatalf("begin after release = %v, want proceed", v)
	}
}

// Regression for the check-then-verify race: hammer begin/end from
// many goroutines and assert the number of concurrently admitted
// attempts never exceeds the cap. Run with -race for full value.
func TestLoginLimiter_ConcurrentReservation(t *testing.T) {
	var l loginLimiter
	var active, peak atomic.Int64
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			source := fmt.Sprintf("10.1.0.%d", i%8)
			for range 50 {
				if l.begin(source, time.Now()) != loginProceed {
					continue
				}
				cur := active.Add(1)
				for {
					p := peak.Load()
					if cur <= p || peak.CompareAndSwap(p, cur) {
						break
					}
				}
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
		if v := l.begin(attacker, now); v != loginProceed {
			t.Fatalf("attacker pre-exhaustion begin = %v, want proceed", v)
		}
		l.end(attacker, false)
	}
	if v := l.begin(attacker, now); v != loginThrottled {
		t.Fatalf("attacker post-exhaustion begin = %v, want throttled", v)
	}
	if v := l.begin(operator, now); v != loginProceed {
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
		if v := l.begin(src, now); v != loginProceed {
			t.Fatal("expected proceed while tokens remain")
		}
		l.end(src, false)
	}
	// Hammer the empty bucket right up to the refill boundary.
	for i := range 50 {
		at := now.Add(time.Duration(i) * (loginRefill - time.Millisecond) / 50)
		if v := l.begin(src, at); v != loginThrottled {
			t.Fatalf("attempt %d before refill = %v, want throttled", i, v)
		}
	}
	// One interval after the last FAILURE-spending attempt, exactly
	// one token exists despite the hammering above.
	if v := l.begin(src, now.Add(loginRefill)); v != loginProceed {
		t.Fatal("expected proceed one refill interval later")
	}
	l.end(src, false)
	if v := l.begin(src, now.Add(loginRefill+time.Millisecond)); v != loginThrottled {
		t.Fatal("second token should not exist yet")
	}
	// Long quiet period refills to the burst cap, not beyond.
	later := now.Add(time.Hour)
	for i := range loginBurst {
		if v := l.begin(src, later); v != loginProceed {
			t.Fatalf("refilled attempt %d = %v, want proceed", i, v)
		}
		l.end(src, false)
	}
	if v := l.begin(src, later); v != loginThrottled {
		t.Fatal("bucket must cap at loginBurst")
	}
}

// A successful login clears the source's history.
func TestLoginLimiter_SuccessResets(t *testing.T) {
	var l loginLimiter
	now := time.Now()
	const src = "192.0.2.20"
	for range loginBurst - 1 {
		if v := l.begin(src, now); v != loginProceed {
			t.Fatal("expected proceed")
		}
		l.end(src, false)
	}
	if v := l.begin(src, now); v != loginProceed {
		t.Fatal("expected proceed for final token")
	}
	l.end(src, true)
	// Fresh bucket again.
	for i := range loginBurst {
		if v := l.begin(src, now); v != loginProceed {
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
		if v := l.begin(source, now); v != loginProceed {
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
