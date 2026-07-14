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
	l.end("10.0.0.0", false, now)
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
				l.end(source, true, time.Now())
			}
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > maxConcurrentLogins {
		t.Fatalf("observed %d concurrent admitted attempts, cap is %d", p, maxConcurrentLogins)
	}
}

// One source hammering failures throttles only itself: the operator
// on a different IP still gets through. Regression for the global
// throttle that let any client hold the login at 429 indefinitely.
func TestLoginLimiter_FailuresScopedPerSource(t *testing.T) {
	var l loginLimiter
	now := time.Now()
	attacker, operator := "203.0.113.7", "10.0.0.5"
	for range loginFailureThreshold {
		if v := l.begin(attacker, now); v != loginProceed {
			t.Fatalf("attacker pre-threshold begin = %v, want proceed", v)
		}
		l.end(attacker, false, now)
	}
	if v := l.begin(attacker, now); v != loginThrottled {
		t.Fatalf("attacker post-threshold begin = %v, want throttled", v)
	}
	if v := l.begin(operator, now); v != loginProceed {
		t.Fatalf("operator begin while attacker throttled = %v, want proceed", v)
	}
	l.end(operator, true, now)
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
		l.end(source, false, now)
		now = now.Add(time.Millisecond)
	}
	l.mu.Lock()
	n := len(l.sources)
	l.mu.Unlock()
	if n > maxTrackedLoginSources {
		t.Fatalf("tracked sources = %d, want ≤ %d", n, maxTrackedLoginSources)
	}
}

func TestLoginSourceKey(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/login", nil)
	r.RemoteAddr = "192.0.2.9:4242"
	if k := loginSourceKey(r); k != "192.0.2.9" {
		t.Fatalf("loginSourceKey = %q, want 192.0.2.9", k)
	}
	r.RemoteAddr = "not-a-hostport"
	if k := loginSourceKey(r); k != "not-a-hostport" {
		t.Fatalf("loginSourceKey fallback = %q, want raw value", k)
	}
}
