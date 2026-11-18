// ansbui — a single-binary web UI for an Ansible control node.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package ttlcache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// withClock swaps in a controllable clock so TTL behaviour can be
// tested without sleeping.
func withClock[V any](c *Cache[V], t *time.Time) {
	c.now = func() time.Time { return *t }
}

func TestGetSetAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := New[string](10)
	withClock(c, &now)

	c.Set("a", "value", time.Minute)
	if got, ok := c.Get("a"); !ok || got != "value" {
		t.Fatalf("Get(a) = %q, %v; want value, true", got, ok)
	}

	// Still live one tick before expiry.
	now = now.Add(time.Minute - time.Nanosecond)
	if _, ok := c.Get("a"); !ok {
		t.Fatal("entry expired early")
	}

	// At expiry it is gone AND removed, not just reported as a miss —
	// the whole point of the change: expired entries used to linger
	// for the process lifetime.
	now = now.Add(time.Nanosecond)
	if _, ok := c.Get("a"); ok {
		t.Fatal("expired entry still served")
	}
	if n := c.Len(); n != 0 {
		t.Fatalf("expired entry retained: Len = %d, want 0", n)
	}
}

// TestCapacityIsHard is the bound that matters: a hostile inventory
// rotating unique keys must not grow the cache without limit, even
// while every entry is still within its TTL.
func TestCapacityIsHard(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const max = 32
	c := New[int](max)
	withClock(c, &now)

	for i := 0; i < max*20; i++ {
		c.Set(fmt.Sprintf("key-%d", i), i, time.Hour) // all live, none expired
		if n := c.Len(); n > max {
			t.Fatalf("cache exceeded its bound after %d inserts: Len = %d, want <= %d", i+1, n, max)
		}
	}
	if n := c.Len(); n != max {
		t.Fatalf("Len = %d, want the cache to stay full at %d", n, max)
	}
}

// Expired entries should be reclaimed in preference to live ones, so
// a cache churning through short-lived failures doesn't evict the
// successful lookups it is meant to be holding.
func TestEvictionPrefersExpiredEntries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := New[string](4)
	withClock(c, &now)

	c.Set("keep", "live", time.Hour)
	for i := 0; i < 3; i++ {
		c.Set(fmt.Sprintf("transient-%d", i), "short", 30*time.Second)
	}
	now = now.Add(time.Minute) // the three transients are now expired

	c.Set("fresh", "live", time.Hour)
	if _, ok := c.Get("keep"); !ok {
		t.Error("a live entry was evicted while expired ones were available")
	}
	if _, ok := c.Get("fresh"); !ok {
		t.Error("newly inserted entry missing")
	}
}

// Overwriting an existing key must not count as growth, or a hot key
// refreshed in a full cache would evict a different entry each time.
func TestReplaceDoesNotEvict(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := New[int](2)
	withClock(c, &now)

	c.Set("a", 1, time.Hour)
	c.Set("b", 2, time.Hour)
	c.Set("a", 99, time.Hour)

	if n := c.Len(); n != 2 {
		t.Fatalf("Len = %d, want 2", n)
	}
	if got, ok := c.Get("a"); !ok || got != 99 {
		t.Errorf("Get(a) = %d, %v; want 99, true", got, ok)
	}
	if _, ok := c.Get("b"); !ok {
		t.Error("b evicted by an in-place replacement of a")
	}
}

func TestMaxBelowOneIsClamped(t *testing.T) {
	c := New[int](0)
	c.Set("a", 1, time.Hour)
	if _, ok := c.Get("a"); !ok {
		t.Fatal("clamped cache stored nothing")
	}
	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1", c.Len())
	}
}

// The caches are shared by the concurrent enrichment fan-out, so
// concurrent access has to be safe. Run with -race to be meaningful.
func TestConcurrentAccess(t *testing.T) {
	c := New[int](64)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				k := fmt.Sprintf("key-%d", j%128)
				c.Set(k, j, time.Minute)
				c.Get(k)
			}
		}()
	}
	wg.Wait()
	if n := c.Len(); n > 64 {
		t.Fatalf("bound violated under concurrency: Len = %d", n)
	}
}
