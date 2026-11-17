// Package ttlcache provides a small bounded, TTL-expiring, in-memory
// cache shared by the inventory-enrichment paths.
//
// It exists because both enrichment caches — the GeoIP result cache
// and the DNS resolution cache — were plain maps that grew for the
// process lifetime. Expiry only decided whether an entry could be
// *reused*; nothing ever removed one, and neither map had a size
// bound. Inventory content is supplied by the control node, so a
// hostile or malfunctioning one could rotate unique addresses and
// hostnames across repeated inventory requests and grow those maps
// without limit, failed lookups included.
//
// Both properties are needed, not just expiry sweeping: without a
// hard cap, a burst of unique keys inside one TTL window still grows
// unbounded.
package ttlcache

import (
	"sync"
	"time"
)

// Cache is a concurrency-safe map from string keys to V with a
// per-entry TTL and a hard capacity. The zero value is not usable;
// call New.
type Cache[V any] struct {
	mu      sync.Mutex
	max     int
	entries map[string]entry[V]

	// now is swappable so tests can advance time without sleeping.
	now func() time.Time
}

type entry[V any] struct {
	val    V
	expiry time.Time
}

// New returns a cache holding at most capacity entries. A capacity
// below 1 is treated as 1 so a misconfigured caller still gets a
// bounded cache rather than one that evicts on every insert or grows
// forever.
func New[V any](capacity int) *Cache[V] {
	if capacity < 1 {
		capacity = 1
	}
	return &Cache[V]{
		max:     capacity,
		entries: make(map[string]entry[V]),
		now:     time.Now,
	}
}

// Get returns the live value for key. An entry past its TTL is
// deleted rather than merely reported as a miss, so a key that is
// never looked up again does not occupy space forever.
func (c *Cache[V]) Get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	if !c.now().Before(e.expiry) {
		delete(c.entries, key)
		var zero V
		return zero, false
	}
	return e.val, true
}

// Set stores val under key for ttl. When the cache is full it first
// drops everything already expired; if that frees nothing, it evicts
// the entry closest to expiring. TTLs are uniform per call site, so
// that approximates FIFO — good enough for caches whose job is to
// absorb repeat lookups within one page render, and far cheaper than
// the bookkeeping true LRU would need.
func (c *Cache[V]) Set(key string, val V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if _, replacing := c.entries[key]; !replacing && len(c.entries) >= c.max {
		c.evictLocked(now)
	}
	c.entries[key] = entry[V]{val: val, expiry: now.Add(ttl)}
}

// evictLocked makes room for one insert. Caller holds c.mu.
func (c *Cache[V]) evictLocked(now time.Time) {
	for k, e := range c.entries {
		if !now.Before(e.expiry) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < c.max {
		return
	}
	// Still full: every entry is live, so drop the one expiring
	// soonest. One O(n) scan, and only on inserts into a full cache.
	var oldestKey string
	var oldest time.Time
	first := true
	for k, e := range c.entries {
		if first || e.expiry.Before(oldest) {
			oldestKey, oldest, first = k, e.expiry, false
		}
	}
	if !first {
		delete(c.entries, oldestKey)
	}
}

// Len reports the number of entries currently held, expired ones
// included (they are removed lazily on access and on eviction).
// Intended for tests and metrics.
func (c *Cache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
