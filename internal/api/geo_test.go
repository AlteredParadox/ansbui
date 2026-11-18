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

package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/geoip"
)

// newTestResolver builds a resolver pointed at a stub ipinfo that
// counts requests, so a test can assert how much outbound work one
// enrichment pass is allowed to generate.
func newTestResolver(t *testing.T, hits *atomic.Int64) *geoResolver {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ip":"203.0.113.9","city":"Testville","country":"NL"}`)
	}))
	t.Cleanup(srv.Close)
	g := newGeoResolver()
	g.client = geoip.NewClient().WithEndpoint(srv.URL)
	return g
}

// publicHosts builds n hosts each with a distinct public ansible_host,
// so every one is a fresh cache key and a fresh lookup.
func publicHosts(n int) []ansible.Host {
	hosts := make([]ansible.Host, n)
	for i := range hosts {
		// 198.51.100.0/24 and 203.0.113.0/24 are TEST-NET ranges and
		// count as public, which is what pickPublicIP checks.
		hosts[i] = ansible.Host{
			Name: fmt.Sprintf("host-%d.example.com", i),
			IP:   fmt.Sprintf("198.51.%d.%d", i/256, i%256),
		}
	}
	return hosts
}

// TestEnrichInventoryCapsHostCount is the bound that stops a hostile
// or malfunctioning control node from turning one inventory request
// into unbounded outbound work. Concurrency was capped before, but
// the total number of lookups was not.
func TestEnrichInventoryCapsHostCount(t *testing.T) {
	var hits atomic.Int64
	g := newTestResolver(t, &hits)

	inv := &ansible.Inventory{Hosts: publicHosts(maxEnrichHosts * 3)}
	g.enrichInventory(context.Background(), inv)

	if got := hits.Load(); got > int64(maxEnrichHosts) {
		t.Errorf("made %d upstream lookups for %d hosts, want at most %d",
			got, len(inv.Hosts), maxEnrichHosts)
	}

	// Hosts beyond the cap are simply left un-enriched — the column is
	// cosmetic, so degrading beats failing the inventory request.
	enriched := 0
	for _, h := range inv.Hosts {
		if h.Region != "" {
			enriched++
		}
	}
	if enriched > maxEnrichHosts {
		t.Errorf("enriched %d hosts, want at most %d", enriched, maxEnrichHosts)
	}
	if enriched == 0 {
		t.Error("no hosts enriched at all — the cap is not the only thing being tested")
	}
}

// A cancelled request must stop the pass promptly rather than
// continuing to spend DNS and ipinfo calls on a response nobody will
// read.
func TestEnrichInventoryStopsOnCancel(t *testing.T) {
	var hits atomic.Int64
	g := newTestResolver(t, &hits)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	inv := &ansible.Inventory{Hosts: publicHosts(200)}
	done := make(chan struct{})
	go func() {
		g.enrichInventory(ctx, inv)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("enrichInventory ignored a cancelled context")
	}
}

// Hosts that already carry a Region (from the inventory itself) are
// skipped, so a re-render costs nothing.
func TestEnrichInventorySkipsPopulatedRegions(t *testing.T) {
	var hits atomic.Int64
	g := newTestResolver(t, &hits)

	inv := &ansible.Inventory{Hosts: publicHosts(5)}
	for i := range inv.Hosts {
		inv.Hosts[i].Region = "preset"
	}
	g.enrichInventory(context.Background(), inv)

	if got := hits.Load(); got != 0 {
		t.Errorf("made %d lookups for already-populated hosts, want 0", got)
	}
}

// The DNS cache must stay bounded no matter how many distinct
// hostnames the control node feeds it.
func TestDNSCacheIsBounded(t *testing.T) {
	g := newGeoResolver()
	for i := 0; i < maxDNSCacheEntries*2; i++ {
		g.dns.Set(fmt.Sprintf("host-%d.invalid", i), "", time.Hour)
	}
	if n := g.dns.Len(); n > maxDNSCacheEntries {
		t.Fatalf("DNS cache grew to %d entries, want at most %d", n, maxDNSCacheEntries)
	}
}
