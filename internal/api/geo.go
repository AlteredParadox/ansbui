package api

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/geoip"
	"github.com/AlteredParadox/ansbui/internal/ttlcache"
)

// maxDNSCacheEntries bounds the hostname cache. Its keys are
// inventory hostnames, i.e. control-node-supplied, and it used to be
// an unbounded map that never removed expired entries — so a
// malfunctioning or hostile control node could grow it for the
// process lifetime by rotating names across inventory requests,
// failed resolutions included.
const maxDNSCacheEntries = 4096

// Bounds on one enrichment pass. maxConcurrent caps how much work is
// in flight; maxEnrichHosts and enrichBudget cap how much there is in
// total. Concurrency alone bounded neither the number of lookups a
// single inventory could trigger nor how long the handler stayed
// parked doing them, so a large inventory could hold a request open
// for as long as the client kept the connection — the server sets no
// WriteTimeout by design — while fanning out DNS and ipinfo traffic.
// Enrichment is cosmetic (a Region column), so exceeding either bound
// degrades to un-enriched hosts rather than failing the request.
const (
	maxConcurrentLookups = 8
	maxEnrichHosts       = 512
	enrichBudget         = 20 * time.Second
)

// geoResolver is the server's geoip helper — one client + a DNS cache
// local to it so repeated inventory requests don't re-resolve every
// FQDN on every reload.
type geoResolver struct {
	client *geoip.Client
	dns    *ttlcache.Cache[string]
}

func newGeoResolver() *geoResolver {
	return &geoResolver{
		client: geoip.NewClient(),
		dns:    ttlcache.New[string](maxDNSCacheEntries),
	}
}

// enrichInventory fills in each host's Region from an ipinfo.io
// lookup. Only runs when the server-side setting is on. Priority of
// candidate IPs per host:
//
//  1. h.IP (ansible_host) if it's a public address
//  2. otherwise, resolve h.Name via DNS and pick the first public
//     answer — this is the common path for Tailscale / Netbird
//     fleets where ansible_host is the mesh address
//
// Hosts whose candidates are all private are left untouched. Lookups
// fan out with a small concurrency cap so a large inventory doesn't
// open hundreds of simultaneous ipinfo.io requests.
// Enrichment is best-effort and bounded twice over: at most
// maxEnrichHosts hosts are attempted, and the whole pass shares
// enrichBudget. Hosts past either bound keep an empty Region, which
// is what they'd have had if the lookup failed.
func (g *geoResolver) enrichInventory(ctx context.Context, inv *ansible.Inventory) {
	ctx, cancel := context.WithTimeout(ctx, enrichBudget)
	defer cancel()

	sem := make(chan struct{}, maxConcurrentLookups)
	var wg sync.WaitGroup
	attempted := 0
	for i := range inv.Hosts {
		h := &inv.Hosts[i]
		if h.Region != "" {
			continue
		}
		if attempted >= maxEnrichHosts {
			break
		}
		attempted++
		// Acquiring the slot before spawning is what paced the loop
		// before, so it also has to observe the budget — otherwise a
		// large inventory would keep queueing work here long after
		// the deadline had passed.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func(h *ansible.Host) {
			defer wg.Done()
			defer func() { <-sem }()
			target := g.pickPublicIP(ctx, *h)
			if target == "" {
				return
			}
			res, err := g.client.Lookup(ctx, target)
			if err != nil || res.Label == "" {
				return
			}
			h.Region = res.Label
		}(h)
	}
	wg.Wait()
}

// pickPublicIP decides which address, if any, to geolocate for host.
// Returns "" when everything available is private.
func (g *geoResolver) pickPublicIP(ctx context.Context, h ansible.Host) string {
	if ip := net.ParseIP(h.IP); ip != nil && geoip.IsPublic(ip) {
		return h.IP
	}
	// h.IP is missing or private — try resolving h.Name.
	name := h.Name
	if name == "" {
		return ""
	}
	if resolved := g.resolvePublic(ctx, name); resolved != "" {
		return resolved
	}
	return ""
}

// resolvePublic is a tiny cached wrapper over net.DefaultResolver.
// Returns the first public IP for name, or "" if none resolves.
// Cache TTL mirrors the geoip cache so a reloaded inventory doesn't
// keep hitting DNS for the same names.
func (g *geoResolver) resolvePublic(ctx context.Context, name string) string {
	if ip, ok := g.dns.Get(name); ok {
		return ip
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	// TTL selection: an authoritative NXDOMAIN and a successful lookup
	// are durable verdicts worth the full 24h. A transient failure
	// (timeout, SERVFAIL, the browser aborting the inventory request
	// mid-enrichment) gets a short negative TTL instead — long enough
	// that a struggling resolver isn't hammered with a fresh 2s lookup
	// on every host on every inventory render, short enough that the
	// column recovers quickly once DNS is healthy again. Not caching
	// at all would reinstate the N×2s-per-render stall.
	ttl := 24 * time.Hour
	if err != nil && !isNXDomain(err) {
		ttl = transientDNSTTL
	}
	pub := ""
	for _, a := range addrs {
		if geoip.IsPublic(a.IP) {
			pub = a.IP.String()
			break
		}
	}
	g.dns.Set(name, pub, ttl)
	return pub
}

// transientDNSTTL bounds how long a transient resolver failure is
// negatively cached. Mirrors geoip.transientErrTTL's intent.
const transientDNSTTL = 30 * time.Second

// isNXDomain reports whether err is an authoritative "name does not
// exist" — a verdict worth caching, unlike transient lookup failures.
func isNXDomain(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
