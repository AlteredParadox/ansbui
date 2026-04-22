package api

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/geoip"
)

// geoResolver is the server's geoip helper — one client + a DNS cache
// local to it so repeated inventory requests don't re-resolve every
// FQDN on every reload.
type geoResolver struct {
	client *geoip.Client
	dnsMu  sync.Mutex
	dns    map[string]dnsCacheEntry2
}

type dnsCacheEntry2 struct {
	ip     string
	expiry time.Time
}

func newGeoResolver() *geoResolver {
	return &geoResolver{
		client: geoip.NewClient(),
		dns:    map[string]dnsCacheEntry2{},
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
// Hosts whose candidates are all private are left untouched.
func (g *geoResolver) enrichInventory(ctx context.Context, inv *ansible.Inventory) {
	for i := range inv.Hosts {
		h := &inv.Hosts[i]
		if h.Region != "" {
			continue
		}
		target := g.pickPublicIP(ctx, *h)
		if target == "" {
			continue
		}
		res, err := g.client.Lookup(ctx, target)
		if err != nil || res.Label == "" {
			continue
		}
		h.Region = res.Label
	}
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
	g.dnsMu.Lock()
	if e, ok := g.dns[name]; ok && time.Now().Before(e.expiry) {
		g.dnsMu.Unlock()
		return e.ip
	}
	g.dnsMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	pub := ""
	if err == nil {
		for _, a := range addrs {
			if geoip.IsPublic(a.IP) {
				pub = a.IP.String()
				break
			}
		}
	}
	g.dnsMu.Lock()
	g.dns[name] = dnsCacheEntry2{ip: pub, expiry: time.Now().Add(24 * time.Hour)}
	g.dnsMu.Unlock()
	return pub
}
