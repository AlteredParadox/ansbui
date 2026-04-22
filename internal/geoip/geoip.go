// Package geoip looks up the rough geographic location of a public
// IP address via ipinfo.io and caches the result in-process.
//
// Only public (non-RFC1918, non-CGNAT, non-loopback) IPs are sent to
// the upstream; calls against private addresses return an error
// early without making a network request.
package geoip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// Result is what the UI ends up consuming. Label is a pre-formatted
// short string suitable for a column ("City, CC" or just "CC").
type Result struct {
	IP      string `json:"ip"`
	City    string `json:"city,omitempty"`
	Region  string `json:"region,omitempty"`  // state / province
	Country string `json:"country,omitempty"` // ISO-3166 alpha-2
	Label   string `json:"label,omitempty"`
}

// Client is safe for concurrent use. The cache lives for the process
// lifetime; a 24h TTL keeps things fresh enough without hammering
// the upstream on every inventory reload.
type Client struct {
	http     *http.Client
	mu       sync.Mutex
	cache    map[string]cacheEntry
	ttl      time.Duration
	endpoint string
}

type cacheEntry struct {
	result Result
	err    error
	expiry time.Time
}

// NewClient returns a client pointing at ipinfo.io. The endpoint is
// configurable via WithEndpoint if a future caller wants to swap to
// a self-hosted geoip service.
func NewClient() *Client {
	return &Client{
		http:     &http.Client{Timeout: 5 * time.Second},
		cache:    map[string]cacheEntry{},
		ttl:      24 * time.Hour,
		endpoint: "https://ipinfo.io",
	}
}

// Lookup returns the cached Result for ip, querying upstream on a
// miss. A nil Result + error is returned for private / loopback /
// CGNAT addresses; callers can ignore those errors and move on.
func (c *Client) Lookup(ctx context.Context, ip string) (Result, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Result{}, fmt.Errorf("%q is not a valid IP", ip)
	}
	if !IsPublic(parsed) {
		return Result{}, errors.New("private / reserved address, not looked up")
	}
	if cached, ok := c.get(ip); ok {
		return cached.result, cached.err
	}
	result, err := c.fetch(ctx, ip)
	c.set(ip, cacheEntry{result: result, err: err, expiry: time.Now().Add(c.ttl)})
	return result, err
}

func (c *Client) get(ip string) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[ip]
	if !ok || time.Now().After(e.expiry) {
		return cacheEntry{}, false
	}
	return e, true
}

func (c *Client) set(ip string, e cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[ip] = e
}

type ipinfoResponse struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Bogon    bool   `json:"bogon,omitempty"`
}

func (c *Client) fetch(ctx context.Context, ip string) (Result, error) {
	url := fmt.Sprintf("%s/%s/json", c.endpoint, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("ipinfo: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return Result{}, fmt.Errorf("ipinfo %d", res.StatusCode)
	}
	var body ipinfoResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return Result{}, fmt.Errorf("decode ipinfo: %w", err)
	}
	if body.Bogon {
		return Result{}, errors.New("ipinfo flagged this address as bogon")
	}
	return Result{
		IP:      body.IP,
		City:    body.City,
		Region:  body.Region,
		Country: body.Country,
		Label:   formatLabel(body),
	}, nil
}

func formatLabel(r ipinfoResponse) string {
	if r.City != "" && r.Country != "" {
		return r.City + ", " + r.Country
	}
	if r.Country != "" {
		return r.Country
	}
	if r.Region != "" {
		return r.Region
	}
	return ""
}

// IsPublic reports whether ip is globally routable — i.e. not
// loopback, not RFC1918, not CGNAT, not link-local, not unspecified.
// CGNAT (100.64.0.0/10, fc00::/7-style equivalents) matters for
// Tailscale / Netbird fleets where ansible_host is a mesh IP but
// the public FQDN resolves to a real address.
func IsPublic(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsPrivate() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return false
	}
	return true
}
