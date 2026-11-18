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
	"strings"
	"time"

	"github.com/AlteredParadox/ansbui/internal/ttlcache"
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

// maxCacheEntries bounds the result cache. Keys are public IPs drawn
// from control-node inventory, so the key space is attacker-
// influenced: the cache used to be an unbounded map that never
// deleted expired entries, which let a hostile or malfunctioning
// control node grow it for the process lifetime by rotating
// addresses across inventory requests (failed lookups included).
// A few thousand entries covers any realistic fleet.
const maxCacheEntries = 4096

// Client is safe for concurrent use. Results are cached with a 24h
// TTL — fresh enough without hammering the upstream on every
// inventory reload — in a bounded cache that evicts on expiry and on
// capacity.
type Client struct {
	http     *http.Client
	cache    *ttlcache.Cache[cacheEntry]
	ttl      time.Duration
	endpoint string
}

type cacheEntry struct {
	result Result
	err    error
}

// NewClient returns a client pointing at ipinfo.io. The endpoint is
// configurable via WithEndpoint if a future caller wants to swap to
// a self-hosted geoip service.
func NewClient() *Client {
	return &Client{
		http:     &http.Client{Timeout: 5 * time.Second},
		cache:    ttlcache.New[cacheEntry](maxCacheEntries),
		ttl:      24 * time.Hour,
		endpoint: "https://ipinfo.io",
	}
}

// WithEndpoint points the client at a different geoip service —
// a self-hosted one, or a stub in tests. The trailing slash is
// trimmed so callers can pass either form.
func (c *Client) WithEndpoint(endpoint string) *Client {
	c.endpoint = strings.TrimRight(endpoint, "/")
	return c
}

// transientErrTTL is how long a transient failure (context
// cancellation, network error, upstream 5xx / rate limit) stays
// cached. Long enough that a burst of inventory reloads doesn't
// hammer a struggling upstream, short enough that one aborted
// browser request can't blank a host's Region column for a day.
const transientErrTTL = 30 * time.Second

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
	c.set(ip, cacheEntry{result: result, err: err}, c.entryTTL(err))
	return result, err
}

// entryTTL picks the cache lifetime for a fetch outcome. Successes
// and permanent verdicts (bogon, 4xx other than timeout/rate-limit)
// keep the full TTL; everything else — including the context
// cancellation from a browser aborting the inventory request
// mid-enrichment — is transient and must not poison the cache.
func (c *Client) entryTTL(err error) time.Duration {
	if err == nil || errors.Is(err, errBogon) {
		return c.ttl
	}
	var status statusError
	if errors.As(err, &status) &&
		status != http.StatusRequestTimeout && status != http.StatusTooManyRequests &&
		status < http.StatusInternalServerError {
		return c.ttl
	}
	return transientErrTTL
}

func (c *Client) get(ip string) (cacheEntry, bool) {
	return c.cache.Get(ip)
}

func (c *Client) set(ip string, e cacheEntry, ttl time.Duration) {
	c.cache.Set(ip, e, ttl)
}

type ipinfoResponse struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Bogon   bool   `json:"bogon,omitempty"`
}

// errBogon and statusError are sentinel / typed errors so entryTTL
// can tell permanent verdicts apart from transient failures.
var errBogon = errors.New("ipinfo flagged this address as bogon")

type statusError int

func (s statusError) Error() string { return fmt.Sprintf("ipinfo %d", int(s)) }

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
		return Result{}, statusError(res.StatusCode)
	}
	var body ipinfoResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return Result{}, fmt.Errorf("decode ipinfo: %w", err)
	}
	if body.Bogon {
		return Result{}, errBogon
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
