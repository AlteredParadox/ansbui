// Package prom queries Prometheus for live host metrics (CPU, memory,
// load, uptime, OS) and returns them keyed by hostname so the UI can
// merge them with the inventory snapshot from ansible.
//
// The queries assume a node_exporter scrape with the host label matching
// the ansible inventory hostname (by default the `instance` label, with
// `:9100` port suffixes stripped). The label is configurable via the
// settings dialog.
package prom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HostMetric is the merged sample for a single host.
type HostMetric struct {
	Host   string  `json:"host"`
	CPU    int     `json:"cpu"`
	Mem    int     `json:"mem"`
	Load   float64 `json:"load"`
	Uptime int     `json:"uptime"`
	OS     string  `json:"os,omitempty"`
	Up     bool    `json:"up"`
}

// Client queries a single Prometheus instance.
type Client struct {
	base  string
	label string
	http  *http.Client
}

// promLabelRE matches the Prometheus label-name grammar. Defined
// here too (mirrored from internal/config) so prom.NewClient is
// self-contained and can fail closed without depending on the
// settings layer to have validated.
var promLabelRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// NewClient constructs a Client. baseURL is the Prometheus root (e.g.
// http://prom:9090). hostLabel is the label name to key on (default
// "instance"). Only http / https URLs are accepted; redirects are
// disabled to prevent a misconfigured Prometheus from bouncing us at
// a cloud metadata endpoint.
func NewClient(baseURL, hostLabel string) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("prometheus URL is empty")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid prometheus URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("prometheus URL scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("prometheus URL is missing a host")
	}
	if hostLabel == "" {
		hostLabel = "instance"
	}
	// Defensive: c.label is interpolated directly into the `avg by
	// (...)` expression below. The settings setter already enforces
	// this grammar, but an on-disk config edited by hand could still
	// contain something hostile — fail closed at construction.
	if !promLabelRE.MatchString(hostLabel) {
		return nil, fmt.Errorf("prometheus label %q must match [a-zA-Z_][a-zA-Z0-9_]*", hostLabel)
	}
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		label: hostLabel,
		http: &http.Client{
			Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// ProbeResult captures per-query diagnostics so the UI can show the
// operator which parts of the Prometheus integration are working and
// which are silently failing.
type ProbeResult struct {
	Name    string `json:"name"`
	Query   string `json:"query"`
	Samples int    `json:"samples"`
	Error   string `json:"error,omitempty"`
}

// MetricsResult bundles the merged host map with per-probe diagnostics.
type MetricsResult struct {
	Metrics map[string]HostMetric `json:"metrics"`
	Probes  []ProbeResult         `json:"probes"`
}

// Metrics issues the node_exporter queries and returns a map keyed by
// host. Per-probe errors are captured into the result's Probes slice so
// the caller can surface them rather than silently showing zero. All
// probes fire in parallel so the whole call completes in the slowest
// single probe's time, not the sum of them.
func (c *Client) Metrics(ctx context.Context) (MetricsResult, error) {
	type probe struct {
		name  string
		query string
		apply func(host string, value float64, m *HostMetric)
	}
	defs := []probe{
		{
			name:  "cpu",
			query: `100 - (avg by (` + c.label + `) (rate(node_cpu_seconds_total{mode="idle"}[1m])) * 100)`,
			apply: func(_ string, v float64, m *HostMetric) { m.CPU = clampPercent(v) },
		},
		{
			name:  "mem",
			query: `(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100`,
			apply: func(_ string, v float64, m *HostMetric) { m.Mem = clampPercent(v) },
		},
		{
			name:  "load",
			query: `node_load1`,
			apply: func(_ string, v float64, m *HostMetric) { m.Load = round2(v) },
		},
		{
			name:  "uptime",
			query: `(time() - node_boot_time_seconds) / 86400`,
			apply: func(_ string, v float64, m *HostMetric) { m.Uptime = int(v) },
		},
		{
			name:  "up",
			query: `up`,
			apply: func(_ string, v float64, m *HostMetric) { m.Up = v > 0 },
		},
	}

	type valueResult struct {
		idx     int
		samples map[string]float64
		err     error
	}

	valueProbes := make([]ProbeResult, len(defs))
	results := make(chan valueResult, len(defs))
	for i, p := range defs {
		valueProbes[i] = ProbeResult{Name: p.name, Query: p.query}
		go func(i int, q string) {
			s, err := c.instantQuery(ctx, q)
			results <- valueResult{idx: i, samples: s, err: err}
		}(i, p.query)
	}

	type labelResult struct {
		labels map[string]map[string]string
		err    error
	}
	const unameQuery = "node_uname_info"
	unameCh := make(chan labelResult, 1)
	go func() {
		l, err := c.instantLabels(ctx, unameQuery)
		unameCh <- labelResult{labels: l, err: err}
	}()

	out := make(map[string]HostMetric)
	var mu sync.Mutex
	apply := func(host string, p probe, v float64) {
		mu.Lock()
		defer mu.Unlock()
		m := out[host]
		m.Host = host
		p.apply(host, v, &m)
		out[host] = m
	}

	for i := 0; i < len(defs); i++ {
		r := <-results
		pr := &valueProbes[r.idx]
		if r.err != nil {
			pr.Error = r.err.Error()
			continue
		}
		pr.Samples = len(r.samples)
		for host, value := range r.samples {
			apply(host, defs[r.idx], value)
		}
	}

	ur := <-unameCh
	unamePR := ProbeResult{Name: "os", Query: unameQuery}
	if ur.err != nil {
		unamePR.Error = ur.err.Error()
	} else {
		unamePR.Samples = len(ur.labels)
		mu.Lock()
		for host, lbls := range ur.labels {
			m := out[host]
			m.Host = host
			m.OS = strings.TrimSpace(lbls["sysname"] + " " + lbls["release"])
			out[host] = m
		}
		mu.Unlock()
	}

	probes := make([]ProbeResult, 0, len(defs)+1)
	probes = append(probes, valueProbes...)
	probes = append(probes, unamePR)
	return MetricsResult{Metrics: out, Probes: probes}, nil
}

type promResp struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]any            `json:"value"`
		} `json:"result"`
	} `json:"data"`
	Error string `json:"error,omitempty"`
}

func (c *Client) instantQuery(ctx context.Context, q string) (map[string]float64, error) {
	resp, err := c.fetch(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make(map[string]float64, len(resp.Data.Result))
	for _, row := range resp.Data.Result {
		host := hostFromLabel(row.Metric, c.label)
		if host == "" {
			continue
		}
		raw, ok := row.Value[1].(string)
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			continue
		}
		out[host] = v
	}
	return out, nil
}

func (c *Client) instantLabels(ctx context.Context, q string) (map[string]map[string]string, error) {
	resp, err := c.fetch(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string]string, len(resp.Data.Result))
	for _, row := range resp.Data.Result {
		host := hostFromLabel(row.Metric, c.label)
		if host == "" {
			continue
		}
		out[host] = row.Metric
	}
	return out, nil
}

func (c *Client) fetch(ctx context.Context, q string) (*promResp, error) {
	u := fmt.Sprintf("%s/api/v1/query?query=%s", c.base, url.QueryEscape(q))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	r, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus request: %w", err)
	}
	defer r.Body.Close()
	if r.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 512))
		return nil, fmt.Errorf("prometheus %d: %s", r.StatusCode, strings.TrimSpace(string(body)))
	}
	var pr promResp
	if err := json.NewDecoder(r.Body).Decode(&pr); err != nil {
		return nil, fmt.Errorf("decode prometheus response: %w", err)
	}
	if pr.Status != "success" {
		return nil, fmt.Errorf("prometheus error: %s", pr.Error)
	}
	return &pr, nil
}

// hostFromLabel extracts the host portion of the configured label,
// stripping the `:port` suffix commonly seen on node_exporter scrapes.
// net.SplitHostPort handles bracketed IPv6 ("[2001:db8::1]:9100");
// the old strip-at-first-colon mangled those to "[2001", colliding
// every v6 host onto one key so hosts silently overwrote each other.
func hostFromLabel(labels map[string]string, key string) string {
	raw := labels[key]
	if raw == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return h
	}
	// No parseable port: a bare hostname, a bare IPv6 literal (colons
	// but no port), or a bracketed literal without a port — return the
	// address itself, brackets trimmed.
	return strings.Trim(raw, "[]")
}

func clampPercent(v float64) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return int(v + 0.5)
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}
