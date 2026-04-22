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
	"net/http"
	"net/url"
	"strings"
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
	base      string
	label     string
	http      *http.Client
}

// NewClient constructs a Client. baseURL is the Prometheus root (e.g.
// http://prom:9090). hostLabel is the label name to key on (default
// "instance").
func NewClient(baseURL, hostLabel string) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("prometheus URL is empty")
	}
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("invalid prometheus URL: %w", err)
	}
	if hostLabel == "" {
		hostLabel = "instance"
	}
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		label: hostLabel,
		http:  &http.Client{Timeout: 8 * time.Second},
	}, nil
}

// Metrics issues the node_exporter queries and returns a map keyed by
// host. Missing / errored queries don't abort the batch — they just
// leave the corresponding field at zero.
func (c *Client) Metrics(ctx context.Context) (map[string]HostMetric, error) {
	out := make(map[string]HostMetric)

	type probe struct {
		query string
		apply func(host string, value float64, m *HostMetric)
	}
	probes := []probe{
		{
			query: `100 - (avg by (` + c.label + `) (rate(node_cpu_seconds_total{mode="idle"}[1m])) * 100)`,
			apply: func(_ string, v float64, m *HostMetric) { m.CPU = clampPercent(v) },
		},
		{
			query: `(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100`,
			apply: func(_ string, v float64, m *HostMetric) { m.Mem = clampPercent(v) },
		},
		{
			query: `node_load1`,
			apply: func(_ string, v float64, m *HostMetric) { m.Load = round2(v) },
		},
		{
			query: `(time() - node_boot_time_seconds) / 86400`,
			apply: func(_ string, v float64, m *HostMetric) { m.Uptime = int(v) },
		},
		{
			query: `up`,
			apply: func(_ string, v float64, m *HostMetric) { m.Up = v > 0 },
		},
	}

	for _, p := range probes {
		samples, err := c.instantQuery(ctx, p.query)
		if err != nil {
			continue
		}
		for host, value := range samples {
			m := out[host]
			m.Host = host
			p.apply(host, value, &m)
			out[host] = m
		}
	}

	// OS info comes from node_uname_info labels rather than a value.
	if labels, err := c.instantLabels(ctx, `node_uname_info`); err == nil {
		for host, lbls := range labels {
			m := out[host]
			m.Host = host
			m.OS = strings.TrimSpace(lbls["nodename"] + " " + lbls["release"])
			if id, ok := lbls["release"]; ok && id != "" {
				m.OS = lbls["sysname"] + " " + id
			}
			out[host] = m
		}
	}
	return out, nil
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
		var v float64
		if _, err := fmt.Sscanf(raw, "%f", &v); err != nil {
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
func hostFromLabel(labels map[string]string, key string) string {
	raw := labels[key]
	if raw == "" {
		return ""
	}
	if idx := strings.IndexByte(raw, ':'); idx > 0 {
		raw = raw[:idx]
	}
	return raw
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
