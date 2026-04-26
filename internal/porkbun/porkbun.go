// Package porkbun is a thin HTTP client for the subset of Porkbun's
// JSON DNS API that the provisioning flow needs: look up an existing
// A record for a hostname, and create a new one when it doesn't
// exist. Auth uses Porkbun's body-embedded `apikey`+`secretapikey`
// pair on every request — there's no header-based form.
package porkbun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Endpoint is the v3 JSON API base. Exposed as a var so tests can
// point at a local httptest server without monkey-patching net/http.
var Endpoint = "https://api.porkbun.com/api/json/v3"

// Client carries the credential pair plus a bounded http.Client.
type Client struct {
	apiKey    string
	secretKey string
	http      *http.Client
}

// New builds a Client with a 15-second per-request timeout — porkbun
// is responsive in practice and a stuck request shouldn't hold up
// a provisioning run.
func New(apiKey, secretKey string) *Client {
	return &Client{
		apiKey:    apiKey,
		secretKey: secretKey,
		http:      &http.Client{Timeout: 15 * time.Second},
	}
}

// Record is the per-record shape Porkbun returns from retrieve calls.
// Only the fields the orchestrator inspects are decoded.
type Record struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     string `json:"ttl"`
}

// FindARecord returns the first A record matching the given
// (domain, subdomain) tuple, or (nil, nil) if no record exists.
// `subdomain` is the prefix below the registered domain — pass ""
// to look up the apex.
func (c *Client) FindARecord(ctx context.Context, domain, subdomain string) (*Record, error) {
	path := fmt.Sprintf("/dns/retrieveByNameType/%s/A", domain)
	if subdomain != "" {
		path += "/" + subdomain
	}
	body, err := c.post(ctx, path, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Status  string   `json:"status"`
		Message string   `json:"message"`
		Records []Record `json:"records"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode porkbun response: %w", err)
	}
	if resp.Status != "SUCCESS" {
		return nil, fmt.Errorf("porkbun: %s", resp.Message)
	}
	if len(resp.Records) == 0 {
		return nil, nil
	}
	return &resp.Records[0], nil
}

// CreateARecord adds a new A record under domain pointing at ip.
// `subdomain` "" creates the apex; otherwise the resulting record
// is `<sub>.<domain>`. ttlSeconds is what Porkbun stores; 300 is
// a sensible default for newly-provisioned hosts.
func (c *Client) CreateARecord(ctx context.Context, domain, subdomain, ip string, ttlSeconds int) error {
	path := fmt.Sprintf("/dns/create/%s", domain)
	payload := map[string]any{
		"name":    subdomain,
		"type":    "A",
		"content": ip,
		"ttl":     fmt.Sprintf("%d", ttlSeconds),
	}
	body, err := c.post(ctx, path, payload)
	if err != nil {
		return err
	}
	var resp struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("decode porkbun response: %w", err)
	}
	if resp.Status != "SUCCESS" {
		return fmt.Errorf("porkbun: %s", resp.Message)
	}
	return nil
}

// post merges the auth pair into extra and POSTs the JSON to path.
// Returns the raw response body for the caller to decode.
func (c *Client) post(ctx context.Context, path string, extra map[string]any) ([]byte, error) {
	payload := map[string]any{
		"apikey":       c.apiKey,
		"secretapikey": c.secretKey,
	}
	for k, v := range extra {
		payload[k] = v
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, Endpoint+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("porkbun http %d: %s", res.StatusCode, string(body))
	}
	return body, nil
}
