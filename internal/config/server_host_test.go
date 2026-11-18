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

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// The server host is dialled and, on first contact, written into
// known_hosts as the name the accepted key belongs to. These tests
// cover what may be stored as one.

func TestValidateServerHost(t *testing.T) {
	good := []string{
		"ctrl.example.com",
		"ctrl",
		"ctrl-01.internal",
		"ctrl_01",
		"host.example.com.",
		"192.0.2.10",
		"2001:db8::1",
		"::1",
		"fe80::1%eth0",
		"fe80::1%2",
		"fe80::1%br-lan.10",
		strings.Repeat("a", 253),
	}
	for _, h := range good {
		if err := ValidateServerHost(h); err != nil {
			t.Errorf("ValidateServerHost(%q) = %v, want accepted", h, err)
		}
	}

	bad := map[string]string{
		"empty":                      "",
		"audit: newline in zone":     "::1%a\n* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK #",
		"audit: comma wildcard zone": "::1%x,*",
		"zone with space":            "fe80::1%eth0 extra",
		"zone with wildcard":         "fe80::1%*",
		"zone with hash":             "fe80::1%a#b",
		"empty zone":                 "fe80::1%",
		"bracketed IPv6":             "[::1]",
		"host with port":             "ctrl.example.com:22",
		"wildcard":                   "*",
		"wildcard domain":            "*.example.com",
		"question mark":              "ctrl?.example.com",
		"comma list":                 "a.example.com,b.example.com",
		"negation":                   "!ctrl.example.com",
		"marker":                     "@cert-authority",
		"hashed-entry prefix":        "|1|abc|def",
		"comment":                    "ctrl#x",
		"space inside":               "ctrl example.com",
		"tab inside":                 "ctrl\texample.com",
		"newline inside":             "ctrl\nexample.com",
		"carriage return":            "ctrl\r",
		"NUL":                        "ctrl\x00",
		"leading dash":               "-oProxyCommand=x",
		"leading dot":                ".example.com",
		"slash":                      "ctrl/example",
		"user at host":               "root@ctrl.example.com",
		"non-ASCII":                  "ctrl.exämple.com",
		"too long":                   strings.Repeat("a", 254),
		"IPv4 with zone":             "192.0.2.10%eth0",
		"garbage with colon":         "not:an:address:zz",
	}
	for name, h := range bad {
		if err := ValidateServerHost(h); err == nil {
			t.Errorf("%s: ValidateServerHost(%q) accepted", name, h)
		}
	}
}

// A record with such a host must not be stored, and the stored host is
// the trimmed one.
func TestUpsertServerValidatesHost(t *testing.T) {
	t.Setenv("ANSBUI_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	m, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const hostile = "::1%a\n* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK #"
	if _, err := m.UpsertServer(Server{Host: hostile, User: "ansible", Port: 2222}); err == nil {
		t.Fatal("UpsertServer stored a host with a newline and a wildcard pattern in its zone")
	}
	if n := len(m.Snapshot().Servers); n != 0 {
		t.Fatalf("%d server record(s) stored after a rejected upsert", n)
	}

	saved, err := m.UpsertServer(Server{Host: "  ctrl.example.com  ", User: "ansible"})
	if err != nil {
		t.Fatalf("UpsertServer with surrounding spaces: %v", err)
	}
	if saved.Host != "ctrl.example.com" {
		t.Fatalf("stored host = %q, want it trimmed", saved.Host)
	}
	if _, err := m.UpsertServer(Server{Host: "   ", User: "ansible"}); err == nil {
		t.Fatal("UpsertServer accepted a blank host")
	}
}

// The Prometheus setting is a base address. A query string or a
// fragment in it let the caller choose the whole path and query of the
// server-side request.
func TestPromURLRejectsQueryAndFragment(t *testing.T) {
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", "")
	for _, raw := range []string{
		"http://127.0.0.1:9090/x?y=",
		"http://127.0.0.1:9090/x?",
		"http://127.0.0.1:9090/x#",
		"http://127.0.0.1:9090/internal/admin?action=reset&x=",
		"http://127.0.0.1:9090/api/v1/query?query=other_metric&x=",
		"http://127.0.0.1:9090/#",
		"http://127.0.0.1:9090?",
		"127.0.0.1:9090/x?y=1",
	} {
		if got, err := normalisePromURL(raw); err == nil {
			t.Errorf("normalisePromURL(%q) = %q, want it rejected", raw, got)
		} else if !strings.Contains(err.Error(), "query string") {
			t.Errorf("normalisePromURL(%q) error = %v, want the base-address message", raw, err)
		}
		if err := CheckPromBaseURL(raw); err == nil {
			t.Errorf("CheckPromBaseURL(%q) accepted", raw)
		}
	}
	// A path prefix is still a base address.
	for _, raw := range []string{"http://127.0.0.1:9090", "http://127.0.0.1:9090/prometheus", "http://localhost:9090/a/b/"} {
		if _, err := normalisePromURL(raw); err != nil {
			t.Errorf("normalisePromURL(%q) = %v, want accepted", raw, err)
		}
	}
}
