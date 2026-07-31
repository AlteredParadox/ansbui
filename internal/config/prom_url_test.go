package config

import (
	"net"
	"strings"
	"testing"
)

// Repeated URL/error fragments used across the table-driven
// tests below — extracted as named constants both for clarity
// and to silence Sonar's S1192 (duplicate string literal).
const (
	urlLoopback4      = "http://127.0.0.1:9090"
	urlPrivateRFC1918 = "http://10.0.0.5:9090"
	urlPromInternal   = "http://prom.internal:9090"
	errMetadataDeny   = "cloud-metadata denylist"
)

type promURLCase struct {
	name     string
	raw      string
	envAllow string
	want     string
	wantErr  string // substring; empty means must succeed
}

// TestNormalisePromURL is a table-driven test of the SSRF
// guardrails on the Prometheus URL setter. The function is the
// only barrier between operator-supplied free-form input and a
// server-side fetch — every accepted shape and every refused
// shape lives here.
func TestNormalisePromURL(t *testing.T) {
	cases := []promURLCase{
		{
			name: "loopback v4 ok by default",
			raw:  urlLoopback4,
			want: urlLoopback4,
		},
		{
			name: "loopback v6 ok by default",
			raw:  "http://[::1]:9090",
			want: "http://[::1]:9090",
		},
		{
			name: "localhost ok by default",
			raw:  "http://localhost:9090",
			want: "http://localhost:9090",
		},
		{
			name:    "rfc1918 rejected without allowlist",
			raw:     urlPrivateRFC1918,
			wantErr: "is not loopback",
		},
		{
			name:     "rfc1918 ok with allowlist",
			raw:      urlPrivateRFC1918,
			envAllow: "10.0.0.5:9090",
			want:     urlPrivateRFC1918,
		},
		{
			name:     "allowlist matches host without port",
			raw:      urlPromInternal,
			envAllow: "prom.internal",
			want:     urlPromInternal,
		},
		{
			name:     "allowlist matches host with port",
			raw:      urlPromInternal,
			envAllow: "prom.internal:9090",
			want:     urlPromInternal,
		},
		{
			name:     "allowlist comma-separated picks one entry",
			raw:      "http://b.example:9090",
			envAllow: "a.example:9090, b.example:9090, c.example:9090",
			want:     "http://b.example:9090",
		},
		{
			name:     "host outside allowlist rejected",
			raw:      "http://wrong.example:9090",
			envAllow: "right.example:9090",
			wantErr:  "is not in ANSBUI_PROM_ALLOWED_HOSTS",
		},
		{
			name:    "aws imds rejected by denylist",
			raw:     "http://169.254.169.254:80",
			wantErr: errMetadataDeny,
		},
		{
			name:    "ecs metadata rejected",
			raw:     "http://169.254.170.2:80",
			wantErr: errMetadataDeny,
		},
		{
			name:    "gcp metadata.google.internal rejected",
			raw:     "http://metadata.google.internal",
			wantErr: errMetadataDeny,
		},
		{
			name:    "nip.io imds bypass rejected",
			raw:     "http://169.254.169.254.nip.io:80",
			wantErr: errMetadataDeny,
		},
		{
			name: "nip.io imds bypass rejected even when on allowlist",
			// Defence in depth: denylist precedes allowlist
			// inside checkPromHost so an operator can't
			// accidentally allowlist a metadata host.
			raw:      "http://169.254.169.254.nip.io:80",
			envAllow: "169.254.169.254.nip.io:80",
			wantErr:  errMetadataDeny,
		},
		{
			name:    "non-canonical link-local rejected",
			raw:     "http://169.254.5.6:9090",
			wantErr: "link-local",
		},
		{
			name:    "file scheme rejected",
			raw:     "file:///etc/passwd",
			wantErr: "scheme must be http or https",
		},
		{
			name: "empty input passes through as empty",
			raw:  "",
			want: "",
		},
		{
			name: "scheme prepended when missing",
			raw:  "127.0.0.1:9090",
			want: urlLoopback4,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { runPromURLCase(t, tc) })
	}
}

// runPromURLCase executes one table entry. Pulled out of the
// loop body to keep TestNormalisePromURL's cognitive complexity
// under Sonar's threshold — the per-case logic is more readable
// here too (one happy/error branch per function).
func runPromURLCase(t *testing.T, tc promURLCase) {
	t.Helper()
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", tc.envAllow)
	got, err := normalisePromURL(tc.raw)
	if tc.wantErr != "" {
		assertErrContains(t, err, tc.wantErr, got)
		return
	}
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != tc.want {
		t.Fatalf("output mismatch: got %q, want %q", got, tc.want)
	}
}

func assertErrContains(t *testing.T, err error, want, got string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want err containing %q, got nil (out=%q)", want, got)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("err mismatch: got %q, want substring %q", err.Error(), want)
	}
}

// TestValidatePromLabel guards the PromQL injection surface — the
// label is interpolated into `avg by (...)` without quoting. The
// allowlisted shape is the Prometheus label-name grammar.
func TestValidatePromLabel(t *testing.T) {
	good := []string{"instance", "host", "_x", "job_name", "Node1", "a"}
	bad := []string{"", "1abc", "instance with space", "instance) + vector(0", "label-with-dash", "a;b", "instance\nrest"}

	for _, s := range good {
		if err := validatePromLabel(s); err != nil {
			t.Errorf("validatePromLabel(%q) returned %v, want nil", s, err)
		}
	}
	for _, s := range bad {
		if err := validatePromLabel(s); err == nil {
			t.Errorf("validatePromLabel(%q) returned nil, want error", s)
		}
	}
}

// TestCheckPromResolvedIP covers the dial-time half of the SSRF
// guard. CheckPromHost can only vet the configured hostname; if
// nothing re-examines where that name actually leads, repointing its
// DNS steers the server-side fetch anywhere.
func TestCheckPromResolvedIP(t *testing.T) {
	mustDeny := []string{
		"169.254.169.254", // AWS/GCP/DO IMDS
		"169.254.170.2",   // ECS task metadata
		"fd00:ec2::254",   // AWS IMDSv6
		"169.254.1.1",     // any link-local
		"fe80::1",         // IPv6 link-local
		"0.0.0.0",
		"224.0.0.1", // multicast
	}
	for _, s := range mustDeny {
		if err := CheckPromResolvedIP(net.ParseIP(s)); err == nil {
			t.Errorf("CheckPromResolvedIP(%s) = nil, want denial", s)
		}
	}

	// With no CIDR pin configured, ordinary destinations still work —
	// a same-host or LAN Prometheus is the normal deployment.
	for _, s := range []string{"127.0.0.1", "::1", "10.1.2.3", "192.168.0.5", "203.0.113.7"} {
		if err := CheckPromResolvedIP(net.ParseIP(s)); err != nil {
			t.Errorf("CheckPromResolvedIP(%s) = %v, want nil", s, err)
		}
	}

	if err := CheckPromResolvedIP(nil); err == nil {
		t.Error("nil IP should be rejected")
	}
}

// The optional CIDR pin is what actually closes rebinding for
// operators who want it: the name may move, but only within the
// network their Prometheus really lives on.
func TestCheckPromResolvedIPCIDRPin(t *testing.T) {
	t.Setenv(promAllowedCIDRsEnv, "10.0.0.0/8, 192.168.1.0/24")

	for _, s := range []string{"10.5.5.5", "192.168.1.20"} {
		if err := CheckPromResolvedIP(net.ParseIP(s)); err != nil {
			t.Errorf("in-range %s rejected: %v", s, err)
		}
	}
	// Previously reachable addresses are now outside the pin.
	for _, s := range []string{"127.0.0.1", "192.168.2.20", "203.0.113.7"} {
		if err := CheckPromResolvedIP(net.ParseIP(s)); err == nil {
			t.Errorf("out-of-range %s allowed", s)
		}
	}
	// The always-denied set stays denied regardless of the pin.
	if err := CheckPromResolvedIP(net.ParseIP("169.254.169.254")); err == nil {
		t.Error("IMDS allowed despite always-deny layer")
	}
}

// A malformed CIDR must fail closed. Skipping bad entries would let a
// typo silently widen the policy to "everything".
func TestCheckPromResolvedIPMalformedCIDRFailsClosed(t *testing.T) {
	t.Setenv(promAllowedCIDRsEnv, "not-a-cidr")
	if err := CheckPromResolvedIP(net.ParseIP("10.0.0.1")); err == nil {
		t.Fatal("malformed CIDR silently allowed the address")
	}
}
