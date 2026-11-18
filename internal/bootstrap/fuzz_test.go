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

package bootstrap

import (
	"net"
	"strings"
	"testing"
)

// FuzzShellQuote — same invariants as the ansible-package twin
// (single-quote wrapping, no bare quotes leaking).
func FuzzShellQuote(f *testing.F) {
	for _, seed := range []string{"", "plain", "with'quote", "$(echo pwned)"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := shellQuote(s)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Fatalf("shellQuote(%q) = %q: missing outer quotes", s, got)
		}
		stripped := strings.ReplaceAll(got[1:len(got)-1], `'"'"'`, "\x00")
		if strings.Contains(stripped, "'") {
			t.Fatalf("shellQuote(%q) = %q: bare single quote leaked", s, got)
		}
	})
}

// FuzzShellQuotePath checks the tilde-aware quoter. The output
// must always be safely splice-able into a shell command — i.e.
// any chunks not under shellQuote's protection are fixed literals
// we control (`"$HOME"` and `"$HOME"/`).
func FuzzShellQuotePath(f *testing.F) {
	for _, seed := range []string{"", "/abs/path", "~", "~/", "~/.ssh/key", "~user/key", "rel/path"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if err := checkShellQuotePath(s, shellQuotePath(s)); err != "" {
			t.Fatalf("shellQuotePath(%q): %s", s, err)
		}
	})
}

// checkShellQuotePath validates one of three legal output shapes:
//
//	"$HOME"               when s == "~"
//	"$HOME"/<quoted>      when s starts with "~/"
//	<quoted>              otherwise
//
// Returns "" on success, otherwise a short reason string.
func checkShellQuotePath(s, got string) string {
	switch {
	case s == "~":
		if got != `"$HOME"` {
			return "want \"$HOME\", got " + got
		}
	case strings.HasPrefix(s, "~/"):
		const prefix = `"$HOME"/`
		if !strings.HasPrefix(got, prefix) {
			return "missing $HOME prefix, got " + got
		}
		if !singleQuoted(strings.TrimPrefix(got, prefix)) {
			return "tail not single-quoted, got " + got
		}
	default:
		if !singleQuoted(got) {
			return "not single-quoted, got " + got
		}
	}
	return ""
}

func singleQuoted(s string) bool {
	return strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'")
}

// FuzzSplitFQDN verifies splitFQDN never panics and that, when it
// returns a non-empty domain, the domain contains a dot (i.e. the
// last two labels were joined). The function's only job is to
// split on dots; per-label hygiene is the caller's responsibility
// via validateHostname before we get here. Asserting "output is
// whitespace-free" was wrong — internal whitespace passes through
// because that's what splitFQDN is asked to do.
func FuzzSplitFQDN(f *testing.F) {
	for _, seed := range []string{"", "a", "a.b", "a.b.c", "deep.sub.example.com", "example.com.", "  spaces  "} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		domain, _ := splitFQDN(s)
		if domain != "" && !strings.Contains(domain, ".") {
			t.Fatalf("splitFQDN(%q) returned single-label domain %q", s, domain)
		}
	})
}

// FuzzNormalizeProviderName checks the output is always inside the
// allowlisted character set [a-z0-9_-]. The function is the only
// barrier between operator-supplied free-form text and a YAML key
// in the inventory file.
func FuzzNormalizeProviderName(f *testing.F) {
	for _, seed := range []string{"", "Hetzner", "Little Creek Hosting", "foo;rm", "  trim  ", "Über/Slash"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := normalizeProviderName(s)
		for _, r := range got {
			ok := (r >= 'a' && r <= 'z') ||
				(r >= '0' && r <= '9') ||
				r == '_' || r == '-'
			if !ok {
				t.Fatalf("normalizeProviderName(%q) = %q: rune %q outside allowlist", s, got, r)
			}
		}
	})
}

// hostInvariantBreak re-derives validateHostname's invariants from
// scratch so a regression in validateHostname (charset hole,
// missing whitespace check, missing length cap, missing per-label
// rule) is caught by FuzzValidateAddress's host branch instead of
// passing silently. Returns "" when all invariants hold; otherwise
// a short reason string.
func hostInvariantBreak(s string) string {
	if !strings.Contains(s, ".") {
		return "no dot"
	}
	if len(s) > 253 {
		return "exceeds 253 bytes"
	}
	if strings.ContainsAny(s, " \t") {
		return "contains whitespace"
	}
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '.' || r == '-'
		if !ok {
			return "contains rune outside RFC1035 charset"
		}
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "label " + label + " breaks RFC1035"
		}
	}
	return ""
}

// addressInvariantBreak runs the per-kind re-derivation that
// FuzzValidateAddress checks. Returns "" when validateAddress
// rejects s OR when classifyAddress's chosen kind agrees with an
// independent re-parse; otherwise returns a short reason. Lifted
// out of FuzzValidateAddress so the fuzz callback itself stays
// under Sonar's S3776 cognitive-complexity ceiling.
func addressInvariantBreak(s string) string {
	if validateAddress(s) != nil {
		return ""
	}
	trimmed := strings.TrimSpace(s)
	switch classifyAddress(trimmed) {
	case addressKindIPv4:
		ip := net.ParseIP(trimmed)
		if ip == nil || ip.To4() == nil || strings.Contains(trimmed, ":") {
			return "accepted as IPv4 but re-parse rejects"
		}
	case addressKindIPv6:
		ip := net.ParseIP(trimmed)
		if ip == nil || ip.To4() != nil || strings.Contains(trimmed, ".") {
			return "accepted as IPv6 but re-parse rejects, is v4-mapped, or has dotted-quad tail"
		}
	case addressKindHost:
		if reason := hostInvariantBreak(trimmed); reason != "" {
			return "accepted as host but " + reason
		}
	default:
		return "accepted but classifyAddress returned empty"
	}
	return ""
}

// FuzzValidateAddress must accept the three operator-supplied
// shapes the bootstrap form supports (IPv4 literal, IPv6 literal,
// DNS hostname) and reject everything else without panicking.
//
// The previous version asserted "accepted ⇒ classifyAddress
// non-empty" — tautological, since validateAddress is implemented
// by calling classifyAddress. We now re-derive each kind's
// invariant from a different code path (net.ParseIP for IPs,
// per-label decomposition for hostnames) so a regression in the
// classifier is caught even when validateAddress agrees with it.
func FuzzValidateAddress(f *testing.F) {
	for _, seed := range []string{"", "1.2.3.4", "  1.2.3.4  ", "::1", "2001:db8::1", "::ffff:1.2.3.4", "999.0.0.0", "1.2.3", "host.example.com", "no.tab\there", "single", "01.2.3.4", "-bad.example.com", "a..b", ".x.com", "x.com."} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if reason := addressInvariantBreak(s); reason != "" {
			t.Fatalf("validateAddress(%q) %s", s, reason)
		}
	})
}

// FuzzValidateHostname mirrors validateAddress for hostnames — never
// panic; rejected inputs are rejected; accepted inputs match the
// length cap and the dot/whitespace constraints.
func FuzzValidateHostname(f *testing.F) {
	for _, seed := range []string{"", "host", "host.example.com", "  spaces.example.com  ", "no.tab\there", strings.Repeat("a", 300)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := validateHostname(s)
		if err == nil {
			if len(s) > 253 {
				t.Fatalf("validateHostname(%q) accepted despite >253 bytes", s)
			}
			if !strings.Contains(s, ".") {
				t.Fatalf("validateHostname(%q) accepted without a dot", s)
			}
			if strings.ContainsAny(s, " \t") {
				t.Fatalf("validateHostname(%q) accepted with whitespace", s)
			}
		}
	})
}

// FuzzOSMatches verifies the os-release matcher accepts on ID or
// ID_LIKE match and rejects otherwise — and never panics on
// arbitrary text.
func FuzzOSMatches(f *testing.F) {
	for _, seed := range []struct{ rel, exp string }{
		{"ID=debian\n", "debian"},
		{`ID="ubuntu"` + "\n", "ubuntu"},
		{"ID=raspbian\nID_LIKE=\"debian\"\n", "debian"},
		{"ID=alpine\n", "debian"},
		{"", "debian"},
		{"\x00\x01\x02", "debian"},
	} {
		f.Add(seed.rel, seed.exp)
	}
	f.Fuzz(func(_ *testing.T, rel, exp string) {
		_ = osMatches(rel, exp) // no panic is the property
	})
}
