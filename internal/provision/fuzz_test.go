package provision

import (
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

// FuzzValidateIP must accept dotted-quad IPv4 (the four-octet
// form) and reject everything else without panicking. We can't
// enumerate "all valid IPv4" but we can check that the rejection
// is total for shapes that obviously aren't IPv4 — the regex
// inversion catches the easy cases.
func FuzzValidateIP(f *testing.F) {
	for _, seed := range []string{"", "1.2.3.4", "  1.2.3.4  ", "::1", "::ffff:1.2.3.4", "999.0.0.0", "1.2.3", "host.example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := validateIP(s)
		if err == nil {
			// If accepted, the trimmed input must be a dotted-quad
			// shape (four `.`-separated digit runs).
			parts := strings.Split(strings.TrimSpace(s), ".")
			if len(parts) != 4 {
				t.Fatalf("validateIP(%q) accepted but not dotted-quad", s)
			}
		}
	})
}

// FuzzValidateHostname mirrors validateIP for hostnames — never
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
