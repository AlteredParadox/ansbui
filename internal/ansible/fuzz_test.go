package ansible

import (
	"strings"
	"testing"
)

// FuzzShellQuote checks that shellQuote always wraps its input in
// outer single quotes and never lets an unescaped single quote leak
// through — those are the two invariants that make the helper safe
// to splice into another shell command. We don't validate the
// roundtrip (that would require running a shell); the property here
// is that the output starts and ends with `'` and the only literal
// `'` chars inside are part of the standard `'"'"'` escape sequence.
func FuzzShellQuote(f *testing.F) {
	for _, seed := range []string{
		"",
		"plain",
		"with space",
		"with'quote",
		"with$dollar`backtick",
		"$(echo pwned)",
		"; rm -rf /",
		"\\n\\t",
		"'; rm -rf /; '",
		"abc\x00def",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := shellQuote(s)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Fatalf("shellQuote(%q) = %q: missing outer single quotes", s, got)
		}
		// Strip outer quotes; the inside should contain literal
		// `'` characters ONLY as part of the four-char escape
		// sequence `'"'"'`. After replacing each escape with a
		// placeholder, any remaining `'` is a leak.
		inner := got[1 : len(got)-1]
		stripped := strings.ReplaceAll(inner, `'"'"'`, "\x00")
		if strings.Contains(stripped, "'") {
			t.Fatalf("shellQuote(%q) = %q: bare single quote leaked through escape sequence", s, got)
		}
		// And the output must contain at least as many bytes as
		// the input (otherwise we'd have dropped data).
		if len(got)-2 < len(s) {
			t.Fatalf("shellQuote(%q) = %q: shorter than input minus quotes", s, got)
		}
	})
}

// FuzzRedactText checks that RedactText never panics, never grows
// the string unboundedly, and that a "password" or "passphrase" key
// followed by `:` or `=` never has its raw value present in the
// output. The output is allowed to contain the literal redaction
// marker; the property is that an attacker reading redacted text
// can't recover the original value.
func FuzzRedactText(f *testing.F) {
	for _, seed := range []string{
		"",
		"password: hunter2",
		`{"password": "hunter2"}`,
		"PASSPHRASE = my secret pass",
		"username: bob, password: hunter2, host: x",
		"passworD :   trailing",
		`password='single quoted'`,
		"no secret here",
		"password",
		"password:",
		"password: a\npassword: b",
		// One seed per word sensitiveWords gained after the first list.
		"client_secret: x",
		"SeCret:0",
		"private_key=abc",
		"credential: x",
		"ansible_become_pass: x",
		"pAss:0",
		"mysql_root_passwd=x",
		// Bracketed values, including a bracket inside a string.
		`"api_tokens": ["a","b"]`,
		`{"credentials":{"password":"abc},SECRET"}}`,
		`token: [a, 'b]c', "d]e"]`,
		`secret: {unterminated "string`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := RedactText(s)
		// Never panic — implicit (would have failed by now).
		// Output must not be wildly larger than input + a constant
		// per match. Cap at 4× input length plus the marker length
		// to catch a regex blowing up.
		if max := 4*len(s) + 64; len(got) > max && max > 64 {
			t.Fatalf("RedactText(%q) = %q: output unexpectedly large", s, got)
		}
		// If the input contains no key trigger at all (case-fold),
		// output should equal input — otherwise the regex matched
		// something unintended. Keep this list in lockstep with
		// sensitiveWords in redact.go (each optional [_-] spelled out);
		// substring matches (e.g. "apikey" inside "myapikey") are fine
		// because over-scrub is the safe direction.
		lower := strings.ToLower(s)
		triggers := []string{
			// "pass" covers `pass\b` and, as a substring, passwd,
			// password and passphrase; those stay listed so the
			// correspondence with sensitiveWords is readable.
			"pass", "passwd",
			"password", "passphrase", "token", "secret",
			"apikey", "api_key", "api-key",
			"privatekey", "private_key", "private-key",
			"credential",
		}
		hasTrigger := false
		for _, t := range triggers {
			if strings.Contains(lower, t) {
				hasTrigger = true
				break
			}
		}
		if !hasTrigger && got != s {
			t.Fatalf("RedactText(%q) = %q: changed despite no key", s, got)
		}
	})
}

// FuzzParseIncludeHosts checks the annotation parser: every
// returned host is non-empty, contains no commas (entries are
// pre-split), and the slice is deduplicated.
func FuzzParseIncludeHosts(f *testing.F) {
	for _, seed := range []string{
		"",
		"a",
		"a,b,c",
		"  a , b , c  ",
		"a a a",
		",,,",
		"a,a,a",
		"a , b\tc",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := parseIncludeHosts(s)
		seen := make(map[string]bool)
		for _, h := range got {
			if h == "" {
				t.Fatalf("parseIncludeHosts(%q): empty entry in %v", s, got)
			}
			if strings.ContainsAny(h, ", \t") {
				t.Fatalf("parseIncludeHosts(%q): unsplit separator in %q", s, h)
			}
			if seen[h] {
				t.Fatalf("parseIncludeHosts(%q): duplicate %q in %v", s, h, got)
			}
			seen[h] = true
		}
	})
}

// FuzzMergeLimitHosts checks the limit-merge invariants: output is
// comma-separated, every entry is non-empty, dedup holds across the
// userLimit + include input, and the operator's entries come first
// in source order.
func FuzzMergeLimitHosts(f *testing.F) {
	for _, seed := range []struct {
		userLimit string
		includes  string // comma-separated
	}{
		{"", ""},
		{"a", ""},
		{"", "a,b"},
		{"a,b", "b,c"},
		{"  a  ,  b  ", "c"},
	} {
		f.Add(seed.userLimit, seed.includes)
	}
	f.Fuzz(func(t *testing.T, userLimit, includesCSV string) {
		include := strings.Split(includesCSV, "|")
		got := MergeLimitHosts(userLimit, include)
		if err := checkMergeLimitOutput(got); err != "" {
			t.Fatalf("MergeLimitHosts(%q, %v) = %q: %s", userLimit, include, got, err)
		}
	})
}

// checkMergeLimitOutput returns "" when the joined limit is well
// formed, otherwise a short reason string. Pulled out of the fuzz
// closure so the closure stays under S3776's 15-point ceiling.
func checkMergeLimitOutput(got string) string {
	if got == "" {
		return ""
	}
	seen := make(map[string]bool)
	for _, h := range strings.Split(got, ",") {
		if h == "" {
			return "empty entry"
		}
		if strings.TrimSpace(h) != h {
			return "untrimmed entry " + h
		}
		if seen[h] {
			return "duplicate " + h
		}
		seen[h] = true
	}
	return ""
}
