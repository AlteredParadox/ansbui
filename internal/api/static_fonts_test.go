package api

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

// The UI is embedded from the repository's web/ directory. These tests
// read that directory as it is, so they fail when the page starts
// loading something from another origin again, or when a font file and
// the record of where it came from stop agreeing.

func webDir(t *testing.T) fs.FS {
	t.Helper()
	const dir = "../../web"
	if _, err := os.Stat(dir + "/index.html"); err != nil {
		t.Fatalf("web directory not found from the test's working directory: %v", err)
	}
	return os.DirFS(dir)
}

// uiSources are the files the browser loads that ansbui's authors
// write: everything under web/ except the vendored libraries.
func uiSources(t *testing.T, web fs.FS) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(web, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p == "vendor" {
				return fs.SkipDir
			}
			return nil
		}
		switch path.Ext(p) {
		case ".html", ".css", ".js", ".jsx":
			data, err := fs.ReadFile(web, p)
			if err != nil {
				return err
			}
			out[p] = string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk web/: %v", err)
	}
	if len(out) < 10 {
		t.Fatalf("only %d UI source files found; the walk is not seeing web/", len(out))
	}
	return out
}

var (
	// A resource reference in HTML: href/src on a tag.
	htmlRefRE = regexp.MustCompile(`(?i)\b(?:href|src)\s*=\s*["']([^"']+)["']`)
	// url(...) and @import in CSS.
	cssURLRE    = regexp.MustCompile(`(?i)url\(\s*['"]?([^'")]+)['"]?\s*\)`)
	cssImportRE = regexp.MustCompile(`(?i)@import\s+(?:url\()?\s*['"]?([^'");\s]+)`)
)

// isLocalRef reports whether ref can only resolve to this origin: a
// relative path or a data: URI — no scheme, no protocol-relative //.
func isLocalRef(ref string) bool {
	if strings.HasPrefix(ref, "data:") {
		return true
	}
	return !strings.Contains(ref, "://") && !strings.HasPrefix(ref, "//") && !strings.Contains(ref, ":")
}

// index.html and the stylesheets reference nothing outside ansbui, and
// every file they do reference exists in the bundle.
func TestUILoadsOnlyItsOwnFiles(t *testing.T) {
	web := webDir(t)
	checked := 0
	for name, src := range uiSources(t, web) {
		var refs []string
		switch path.Ext(name) {
		case ".html":
			for _, m := range htmlRefRE.FindAllStringSubmatch(src, -1) {
				refs = append(refs, m[1])
			}
		case ".css":
			for _, m := range cssURLRE.FindAllStringSubmatch(src, -1) {
				refs = append(refs, m[1])
			}
			for _, m := range cssImportRE.FindAllStringSubmatch(src, -1) {
				refs = append(refs, m[1])
			}
		default:
			continue
		}
		for _, ref := range refs {
			checked++
			if !isLocalRef(ref) {
				t.Errorf("%s loads %q from another origin", name, ref)
				continue
			}
			if strings.HasPrefix(ref, "data:") {
				continue
			}
			target := path.Join(path.Dir(name), ref)
			if _, err := fs.Stat(web, target); err != nil {
				t.Errorf("%s references %q, which is not in web/ (%s)", name, ref, target)
			}
		}
	}
	if checked < 15 {
		t.Fatalf("only %d references checked; the patterns are not matching the sources", checked)
	}
	// The specific hosts this page used to contact.
	for name, src := range uiSources(t, web) {
		for _, host := range []string{"fonts.googleapis.com", "fonts.gstatic.com", "unpkg.com"} {
			if path.Ext(name) != ".html" && path.Ext(name) != ".css" {
				continue
			}
			if strings.Contains(src, "//"+host) {
				t.Errorf("%s still names %s", name, host)
			}
		}
	}
}

func TestIsLocalRef(t *testing.T) {
	for _, ref := range []string{"styles/app.css", "../fonts/InterVariable.woff2", "vendor/babel.min.js", "data:image/svg+xml;utf8,<svg/>", "./a.css"} {
		if !isLocalRef(ref) {
			t.Errorf("isLocalRef(%q) = false", ref)
		}
	}
	for _, ref := range []string{"https://fonts.googleapis.com/css2?family=Inter", "http://example.test/a.css", "//fonts.gstatic.com/x.woff2", "javascript:alert(1)", "ftp://x/y"} {
		if isLocalRef(ref) {
			t.Errorf("isLocalRef(%q) = true", ref)
		}
	}
}

var (
	fontFaceSrcRE = regexp.MustCompile(`url\('\.\./fonts/([^']+)'\)`)
	// A README table row: | `file.woff2` | … | `<64 hex>` |
	fontRowRE = regexp.MustCompile("(?m)^\\| `([^`]+\\.woff2)` \\|.*\\| `([0-9a-f]{64})` \\|$")
)

// Every font the stylesheet declares is in web/fonts/, every font file
// there is declared and has its checksum recorded, and the bytes match
// the record. The files are binary and came from a download; this is
// what ties them to a named upstream release.
func TestFontFilesMatchTheirRecord(t *testing.T) {
	web := webDir(t)
	readme, err := fs.ReadFile(web, "fonts/README.md")
	if err != nil {
		t.Fatalf("read fonts/README.md: %v", err)
	}
	recorded := map[string]string{}
	for _, m := range fontRowRE.FindAllStringSubmatch(string(readme), -1) {
		recorded[m[1]] = m[2]
	}
	if len(recorded) == 0 {
		t.Fatal("no font checksums found in fonts/README.md")
	}

	css, err := fs.ReadFile(web, "styles/tokens.css")
	if err != nil {
		t.Fatalf("read tokens.css: %v", err)
	}
	declared := map[string]bool{}
	for _, m := range fontFaceSrcRE.FindAllStringSubmatch(string(css), -1) {
		declared[m[1]] = true
	}
	if len(declared) == 0 {
		t.Fatal("no @font-face src found in tokens.css")
	}

	entries, err := fs.ReadDir(web, "fonts")
	if err != nil {
		t.Fatalf("read fonts/: %v", err)
	}
	present := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".woff2") {
			continue
		}
		present[e.Name()] = true
		data, err := fs.ReadFile(web, "fonts/"+e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if string(data[:4]) != "wOF2" {
			t.Errorf("%s is not a WOFF2 file", e.Name())
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		switch want, ok := recorded[e.Name()]; {
		case !ok:
			t.Errorf("%s has no checksum in fonts/README.md", e.Name())
		case got != want:
			t.Errorf("%s: sha256 %s, README records %s", e.Name(), got, want)
		}
		if !declared[e.Name()] {
			t.Errorf("%s is shipped but no @font-face uses it", e.Name())
		}
	}
	for name := range declared {
		if !present[name] {
			t.Errorf("tokens.css declares %s, which is not in web/fonts/", name)
		}
	}
	for name := range recorded {
		if !present[name] {
			t.Errorf("fonts/README.md records %s, which is not in web/fonts/", name)
		}
	}
	for _, lic := range []string{"fonts/Inter-LICENSE.txt", "fonts/JetBrainsMono-OFL.txt"} {
		data, err := fs.ReadFile(web, lic)
		if err != nil || !strings.Contains(string(data), "SIL Open Font License") {
			t.Errorf("%s: missing or not the Open Font License (%v)", lic, err)
		}
	}
}

// The font files are served with the font type and the same headers as
// everything else.
func TestFontsAreServed(t *testing.T) {
	s := &Server{WebRoot: webDir(t)}
	h := s.Handler()
	for _, name := range []string{"InterVariable.woff2", "JetBrainsMono-Regular.woff2", "JetBrainsMono-Medium.woff2", "JetBrainsMono-SemiBold.woff2"} {
		r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/fonts/"+name, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("GET /fonts/%s = %d", name, w.Code)
		}
		if got := w.Header().Get("Content-Type"); got != "font/woff2" {
			t.Errorf("/fonts/%s Content-Type = %q, want font/woff2", name, got)
		}
		if w.Header().Get("Etag") == "" || w.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("/fonts/%s lacks the ETag or policy header: %v", name, w.Header())
		}
		if !strings.HasPrefix(w.Body.String(), "wOF2") {
			t.Errorf("/fonts/%s body is not the font file", name)
		}
		// Revalidation works for the binary files too.
		r2 := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/fonts/"+name, nil)
		r2.Header.Set("If-None-Match", w.Header().Get("Etag"))
		w2 := httptest.NewRecorder()
		h.ServeHTTP(w2, r2)
		if w2.Code != http.StatusNotModified {
			t.Errorf("revalidating /fonts/%s = %d, want 304", name, w2.Code)
		}
	}
}

// parseCSP splits a policy into directive → sources.
func parseCSP(policy string) map[string][]string {
	out := map[string][]string{}
	for _, part := range strings.Split(policy, ";") {
		f := strings.Fields(part)
		if len(f) == 0 {
			continue
		}
		out[f[0]] = f[1:]
	}
	return out
}

// The policy, directive by directive. A change here should be a
// decision, not a side effect.
func TestContentSecurityPolicy(t *testing.T) {
	got := parseCSP(contentSecurityPolicy)
	want := map[string]string{
		"default-src":     "'self'",
		"script-src":      "'self' 'unsafe-inline'",
		"style-src":       "'self'",
		"img-src":         "'self' data:",
		"font-src":        "'self'",
		"connect-src":     "'self'",
		"object-src":      "'none'",
		"base-uri":        "'none'",
		"form-action":     "'self'",
		"frame-ancestors": "'none'",
	}
	if len(got) != len(want) {
		t.Errorf("policy has %d directives, want %d: %s", len(got), len(want), contentSecurityPolicy)
	}
	for directive, sources := range want {
		if strings.Join(got[directive], " ") != sources {
			t.Errorf("%s = %q, want %q", directive, strings.Join(got[directive], " "), sources)
		}
	}
	// Whatever else changes: no other origin, no wildcard, no scheme
	// source that would admit one, and inline code only where the
	// in-browser compiler needs it.
	for directive, sources := range got {
		for _, src := range sources {
			if strings.Contains(src, "*") || strings.Contains(src, "//") || src == "https:" || src == "http:" || src == "blob:" {
				t.Errorf("%s allows %q", directive, src)
			}
			if src == "'unsafe-eval'" {
				t.Errorf("%s allows 'unsafe-eval'; the UI loads without it", directive)
			}
			if src == "'unsafe-inline'" && directive != "script-src" {
				t.Errorf("%s allows 'unsafe-inline'", directive)
			}
			if src == "data:" && directive != "img-src" {
				t.Errorf("%s allows data:", directive)
			}
		}
	}
}
