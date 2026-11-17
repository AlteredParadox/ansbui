package api

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// These tests pin down what the static handler does with a request path
// that tries to leave the web root. The handler passes the path to an
// fs.FS, and io/fs refuses any name that is not a clean, relative,
// slash-separated path (fs.ValidPath): no "..", no leading slash. So an
// escaping path is "not found", and the handler's fallback serves
// index.html. Static analysis cannot see that contract and reports the
// two fs calls as path traversal (gosecurity:S2083); these tests are the
// evidence that they are not.

const (
	indexBody  = "<!doctype html><title>index</title>"
	appBody    = "console.log('app')"
	libBody    = "console.log('lib')"
	secretBody = "TOP-SECRET-outside-the-web-root"
)

// staticRoots returns the kinds of filesystem the server can be given,
// each holding the same web bundle, and each with a secret.txt one level
// ABOVE the web root that must never be served.
func staticRoots(t *testing.T) map[string]fs.FS {
	t.Helper()

	// Production shape: main.go embeds the tree and passes
	// fs.Sub(embedded, "web"). An embed.FS cannot be built in a test, so
	// a MapFS stands in for the embedded parent.
	parent := fstest.MapFS{
		"web/index.html":    {Data: []byte(indexBody)},
		"web/app.js":        {Data: []byte(appBody)},
		"web/vendor/lib.js": {Data: []byte(libBody)},
		"secret.txt":        {Data: []byte(secretBody)},
	}
	sub, err := fs.Sub(parent, "web")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}

	// A real directory, in case the bundle is ever served from disk
	// instead (serveStaticFile already allows for "a future FS swap").
	dir := t.TempDir()
	for name, body := range map[string]string{
		"web/index.html":    indexBody,
		"web/app.js":        appBody,
		"web/vendor/lib.js": libBody,
		"secret.txt":        secretBody,
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return map[string]fs.FS{
		"sub of a parent fs": sub,
		"directory on disk":  os.DirFS(filepath.Join(dir, "web")),
	}
}

// escapingPaths are URL paths, as the handler sees them in r.URL.Path
// (already percent-decoded by net/http), that aim at ../secret.txt or at
// an absolute file.
var escapingPaths = []string{
	"/../secret.txt",
	"/..",
	"/../",
	"/./../secret.txt",
	"/vendor/../../secret.txt",
	"/vendor/../../../secret.txt",
	"/app.js/../../secret.txt",
	"//secret.txt",
	"//../secret.txt",
	"/..\\secret.txt",
	"/..%2fsecret.txt", // a literal percent sign that survived decoding
	"/%2e%2e/secret.txt",
	"/etc/passwd",
	"//etc/passwd",
	"/../web/../secret.txt",
	"/secret.txt",
	"/\x00/../secret.txt",
}

func TestStaticHandlerServesAssetsAndFallsBackToIndex(t *testing.T) {
	for kind, root := range staticRoots(t) {
		t.Run(kind, func(t *testing.T) {
			s := &Server{WebRoot: root}
			for path, want := range map[string]string{
				"/":              indexBody,
				"/index.html":    indexBody,
				"/app.js":        appBody,
				"/vendor/lib.js": libBody,
				// Unknown paths and bare directories get the app shell,
				// so client-side routes survive a reload.
				"/no/such/page": indexBody,
				"/vendor":       indexBody,
				"/vendor/":      indexBody,
			} {
				w := serveStaticPath(s, path)
				if w.Code != http.StatusOK || w.Body.String() != want {
					t.Errorf("GET %q = %d %q, want 200 %q", path, w.Code, w.Body.String(), want)
				}
			}
		})
	}
}

// The handler is called directly, with r.URL.Path set by hand, so the
// path reaches it exactly as written.
func TestStaticHandlerDoesNotLeaveWebRoot(t *testing.T) {
	for kind, root := range staticRoots(t) {
		t.Run(kind, func(t *testing.T) {
			s := &Server{WebRoot: root}
			for _, path := range escapingPaths {
				w := serveStaticPath(s, path)
				body := w.Body.String()
				if strings.Contains(body, secretBody) {
					t.Fatalf("GET %q served the file outside the web root", path)
				}
				// Not a 404: an unresolvable path is an unknown path, and
				// those fall back to the app shell.
				if w.Code != http.StatusOK || body != indexBody {
					t.Errorf("GET %q = %d %q, want the index.html fallback", path, w.Code, body)
				}
			}
		})
	}
}

// The same attempts as raw request targets through the whole handler
// chain. net/http's mux redirects a path with literal dot segments to
// the cleaned path, but a percent-encoded one ("/%2e%2e/secret.txt")
// passes through it and reaches the static handler as "/../secret.txt".
// So the mux is not the defence; the filesystem is. Either outcome is
// acceptable here: a redirect, or the app shell. The file outside the
// root is not.
func TestHandlerDoesNotLeaveWebRoot(t *testing.T) {
	targets := []string{
		"/../secret.txt",
		"/%2e%2e/secret.txt",
		"/%2E%2E/secret.txt",
		"/..%2fsecret.txt",
		"/..%2Fsecret.txt",
		"/%2e%2e%2fsecret.txt",
		"/vendor/../../secret.txt",
		"/vendor/%2e%2e/%2e%2e/secret.txt",
		"/vendor/..%2f..%2fsecret.txt",
		"/.%2e/secret.txt",
		"/..%5csecret.txt",
		"/%252e%252e/secret.txt", // double-encoded: decodes once, to "%2e%2e"
		"//secret.txt",
		"/secret.txt",
	}
	for kind, root := range staticRoots(t) {
		t.Run(kind, func(t *testing.T) {
			s := &Server{Addr: selfHost, WebRoot: root}
			h := s.Handler()
			for _, target := range targets {
				req := httptest.NewRequest(http.MethodGet, target, nil)
				req.Host = selfHost
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)

				body := w.Body.String()
				if strings.Contains(body, secretBody) {
					t.Fatalf("GET %s served the file outside the web root", target)
				}
				switch w.Code {
				case http.StatusOK:
					if body != indexBody {
						t.Errorf("GET %s = 200 %q, want the index.html fallback", target, body)
					}
				case http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
					// Follow it: the cleaned path must not resolve to the
					// secret either.
					loc := w.Header().Get("Location")
					req2 := httptest.NewRequest(http.MethodGet, loc, nil)
					req2.Host = selfHost
					w2 := httptest.NewRecorder()
					h.ServeHTTP(w2, req2)
					if w2.Code != http.StatusOK || w2.Body.String() != indexBody {
						t.Errorf("GET %s redirected to %q, which gave %d %q, want the index.html fallback",
							target, loc, w2.Code, w2.Body.String())
					}
				default:
					t.Errorf("GET %s = %d %q, want 200 or a redirect", target, w.Code, body)
				}
			}
		})
	}
}

// serveStaticFile and staticETag are the two calls the analyser flags.
// Given an escaping name directly, with no handler in front, each must
// refuse it on its own.
func TestStaticFileHelpersRejectEscapingNames(t *testing.T) {
	names := []string{
		"../secret.txt",
		"vendor/../../secret.txt",
		"./../secret.txt",
		"/secret.txt",
		"..",
		"vendor/../app.js", // inside the root, but not a clean path: still refused
	}
	for kind, root := range staticRoots(t) {
		t.Run(kind, func(t *testing.T) {
			s := &Server{WebRoot: root}
			for _, name := range names {
				if etag := s.staticETag(name); etag != "" {
					t.Errorf("staticETag(%q) = %q, want no ETag", name, etag)
				}
				w := httptest.NewRecorder()
				s.serveStaticFile(w, httptest.NewRequest(http.MethodGet, "/", nil), name)
				if w.Code != http.StatusNotFound {
					t.Errorf("serveStaticFile(%q) = %d, want 404", name, w.Code)
				}
				if strings.Contains(w.Body.String(), secretBody) {
					t.Fatalf("serveStaticFile(%q) served the file outside the web root", name)
				}
			}
			// Sanity: the same helpers do serve a real asset, so the
			// refusals above are not just "nothing works".
			if s.staticETag("app.js") == "" {
				t.Error(`staticETag("app.js") is empty, want a content hash`)
			}
		})
	}
}

// serveStaticPath calls the static handler with r.URL.Path set verbatim.
func serveStaticPath(s *Server, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.URL.Path = path
	w := httptest.NewRecorder()
	s.staticHandler().ServeHTTP(w, req)
	return w
}
