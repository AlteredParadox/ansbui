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

package prom

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// The configured Prometheus URL is a base address; these tests cover
// what is sent to it and what is taken back from it.

// recordingProm answers every request with an empty success vector and
// keeps the request URIs it saw.
type recordingProm struct {
	mu   sync.Mutex
	uris []string
}

func (p *recordingProm) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.uris = append(p.uris, r.URL.RequestURI())
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
}

func (p *recordingProm) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.uris...)
}

// Every request is <base path>/api/v1/query with exactly one parameter,
// "query", holding one of the fixed expressions.
func TestMetricsSendsOnlyFixedQueries(t *testing.T) {
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", "")
	for _, prefix := range []string{"", "/prometheus", "/a/b/"} {
		t.Run("prefix "+prefix, func(t *testing.T) {
			rec := &recordingProm{}
			srv := httptest.NewServer(rec)
			defer srv.Close()
			c, err := NewClient(srv.URL+prefix, "instance")
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			res, err := c.Metrics(context.Background())
			if err != nil {
				t.Fatalf("Metrics: %v", err)
			}
			fixed := map[string]bool{}
			for _, p := range res.Probes {
				if p.Error != "" {
					t.Errorf("probe %s failed: %s", p.Name, p.Error)
				}
				fixed[p.Query] = true
			}
			uris := rec.seen()
			if len(uris) != len(res.Probes) {
				t.Fatalf("server saw %d requests for %d probes: %v", len(uris), len(res.Probes), uris)
			}
			wantPath := strings.TrimRight(prefix, "/") + "/api/v1/query"
			for _, raw := range uris {
				u, err := url.ParseRequestURI(raw)
				if err != nil {
					t.Fatalf("request URI %q: %v", raw, err)
				}
				if u.Path != wantPath {
					t.Errorf("request path = %q, want %q", u.Path, wantPath)
				}
				q := u.Query()
				if len(q) != 1 || len(q["query"]) != 1 {
					t.Errorf("request %q does not carry exactly one query parameter", raw)
					continue
				}
				if !fixed[q.Get("query")] {
					t.Errorf("request carried an expression that is not one of the fixed probes: %q", q.Get("query"))
				}
			}
		})
	}
}

// A stored URL with a query string or fragment is refused before any
// request is made: the settings endpoint rejects it now, but a
// config.json saved by an older release never met that check.
func TestNewClientRefusesQueryAndFragment(t *testing.T) {
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", "")
	rec := &recordingProm{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	for _, suffix := range []string{
		"/internal/admin?action=reset&x=",
		"/internal/admin#",
		"/api/v1/query?query=other_metric&x=",
		"/x?",
		"?",
		"#",
	} {
		if _, err := NewClient(srv.URL+suffix, "instance"); err == nil {
			t.Errorf("NewClient accepted base %q", suffix)
		}
	}
	if got := rec.seen(); len(got) != 0 {
		t.Fatalf("requests were sent for refused URLs: %v", got)
	}
}

// The error text of a response is whatever the peer wrote. It comes
// back as one short, quoted line.
func TestRemoteErrorTextIsBoundedAndSingleLine(t *testing.T) {
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", "")
	forged := "boom\n2026/11/18 09:00:00 \"POST\" \"/api/login\" 200 1.234ms\r\n" + strings.Repeat("A", 1<<20)
	body, err := json.Marshal(map[string]string{"status": "error", "errorType": "bad_data", "error": forged})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "instance")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	res, err := c.Metrics(context.Background())
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	if len(res.Probes) == 0 {
		t.Fatal("no probes")
	}
	for _, p := range res.Probes {
		if p.Error == "" {
			t.Fatalf("probe %s reported no error", p.Name)
		}
		if strings.ContainsAny(p.Error, "\r\n") {
			t.Fatalf("probe %s error spans lines: %q", p.Name, p.Error)
		}
		if len(p.Error) > 400 {
			t.Fatalf("probe %s error is %d bytes", p.Name, len(p.Error))
		}
		if !strings.HasPrefix(p.Error, `prometheus error: "boom\n2026/11/18`) {
			t.Fatalf("probe %s error lost its head or is not quoted: %.80s", p.Name, p.Error)
		}
	}
}

func TestRemoteErrorText(t *testing.T) {
	if got := remoteErrorText("bad_data: parse error"); got != `"bad_data: parse error"` {
		t.Fatalf("short message = %s", got)
	}
	if got := remoteErrorText(""); got != `""` {
		t.Fatalf("empty message = %s", got)
	}
	// The cut never splits a rune, and says that it cut.
	long := remoteErrorText(strings.Repeat("é", 500))
	if !strings.HasSuffix(long, `…"`) || strings.Contains(long, `\x`) {
		t.Fatalf("long message badly cut: %.40s … %s", long, long[len(long)-12:])
	}
	if got := remoteErrorText("a\u2028b\x00c\x1b[31m"); strings.ContainsAny(got, "\u2028\x00\x1b") {
		t.Fatalf("control characters survived: %q", got)
	}
}
