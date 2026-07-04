package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AlteredParadox/ansbui/internal/porkbun"
)

// TestEnsureRecordIPv6CaseInsensitive locks in the loop-2 fix:
// porkbun returns AAAA content lowercased, so an operator who entered
// `2001:DB8::1` would otherwise see every retry treat the existing
// record as a "conflict" against their literal input. ensureRecord
// canonicalises via net.ParseIP().String() and compares via
// net.IP.Equal to round-trip cleanly. A regression that drops either
// half of that fix surfaces here as a non-nil error and a "fail" emit.
func TestEnsureRecordIPv6CaseInsensitive(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/dns/retrieveByNameType/") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"SUCCESS","records":[{"id":"1","name":"vps.example.com","type":"AAAA","content":"2001:db8::1","ttl":"300"}]}`)
			return
		}
		// Any other endpoint (specifically /dns/create/...) means a
		// regression has the function trying to overwrite a record
		// it should have recognised as already-correct.
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"status":"ERROR","message":"unexpected porkbun call: %s"}`, r.URL.Path)
	}))
	defer srv.Close()

	origEndpoint := porkbun.Endpoint
	porkbun.Endpoint = srv.URL
	defer func() { porkbun.Endpoint = origEndpoint }()

	pb := porkbun.New("test-key", "test-secret")
	var emits []string
	emit := func(typ, text string) { emits = append(emits, typ+": "+text) }

	if err := ensureRecord(context.Background(), pb, "AAAA", "example.com", "vps", "2001:DB8::1", emit); err != nil {
		t.Fatalf("ensureRecord returned error %v; emits=%v", err, emits)
	}
	if len(paths) != 1 {
		t.Fatalf("expected exactly 1 porkbun call (retrieve only), got %d: %v", len(paths), paths)
	}
	var sawOK bool
	for _, e := range emits {
		if strings.HasPrefix(e, "ok:") && strings.Contains(e, "already correct") {
			sawOK = true
		}
		if strings.HasPrefix(e, "fail:") {
			t.Fatalf("ensureRecord emitted fail: %v", emits)
		}
	}
	if !sawOK {
		t.Fatalf("expected an 'ok: ... already correct' emit, got %v", emits)
	}
}

// TestEnsureRecordConcurrentSameFQDN locks in the TOCTOU fix: two
// concurrent bootstraps of the same fqdn with different IPs must not
// both pass the "no records" check and create a round-robin pair —
// the exact state ensureRecord's conflict guard exists to prevent.
// The fake porkbun widens the find→create window with a small sleep;
// without the per-fqdn mutex this test ends with two A records.
func TestEnsureRecordConcurrentSameFQDN(t *testing.T) {
	var storeMu sync.Mutex
	var contents []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/dns/retrieveByNameType/"):
			storeMu.Lock()
			rows := make([]string, len(contents))
			for i, c := range contents {
				rows[i] = fmt.Sprintf(`{"id":"%d","name":"vps.example.com","type":"A","content":"%s","ttl":"300"}`, i+1, c)
			}
			storeMu.Unlock()
			time.Sleep(30 * time.Millisecond)
			fmt.Fprintf(w, `{"status":"SUCCESS","records":[%s]}`, strings.Join(rows, ","))
		case strings.HasPrefix(r.URL.Path, "/dns/create/"):
			var req struct {
				Content string `json:"content"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			storeMu.Lock()
			contents = append(contents, req.Content)
			storeMu.Unlock()
			fmt.Fprint(w, `{"status":"SUCCESS","id":"1"}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"status":"ERROR","message":"unexpected call"}`)
		}
	}))
	defer srv.Close()

	origEndpoint := porkbun.Endpoint
	porkbun.Endpoint = srv.URL
	defer func() { porkbun.Endpoint = origEndpoint }()
	pb := porkbun.New("test-key", "test-secret")

	emit := func(string, string) { /* progress events irrelevant here — only the record store matters */ }
	errs := make(chan error, 2)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		go func(ip string) {
			errs <- ensureRecord(context.Background(), pb, "A", "example.com", "vps", ip, emit)
		}(ip)
	}
	var failures int
	for range 2 {
		if err := <-errs; err != nil {
			failures++
			if !strings.Contains(err.Error(), "record(s) exist") {
				t.Errorf("unexpected error text: %v", err)
			}
		}
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	if len(contents) != 1 {
		t.Fatalf("record store holds %d records %v — the find→create race created a round-robin set", len(contents), contents)
	}
	if failures != 1 {
		t.Errorf("expected exactly one run to fail with a conflict, got %d failures", failures)
	}
}
