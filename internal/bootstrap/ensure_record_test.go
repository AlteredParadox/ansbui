package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
