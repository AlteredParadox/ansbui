package prom

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostFromLabel(t *testing.T) {
	const (
		fqdnHost = "web1.example.com"
		v6Host   = "2001:db8::1"
	)
	cases := []struct {
		in   string
		want string
	}{
		{"web1.example.com:9100", fqdnHost},
		{fqdnHost, fqdnHost},
		{"203.0.113.7:9100", "203.0.113.7"},
		{"[2001:db8::1]:9100", v6Host},
		{"[2001:db8::2]:9100", "2001:db8::2"}, // must not collide with ::1
		{v6Host, v6Host},                      // bare v6, no port
		{"[2001:db8::1]", v6Host},             // bracketed, no port
		{"", ""},
	}
	for _, c := range cases {
		got := hostFromLabel(map[string]string{"instance": c.in}, "instance")
		if got != c.want {
			t.Errorf("hostFromLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestClampPercentNaN(t *testing.T) {
	if got := clampPercent(math.NaN()); got != 0 {
		t.Errorf("clampPercent(NaN) = %d, want 0", got)
	}
}

// TestInstantQuerySkipsNaNAndInf: MemTotal=0 turns the mem expression
// into NaN, which Prometheus serialises verbatim — those samples must
// be dropped, not converted to garbage integers.
func TestInstantQuerySkipsNaNAndInf(t *testing.T) {
	// Hermetic: an allowlist in the dev environment would reject the
	// loopback httptest URL.
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"instance":"good:9100"},"value":[0,"42.5"]},
			{"metric":{"instance":"nan:9100"},"value":[0,"NaN"]},
			{"metric":{"instance":"inf:9100"},"value":[0,"+Inf"]}
		]}}`)
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL, "instance")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	out, err := c.instantQuery(context.Background(), "whatever")
	if err != nil {
		t.Fatalf("instantQuery: %v", err)
	}
	if v, ok := out["good"]; !ok || v != 42.5 {
		t.Errorf("good sample missing/wrong: %v", out)
	}
	for _, host := range []string{"nan", "inf"} {
		if _, ok := out[host]; ok {
			t.Errorf("%s sample should have been skipped, got %v", host, out[host])
		}
	}
}

// TestNewClientEnforcesSSRFAllowlist: the settings endpoint validates
// at write time, but a hand-edited config.json bypasses it — the
// fetch-time client must apply the same allowlist.
func TestNewClientEnforcesSSRFAllowlist(t *testing.T) {
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", "")
	if _, err := NewClient("http://169.254.169.254", "instance"); err == nil {
		t.Error("IMDS address must be rejected at fetch time")
	}
	if _, err := NewClient("http://10.0.0.5:9090", "instance"); err == nil {
		t.Error("non-loopback host must be rejected without an allowlist entry")
	}
	if _, err := NewClient("http://127.0.0.1:9090", "instance"); err != nil {
		t.Errorf("loopback must stay allowed, got: %v", err)
	}
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", "prom.internal:9090")
	if _, err := NewClient("http://prom.internal:9090", "instance"); err != nil {
		t.Errorf("allowlisted host rejected: %v", err)
	}
}
