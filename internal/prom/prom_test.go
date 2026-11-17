package prom

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestInstantQueryCollapsesMultiTargetHost: a host scraped by several
// exporters yields one `up` row per port; after the port is stripped
// they share a host key and must collapse deterministically to "up if
// any target is up" — not last-write-wins on Prometheus row order.
func TestInstantQueryCollapsesMultiTargetHost(t *testing.T) {
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", "")
	// Same two targets, both orderings — the result must not depend on
	// which row Prometheus lists first.
	bodies := []string{
		`[{"metric":{"instance":"web1:9100"},"value":[0,"1"]},{"metric":{"instance":"web1:9115"},"value":[0,"0"]}]`,
		`[{"metric":{"instance":"web1:9115"},"value":[0,"0"]},{"metric":{"instance":"web1:9100"},"value":[0,"1"]}]`,
	}
	for _, rows := range bodies {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":%s}}`, rows)
		}))
		c, err := NewClient(srv.URL, "instance")
		if err != nil {
			srv.Close()
			t.Fatalf("NewClient: %v", err)
		}
		out, err := c.instantQuery(context.Background(), "up")
		srv.Close()
		if err != nil {
			t.Fatalf("instantQuery: %v", err)
		}
		if out["web1"] != 1 {
			t.Errorf("web1 up collapsed to %v, want 1 (up if any target up); rows=%s", out["web1"], rows)
		}
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

// promStub answers every query with an empty result and reports the
// Basic auth it was sent, if any.
type sentAuth struct {
	user, pass string
	ok         bool
}

func promStub(got chan<- sentAuth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		got <- sentAuth{u, p, ok}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	})
}

// TestURLCredentialsAreSentAsBasicAuth pins what happens to a
// user:password written into the Prometheus URL: the client keeps it
// and net/http turns it into an Authorization: Basic header on every
// query. That is why such a URL is accepted only with https (next
// test), and why the README says so.
func TestURLCredentialsAreSentAsBasicAuth(t *testing.T) {
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", "")
	got := make(chan sentAuth, 1)
	srv := httptest.NewTLSServer(promStub(got))
	defer srv.Close()
	// query runs "up" through a client that trusts the test server's
	// certificate; everything else is the client NewClient built.
	query := func(rawURL string) {
		t.Helper()
		c, err := NewClient(rawURL, "instance")
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		c.http.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
		if _, err := c.instantQuery(context.Background(), "up"); err != nil {
			t.Fatalf("instantQuery: %v", err)
		}
	}

	query(strings.Replace(srv.URL, "https://", "https://scraper:s3cret@", 1))
	if s := <-got; !s.ok || s.user != "scraper" || s.pass != "s3cret" {
		t.Fatalf("server saw basic auth %+v, want scraper / s3cret", s)
	}

	// Without credentials in the URL, none are sent.
	query(srv.URL)
	if s := <-got; s.ok {
		t.Fatalf("server saw basic auth %+v from a URL with no credentials", s)
	}
}

// TestNewClientRefusesCredentialsOverPlainHTTP: the settings endpoint
// refuses such a URL, but a config.json edited by hand, or saved
// before the rule existed, never goes through it. The client has to
// refuse too, before anything is sent.
func TestNewClientRefusesCredentialsOverPlainHTTP(t *testing.T) {
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", "")
	got := make(chan sentAuth, 1)
	srv := httptest.NewServer(promStub(got))
	defer srv.Close()

	for _, creds := range []string{"scraper:s3cret@", "scraper@", "@"} {
		_, err := NewClient(strings.Replace(srv.URL, "http://", "http://"+creds, 1), "instance")
		if err == nil {
			t.Fatalf("NewClient accepted %q over plain http", creds)
		}
		if !strings.Contains(err.Error(), "accepted only with https://") {
			t.Errorf("%q: unexpected error %v", creds, err)
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("error repeats the password: %v", err)
		}
	}
	select {
	case s := <-got:
		t.Fatalf("a request reached the server: %+v", s)
	default:
	}

	// The same server without credentials in the URL is still fine.
	c, err := NewClient(srv.URL, "instance")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.instantQuery(context.Background(), "up"); err != nil {
		t.Fatalf("instantQuery: %v", err)
	}
	if s := <-got; s.ok {
		t.Fatalf("server saw basic auth %+v from a URL with no credentials", s)
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

// TestPinnedDialContextRefusesMetadataAddress drives the transport
// end to end: a hostname that resolves to a cloud-metadata address
// must be refused at dial time, not merely at config time.
// CheckPromHost vets the name, but the default transport used to
// resolve and connect independently — so the value checked and the
// value dialed were never the same thing.
func TestPinnedDialContextRefusesMetadataAddress(t *testing.T) {
	// An IP literal takes the same validation path as a resolved
	// answer, so it exercises the policy without needing custom DNS.
	_, err := pinnedDialContext(context.Background(), "tcp", "169.254.169.254:80")
	if err == nil {
		t.Fatal("dialed the cloud-metadata address")
	}
	if !strings.Contains(err.Error(), "metadata") && !strings.Contains(err.Error(), "link-local") {
		t.Errorf("unexpected error, want a policy denial: %v", err)
	}

	if _, err := pinnedDialContext(context.Background(), "tcp", "169.254.1.1:9090"); err == nil {
		t.Error("dialed a link-local address")
	}
}

// The pin must not break the normal case: a reachable, policy-allowed
// address still connects.
func TestPinnedDialContextAllowsNormalTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		if c, aerr := ln.Accept(); aerr == nil {
			_ = c.Close()
		}
	}()

	conn, err := pinnedDialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("policy-allowed target refused: %v", err)
	}
	_ = conn.Close()
}

// And the CIDR pin, when set, is enforced at the socket boundary.
func TestPinnedDialContextHonoursCIDRPin(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	t.Setenv("ANSBUI_PROM_ALLOWED_CIDRS", "10.0.0.0/8")
	if _, err := pinnedDialContext(context.Background(), "tcp", ln.Addr().String()); err == nil {
		t.Fatal("loopback dialed despite a 10.0.0.0/8 pin")
	}
}
