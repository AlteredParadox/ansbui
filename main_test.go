package main

import (
	"bytes"
	"log"
	"path/filepath"
	"strings"
	"testing"
)

// The credential must resolve next to config.json (so ANSBUI_CONFIG
// alone is enough for -set-password), and ANSBUI_AUTH_CREDENTIAL must
// override it outright.
func TestCredentialPath(t *testing.T) {
	t.Run("derives from the config dir", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.json")
		t.Setenv("ANSBUI_CONFIG", cfg)
		t.Setenv("ANSBUI_AUTH_CREDENTIAL", "")
		got, err := credentialPath()
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(dir, "auth_credential"); got != want {
			t.Fatalf("credentialPath = %q, want %q", got, want)
		}
	})

	t.Run("explicit override wins", func(t *testing.T) {
		t.Setenv("ANSBUI_CONFIG", "/somewhere/config.json")
		t.Setenv("ANSBUI_AUTH_CREDENTIAL", "/custom/cred")
		got, err := credentialPath()
		if err != nil {
			t.Fatal(err)
		}
		if got != "/custom/cred" {
			t.Fatalf("credentialPath = %q, want /custom/cred", got)
		}
	})
}

// ANSBUI_AUTH_REQUIRED accepts the same truthy values as
// ANSBUI_INSECURE_SSH; anything else keeps the historical
// fail-open-on-missing-credential behaviour.
func TestAuthRequired(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want bool
	}{
		{"1", true}, {"true", true}, {"TRUE", true}, {" true ", true},
		{"", false}, {"0", false}, {"no", false}, {"yes", false},
	} {
		t.Setenv("ANSBUI_AUTH_REQUIRED", tc.v)
		if got := authRequired(); got != tc.want {
			t.Fatalf("authRequired with %q = %v, want %v", tc.v, got, tc.want)
		}
	}
}

// The startup rule for built-in login: no password means no start,
// unless the operator opted out; ANSBUI_AUTH_REQUIRED beats the
// opt-out.
func TestDecideAuthPosture(t *testing.T) {
	const cred = "/data/auth_credential"
	for _, tc := range []struct {
		name                        string
		hasCred, allow, required    bool
		wantFatal, wantNoticeSubstr string
	}{
		{name: "password set", hasCred: true, wantNoticeSubstr: "login required"},
		{name: "password set, auth required", hasCred: true, required: true, wantNoticeSubstr: "login required"},
		{name: "password set but opt-out left in the unit", hasCred: true, allow: true, wantNoticeSubstr: "Remove it"},
		{name: "no password", wantFatal: "refusing to start"},
		{name: "no password, opted out", allow: true, wantNoticeSubstr: "WITHOUT built-in login"},
		{name: "no password, auth required", required: true, wantFatal: "ANSBUI_AUTH_REQUIRED is set"},
		{name: "no password, opted out, auth required wins", allow: true, required: true, wantFatal: "ANSBUI_AUTH_REQUIRED is set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := decideAuthPosture(tc.hasCred, tc.allow, tc.required, cred)
			if tc.wantFatal == "" {
				if got.fatal != "" {
					t.Fatalf("refused to start: %s", got.fatal)
				}
				if !strings.Contains(got.notice, tc.wantNoticeSubstr) {
					t.Fatalf("notice = %q, want it to contain %q", got.notice, tc.wantNoticeSubstr)
				}
				return
			}
			if !strings.Contains(got.fatal, tc.wantFatal) {
				t.Fatalf("fatal = %q, want it to contain %q", got.fatal, tc.wantFatal)
			}
			if got.notice != "" {
				t.Fatalf("a refusal also carries a start-up notice: %q", got.notice)
			}
			if !strings.Contains(got.fatal, cred) {
				t.Fatalf("refusal does not name the credential path: %q", got.fatal)
			}
		})
	}
	// The plain refusal tells the operator both ways out, and why the
	// second one is narrow.
	msg := decideAuthPosture(false, false, false, cred).fatal
	for _, want := range []string{"-set-password", "-allow-unauthenticated", allowUnauthenticatedEnv + "=1", "local connections"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not mention %q: %s", want, msg)
		}
	}
	// The opted-out notice says who can reach the port.
	if msg := decideAuthPosture(false, true, false, cred).notice; !strings.Contains(msg, "every user and process on this host") {
		t.Errorf("opt-out notice does not say local users can connect: %s", msg)
	}
}

// The opt-out variable accepts exactly the values the other on/off
// variables do; a near miss leaves ansbui refusing to start.
func TestEnvTrue(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want bool
	}{
		{"1", true}, {"true", true}, {"True", true}, {" 1 ", true},
		{"", false}, {"0", false}, {"false", false}, {"yes", false}, {"on", false}, {"2", false},
	} {
		t.Setenv(allowUnauthenticatedEnv, tc.v)
		if got := envTrue(allowUnauthenticatedEnv); got != tc.want {
			t.Fatalf("envTrue with %q = %v, want %v", tc.v, got, tc.want)
		}
	}
}

// captureLog runs fn and returns what it wrote to the standard logger.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	fn()
	return buf.String()
}

// The postures that do start are announced in the log.
func TestAnnounceAuthPostureLogsTheStartingPosture(t *testing.T) {
	t.Setenv("ANSBUI_AUTH_REQUIRED", "")
	if out := captureLog(t, func() { announceAuthPosture(true, false, "/data/auth_credential") }); !strings.Contains(out, "login required") {
		t.Fatalf("with a password: %q", out)
	}
	if out := captureLog(t, func() { announceAuthPosture(false, true, "/data/auth_credential") }); !strings.Contains(out, "WITHOUT built-in login") {
		t.Fatalf("opted out: %q", out)
	}
}

// A listen address beyond loopback is called out, with or without a
// password; a loopback one is not.
func TestWarnIfExposed(t *testing.T) {
	for _, tc := range []struct {
		addr        string
		authEnabled bool
		want        string
	}{
		{"127.0.0.1:8787", false, ""},
		{"[::1]:8787", true, ""},
		{"localhost:8787", false, ""},
		{"not a host port", false, ""},
		{"0.0.0.0:8787", true, "built-in login enabled"},
		{":8787", false, "NO login password"},
		{"192.0.2.10:8787", false, "NO login password"},
		{"[::]:8787", true, "built-in login enabled"},
	} {
		out := captureLog(t, func() { warnIfExposed(tc.addr, tc.authEnabled) })
		if tc.want == "" && out != "" {
			t.Errorf("warnIfExposed(%q) logged %q, want nothing", tc.addr, out)
		}
		if tc.want != "" && !strings.Contains(out, tc.want) {
			t.Errorf("warnIfExposed(%q, auth=%v) logged %q, want it to contain %q", tc.addr, tc.authEnabled, out, tc.want)
		}
	}
}
