package main

import (
	"path/filepath"
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
