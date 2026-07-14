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
