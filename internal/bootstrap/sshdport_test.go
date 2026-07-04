package bootstrap

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSshdPortScriptSyntax checks the generated script is valid sh —
// the no-op guard is now a shell function plus a compound if joined
// into the "; "-separated one-liner, which is easy to break.
func TestSshdPortScriptSyntax(t *testing.T) {
	script := sshdPortScript(4242)
	cmd := exec.Command("sh", "-n", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated script is not valid sh: %v\n%s\nscript:\n%s", err, out, script)
	}
}

// TestSshdPortScriptNoOpGatedOnListener runs just the ground-truth
// guard (the lines up to the config edit) against a fake `ss`, proving
// the early exit follows the actual listener — a box whose config
// already says TARGET but whose listener is still on 22 must NOT
// early-exit (that half-flipped state is exactly what the socket
// remediation exists to fix).
func TestSshdPortScriptNoOpGatedOnListener(t *testing.T) {
	// The guard prelude: the listening() helper, HAVE_SS, and the
	// no-op decision — taken verbatim from the generated script so we
	// exercise the real logic, then a marker if it falls through.
	full := sshdPortScript(4242)
	guard := guardPrelude(t, full) + `; echo PROCEEDED`

	cases := []struct {
		name       string
		ssListens  string // what fake ss reports as the listening port
		wantExit0  bool
		wantOutput string
	}{
		{"listener already on target", "4242", true, "already listening"},
		{"config flipped but listener still on 22", "22", false, "PROCEEDED"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			// Fake ss prints one LISTEN line for the configured port.
			ss := "#!/bin/sh\necho 'LISTEN 0 128 0.0.0.0:" + c.ssListens + " 0.0.0.0:*'\n"
			if err := os.WriteFile(filepath.Join(dir, "ss"), []byte(ss), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "-c", guard)
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, _ := cmd.CombinedOutput()
			got := string(out)
			if !strings.Contains(got, c.wantOutput) {
				t.Errorf("output %q does not contain %q", got, c.wantOutput)
			}
			if c.wantExit0 && strings.Contains(got, "PROCEEDED") {
				t.Errorf("expected early no-op exit, but the script proceeded: %q", got)
			}
		})
	}
}

// guardPrelude extracts the "; "-joined statements of the generated
// script up to (but not including) the config-edit line, so a test can
// run the listener-based no-op decision in isolation without the edit
// touching /etc/ssh.
func guardPrelude(t *testing.T, script string) string {
	t.Helper()
	parts := strings.Split(script, "; ")
	for i, p := range parts {
		// The config-edit `if` head — the first statement after the
		// no-op guard. `grep -qE` (not the no-ss branch's `grep -hE`)
		// makes it unambiguous.
		if strings.Contains(p, "if grep -qE") && strings.Contains(p, "/etc/ssh/sshd_config") {
			return strings.Join(parts[:i], "; ")
		}
	}
	t.Fatalf("could not find config-edit boundary in script:\n%s", script)
	return ""
}
