package bootstrap

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSudo emulates the sudo behaviors the wrapper depends on:
// `-n true` answers from ANSBUI_TEST_SUDO_MODE, `-n <cmd>` runs the
// command only in warm mode, and `-k -S -p ”` always reads exactly
// one password line from stdin before running the command — which is
// precisely the property the real `-k` provides.
const fakeSudo = `#!/bin/bash
mode="$ANSBUI_TEST_SUDO_MODE"
if [ "$1" = "-n" ] && [ "$2" = "true" ]; then
	[ "$mode" = "warm" ] && exit 0 || exit 1
fi
if [ "$1" = "-n" ]; then
	shift
	if [ "$mode" != "warm" ]; then echo "sudo: a password is required" >&2; exit 1; fi
	exec "$@"
fi
if [ "$1" = "-k" ] && [ "$2" = "-S" ] && [ "$3" = "-p" ]; then
	shift 4
	IFS= read -r pw
	if [ "$pw" != "$ANSBUI_TEST_SUDO_PW" ]; then echo "sudo: incorrect password attempt" >&2; exit 1; fi
	exec "$@"
fi
echo "fake sudo: unexpected args: $*" >&2
exit 97
`

// runWrapper executes sudoWrapper(cmd) under sh with the fake sudo
// first on PATH, feeding stdin exactly as runRoot would.
func runWrapper(t *testing.T, mode, sudoPW, cmd, stdin string) (string, string, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sudo"), []byte(fakeSudo), 0o755); err != nil {
		t.Fatalf("write fake sudo: %v", err)
	}
	c := exec.Command("sh", "-c", sudoWrapper(cmd))
	c.Env = append(os.Environ(),
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ANSBUI_TEST_SUDO_MODE="+mode,
		"ANSBUI_TEST_SUDO_PW=s3cret!",
	)
	c.Stdin = strings.NewReader(sudoPW + "\n" + stdin)
	var so, se bytes.Buffer
	c.Stdout = &so
	c.Stderr = &se
	err := c.Run()
	return so.String(), se.String(), err
}

// The inner command reads its own secret from stdin, exactly like the
// chpasswd feed during bootstrap. Whatever it reads first must be the
// payload — never the operator's sudo password.
const innerReadsSecret = `IFS= read -r first; printf 'inner-got:%s' "$first"`

func TestSudoWrapperColdCache(t *testing.T) {
	so, se, err := runWrapper(t, "cold", "s3cret!", innerReadsSecret, "payload\n")
	if err != nil {
		t.Fatalf("wrapper failed: %v (stderr: %s)", err, se)
	}
	if so != "inner-got:payload" {
		t.Errorf("inner command stdin desynced: %q", so)
	}
}

func TestSudoWrapperWarmCache(t *testing.T) {
	so, se, err := runWrapper(t, "warm", "s3cret!", innerReadsSecret, "payload\n")
	if err != nil {
		t.Fatalf("wrapper failed: %v (stderr: %s)", err, se)
	}
	if so != "inner-got:payload" {
		t.Errorf("inner command stdin desynced: %q", so)
	}
}

func TestSudoWrapperWrongPassword(t *testing.T) {
	_, se, err := runWrapper(t, "cold", "not-the-password", innerReadsSecret, "payload\n")
	if err == nil {
		t.Fatal("wrapper succeeded with wrong sudo password")
	}
	if !strings.Contains(se, "incorrect password") {
		t.Errorf("stderr lacks sudo's failure message: %q", se)
	}
}
