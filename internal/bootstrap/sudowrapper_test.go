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
// `-n true` answers from ANSBUI_TEST_SUDO_MODE; `-n <cmd>` runs only in
// warm mode; `-k -S -p ” -v` validates one password line; and
// `-k -S -p ” bash -c <cmd>` reads one password line then runs the
// command. Every password it reads is appended to ANSBUI_TEST_SUDO_LOG
// so a test can assert the inner command's stdin never reached sudo.
// Each invocation reads exactly one line — the property the real
// `-k -S` fed from a single-line pipe provides — so a wrong password
// hits EOF rather than consuming follow-on secrets.
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
	[ -n "$ANSBUI_TEST_SUDO_LOG" ] && printf '%s\n' "$pw" >> "$ANSBUI_TEST_SUDO_LOG"
	if [ "$pw" != "$ANSBUI_TEST_SUDO_PW" ]; then echo "sudo: incorrect password attempt" >&2; exit 1; fi
	if [ "$1" = "-v" ]; then exit 0; fi
	exec "$@"
fi
echo "fake sudo: unexpected args: $*" >&2
exit 97
`

// runWrapper executes sudoWrapper(cmd) under sh with the fake sudo
// first on PATH, feeding stdin exactly as runRoot would. Returns
// stdout, stderr, the passwords sudo saw (newline-joined), and the
// run error.
func runWrapper(t *testing.T, mode, sudoPW, cmd, stdin string) (stdout, stderr, sudoSaw string, err error) {
	t.Helper()
	dir := t.TempDir()
	if werr := os.WriteFile(filepath.Join(dir, "sudo"), []byte(fakeSudo), 0o755); werr != nil {
		t.Fatalf("write fake sudo: %v", werr)
	}
	logPath := filepath.Join(dir, "sudo-attempts.log")
	c := exec.Command("sh", "-c", sudoWrapper(cmd))
	c.Env = append(os.Environ(),
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ANSBUI_TEST_SUDO_MODE="+mode,
		"ANSBUI_TEST_SUDO_PW=s3cret!",
		"ANSBUI_TEST_SUDO_LOG="+logPath,
	)
	c.Stdin = strings.NewReader(sudoPW + "\n" + stdin)
	var so, se bytes.Buffer
	c.Stdout = &so
	c.Stderr = &se
	err = c.Run()
	saw, _ := os.ReadFile(logPath)
	return so.String(), se.String(), string(saw), err
}

// The inner command reads its own secret from stdin, exactly like the
// chpasswd feed during bootstrap. Whatever it reads first must be the
// payload — never the operator's sudo password.
const innerReadsSecret = `IFS= read -r first; printf 'inner-got:%s' "$first"`

// testPayload is the inner command's own stdin line — what chpasswd
// would read during a real bootstrap.
const testPayload = "payload\n"

func TestSudoWrapperColdCache(t *testing.T) {
	so, se, _, err := runWrapper(t, "cold", "s3cret!", innerReadsSecret, testPayload)
	if err != nil {
		t.Fatalf("wrapper failed: %v (stderr: %s)", err, se)
	}
	if so != "inner-got:payload" {
		t.Errorf("inner command stdin desynced: %q", so)
	}
}

func TestSudoWrapperWarmCache(t *testing.T) {
	so, se, _, err := runWrapper(t, "warm", "s3cret!", innerReadsSecret, testPayload)
	if err != nil {
		t.Fatalf("wrapper failed: %v (stderr: %s)", err, se)
	}
	if so != "inner-got:payload" {
		t.Errorf("inner command stdin desynced: %q", so)
	}
}

func TestSudoWrapperWrongPassword(t *testing.T) {
	// Distinctive payload so we can prove it never reached sudo.
	const secretPayload = "SUPER-SECRET-ANSIBLE-PW\n"
	_, se, sudoSaw, err := runWrapper(t, "cold", "not-the-password", innerReadsSecret, secretPayload)
	if err == nil {
		t.Fatal("wrapper succeeded with wrong sudo password")
	}
	if !strings.Contains(se, "incorrect password") {
		t.Errorf("stderr lacks sudo's failure message: %q", se)
	}
	// The validation gate must fail on the isolated password pipe
	// before the payload is ever piped to sudo — so the generated
	// ansible password can't be submitted to PAM as a retry attempt.
	if strings.Contains(sudoSaw, "SUPER-SECRET") {
		t.Errorf("payload leaked into a sudo password attempt: sudo saw %q", sudoSaw)
	}
	// Exactly one attempt: the wrong password, once.
	if got := strings.Count(strings.TrimSpace(sudoSaw), "\n"); got != 0 {
		t.Errorf("expected a single sudo password attempt, sudo saw %q", sudoSaw)
	}
}
