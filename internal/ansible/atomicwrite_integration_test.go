package ansible

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// bashNotAvailable is the skip reason for tests that need a real
// bash to exercise the atomic-write script. Some minimal CI
// images (alpine, distroless) don't ship bash by default.
const bashNotAvailable = "bash not available"

// TestAtomicWriteScript_SymlinkRefusal exercises the bash script
// writeFileAtomicViaStdin hands to the remote shell, against a
// local bash. Two paths matter for the security boundary:
//
//   - destination is a symlink → refuse, exit 2, stderr message,
//     symlink target is unmodified.
//   - destination is a regular file or absent → succeed, content
//     replaces the destination atomically (same dev rename).
//
// We can't replicate the ssh.Session timing exactly, but the
// script is the load-bearing artifact: any change that lets a
// symlink survive the precondition check would be visible here.
func TestAtomicWriteScript_SymlinkRefusal(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip(bashNotAvailable)
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")

	originalContent := []byte("ORIGINAL CONTENT — must survive\n")
	if err := os.WriteFile(target, originalContent, 0o644); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	script := atomicWriteScript(link)
	cmd := exec.Command("bash", "-c", script)
	cmd.Stdin = strings.NewReader("ATTACKER CONTENT")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %v", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit code 2, got %d (stderr=%q)", exitErr.ExitCode(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "refusing to write through symlink") {
		t.Fatalf("expected refusal message, stderr=%q", stderr.String())
	}

	// Symlink target must be unchanged.
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if !bytes.Equal(got, originalContent) {
		t.Fatalf("symlink target was modified: got %q, want %q", got, originalContent)
	}
	// Symlink itself must still point to target.
	resolved, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if resolved != target {
		t.Fatalf("symlink redirected: got %q, want %q", resolved, target)
	}
}

// TestAtomicWriteScript_NewFile is the happy path: writing to a
// path that doesn't exist creates it 0644 with the supplied
// content via an atomic rename.
func TestAtomicWriteScript_NewFile(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip(bashNotAvailable)
	}

	dir := t.TempDir()
	dest := filepath.Join(dir, "new.txt")
	want := "fresh content\n"

	cmd := exec.Command("bash", "-c", atomicWriteScript(dest))
	cmd.Stdin = strings.NewReader(want)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != want {
		t.Fatalf("content mismatch: got %q want %q", got, want)
	}
	st, _ := os.Stat(dest)
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("new file mode = %o, want 0644", st.Mode().Perm())
	}
}

// TestAtomicWriteScript_PreservesMode is the second happy path:
// overwriting an existing file preserves its mode bits (so a
// previously-tightened 0600 file isn't relaxed by a vault rewrite).
func TestAtomicWriteScript_PreservesMode(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip(bashNotAvailable)
	}

	dir := t.TempDir()
	dest := filepath.Join(dir, "exists.txt")
	if err := os.WriteFile(dest, []byte("old"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cmd := exec.Command("bash", "-c", atomicWriteScript(dest))
	cmd.Stdin = strings.NewReader("new content")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}

	st, _ := os.Stat(dest)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode after rewrite = %o, want 0600 (preservation broken)", st.Mode().Perm())
	}
}

// The confinement tests below exercise the preamble against a local
// bash: a symlinked directory inside the workDir that points outside
// the tree must be refused (exit 3) for both reads and writes, an
// in-tree symlink destination must hit the writer's exit-2 refusal,
// and a normal in-tree path must still work. This is the
// physical-path check that validateRelPath's lexical rules can't
// provide. Shared layout comes from newConfineFixture; runConfined
// centralises the bash invocation.

// confineFixture is the on-disk layout: work/ (the confined tree,
// containing linkdir → outside/) and outside/ (holding secret.yml).
type confineFixture struct {
	work, outside string
}

func newConfineFixture(t *testing.T) confineFixture {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip(bashNotAvailable)
	}
	dir := t.TempDir()
	f := confineFixture{work: filepath.Join(dir, "work"), outside: filepath.Join(dir, "outside")}
	for _, d := range []string{f.work, f.outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.Symlink(f.outside, filepath.Join(f.work, "linkdir")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.outside, "secret.yml"), []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return f
}

// runConfined executes script under bash with the given stdin and
// returns stderr plus the exit code (0 = success).
func runConfined(t *testing.T, script, stdin string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", "-c", script)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stderr.String(), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("bash did not run: %v", err)
	}
	return stderr.String(), exitErr.ExitCode()
}

// Write through the symlinked dir → refused, nothing lands outside.
func TestConfinedWrite_SymlinkedDirEscapeRefused(t *testing.T) {
	t.Parallel()
	f := newConfineFixture(t)
	script := confineParentToWorkDirScript(f.work, "linkdir/evil.yml") + `; ` + atomicWriteScriptFor(`"$TGT"`)
	stderr, code := runConfined(t, script, "pwned")
	if code != 3 || !strings.Contains(stderr, "outside the configured workDir") {
		t.Fatalf("expected exit 3 with confinement message, got %d (stderr=%q)", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(f.outside, "evil.yml")); !os.IsNotExist(err) {
		t.Fatal("write escaped the workDir through the symlinked directory")
	}
}

// Read through the symlinked dir → refused too.
func TestConfinedRead_SymlinkedDirEscapeRefused(t *testing.T) {
	t.Parallel()
	f := newConfineFixture(t)
	script := confineToWorkDirScript(f.work, "linkdir/secret.yml") + `; cat -- "$TGT"`
	out, err := exec.Command("bash", "-c", script).CombinedOutput()
	if err == nil || strings.Contains(string(out), "secret") {
		t.Fatalf("read escaped the workDir: err=%v out=%q", err, out)
	}
}

// A final-component symlink (even fully in-tree) must hit the
// writer's exit-2 refusal, not be resolved and followed — the
// parent-only confinement is what keeps [ -L "$TGT" ] honest.
func TestConfinedWrite_InTreeSymlinkDestinationRefused(t *testing.T) {
	t.Parallel()
	f := newConfineFixture(t)
	target := filepath.Join(f.work, "real.yml")
	if err := os.WriteFile(target, []byte("keep me\n"), 0o644); err != nil {
		t.Fatalf("seed in-tree target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(f.work, "alias.yml")); err != nil {
		t.Fatalf("in-tree symlink: %v", err)
	}
	script := confineParentToWorkDirScript(f.work, "alias.yml") + `; ` + atomicWriteScriptFor(`"$TGT"`)
	stderr, code := runConfined(t, script, "clobber")
	if code != 2 {
		t.Fatalf("expected exit 2 for in-tree symlink destination, got %d (stderr=%q)", code, stderr)
	}
	if got, _ := os.ReadFile(target); string(got) != "keep me\n" {
		t.Fatalf("in-tree symlink target was modified: %q", got)
	}
}

// Plain in-tree write (including a new file in a real subdir) works.
func TestConfinedWrite_InTreeSucceeds(t *testing.T) {
	t.Parallel()
	f := newConfineFixture(t)
	if err := os.MkdirAll(filepath.Join(f.work, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	script := confineParentToWorkDirScript(f.work, "sub/ok.yml") + `; ` + atomicWriteScriptFor(`"$TGT"`)
	if stderr, code := runConfined(t, script, "fine\n"); code != 0 {
		t.Fatalf("in-tree write failed: exit %d (stderr=%q)", code, stderr)
	}
	got, err := os.ReadFile(filepath.Join(f.work, "sub", "ok.yml"))
	if err != nil || string(got) != "fine\n" {
		t.Fatalf("in-tree write content: %q err=%v", got, err)
	}
}
