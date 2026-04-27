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
		t.Skip("bash not available")
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
		t.Skip("bash not available")
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
		t.Skip("bash not available")
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
