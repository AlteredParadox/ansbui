package ansible

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
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

// The tests below cover the temp file the atomic write goes through,
// and the exactness of the path the confinement check looks at. Each
// reproduces something another local user on the control node could
// do to the previous script.

// uploadInFlight starts the write script for dest with its stdin held
// open, feeds it `partial`, and waits for the temp file to appear. It
// returns the temp file's path and a finish func that sends `rest`,
// closes stdin and waits for the script.
func uploadInFlight(t *testing.T, dest, partial string) (tmpPath string, finish func(rest string) error) {
	t.Helper()
	cmd := exec.Command("bash", "-c", atomicWriteScript(dest))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	finish = func(rest string) error {
		_, _ = stdin.Write([]byte(rest))
		_ = stdin.Close()
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("%w (stderr=%q)", err, stderr.String())
		}
		return nil
	}
	if _, err := stdin.Write([]byte(partial)); err != nil {
		t.Fatal(err)
	}
	// The temp file exists once mktemp has run; its content arrives
	// when cat has read what we wrote.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		matches, _ := filepath.Glob(dest + ".tmp.*")
		if len(matches) == 1 {
			if data, _ := os.ReadFile(matches[0]); string(data) == partial {
				return matches[0], finish
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = finish("")
	t.Fatalf("no temp file with the partial content appeared next to %s", dest)
	return "", nil
}

// While a file is being uploaded its new content must not be readable
// by anyone the finished file would not be readable by. The temp file
// used to be created under the account's umask (typically 0644) and
// chmod'ed only at the end, so the new content of a 0600 vault or
// group_vars file was world-readable for the whole upload.
func TestAtomicWriteScript_TempFileIsPrivateDuringUpload(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip(bashNotAvailable)
	}
	// A permissive umask, as a login account commonly has. The script
	// must not depend on it. (Process-wide, hence no t.Parallel.)
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	for _, c := range []struct {
		name     string
		existing os.FileMode // 0 = destination does not exist yet
		want     os.FileMode // mode of the finished file
	}{
		{"existing 0600 file", 0o600, 0o600},
		{"existing 0640 file", 0o640, 0o640},
		{"new file", 0, 0o644},
	} {
		t.Run(c.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "secrets.yml")
			if c.existing != 0 {
				if err := os.WriteFile(dest, []byte("old\n"), c.existing); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dest, c.existing); err != nil { // WriteFile is subject to the umask
					t.Fatal(err)
				}
			}
			tmp, finish := uploadInFlight(t, dest, "ansible_become_pass: dummy-secret-1\n")
			st, err := os.Stat(tmp)
			if err != nil {
				_ = finish("")
				t.Fatal(err)
			}
			if st.Mode().Perm() != 0o600 {
				t.Errorf("temp file is %o during the upload, want 0600", st.Mode().Perm())
			}
			if err := finish("more: content\n"); err != nil {
				t.Fatalf("script failed: %v", err)
			}
			got, err := os.ReadFile(dest)
			if err != nil || string(got) != "ansible_become_pass: dummy-secret-1\nmore: content\n" {
				t.Fatalf("destination content %q, err %v", got, err)
			}
			if st, _ := os.Stat(dest); st.Mode().Perm() != c.want {
				t.Errorf("finished file is %o, want %o", st.Mode().Perm(), c.want)
			}
			if left, _ := filepath.Glob(dest + ".tmp.*"); len(left) != 0 {
				t.Errorf("temp file left behind: %v", left)
			}
		})
	}
}

// The temp file's name must not be guessable. It used to be
// `<dest>.tmp.<pid of the shell>`, opened with a plain redirection, so
// another user planted symlinks at that name for a range of upcoming
// pids: the upload was written through the link to a file of their
// choosing, that file was chmod'ed, and the link itself was renamed
// over the destination.
func TestAtomicWriteScript_PlantedTempSymlinkIsNotFollowed(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip(bashNotAvailable)
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "site.yml")
	victim := filepath.Join(t.TempDir(), "victim.conf")
	if err := os.WriteFile(victim, []byte("VICTIM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Every pid the shell could plausibly get next. If pid numbering
	// here is not sequential the plant misses and this test proves
	// nothing about the old script — but it can never fail the new
	// one for that reason.
	self := os.Getpid()
	for pid := self; pid < self+4000; pid++ {
		if err := os.Symlink(victim, dest+".tmp."+strconv.Itoa(pid)); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command("bash", "-c", atomicWriteScript(dest))
	cmd.Stdin = strings.NewReader("operator content\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}

	if got, _ := os.ReadFile(victim); string(got) != "VICTIM\n" {
		t.Errorf("the upload was written through a planted link: victim now holds %q", got)
	}
	if st, _ := os.Stat(victim); st.Mode().Perm() != 0o600 {
		t.Errorf("the victim file's mode was changed to %o", st.Mode().Perm())
	}
	fi, err := os.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("a planted link was renamed over the destination")
	}
	if got, _ := os.ReadFile(dest); string(got) != "operator content\n" {
		t.Errorf("destination content %q", got)
	}
}

// An early exit must not delete anything named by the environment the
// script inherited. The EXIT trap used to read $TMP before the script
// assigned it, and TMP is a conventional variable for the temp
// directory: with it exported, the symlink refusal ran `rm -f` on it
// (and exited 1 instead of 2 when it named a directory, which is how
// this was first noticed).
func TestAtomicWriteScript_EarlyExitIgnoresInheritedVariables(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip(bashNotAvailable)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.txt")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"TMP", "ANSBUI_TMPF"} {
		for _, kind := range []string{"file", "directory"} {
			t.Run(name+" names a "+kind, func(t *testing.T) {
				precious := filepath.Join(t.TempDir(), "precious")
				if kind == "file" {
					if err := os.WriteFile(precious, []byte("do not delete\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Mkdir(precious, 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("bash", "-c", atomicWriteScript(link)) // refused: destination is a symlink
				cmd.Env = append(os.Environ(), name+"="+precious)
				cmd.Stdin = strings.NewReader("x")
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				err := cmd.Run()
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
					t.Errorf("exit = %v, want 2 (stderr=%q)", err, stderr.String())
				}
				if _, err := os.Stat(precious); err != nil {
					t.Errorf("the %s named by $%s was removed: %v", kind, name, err)
				}
			})
		}
	}
}

// A directory at the destination is refused. `mv` without -T moved the
// temp file INTO it and reported success, so the save appeared to work
// and left `<name>.tmp.<pid>` inside the directory.
func TestAtomicWriteScript_DirectoryDestinationRefused(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip(bashNotAvailable)
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "group_vars")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	stderr, code := runConfined(t, atomicWriteScript(dest), "content\n")
	if code != 2 || !strings.Contains(stderr, "refusing to replace a directory") {
		t.Fatalf("exit %d (stderr=%q), want 2 with a refusal", code, stderr)
	}
	for _, d := range []string{dir, dest} {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.Contains(e.Name(), ".tmp.") {
				t.Errorf("temp file left in %s: %s", d, e.Name())
			}
		}
	}
}

// A failure after the temp file exists removes it.
func TestAtomicWriteScript_FailureRemovesTempFile(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip(bashNotAvailable)
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "site.yml")
	// A stat that reports a mode chmod will reject makes the script
	// fail between creating the temp file and renaming it.
	bin := t.TempDir()
	fakeStat := "#!/bin/sh\necho not-a-mode\n"
	if err := os.WriteFile(filepath.Join(bin, "stat"), []byte(fakeStat), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", atomicWriteScript(dest))
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Stdin = strings.NewReader("new\n")
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("script succeeded with an unusable mode:\n%s", out)
	}
	if got, _ := os.ReadFile(dest); string(got) != "old\n" {
		t.Errorf("destination changed by a failed write: %q", got)
	}
	if left, _ := filepath.Glob(dest + ".tmp.*"); len(left) != 0 {
		t.Errorf("temp file left behind after a failure: %v", left)
	}
}

// newlineFixture is a workDir holding a link whose TARGET is `second`
// followed by a newline (a name that does not exist), next to
// `second` itself: a link out of the tree. realpath resolves the
// first link to "<work>/second\n"; a command substitution that strips
// the newline turns that into "<work>/second", which the confinement
// check accepts and the following command follows out of the tree.
func newlineFixture(t *testing.T, first, second string, secondIsDir bool) confineFixture {
	t.Helper()
	f := newConfineFixture(t)
	if err := os.Symlink(second+"\n", filepath.Join(f.work, first)); err != nil {
		t.Fatalf("symlink with a newline in its target: %v", err)
	}
	outsideTarget := filepath.Join(f.outside, "secret.yml")
	if secondIsDir {
		outsideTarget = f.outside
	}
	if err := os.Symlink(outsideTarget, filepath.Join(f.work, second)); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestConfinedRead_NewlineSuffixedLinkTargetDoesNotEscape(t *testing.T) {
	t.Parallel()
	f := newlineFixture(t, "notes.yml", "real.yml", false)
	script := confineToWorkDirScript(f.work, "notes.yml") + `; cat -- "$TGT"`
	out, err := exec.Command("bash", "-c", script).CombinedOutput()
	if strings.Contains(string(out), "secret") {
		t.Fatalf("read escaped the workDir through a newline-suffixed link target: %q", out)
	}
	if err == nil {
		t.Fatalf("read of a path that resolves to a nonexistent name succeeded: %q", out)
	}
}

func TestConfinedWrite_NewlineSuffixedLinkTargetDoesNotEscape(t *testing.T) {
	t.Parallel()
	f := newlineFixture(t, "vars", "realdir", true)
	script := confineParentToWorkDirScript(f.work, "vars/new.yml") + `; ` + atomicWriteScriptFor(`"$TGT"`)
	stderr, code := runConfined(t, script, "operator content\n")
	if _, err := os.Stat(filepath.Join(f.outside, "new.yml")); !os.IsNotExist(err) {
		t.Fatalf("write escaped the workDir through a newline-suffixed link target (stat err %v)", err)
	}
	entries, _ := os.ReadDir(f.outside)
	if len(entries) != 1 { // secret.yml only
		t.Errorf("unexpected entries outside the workDir: %v", entries)
	}
	if code == 0 {
		t.Errorf("write into a directory that does not exist succeeded (stderr=%q)", stderr)
	}
}

// The exact-path capture must not change what an ordinary path
// resolves to, including names with spaces and a workDir reached
// through a symlink.
func TestConfinedPaths_OrdinaryNamesStillResolve(t *testing.T) {
	t.Parallel()
	f := newConfineFixture(t)
	sub := filepath.Join(f.work, "group vars")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "all in.yml"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(filepath.Dir(f.work), "work-alias")
	if err := os.Symlink(f.work, alias); err != nil {
		t.Fatal(err)
	}
	for _, wd := range []string{f.work, alias} {
		out, err := exec.Command("bash", "-c", confineToWorkDirScript(wd, "group vars/all in.yml")+`; cat -- "$TGT"`).CombinedOutput()
		if err != nil || string(out) != "hello\n" {
			t.Errorf("read via %s: %q, %v", wd, out, err)
		}
		script := confineParentToWorkDirScript(wd, "group vars/new one.yml") + `; ` + atomicWriteScriptFor(`"$TGT"`)
		if stderr, code := runConfined(t, script, "written\n"); code != 0 {
			t.Errorf("write via %s: exit %d (stderr=%q)", wd, code, stderr)
		}
		if got, _ := os.ReadFile(filepath.Join(sub, "new one.yml")); string(got) != "written\n" {
			t.Errorf("write via %s landed as %q", wd, got)
		}
	}
	// A missing workDir is still exit 3 with its own message.
	stderr, code := runConfined(t, confineToWorkDirScript(filepath.Join(f.work, "nope"), "a.yml"), "")
	if code != 3 || !strings.Contains(stderr, "workDir not found") {
		t.Errorf("missing workDir: exit %d (stderr=%q)", code, stderr)
	}
}
