package ansible

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
	"golang.org/x/crypto/ssh"
)

// vaultRunTimeout bounds a single ansible-vault invocation.
// Generous enough for large encrypted files on a slow link, but
// bounded so a stuck remote shell can't hang the request forever.
const vaultRunTimeout = 30 * time.Second

// VaultFile is the summary shape the UI consumes for the vault list.
// Only metadata — no decrypted content — is returned by list calls.
type VaultFile struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	Size     int    `json:"size,omitempty"`
	Modified string `json:"modified,omitempty"`
	// VaultID is the optional label encoded in the header of
	// $ANSIBLE_VAULT;1.2;AES256;<id>. Empty for 1.1 headers.
	VaultID string `json:"vaultId,omitempty"`
	// Kind is "whole" for files encrypted end-to-end with
	// `ansible-vault encrypt`, or "inline" for plain YAML files that
	// embed `!vault |` per-value encryption (typical in group_vars /
	// host_vars). ansible-vault view only works on whole-file vaults;
	// the UI uses Kind to adjust the dialog copy and avoid calling
	// view on an inline file.
	Kind string `json:"kind,omitempty"`
}

// ListVaultFiles walks the server's workDir and returns any file that
// contains a $ANSIBLE_VAULT header — either at the start of a line
// (whole-file encrypted) or on an indented line following `!vault |`
// (per-value encrypted group_vars / host_vars). One grep invocation
// catches both; annotateVaultFiles then looks at each match's first
// line to decide the Kind.
func ListVaultFiles(ctx context.Context, pool *sshpool.Pool, srv config.Server) ([]VaultFile, error) {
	if srv.WorkDir == "" {
		return nil, errors.New("server has no workDir configured")
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return nil, err
	}
	// -l prints filenames; -r recurses; -m1 stops at first match per file.
	// Leading [[:space:]]* allows the $ANSIBLE_VAULT marker to appear
	// indented (under `!vault |`), not only at column 0.
	cmd := fmt.Sprintf(
		"cd %s && grep -rlm1 -E '^[[:space:]]*\\$ANSIBLE_VAULT;[0-9]+\\.[0-9]+;' . 2>/dev/null || true",
		shellQuote(srv.WorkDir),
	)
	stdout, _, err := sshpool.Run(cli, cmd)
	if err != nil {
		return nil, fmt.Errorf("list vault files: %w", err)
	}
	paths := strings.Split(strings.TrimSpace(stdout), "\n")
	out := make([]VaultFile, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(strings.TrimPrefix(p, "./"))
		if p == "" {
			continue
		}
		out = append(out, VaultFile{
			Path: p,
			Name: path.Base(p),
		})
	}
	annotateVaultFiles(ctx, pool, srv, out)
	return out, nil
}

// annotateVaultFiles best-effort enriches each entry with its size,
// mtime, and vault-id label in one batch stat + head call.
func annotateVaultFiles(ctx context.Context, pool *sshpool.Pool, srv config.Server, files []VaultFile) {
	if len(files) == 0 {
		return
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "cd %s && ", shellQuote(srv.WorkDir))
	for _, f := range files {
		// stat doesn't interpret \t in -c format strings, so use a
		// space separator — unambiguous for "size mtime".
		fmt.Fprintf(&b, "printf '>>%s\\n'; stat -c '%%s %%Y' %s 2>/dev/null; head -n1 %s 2>/dev/null; ",
			f.Path, shellQuote(f.Path), shellQuote(f.Path))
	}
	stdout, _, err := sshpool.Run(cli, b.String())
	if err != nil {
		return
	}
	parseVaultAnnotations(stdout, files)
}

func parseVaultAnnotations(stdout string, files []VaultFile) {
	byPath := make(map[string]*VaultFile, len(files))
	for i := range files {
		byPath[files[i].Path] = &files[i]
	}
	var current *VaultFile
	var step int
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, ">>") {
			current = byPath[strings.TrimPrefix(line, ">>")]
			step = 0
			continue
		}
		if current == nil {
			continue
		}
		applyAnnotationLine(current, step, line)
		step++
	}
}

// applyAnnotationLine is dispatched from parseVaultAnnotations so the
// outer loop stays flat (Sonar go:S3776). step 0 = stat output, step
// 1 = first line of the file; anything beyond is ignored.
func applyAnnotationLine(v *VaultFile, step int, line string) {
	switch step {
	case 0:
		readStatLine(v, line)
	case 1:
		readFirstContentLine(v, line)
	}
}

// readStatLine parses "<size> <mtime>" — stat -c doesn't interpret
// backslash escapes, so the separator is a literal space.
func readStatLine(v *VaultFile, line string) {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) == 0 {
		return
	}
	fmt.Sscanf(parts[0], "%d", &v.Size)
}

// readFirstContentLine classifies the file as whole-file vs inline
// vault, and pulls the optional vault-id out of a whole-file header.
func readFirstContentLine(v *VaultFile, line string) {
	if !strings.HasPrefix(line, "$ANSIBLE_VAULT;") {
		v.Kind = "inline"
		return
	}
	v.Kind = "whole"
	fields := strings.Split(line, ";")
	if len(fields) >= 4 {
		v.VaultID = fields[3]
	}
}

// ViewVault decrypts the file at rel using the given password and
// returns the plaintext. The password never appears in argv (it goes
// via stdin into a bash `cat <<<` + process-substitution fd) and is
// not written to disk.
func ViewVault(ctx context.Context, pool *sshpool.Pool, srv config.Server, rel, password string) (string, error) {
	if err := validateRelPath(rel); err != nil {
		return "", err
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return "", err
	}
	full := path.Join(srv.WorkDir, rel)
	script := fmt.Sprintf(
		`PASS=$(cat) && exec 3< <(printf '%%s' "$PASS") && ansible-vault view %s --vault-password-file=/dev/fd/3`,
		shellQuote(full),
	)
	return runVaultScript(ctx, cli, script, password)
}

// WriteVault encrypts plaintext with the supplied password and writes
// the ciphertext to rel, creating it if necessary. Plaintext is
// base64-encoded inline in the shell command (not via stdin — stdin
// carries the password) to keep the two channels separate.
func WriteVault(ctx context.Context, pool *sshpool.Pool, srv config.Server, rel, password, plaintext string) error {
	if err := validateRelPath(rel); err != nil {
		return err
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return err
	}
	full := path.Join(srv.WorkDir, rel)
	b64 := base64.StdEncoding.EncodeToString([]byte(plaintext))
	script := fmt.Sprintf(
		`PASS=$(cat) && exec 3< <(printf '%%s' "$PASS") && printf %%s %s | base64 -d | ansible-vault encrypt --output=%s --vault-password-file=/dev/fd/3 -`,
		shellQuote(b64),
		shellQuote(full),
	)
	if _, err := runVaultScript(ctx, cli, script, password); err != nil {
		return err
	}
	return nil
}

// runVaultScript opens a session, pipes the password into stdin, runs
// the supplied bash script and returns stdout / an error that carries
// stderr so the UI can surface "wrong password" messages. The run is
// bounded by ctx and an internal timeout so a stuck remote shell
// won't hang the request.
func runVaultScript(ctx context.Context, cli *ssh.Client, script, password string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, vaultRunTimeout)
	defer cancel()
	sess, err := cli.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	sess.Stdin = bytes.NewBufferString(password)
	// bash is required for <(...) process substitution. /usr/bin/env
	// resolves whichever bash is on PATH on the remote.
	cmd := "/usr/bin/env bash -c " + shellQuote(script)
	if err := sess.Start(cmd); err != nil {
		return "", fmt.Errorf("start ansible-vault: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			return stdout.String(), fmt.Errorf("ansible-vault: %s", msg)
		}
		return stdout.String(), nil
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGTERM)
		// Belt and suspenders: if the remote ignores SIGTERM we'd
		// park forever on <-done. Forcibly close the session after a
		// short grace so Wait() returns.
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = sess.Close()
			<-done
		}
		return stdout.String(), fmt.Errorf("ansible-vault: %w", ctx.Err())
	}
}
