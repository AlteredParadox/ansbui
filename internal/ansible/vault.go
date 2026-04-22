package ansible

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/AlteredParadox/relay/internal/config"
	"github.com/AlteredParadox/relay/internal/sshpool"
	"golang.org/x/crypto/ssh"
)

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
}

// ListVaultFiles walks the server's workDir and returns any YAML/YML
// (or extensionless) file whose first line starts with $ANSIBLE_VAULT.
// We use a single grep invocation rather than a find+cat loop to avoid
// a round-trip per candidate file.
func ListVaultFiles(ctx context.Context, pool *sshpool.Pool, srv config.Server) ([]VaultFile, error) {
	if srv.WorkDir == "" {
		return nil, errors.New("server has no workDir configured")
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return nil, err
	}
	// -l prints filenames; -r recurses; -m1 stops at first match per file;
	// -- stops flag parsing. We read the first line of each match to
	// grab the optional vault-id.
	cmd := fmt.Sprintf(
		"cd %s && grep -rlm1 -E '^\\$ANSIBLE_VAULT;[0-9]+\\.[0-9]+;' . 2>/dev/null || true",
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
		fmt.Fprintf(&b, "printf '>>%s\\n'; stat -c '%%s\\t%%Y' %s 2>/dev/null; head -n1 %s 2>/dev/null; ",
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
		switch step {
		case 0:
			// stat line: size<TAB>mtime
			parts := strings.SplitN(line, "\t", 2)
			if len(parts) == 2 {
				fmt.Sscanf(parts[0], "%d", &current.Size)
			}
			step = 1
		case 1:
			// header line: $ANSIBLE_VAULT;1.2;AES256;label
			fields := strings.Split(line, ";")
			if len(fields) >= 4 {
				current.VaultID = fields[3]
			}
			step = 2
		}
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
		`PASS=$(cat) && exec 3< <(cat <<< "$PASS") && ansible-vault view %s --vault-password-file=/dev/fd/3`,
		shellQuote(full),
	)
	return runVaultScript(cli, script, password)
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
		`PASS=$(cat) && exec 3< <(cat <<< "$PASS") && printf %%s %s | base64 -d | ansible-vault encrypt --output=%s --vault-password-file=/dev/fd/3 -`,
		shellQuote(b64),
		shellQuote(full),
	)
	if _, err := runVaultScript(cli, script, password); err != nil {
		return err
	}
	return nil
}

// runVaultScript opens a session, pipes the password into stdin, runs
// the supplied bash script and returns stdout / an error that carries
// stderr so the UI can surface "wrong password" messages.
func runVaultScript(cli *ssh.Client, script, password string) (string, error) {
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
	if err := sess.Run(cmd); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.String(), fmt.Errorf("ansible-vault: %s", msg)
	}
	return stdout.String(), nil
}
