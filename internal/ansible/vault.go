package ansible

import (
	"context"
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
// the ciphertext to rel, creating it if necessary. Both the password
// and plaintext travel over the session's stdin: line 1 is the
// password (consumed by `read -r`), the rest is the plaintext that
// `ansible-vault encrypt -` reads from stdin and writes (encrypted)
// to --output. This keeps the password out of argv and avoids the
// 128 KB MAX_ARG_STRLEN ceiling that an embedded base64 plaintext
// would hit on values larger than ~95 KB.
func WriteVault(ctx context.Context, pool *sshpool.Pool, srv config.Server, rel, password, plaintext string) error {
	if err := validateRelPath(rel); err != nil {
		return err
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return err
	}
	full := path.Join(srv.WorkDir, rel)
	script := fmt.Sprintf(
		`IFS= read -r PASS && exec 3< <(printf '%%s' "$PASS") && ansible-vault encrypt --output=%s --vault-password-file=/dev/fd/3 -`,
		shellQuote(full),
	)
	if _, err := runVaultScript(ctx, cli, script, password+"\n"+plaintext); err != nil {
		return err
	}
	return nil
}

// runVaultScript is a thin wrapper over runRemoteScript that prefixes
// errors with "ansible-vault:" so the UI surfaces vault-specific
// messages ("wrong password", "no vault secrets found") with their
// origin attached. `stdin` is the bytes piped to the bash script —
// for vault scripts this is typically the password (consumed by
// `PASS=$(cat)`) or the password followed by ciphertext / plaintext
// (split via `read -r`).
//
// Wraps ctx with vaultRunTimeout so a wedged ansible-vault
// invocation can't hang a UI request indefinitely. runRemoteScript
// no longer applies this bound itself — we own it at the vault
// boundary so atomic-write callers (provisioning) get the more
// generous remoteWriteTimeout instead.
func runVaultScript(ctx context.Context, cli *ssh.Client, script, stdin string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, vaultRunTimeout)
	defer cancel()
	stdout, stderr, err := runRemoteScript(ctx, cli, script, stdin)
	if err == nil {
		return stdout, nil
	}
	if stderr == "" {
		stderr = err.Error()
	}
	return stdout, fmt.Errorf("ansible-vault: %s", stderr)
}
