package ansible

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
	"golang.org/x/crypto/ssh"
)

// InlineVaultKey describes a `key: !vault |` block found inside an
// inline vault file. The line range is 1-indexed and inclusive on both
// ends — StartLine points at the `key: !vault |` line, EndLine at the
// final hex line of the ciphertext.
type InlineVaultKey struct {
	Name      string `json:"name"`
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine"`
}

// inlineKeyHeaderRE matches the `key: !vault |` opening line. The name
// is captured for the parser; argKeyRE validates user-supplied names
// before they reach the shell, so the same character class is used
// here for symmetry.
var inlineKeyHeaderRE = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*):\s*!vault\s*\|\s*$`)

// parseInlineVaultKeys walks the file content one line at a time,
// recording each `!vault |` block. The block's payload is the
// indented ciphertext lines that follow the header; a line that is
// blank or starts at column zero ends the block.
func parseInlineVaultKeys(content string) []InlineVaultKey {
	lines := strings.Split(content, "\n")
	var keys []InlineVaultKey
	i := 0
	for i < len(lines) {
		m := inlineKeyHeaderRE.FindStringSubmatch(lines[i])
		if m == nil {
			i++
			continue
		}
		header := i // 0-indexed
		end := header
		j := header + 1
		for j < len(lines) && len(lines[j]) > 0 && (lines[j][0] == ' ' || lines[j][0] == '\t') {
			end = j
			j++
		}
		keys = append(keys, InlineVaultKey{
			Name:      m[1],
			StartLine: header + 1,
			EndLine:   end + 1,
		})
		i = j
	}
	return keys
}

// extractCiphertext returns the dedented ciphertext for one key —
// joined by newlines, with leading whitespace stripped per line so
// `ansible-vault decrypt -` can read it as a standalone payload.
func extractCiphertext(content string, key InlineVaultKey) string {
	lines := strings.Split(content, "\n")
	if key.StartLine >= key.EndLine {
		return ""
	}
	body := lines[key.StartLine:key.EndLine]
	out := make([]string, 0, len(body))
	for _, ln := range body {
		out = append(out, strings.TrimSpace(ln))
	}
	return strings.Join(out, "\n")
}

// readRemoteFile reads the file at rel (relative to srv.WorkDir) over
// SSH. No decryption — just a `cat`. Used to grab inline vault files
// for parsing and patching.
func readRemoteFile(ctx context.Context, pool *sshpool.Pool, srv config.Server, rel string) (string, error) {
	if err := validateRelPath(rel); err != nil {
		return "", err
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return "", err
	}
	full := path.Join(srv.WorkDir, rel)
	cmd := fmt.Sprintf("cat %s", shellQuote(full))
	stdout, stderr, err := sshpool.Run(cli, cmd)
	if err != nil {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("read %s: %s", rel, msg)
	}
	return stdout, nil
}

// ListInlineVaultKeys reads the file and returns every key whose value
// is a `!vault |` block. Plain (cleartext) keys are deliberately
// ignored — those don't need a UI editor since they're already
// readable by anyone with shell access.
func ListInlineVaultKeys(ctx context.Context, pool *sshpool.Pool, srv config.Server, rel string) ([]InlineVaultKey, error) {
	content, err := readRemoteFile(ctx, pool, srv, rel)
	if err != nil {
		return nil, err
	}
	return parseInlineVaultKeys(content), nil
}

// DecryptInlineVaultValue extracts the ciphertext for varName from the
// inline file at rel and pipes it through `ansible-vault decrypt`.
// The password is sent as the first line of stdin, the ciphertext
// follows; the bash wrapper splits them via `read -r`.
func DecryptInlineVaultValue(ctx context.Context, pool *sshpool.Pool, srv config.Server, rel, varName, password string) (string, error) {
	if err := validateRelPath(rel); err != nil {
		return "", err
	}
	if !argKeyRE.MatchString(varName) {
		return "", fmt.Errorf("invalid var name %q (must match %s)", varName, argKeyRE)
	}
	content, err := readRemoteFile(ctx, pool, srv, rel)
	if err != nil {
		return "", err
	}
	keys := parseInlineVaultKeys(content)
	var key *InlineVaultKey
	for i := range keys {
		if keys[i].Name == varName {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		return "", fmt.Errorf("no inline vault key %q in %s", varName, rel)
	}
	cipher := extractCiphertext(content, *key)
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return "", err
	}
	// First line of stdin → PASS via `read -r`. Remainder is the
	// ciphertext that ansible-vault decrypt reads from `-`.
	script := `IFS= read -r PASS && exec 3< <(printf '%s' "$PASS") && ansible-vault decrypt --vault-password-file=/dev/fd/3 --output=- -`
	plaintext, err := runVaultScript(ctx, cli, script, password+"\n"+cipher)
	if err != nil {
		return "", err
	}
	// ansible-vault decrypt --output=- prints the plaintext exactly as
	// it was when encrypt_string was called: no trailing newline added.
	return plaintext, nil
}

// UpsertInlineVaultValue encrypts plaintext under varName with the
// supplied password and either replaces an existing `!vault |` block
// of the same name or appends a new one. The rest of the file —
// comments, cleartext keys, blank lines — is preserved verbatim.
func UpsertInlineVaultValue(ctx context.Context, pool *sshpool.Pool, srv config.Server, rel, varName, plaintext, password string) error {
	if err := validateRelPath(rel); err != nil {
		return err
	}
	if !argKeyRE.MatchString(varName) {
		return fmt.Errorf("invalid var name %q (must match %s)", varName, argKeyRE)
	}
	if password == "" {
		return fmt.Errorf("password is required")
	}
	content, err := readRemoteFile(ctx, pool, srv, rel)
	if err != nil {
		return err
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return err
	}
	// Same stdin trick as decrypt: line 1 is the password, the rest is
	// the plaintext to encrypt. encrypt_string writes a YAML snippet
	// of the form "<varname>: !vault |\n  $ANSIBLE_VAULT;...\n  ...".
	script := fmt.Sprintf(
		`IFS= read -r PASS && exec 3< <(printf '%%s' "$PASS") && ansible-vault encrypt_string --vault-password-file=/dev/fd/3 --stdin-name=%s`,
		shellQuote(varName),
	)
	snippet, err := runVaultScript(ctx, cli, script, password+"\n"+plaintext)
	if err != nil {
		return err
	}
	snippet = strings.TrimRight(snippet, "\n")
	if snippet == "" {
		return fmt.Errorf("encrypt_string returned empty output")
	}
	newContent := spliceInlineSnippet(content, varName, snippet)
	return writeInlineVaultFile(ctx, cli, srv, rel, newContent)
}

// spliceInlineSnippet returns content with the !vault | block for
// varName replaced by snippet, or — if no such block exists — with
// snippet appended. snippet is expected to be the verbatim output of
// `ansible-vault encrypt_string` (already starts with "<name>: !vault |").
func spliceInlineSnippet(content, varName, snippet string) string {
	keys := parseInlineVaultKeys(content)
	var existing *InlineVaultKey
	for i := range keys {
		if keys[i].Name == varName {
			existing = &keys[i]
			break
		}
	}
	if existing != nil {
		lines := strings.Split(content, "\n")
		var b strings.Builder
		if existing.StartLine > 1 {
			b.WriteString(strings.Join(lines[:existing.StartLine-1], "\n"))
			b.WriteString("\n")
		}
		b.WriteString(snippet)
		if existing.EndLine < len(lines) {
			b.WriteString("\n")
			b.WriteString(strings.Join(lines[existing.EndLine:], "\n"))
		}
		return b.String()
	}
	trimmed := strings.TrimRight(content, "\n")
	if trimmed == "" {
		return snippet + "\n"
	}
	return trimmed + "\n" + snippet + "\n"
}

// writeInlineVaultFile ships content to the remote and atomically
// replaces the file at rel. Hardening:
//   - File content streams over the SSH session's stdin and lands
//     via `cat > "$TMP"`, NOT base64-embedded in argv. Linux's
//     MAX_ARG_STRLEN caps each argv element at 128 KB (PAGE_SIZE × 32),
//     so a base64-in-argv approach would silently fail at the
//     rewrite step on payloads larger than ~95 KB. Stdin has no such
//     bound.
//   - `set -eo pipefail` so a failure inside any pipeline stops the
//     chain instead of falling through to chmod+mv.
//   - EXIT trap removes the tempfile if anything aborts midway (other
//     than SIGKILL, which bash can't catch) so a partial `*.tmp.$$`
//     doesn't linger in the operator's workdir.
//   - `[ -L "$FULL" ]` refuses to write when the destination is a
//     symlink. rename(2) doesn't follow symlinks at the destination —
//     it replaces the link itself with the source file — so this isn't
//     a "stop mv from clobbering the symlink target" guard. It's
//     defense-in-depth: an honest-mistake symlink in the workdir
//     would otherwise be silently destroyed and replaced with a
//     regular file. A determined local racer can still swap a regular
//     file for a symlink between this check and `mv`; that's an
//     accepted risk for a single-operator deployment.
//   - mode bits are preserved via stat+chmod so a freshly-written
//     file doesn't drift to umask defaults. Owner is not preserved —
//     the new file is owned by the SSH user; acceptable here because
//     the SSH user is the operator and owns the workdir.
func writeInlineVaultFile(ctx context.Context, cli *ssh.Client, srv config.Server, rel, content string) error {
	full := path.Join(srv.WorkDir, rel)
	q := shellQuote(full)
	script := fmt.Sprintf(
		`set -eo pipefail; trap '[ -n "${TMP:-}" ] && rm -f "$TMP"' EXIT; `+
			`if [ -L %s ]; then echo "refusing to write through symlink" >&2; exit 2; fi; `+
			`PERM=$(stat -c '%%a' %s); `+
			`TMP=%s.tmp.$$; `+
			`cat > "$TMP"; `+
			`chmod "$PERM" "$TMP"; `+
			`mv "$TMP" %s`,
		q, q, q, q,
	)
	_, stderr, err := runRemoteScript(ctx, cli, script, content)
	if err != nil {
		if stderr == "" {
			stderr = err.Error()
		}
		return fmt.Errorf("write %s: %s", rel, stderr)
	}
	return nil
}
