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
	if err := validateVaultPassword(password); err != nil {
		return "", err
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
	if err := validateVaultPassword(password); err != nil {
		return err
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

// writeInlineVaultFile delegates the atomic write to the shared
// stdin-streaming helper and wraps the error with the rel path so
// the UI surfaces a useful message.
func writeInlineVaultFile(ctx context.Context, cli *ssh.Client, srv config.Server, rel, content string) error {
	full := path.Join(srv.WorkDir, rel)
	stderr, err := writeFileAtomicViaStdin(ctx, cli, full, content)
	if err != nil {
		if stderr == "" {
			stderr = err.Error()
		}
		return fmt.Errorf("write %s: %s", rel, stderr)
	}
	return nil
}
