package ansible

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
)

// Playbook is a summary of a single YAML playbook file on the remote
// ansible server.
//
// Include is the parsed `# ansbui-include: host1, host2` annotation
// (see parseIncludeHosts). Always-include hosts get auto-merged
// into --limit at run time so the operator typing a single VPS
// name in the form still hits the orchestration set the playbook
// requires (control node, monitoring, etc.). The annotation is a
// comment because Ansible's play schema is closed and rejects
// unknown top-level keys.
type Playbook struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Targets     string   `json:"targets"`
	Include     []string `json:"include,omitempty"`
	Size        int      `json:"size"`
	Modified    string   `json:"modified,omitempty"`
	YAML        string   `json:"yaml,omitempty"`
}

var safeNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ListPlaybooks lists `*.yml` / `*.yaml` files in the server's workDir.
func ListPlaybooks(ctx context.Context, pool *sshpool.Pool, srv config.Server) ([]Playbook, error) {
	if srv.WorkDir == "" {
		return nil, errors.New("server has no workDir configured; set it to the directory containing your playbooks")
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf(
		"cd %s && find . -maxdepth 3 -type f "+
			"\\( -name '*.yml' -o -name '*.yaml' \\) "+
			// Skip the usual Ansible dirs that hold YAML but aren't
			// playbooks: variable files, role internals, inventory
			// definitions, jinja templates, static file payloads.
			"-not -path './host_vars/*' "+
			"-not -path './group_vars/*' "+
			"-not -path './roles/*' "+
			"-not -path './collections/*' "+
			"-not -path './inventory/*' "+
			"-not -path './inventories/*' "+
			"-not -path './vars/*' "+
			"-not -path './defaults/*' "+
			"-not -path './tasks/*' "+
			"-not -path './handlers/*' "+
			"-not -path './meta/*' "+
			"-not -path './files/*' "+
			"-not -path './templates/*' "+
			"-not -path './library/*' "+
			"-not -path './*_plugins/*' "+
			"-not -path './.*' "+
			"-printf '%%P\\t%%s\\t%%T@\\n'",
		shellQuote(srv.WorkDir),
	)
	stdout, stderr, err := sshpool.Run(cli, cmd)
	if err != nil {
		return nil, fmt.Errorf("list playbooks: %w (stderr: %s)", err, strings.TrimSpace(stderr))
	}
	return parsePlaybookList(stdout), nil
}

func parsePlaybookList(raw string) []Playbook {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	out := make([]Playbook, 0, len(lines))
	for _, line := range lines {
		if p, ok := parsePlaybookLine(line); ok {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// parsePlaybookLine decodes one tab-separated `find -printf` row
// of the form `relpath\tsize\tmtime`. Size and mtime are
// best-effort: a malformed numeric field leaves the corresponding
// Playbook field at its zero value, which is what the UI already
// renders as "unknown".
func parsePlaybookLine(line string) (Playbook, bool) {
	if line == "" {
		return Playbook{}, false
	}
	parts := strings.SplitN(line, "\t", 3)
	if len(parts) < 1 {
		return Playbook{}, false
	}
	rel := parts[0]
	name := path.Base(rel)
	p := Playbook{
		ID:   "pb-" + strings.TrimSuffix(strings.TrimSuffix(name, ".yml"), ".yaml"),
		Name: name,
		Path: rel,
	}
	if len(parts) >= 2 {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			p.Size = n
		}
	}
	if len(parts) >= 3 {
		if ts, err := strconv.ParseFloat(parts[2], 64); err == nil && ts > 0 {
			p.Modified = time.Unix(int64(ts), 0).UTC().Format(time.RFC3339)
		}
	}
	return p, true
}

// LoadPlaybook reads a single playbook's YAML contents.
func LoadPlaybook(ctx context.Context, pool *sshpool.Pool, srv config.Server, rel string) (Playbook, error) {
	if err := validateRelPath(rel); err != nil {
		return Playbook{}, err
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return Playbook{}, err
	}
	full := path.Join(srv.WorkDir, rel)
	cmd := fmt.Sprintf("cat %s", shellQuote(full))
	stdout, stderr, err := sshpool.Run(cli, cmd)
	if err != nil {
		return Playbook{}, fmt.Errorf("read playbook %s: %w (stderr: %s)", rel, err, strings.TrimSpace(stderr))
	}
	p := Playbook{
		ID:   "pb-" + strings.TrimSuffix(strings.TrimSuffix(path.Base(rel), ".yml"), ".yaml"),
		Name: path.Base(rel),
		Path: rel,
		YAML: stdout,
	}
	annotateFromYAML(&p)
	return p, nil
}

// SavePlaybook writes YAML back to the remote file via the shared
// atomic-write helper: stat+chmod preserves the playbook's mode,
// the symlink guard refuses to clobber an operator-placed link,
// and the tempfile+rename keeps a half-streamed save from
// truncating the working file. YAML rides over the SSH session's
// stdin so big playbooks don't hit MAX_ARG_STRLEN.
func SavePlaybook(ctx context.Context, pool *sshpool.Pool, srv config.Server, rel, yaml string) error {
	if err := validateRelPath(rel); err != nil {
		return err
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return err
	}
	full := path.Join(srv.WorkDir, rel)
	stderr, err := writeFileAtomicViaStdin(ctx, cli, full, yaml)
	if err != nil {
		if stderr == "" {
			stderr = err.Error()
		}
		return fmt.Errorf("write playbook %s: %s", rel, stderr)
	}
	return nil
}

// validateRelPath rejects paths that would escape the workDir. We only
// allow alnum + `._-` segments to keep out `..`, leading `/`, spaces, etc.
func validateRelPath(rel string) error {
	if rel == "" {
		return errors.New("playbook path is required")
	}
	if strings.HasPrefix(rel, "/") {
		return errors.New("playbook path must be relative to the server workDir")
	}
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("invalid path segment: %q", part)
		}
		if !safeNameRE.MatchString(part) {
			return fmt.Errorf("invalid characters in path segment: %q", part)
		}
	}
	return nil
}

var hostsRE = regexp.MustCompile(`(?m)^\s*hosts:\s*(.+?)\s*$`)

// includeRE matches the per-line `# ansbui-include: a, b, c`
// annotation. Bounded — anchored to start of line, no nested
// repetition (S5852-safe). Comments at any indent or with
// optional space after `#` are accepted.
//
// This is a regex over the raw YAML, not a parser-aware match —
// a `# ansbui-include:` line buried inside a YAML block scalar
// (`shell: |` etc.) would also match. The blast radius is
// bounded because the resulting hosts have to already exist in
// the inventory for ansible's `--limit` to act on them, but
// operators reviewing imported playbooks should know that any
// such line is honoured by ansbui's prep step.
var includeRE = regexp.MustCompile(`(?m)^\s*#\s*ansbui-include:\s*(.+?)\s*$`)

func annotateFromYAML(p *Playbook) {
	if m := hostsRE.FindStringSubmatch(p.YAML); len(m) == 2 {
		p.Targets = strings.Trim(m[1], `"'`)
	}
	p.Include = parseIncludesFromYAML(p.YAML)
}

// parseIncludesFromYAML returns the union of all
// `# ansbui-include:` annotations in the playbook, deduplicated
// in source order. ansible's `--limit` is global to the run
// (one effective set across every play), so unioning matches the
// runtime semantic — a playbook with two plays each declaring
// their own include line should target both sets, not just the
// first one we encountered.
func parseIncludesFromYAML(yaml string) []string {
	matches := includeRE.FindAllStringSubmatch(yaml, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, m := range matches {
		for _, h := range parseIncludeHosts(m[1]) {
			if seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// parseIncludeHosts splits the annotation's payload into a
// deduplicated host list. Accepts comma- or whitespace-separated
// values so operators can write either `a, b, c` or `a b c`.
// Order is preserved (operator's intent often matters for
// readability even though ansible's --limit is a set). Returns
// nil — not an empty slice — when there are no usable tokens, so
// callers can use `len(out) > 0` and `reflect.DeepEqual(out, nil)`
// interchangeably.
func parseIncludeHosts(s string) []string {
	raw := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	seen := make(map[string]bool, len(raw))
	var out []string
	for _, h := range raw {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// MergeLimitHosts combines the operator-supplied --limit value
// with the playbook's auto-include set, deduplicating in
// operator-first order. Empty operator limit yields just the
// include set; empty include set yields the operator's limit
// unchanged.
//
// Both userLimit and entries in include[] are split on commas
// and trimmed: the parser already produces single-host entries,
// but a future caller (or a hand-built list) passing "h1,h2" as
// one entry would otherwise corrupt the joined string. Symmetric
// splitting makes this defensive against shape drift.
func MergeLimitHosts(userLimit string, include []string) string {
	seen := make(map[string]bool)
	var out []string
	addAll := func(s string) {
		for _, h := range strings.Split(s, ",") {
			h = strings.TrimSpace(h)
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
	}
	addAll(userLimit)
	for _, raw := range include {
		addAll(raw)
	}
	return strings.Join(out, ",")
}
