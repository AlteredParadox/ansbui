package ansible

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/AlteredParadox/relay/internal/config"
	"github.com/AlteredParadox/relay/internal/sshpool"
)

// Playbook is a summary of a single YAML playbook file on the remote
// ansible server.
type Playbook struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Targets     string   `json:"targets"`
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
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 1 {
			continue
		}
		rel := parts[0]
		name := path.Base(rel)
		p := Playbook{
			ID:   "pb-" + strings.TrimSuffix(strings.TrimSuffix(name, ".yml"), ".yaml"),
			Name: name,
			Path: rel,
		}
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &p.Size)
		}
		if len(parts) >= 3 {
			var ts float64
			fmt.Sscanf(parts[2], "%f", &ts)
			if ts > 0 {
				p.Modified = time.Unix(int64(ts), 0).UTC().Format(time.RFC3339)
			}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
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

// SavePlaybook writes YAML back to the remote file. Content is base64-
// encoded over SSH so newlines and quotes survive transit without
// further escaping.
func SavePlaybook(ctx context.Context, pool *sshpool.Pool, srv config.Server, rel, yaml string) error {
	if err := validateRelPath(rel); err != nil {
		return err
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return err
	}
	full := path.Join(srv.WorkDir, rel)
	encoded := base64.StdEncoding.EncodeToString([]byte(yaml))
	cmd := fmt.Sprintf("printf %%s %s | base64 -d > %s", shellQuote(encoded), shellQuote(full))
	_, stderr, err := sshpool.Run(cli, cmd)
	if err != nil {
		return fmt.Errorf("write playbook %s: %w (stderr: %s)", rel, err, strings.TrimSpace(stderr))
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

func annotateFromYAML(p *Playbook) {
	if m := hostsRE.FindStringSubmatch(p.YAML); len(m) == 2 {
		p.Targets = strings.Trim(m[1], `"'`)
	}
}
