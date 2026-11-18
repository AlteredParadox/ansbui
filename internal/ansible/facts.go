// ansbui — a single-binary web UI for an Ansible control node.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package ansible

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
)

// FactsResult is the shape returned to the UI. Facts is the inner
// ansible_facts map (keys like ansible_distribution, ansible_eth0, …).
// Raw keeps the full top-level JSON ansible emitted in case a caller
// needs non-facts keys (changed, _ansible_no_log, etc).
type FactsResult struct {
	Host  string         `json:"host"`
	Facts map[string]any `json:"facts"`
	Raw   map[string]any `json:"raw,omitempty"`
}

// GatherFacts runs `ansible <host> -m setup --one-line` on the active
// server and parses the single-line response. host may be any target
// expression ansible accepts but the UI calls this with a concrete
// host name; if the expression matches multiple hosts we return the
// first SUCCESS line.
// ErrFactsHost is returned for a facts request whose host is not a
// plain host name (see ValidHostName).
var ErrFactsHost = errors.New("host must be a single host name: letters, digits, '.', '-', '_' and ':' only, not starting with '-'")

func GatherFacts(ctx context.Context, pool *sshpool.Pool, srv config.Server, host string) (FactsResult, error) {
	if strings.TrimSpace(host) == "" {
		return FactsResult{}, fmt.Errorf("host is required")
	}
	if !ValidHostName(host) {
		return FactsResult{}, ErrFactsHost
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return FactsResult{}, err
	}
	var b strings.Builder
	if srv.WorkDir != "" {
		fmt.Fprintf(&b, "cd %s && ", shellQuote(srv.WorkDir))
	}
	// `--one-line` is deprecated in ansible-core 2.23. The same output
	// format is available via the oneline stdout callback, with the
	// bonus of no deprecation warnings landing in stdout.
	b.WriteString("ANSIBLE_FORCE_COLOR=0 ANSIBLE_STDOUT_CALLBACK=oneline ANSIBLE_LOAD_CALLBACK_PLUGINS=True ansible ")
	b.WriteString(shellQuote(host))
	b.WriteString(" -m ansible.builtin.setup")
	if srv.Inventory != "" {
		b.WriteString(" -i ")
		b.WriteString(shellQuote(srv.Inventory))
	}
	b.WriteString(" 2>&1")
	stdout, _, err := sshpool.Run(ctx, cli, b.String())
	if err != nil {
		return FactsResult{}, fmt.Errorf("gather facts for %s: %w (ansible output: %s)", host, err, truncate(stdout, 400))
	}
	return parseFactsOutput(host, stdout)
}

// parseFactsOutput scans ansible's oneline output for the first
// SUCCESS line belonging to `host` (or any host, if that single
// lookup fails) and decodes the JSON that follows ` => `. Failure
// lines (UNREACHABLE!, FAILED!, …) bubble up as errors carrying the
// ansible message so the UI can show it verbatim.
func parseFactsOutput(host, stdout string) (FactsResult, error) {
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		idx := strings.Index(line, " => ")
		if idx < 0 {
			continue
		}
		head := line[:idx]
		body := line[idx+len(" => "):]
		if !strings.Contains(head, "SUCCESS") {
			return FactsResult{}, fmt.Errorf("ansible: %s", strings.TrimSpace(line))
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(body), &raw); err != nil {
			return FactsResult{}, fmt.Errorf("decode facts: %w", err)
		}
		facts, _ := raw["ansible_facts"].(map[string]any)
		return FactsResult{Host: host, Facts: facts, Raw: raw}, nil
	}
	// Look for common "didn't run" messages before the generic fallback.
	if strings.Contains(stdout, "Could not match supplied host pattern") ||
		strings.Contains(stdout, "No hosts matched") {
		return FactsResult{}, fmt.Errorf("host %q isn't in the inventory the active server resolves", host)
	}
	return FactsResult{}, fmt.Errorf("no SUCCESS line found in ansible output: %s", truncate(stdout, 400))
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
