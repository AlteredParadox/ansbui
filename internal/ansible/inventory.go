// Package ansible wraps the ansible / ansible-playbook / ansible-inventory
// CLIs via the sshpool. It intentionally treats the remote host as the
// source of truth — we never parse inventory files ourselves.
package ansible

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
)

// Group mirrors the shape of `ansible-inventory --list` group records.
type Group struct {
	ID     string         `json:"id"`
	Name   string         `json:"name"`
	Parent *string        `json:"parent"`
	Vars   map[string]any `json:"vars"`
}

// Host mirrors the host records in `ansible-inventory --list`.
type Host struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	IP             string         `json:"ip"`
	Groups         []string       `json:"groups"`
	Region         string         `json:"region,omitempty"`
	OS             string         `json:"os,omitempty"`
	Status         string         `json:"status"`
	CPU            int            `json:"cpu"`
	Mem            int            `json:"mem"`
	Load           float64        `json:"load"`
	Uptime         int            `json:"uptime,omitempty"`
	Tags           []string       `json:"tags"`
	Vars           map[string]any `json:"vars,omitempty"`
	LastPlaybook   string         `json:"lastPlaybook,omitempty"`
	LastPlaybookAt time.Time      `json:"lastPlaybookAt,omitempty"`
}

// Inventory is the full snapshot the UI consumes.
type Inventory struct {
	Groups []Group `json:"groups"`
	Hosts  []Host  `json:"hosts"`
}

// FetchInventory runs `ansible-inventory --list` on the remote ansible
// server and normalises the output to the UI shape.
func FetchInventory(ctx context.Context, pool *sshpool.Pool, srv config.Server) (Inventory, error) {
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return Inventory{}, err
	}
	cmd := buildInventoryCmd(srv)
	stdout, stderr, err := sshpool.Run(cli, cmd)
	if err != nil {
		return Inventory{}, fmt.Errorf("ansible-inventory failed: %w (stderr: %s)", err, strings.TrimSpace(stderr))
	}
	return parseInventory(stdout)
}

func buildInventoryCmd(srv config.Server) string {
	var b strings.Builder
	if srv.WorkDir != "" {
		fmt.Fprintf(&b, "cd %s && ", shellQuote(srv.WorkDir))
	}
	b.WriteString("ansible-inventory --list")
	if srv.Inventory != "" {
		fmt.Fprintf(&b, " -i %s", shellQuote(srv.Inventory))
	}
	return b.String()
}

// rawInventory captures just the pieces of `ansible-inventory --list` we
// care about.
type rawInventory struct {
	Meta struct {
		HostVars map[string]map[string]any `json:"hostvars"`
	} `json:"_meta"`
}

func parseInventory(raw string) (Inventory, error) {
	// The top-level object is a map where keys are group names (plus
	// "_meta") and values are objects that may contain "hosts", "children"
	// and "vars". We decode twice: once into a generic map for group
	// traversal, once into rawInventory for the host-vars map.
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &top); err != nil {
		return Inventory{}, fmt.Errorf("decode inventory: %w", err)
	}
	var meta rawInventory
	if err := json.Unmarshal([]byte(raw), &meta); err != nil {
		return Inventory{}, fmt.Errorf("decode inventory meta: %w", err)
	}

	groups, hostGroups := walkGroups(top)
	inv := Inventory{
		Groups: groups,
		Hosts:  collectHosts(hostGroups, meta.Meta.HostVars),
	}
	sortInventory(&inv)
	return inv, nil
}

func walkGroups(top map[string]json.RawMessage) ([]Group, map[string][]string) {
	groups := make([]Group, 0, len(top))
	parents := make(map[string]string)
	hostGroups := make(map[string][]string)

	for name, payload := range top {
		if name == "_meta" {
			continue
		}
		node := decodeGroupNode(payload)
		for _, child := range node.Children {
			parents[child] = name
		}
		for _, host := range node.Hosts {
			hostGroups[host] = append(hostGroups[host], name)
		}
		groups = append(groups, Group{
			ID:   name,
			Name: name,
			Vars: node.Vars,
		})
	}
	for i := range groups {
		if p, ok := parents[groups[i].ID]; ok {
			pp := p
			groups[i].Parent = &pp
		}
	}
	return groups, hostGroups
}

type groupNode struct {
	Children []string       `json:"children"`
	Hosts    []string       `json:"hosts"`
	Vars     map[string]any `json:"vars"`
}

func decodeGroupNode(payload json.RawMessage) groupNode {
	var n groupNode
	// `ansible-inventory` occasionally emits empty arrays instead of
	// objects, so tolerate the decode error and fall through to an empty
	// node.
	_ = json.Unmarshal(payload, &n)
	return n
}

func collectHosts(hostGroups map[string][]string, hostVars map[string]map[string]any) []Host {
	hosts := make([]Host, 0, len(hostGroups))
	for name, groups := range hostGroups {
		vars := hostVars[name]
		hosts = append(hosts, Host{
			ID:     "host-" + name,
			Name:   name,
			IP:     stringVar(vars, "ansible_host", name),
			Groups: dedupe(append([]string{}, groups...)),
			Region: RegionFromHostname(name),
			OS:     stringVar(vars, "ansible_distribution", ""),
			Status: "ok",
			Vars:   vars,
		})
	}
	return hosts
}

func stringVar(vars map[string]any, key, fallback string) string {
	if v, ok := vars[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return fallback
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sortInventory(inv *Inventory) {
	sort.Slice(inv.Groups, func(i, j int) bool { return inv.Groups[i].Name < inv.Groups[j].Name })
	sort.Slice(inv.Hosts, func(i, j int) bool { return inv.Hosts[i].Name < inv.Hosts[j].Name })
}

// shellQuote wraps a value in single quotes so it survives expansion on
// the remote shell. Used for inventory / workdir paths supplied by the
// operator — we never splice raw user input here.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
