package bootstrap

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// inventoryUmbrellaGroups is the chain of intermediate groups every
// new host gets nested under, in order from the outermost. The
// existing fleet's convention is `all → vps_servers → debian_servers
// → <provider>`; bootstrap v1 only handles Debian/Ubuntu so
// debian_servers is hardcoded here. If a future revision adds e.g.
// a freebsd_servers branch, this is the place to dispatch on distro.
var inventoryUmbrellaGroups = []string{"vps_servers", "debian_servers"}

// reservedGroupNames are group names a provider must never take:
// "all" and "ungrouped" are reserved by ansible itself (an inventory
// that redefines them under children refuses to load, breaking every
// fleet operation), and nesting an umbrella group inside itself
// (`debian_servers` under `debian_servers`) is a duplicate-group
// layout whose behaviour is parser-dependent.
func isReservedGroupName(name string) bool {
	if name == "all" || name == "ungrouped" {
		return true
	}
	for _, g := range inventoryUmbrellaGroups {
		if name == g {
			return true
		}
	}
	return false
}

// addHostToInventoryYAML returns a new inventory file content with
// fqdn registered as a host inside `all.children.vps_servers.
// children.debian_servers.children.<provider>.hosts`. Any node
// along that path that doesn't exist is created. Existing comments
// and adjacent keys are preserved because we mutate yaml.Node trees,
// not flat maps.
//
// Idempotent: if the host is already present anywhere under the
// target provider's subtree, the original content is returned
// unchanged. A host found under any other group is an error — the
// same host in two groups is silent fan-out the bootstrap workflow
// can't undo.
func addHostToInventoryYAML(content []byte, provider, fqdn string) ([]byte, error) {
	if provider == "" {
		return nil, errors.New("provider name is required")
	}
	if isReservedGroupName(provider) {
		return nil, fmt.Errorf("provider name %q collides with a reserved/umbrella ansible group — pick a different provider label", provider)
	}
	if fqdn == "" {
		return nil, errors.New("fqdn is required")
	}
	root, top, preamble, err := parseInventoryRoot(content)
	if err != nil {
		return nil, err
	}
	if err := guardNoLegacyTopLevel(top); err != nil {
		return nil, err
	}
	// Whole-tree duplicate scan before any mutation: covers hosts
	// nested in provider subgroups, other umbrella branches, and
	// top-level groups — not just direct provider siblings.
	for i := 0; i+1 < len(top.Content); i += 2 {
		path := hostGroupPath(top.Content[i].Value, top.Content[i+1], fqdn)
		if path == nil {
			continue
		}
		for _, g := range path {
			if g == provider {
				return content, nil // already ours, possibly in a subgroup
			}
		}
		return nil, fmt.Errorf("host %q is already registered under group %q — remove it from there before re-bootstrapping under %q", fqdn, path[len(path)-1], provider)
	}
	childrenNode, err := ensureUmbrellaPath(top)
	if err != nil {
		return nil, err
	}
	providerNode, err := findOrCreateMapValue(childrenNode, provider)
	if err != nil {
		return nil, err
	}
	hostsNode, err := findOrCreateMapValue(providerNode, "hosts")
	if err != nil {
		return nil, err
	}
	appendHostNode(hostsNode, fqdn)
	return encodeInventory(root, content, preamble)
}

// hostGroupPath returns the chain of group names (starting at name)
// leading to the `hosts:` entry containing fqdn inside node's
// subtree, or nil if the host isn't there.
func hostGroupPath(name string, node *yaml.Node, fqdn string) []string {
	if hosts := findMapValue(node, "hosts"); findMapValue(hosts, fqdn) != nil {
		return []string{name}
	}
	children := findMapValue(node, "children")
	if children == nil || children.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(children.Content); i += 2 {
		if p := hostGroupPath(children.Content[i].Value, children.Content[i+1], fqdn); p != nil {
			return append([]string{name}, p...)
		}
	}
	return nil
}

// parseInventoryRoot turns operator-supplied inventory bytes into
// a yaml.Node tree, returning the document root (for re-encode),
// the top-level mapping (for findOrCreateMapValue walks), and a
// preamble to re-prepend at encode time. An empty input yields an
// empty `all: {}` root rather than an error so a fresh-host
// bootstrap into a never-existed inventory still works.
//
// The preamble covers the comment-only file: it parses to an empty
// document, so the node tree we build from scratch would silently
// drop the operator's comments on re-encode. We keep the original
// text and glue it back on top.
func parseInventoryRoot(content []byte) (root, top *yaml.Node, preamble string, err error) {
	var doc yaml.Node
	if len(bytes.TrimSpace(content)) == 0 {
		doc = emptyInventoryRoot()
	} else if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, nil, "", fmt.Errorf("parse inventory yaml: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		// Parsed but produced no document node: comments and/or
		// whitespace only. Preserve the original text verbatim.
		if len(bytes.TrimSpace(content)) > 0 {
			preamble = strings.TrimRight(string(content), "\n") + "\n"
		}
		doc = emptyInventoryRoot()
	}
	top = doc.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, nil, "", errors.New("inventory top-level must be a YAML mapping (e.g. `all:`)")
	}
	return &doc, top, preamble, nil
}

// guardNoLegacyTopLevel refuses to bifurcate if any umbrella group
// already lives at the top level (legacy pre-`all` inventory
// layout). Creating a nested copy would split the fleet across two
// same-named groups and ansible's behaviour on duplicates is
// parser-dependent.
func guardNoLegacyTopLevel(top *yaml.Node) error {
	for _, group := range inventoryUmbrellaGroups {
		if existing := findMapValue(top, group); existing != nil {
			return fmt.Errorf("inventory has top-level group %q — move it under all.children before bootstrap so the new host doesn't get added to a duplicate group", group)
		}
	}
	return nil
}

// ensureUmbrellaPath walks `all.children.<umbrella>...children` in
// the YAML tree, creating any missing rungs, and returns the leaf
// `children` map where provider groups live as keys. Errors if a
// node on the path exists but isn't a mapping (e.g. a `children:`
// holding a sequence or a scalar) — rewriting it would destroy the
// operator's data.
func ensureUmbrellaPath(top *yaml.Node) (*yaml.Node, error) {
	cur, err := findOrCreateMapValue(top, "all")
	if err != nil {
		return nil, err
	}
	for _, group := range inventoryUmbrellaGroups {
		if cur, err = findOrCreateMapValue(cur, "children"); err != nil {
			return nil, err
		}
		if cur, err = findOrCreateMapValue(cur, group); err != nil {
			return nil, err
		}
	}
	return findOrCreateMapValue(cur, "children")
}

// appendHostNode adds fqdn as a `<fqdn>:` (bare-key, no value) entry
// under hostsNode. Empty scalar with the !!null tag renders that
// way, matching how operators usually hand-write ansible inventory
// entries.
func appendHostNode(hostsNode *yaml.Node, fqdn string) {
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: fqdn}
	valNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null"}
	hostsNode.Content = append(hostsNode.Content, keyNode, valNode)
}

// encodeInventory renders root back to bytes, preserving the
// operator's original indent so a re-encode with a hardcoded
// 2-space indent against a 4-space file doesn't reflow every
// nested key (churn-heavy diff, breaks downstream tooling).
// preamble (the original text of a comment-only file, or "") is
// glued back on top so those comments survive the rewrite.
func encodeInventory(root *yaml.Node, content []byte, preamble string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(preamble)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(detectYAMLIndent(content))
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("encode inventory yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("close yaml encoder: %w", err)
	}
	return buf.Bytes(), nil
}

// detectYAMLIndent counts the leading-space width of the first
// indented line in content. Returns 2 (yaml.v3's default) when the
// file is empty, has no nested structure yet, or uses tabs (yaml
// rejects tabs anyway, so a tab-using file is already bad input).
// Caps at 8 so a freak first-indented-line of `      ` doesn't
// produce a 6-space-indented re-render. Whitespace-only lines are
// skipped — trailing spaces on a blank line aren't indentation.
func detectYAMLIndent(content []byte) int {
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		var n int
		for _, r := range line {
			if r != ' ' {
				break
			}
			n++
		}
		if n > 0 {
			if n > 8 {
				return 8
			}
			return n
		}
	}
	return 2
}

// emptyInventoryRoot returns the YAML node tree for `all: {}` —
// used when the inventory file was empty or wasn't valid YAML at
// all.
func emptyInventoryRoot() yaml.Node {
	return yaml.Node{
		Kind: yaml.DocumentNode,
		Content: []*yaml.Node{
			{Kind: yaml.MappingNode, Tag: "!!map"},
		},
	}
}

// findMapValue walks m's key/value pairs and returns the value
// node for key, or nil if the key isn't present.
func findMapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// findOrCreateMapValue returns the value node for key inside m,
// creating an empty mapping under that key if it didn't exist. The
// host's value lives at the leaves of the tree (`hosts: { fqdn: }`)
// — every intermediate level is a mapping.
//
// A key that exists but holds something we can't hang children off —
// a sequence, a non-empty scalar, an alias — is an error: silently
// rewriting it to a mapping (the old behaviour) destroyed whatever
// the operator had there.
func findOrCreateMapValue(m *yaml.Node, key string) (*yaml.Node, error) {
	if v := findMapValue(m, key); v != nil {
		// A !!null scalar (e.g. `web:` with no body) upgrades to a
		// mapping in place so we can hang children off it.
		if v.Kind == yaml.ScalarNode && (v.Tag == "!!null" || v.Value == "") {
			v.Kind = yaml.MappingNode
			v.Tag = "!!map"
			v.Value = ""
		}
		if v.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("inventory key %q exists but is not a mapping — fix the file by hand before bootstrap (refusing to overwrite it)", key)
		}
		return v, nil
	}
	if m.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("inventory node holding %q is not a mapping — fix the file by hand before bootstrap (refusing to overwrite it)", key)
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, keyNode, valNode)
	return valNode, nil
}
