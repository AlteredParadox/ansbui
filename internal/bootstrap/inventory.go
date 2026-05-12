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

// addHostToInventoryYAML returns a new inventory file content with
// fqdn registered as a host inside `all.children.vps_servers.
// children.debian_servers.children.<provider>.hosts`. Any node
// along that path that doesn't exist is created. Existing comments
// and adjacent keys are preserved because we mutate yaml.Node trees,
// not flat maps.
//
// Idempotent: if the host is already present, the original content
// is returned unchanged.
func addHostToInventoryYAML(content []byte, provider, fqdn string) ([]byte, error) {
	if provider == "" {
		return nil, errors.New("provider name is required")
	}
	if fqdn == "" {
		return nil, errors.New("fqdn is required")
	}
	root, top, err := parseInventoryRoot(content)
	if err != nil {
		return nil, err
	}
	if err := guardNoLegacyTopLevel(top); err != nil {
		return nil, err
	}
	childrenNode := ensureUmbrellaPath(top)
	if err := guardNoCrossProviderDup(childrenNode, provider, fqdn); err != nil {
		return nil, err
	}
	providerNode := findOrCreateMapValue(childrenNode, provider)
	hostsNode := findOrCreateMapValue(providerNode, "hosts")
	if findMapValue(hostsNode, fqdn) != nil {
		return content, nil
	}
	appendHostNode(hostsNode, fqdn)
	return encodeInventory(root, content)
}

// parseInventoryRoot turns operator-supplied inventory bytes into
// a yaml.Node tree, returning both the document root (for re-encode)
// and the top-level mapping (for findOrCreateMapValue walks). An
// empty/invalid input yields an empty `all: {}` root rather than an
// error so a fresh-host bootstrap into a never-existed inventory
// still works.
func parseInventoryRoot(content []byte) (*yaml.Node, *yaml.Node, error) {
	var root yaml.Node
	if len(bytes.TrimSpace(content)) == 0 {
		root = emptyInventoryRoot()
	} else if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, nil, fmt.Errorf("parse inventory yaml: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		root = emptyInventoryRoot()
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		return nil, nil, errors.New("inventory top-level must be a YAML mapping (e.g. `all:`)")
	}
	return &root, top, nil
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
// `children` map where provider groups live as keys.
func ensureUmbrellaPath(top *yaml.Node) *yaml.Node {
	cur := findOrCreateMapValue(top, "all")
	for _, group := range inventoryUmbrellaGroups {
		cur = findOrCreateMapValue(cur, "children")
		cur = findOrCreateMapValue(cur, group)
	}
	return findOrCreateMapValue(cur, "children")
}

// guardNoCrossProviderDup refuses to register fqdn under provider X
// if it already lives under provider Y. Otherwise an operator who
// retries with a different provider after a transient porkbun
// failure ends up with the host listed in two provider groups, and
// ansible-inventory reports it as a member of both — silent fan-out
// the bootstrap workflow can't undo.
func guardNoCrossProviderDup(childrenNode *yaml.Node, provider, fqdn string) error {
	if childrenNode.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(childrenNode.Content); i += 2 {
		siblingProvider := childrenNode.Content[i].Value
		if siblingProvider == provider {
			continue
		}
		siblingHosts := findMapValue(childrenNode.Content[i+1], "hosts")
		if findMapValue(siblingHosts, fqdn) != nil {
			return fmt.Errorf("host %q is already registered under provider %q — remove it from there before re-bootstrapping under %q", fqdn, siblingProvider, provider)
		}
	}
	return nil
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
func encodeInventory(root *yaml.Node, content []byte) ([]byte, error) {
	var buf bytes.Buffer
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
// produce a 6-space-indented re-render.
func detectYAMLIndent(content []byte) int {
	for _, line := range strings.Split(string(content), "\n") {
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
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
func findOrCreateMapValue(m *yaml.Node, key string) *yaml.Node {
	if v := findMapValue(m, key); v != nil {
		// If the existing slot is a !!null (e.g. `web:` with no body)
		// we have to upgrade it to a mapping in place so we can hang
		// children off it.
		if v.Kind == yaml.ScalarNode && (v.Tag == "!!null" || v.Value == "") {
			v.Kind = yaml.MappingNode
			v.Tag = "!!map"
			v.Value = ""
		}
		return v
	}
	if m.Kind != yaml.MappingNode {
		m.Kind = yaml.MappingNode
		m.Tag = "!!map"
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, keyNode, valNode)
	return valNode
}
