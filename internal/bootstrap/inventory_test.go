package bootstrap

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	existingHost = "web1.example.com"
	newHost      = "x.example.com"
)

const inventoryBase = `all:
  children:
    vps_servers:
      children:
        debian_servers:
          children:
            hetzner:
              hosts:
                web1.example.com:
`

func mustAdd(t *testing.T, content, provider, fqdn string) string {
	t.Helper()
	out, err := addHostToInventoryYAML([]byte(content), provider, fqdn)
	if err != nil {
		t.Fatalf("addHostToInventoryYAML(%q, %q): %v", provider, fqdn, err)
	}
	// Whatever we produce must stay parseable.
	var check map[string]any
	if err := yaml.Unmarshal(out, &check); err != nil {
		t.Fatalf("output is not valid YAML: %v\n%s", err, out)
	}
	return string(out)
}

func TestAddHostCreatesUmbrellaPath(t *testing.T) {
	out := mustAdd(t, "", "hetzner", "new1.example.com")
	for _, want := range []string{"vps_servers", "debian_servers", "hetzner", "new1.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestAddHostIdempotentDirect(t *testing.T) {
	out, err := addHostToInventoryYAML([]byte(inventoryBase), "hetzner", existingHost)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != inventoryBase {
		t.Error("existing host should return content unchanged")
	}
}

func TestAddHostIdempotentNestedSubgroup(t *testing.T) {
	content := `all:
  children:
    vps_servers:
      children:
        debian_servers:
          children:
            hetzner:
              children:
                hetzner_fsn:
                  hosts:
                    web1.example.com:
`
	out, err := addHostToInventoryYAML([]byte(content), "hetzner", existingHost)
	if err != nil {
		t.Fatalf("host nested in own provider subgroup must be idempotent, got: %v", err)
	}
	if string(out) != content {
		t.Error("nested-own-subgroup host should return content unchanged (old code duplicated it into hetzner.hosts)")
	}
}

func TestAddHostCrossProviderDirect(t *testing.T) {
	if _, err := addHostToInventoryYAML([]byte(inventoryBase), "ovh", existingHost); err == nil {
		t.Fatal("expected cross-provider duplicate error")
	}
}

func TestAddHostCrossProviderNestedSubgroup(t *testing.T) {
	content := `all:
  children:
    vps_servers:
      children:
        debian_servers:
          children:
            hetzner:
              children:
                hetzner_fsn:
                  hosts:
                    web1.example.com:
`
	_, err := addHostToInventoryYAML([]byte(content), "ovh", existingHost)
	if err == nil {
		t.Fatal("expected duplicate error for host in another provider's nested subgroup (old check missed this)")
	}
	if !strings.Contains(err.Error(), "hetzner_fsn") {
		t.Errorf("error should name the group holding the host, got: %v", err)
	}
}

func TestAddHostDupInOtherTopLevelGroup(t *testing.T) {
	content := `all:
  hosts:
    web1.example.com:
`
	if _, err := addHostToInventoryYAML([]byte(content), "ovh", existingHost); err == nil {
		t.Fatal("expected duplicate error for host under all.hosts")
	}
}

func TestAddHostReservedProviderNames(t *testing.T) {
	for _, provider := range []string{"all", "ungrouped", "vps_servers", "debian_servers"} {
		if _, err := addHostToInventoryYAML([]byte(inventoryBase), provider, newHost); err == nil {
			t.Errorf("provider %q must be rejected as reserved", provider)
		}
	}
}

func TestAddHostRefusesNonMappingNodes(t *testing.T) {
	cases := map[string]string{
		"sequence all":      "all:\n  - one\n  - two\n",
		"scalar children":   "all:\n  children: oops\n",
		"sequence children": "all:\n  children:\n    - vps_servers\n",
	}
	for name, content := range cases {
		if _, err := addHostToInventoryYAML([]byte(content), "hetzner", newHost); err == nil {
			t.Errorf("%s: expected error instead of silently rewriting the node\ninput:\n%s", name, content)
		}
	}
}

func TestAddHostPreservesCommentOnlyFile(t *testing.T) {
	content := "# fleet inventory\n# managed with care\n"
	out := mustAdd(t, content, "hetzner", newHost)
	if !strings.Contains(out, "# fleet inventory") || !strings.Contains(out, "# managed with care") {
		t.Errorf("comments from a comment-only file were dropped:\n%s", out)
	}
	if !strings.Contains(out, newHost) {
		t.Errorf("host missing from output:\n%s", out)
	}
}

func TestDetectYAMLIndentSkipsWhitespaceOnlyLines(t *testing.T) {
	content := "all:\n   \n    children:\n"
	if got := detectYAMLIndent([]byte(content)); got != 4 {
		t.Errorf("detectYAMLIndent = %d, want 4 (whitespace-only line must not win)", got)
	}
}

func TestAddHostUpgradesBareNullKeys(t *testing.T) {
	out := mustAdd(t, "all:\n", "hetzner", newHost)
	if !strings.Contains(out, newHost) {
		t.Errorf("bare `all:` should upgrade to a mapping:\n%s", out)
	}
}
