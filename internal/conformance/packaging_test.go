package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func readJSON(t *testing.T, path string, into any) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root(), path)) //nolint:gosec // a path inside this repository
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// SPEC appendix L section 8.3: the plugin is a marketplace entry pointing at
// a plugin that serves the MCP server and ships one skill. What an agent is
// told to do before a deletion lives in that skill, so its shape is checked
// like code.
func TestThePluginServesTheReadOnlyServerAndItsSkill(t *testing.T) {
	var marketplace struct {
		Name    string `json:"name"`
		Plugins []struct {
			Name   string `json:"name"`
			Source string `json:"source"`
		} `json:"plugins"`
	}
	readJSON(t, ".claude-plugin/marketplace.json", &marketplace)
	if marketplace.Name != "az-can-i-delete" || len(marketplace.Plugins) != 1 {
		t.Fatalf("marketplace = %+v", marketplace)
	}
	plugin := filepath.Clean(marketplace.Plugins[0].Source)

	var manifest struct {
		Name       string `json:"name"`
		Skills     string `json:"skills"`
		MCPServers string `json:"mcpServers"`
	}
	readJSON(t, filepath.Join(plugin, ".claude-plugin", "plugin.json"), &manifest)
	if manifest.Name != marketplace.Plugins[0].Name {
		t.Fatalf("plugin %q is listed as %q", manifest.Name, marketplace.Plugins[0].Name)
	}

	var servers struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	readJSON(t, filepath.Join(plugin, manifest.MCPServers), &servers)
	server, ok := servers.MCPServers["az-can-i-delete"]
	if !ok || server.Command != "az-can-i-delete" || strings.Join(server.Args, " ") != "mcp" {
		t.Fatalf("servers = %+v", servers)
	}

	skillDir := filepath.Join(root(), plugin, manifest.Skills, "az-can-i-delete")
	body, err := os.ReadFile(filepath.Join(skillDir, "SKILL.md")) //nolint:gosec // a path inside this repository
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(body), "---\n", 3)
	if len(parts) != 3 || parts[0] != "" {
		t.Fatal("SKILL.md has no frontmatter")
	}
	var front struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	}
	if err := yaml.Unmarshal([]byte(parts[1]), &front); err != nil {
		t.Fatal(err)
	}
	// The agentskills.io rules the specification cites.
	if !regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`).MatchString(front.Name) || len(front.Name) > 64 ||
		front.Name != filepath.Base(skillDir) {
		t.Errorf("skill name %q", front.Name)
	}
	if front.Description == "" || len(front.Description) > 1024 {
		t.Errorf("skill description is %d characters", len(front.Description))
	}
	// Scoped to what v0.1 analyzes: the specification says the proposed
	// description overclaimed VNet and Container Apps.
	for _, overclaim := range []string{"virtual network", "VNet", "Container App"} {
		if strings.Contains(string(body), overclaim) {
			t.Errorf("SKILL.md names %s, which v0.1 does not analyze", overclaim)
		}
	}
	// The instruction the skill exists to give.
	for _, must := range []string{"can_i_delete", "never delete on `no` or `tentative`", "requiredHumanQuestion", "untrusted"} {
		if !strings.Contains(string(body), must) {
			t.Errorf("SKILL.md does not say %q", must)
		}
	}
}

// SPEC section 11: every day-1 test that changes 0.1 behaviour has a runbook
// entry, so none of them is forgotten between writing the rule and trusting it.
func TestTheDayOneRunbookCoversEveryTest(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(root(), "docs", "day1.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []string{"H1", "H5", "H7", "H10", "H11", "H17", "H9", "T25b"} {
		if !strings.Contains(string(body), "## "+test+" ") {
			t.Errorf("docs/day1.md has no section for %s", test)
		}
	}
	for _, scenario := range []string{"storage-no-pe", "storage-tentative-defender", "storage-untrusted-tag", "site-tentative-linux-consumption"} {
		if !strings.Contains(string(body), scenario) {
			t.Errorf("docs/day1.md does not say how to record %s", scenario)
		}
	}
}
