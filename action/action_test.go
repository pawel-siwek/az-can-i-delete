// Package action tests the composite GitHub Action's scripts: the id
// extraction of SPEC appendix E section 9.2 and the fail policy of section
// 9.3. The scripts are run as the action runs them, with bash and jq; the
// check itself is replaced by the results it would have written.
package action

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const sub = "/subscriptions/00000000-0000-0000-0000-000000000001/resourcegroups/"

// tools makes sure the scripts can run. In CI a missing tool is a failure:
// the runner is supposed to have them, and a skipped test is a test that
// passed without running.
func tools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("CI") != "" {
				t.Fatalf("%s is not installed", tool)
			}
			t.Skipf("%s is not installed; the action's scripts need it", tool)
		}
	}
}

func script(t *testing.T, name string, env []string, args ...string) (string, error) {
	t.Helper()
	path, err := filepath.Abs(name)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{path}, args...)...) //nolint:gosec // the script is this package's own
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func read(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path) //nolint:gosec // a path inside the test's own temporary directory
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTerraformDeletesAndReplacementsAreExtracted(t *testing.T) {
	tools(t)
	out := t.TempDir()
	if log, err := script(t, "extract.sh", []string{"TF_PLAN_JSON=" + fixture(t, "tfplan.json")}, out); err != nil {
		t.Fatalf("%v: %s", err, log)
	}
	want := sub + "rg/providers/microsoft.storage/storageaccounts/stlogs\tdelete\n" +
		sub + "rg/providers/microsoft.network/networkinterfaces/nic-old-01\tdelete\n"
	if got := read(t, filepath.Join(out, "changes.tsv")); got != want {
		t.Fatalf("changes:\n%s\nwant:\n%s", got, want)
	}
	if got := strings.TrimSpace(read(t, filepath.Join(out, "skipped"))); got != "1" {
		t.Fatalf("skipped = %s, want the one data-plane id", got)
	}
}

func TestStackWhatIfLabelsDetachPotentialAndUnsupported(t *testing.T) {
	tools(t)
	out := t.TempDir()
	if log, err := script(t, "extract.sh", []string{"STACK_WHATIF_JSON=" + fixture(t, "stack-whatif.json")}, out); err != nil {
		t.Fatalf("%v: %s", err, log)
	}
	want := sub + "rg/providers/microsoft.web/sites/func-batch\tdelete (potential)\n" +
		sub + "rg/providers/microsoft.network/networkinterfaces/nic-old-01\tdetach\n"
	if got := read(t, filepath.Join(out, "changes.tsv")); got != want {
		t.Fatalf("changes:\n%s\nwant:\n%s", got, want)
	}
	if got := read(t, filepath.Join(out, "unsupported.txt")); got != sub+"rg/providers/microsoft.compute/disks/d-unknown\n" {
		t.Fatalf("unsupported = %q", got)
	}
}

func TestCompleteModeArmWhatIfReadsOnlyDeletes(t *testing.T) {
	tools(t)
	out := t.TempDir()
	// A workflow passes a path relative to its workspace, which is this
	// package's directory here.
	if log, err := script(t, "extract.sh", []string{"ARM_WHATIF_JSON=testdata/arm-whatif.json"}, out); err != nil {
		t.Fatalf("%v: %s", err, log)
	}
	if got := read(t, filepath.Join(out, "ids.txt")); got != sub+"rg/providers/microsoft.compute/disks/disk-old\n" {
		t.Fatalf("ids = %q", got)
	}
}

// The same resource named by two sources is checked once; the first source
// decides how it is labelled.
func TestIdsAreDedupedAcrossSources(t *testing.T) {
	tools(t)
	out := t.TempDir()
	env := []string{
		"RESOURCE_IDS=\n  /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/NIC-OLD-01  \n\n",
		"TF_PLAN_JSON=" + fixture(t, "tfplan.json"),
		"STACK_WHATIF_JSON=" + fixture(t, "stack-whatif.json"),
	}
	if log, err := script(t, "extract.sh", env, out); err != nil {
		t.Fatalf("%v: %s", err, log)
	}
	lines := strings.Split(strings.TrimSpace(read(t, filepath.Join(out, "ids.txt"))), "\n")
	if len(lines) != 3 || lines[0] != sub+"rg/providers/microsoft.network/networkinterfaces/nic-old-01" {
		t.Fatalf("ids = %q", lines)
	}
}

func TestNoInputMeansNoPlannedDeletions(t *testing.T) {
	tools(t)
	out := t.TempDir()
	if log, err := script(t, "extract.sh", nil, out); err != nil {
		t.Fatalf("%v: %s", err, log)
	}
	if log, err := script(t, "policy.sh", nil, out); err != nil {
		t.Fatalf("an empty plan failed: %v %s", err, log)
	}
	if read(t, filepath.Join(out, "verdict")) != "none\n" || !strings.Contains(read(t, filepath.Join(out, "summary.md")), "no planned deletions") {
		t.Fatalf("verdict %q summary %q", read(t, filepath.Join(out, "verdict")), read(t, filepath.Join(out, "summary.md")))
	}
}

func report(verdict, reasonClass string) map[string]any {
	return map[string]any{
		"schemaVersion": "2", "verdict": verdict, "reasonClass": reasonClass, "rulesDate": "2026-09-21",
		"resourceId":   "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st-logs-prod",
		"resourceType": "Microsoft.Storage/storageAccounts",
		"window":       map[string]any{"requested": map[string]any{"start": "2026-06-23T00:00:00Z", "end": "2026-09-21T00:00:00Z", "days": 90}},
		"evidence": []any{
			map[string]any{"status": "present", "tier": 2, "summary": "approved private endpoint | pe-sql-01"},
			map[string]any{"status": "absent", "tier": 1, "summary": "no lock"},
		},
		"unknowns": []any{},
	}
}

func errorResult(code string) map[string]any {
	return map[string]any{"schemaVersion": "2", "error": map[string]any{"code": code}}
}

// planned writes two planned deletions and the results the check produced.
func planned(t *testing.T, results ...map[string]any) string {
	t.Helper()
	out := t.TempDir()
	changes := sub + "rg/providers/microsoft.storage/storageaccounts/st-logs-prod\tdelete\n" +
		sub + "rg/providers/microsoft.network/networkinterfaces/nic-old-01\tdetach\n"
	var document any = results
	if len(results) == 1 {
		document = results[0]
	}
	body, _ := json.Marshal(document)
	for name, content := range map[string]string{
		"changes.tsv": changes, "unsupported.txt": "", "skipped": "0\n", "results.json": string(body),
	} {
		if err := os.WriteFile(filepath.Join(out, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestThePolicy(t *testing.T) {
	tools(t)
	cases := []struct {
		name     string
		results  []map[string]any
		failOn   string
		toolExit string
		verdict  string
		fails    bool
	}{
		{"all yes", []map[string]any{report("yes", "no-evidence-of-use"), report("yes", "no-evidence-of-use")}, "no", "0", "yes", false},
		{"a no fails by default", []map[string]any{report("no", "in-use"), report("yes", "no-evidence-of-use")}, "no", "0", "no", true},
		{"a tentative warns by default", []map[string]any{report("tentative", "inconclusive"), report("yes", "no-evidence-of-use")}, "no", "0", "tentative", false},
		{"a tentative fails when asked", []map[string]any{report("tentative", "inconclusive"), report("yes", "no-evidence-of-use")}, "tentative", "0", "tentative", true},
		{"not found is a pass", []map[string]any{errorResult("not-found"), report("yes", "no-evidence-of-use")}, "tentative", "3", "yes", false},
		{"a runtime error never passes", []map[string]any{errorResult("runtime"), report("yes", "no-evidence-of-use")}, "no", "1", "error", true},
		{"a missing result never passes", []map[string]any{report("yes", "no-evidence-of-use")}, "no", "0", "error", true},
		{"a tool failure never passes", []map[string]any{report("yes", "no-evidence-of-use"), report("yes", "no-evidence-of-use")}, "no", "4", "yes", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := planned(t, tc.results...)
			log, err := script(t, "policy.sh", []string{"FAIL_ON=" + tc.failOn, "TOOL_EXIT=" + tc.toolExit}, out)
			var exit *exec.ExitError
			failed := errors.As(err, &exit)
			if err != nil && !failed {
				t.Fatal(err)
			}
			if failed != tc.fails {
				t.Fatalf("failed = %v, want %v: %s", failed, tc.fails, log)
			}
			if got := strings.TrimSpace(read(t, filepath.Join(out, "verdict"))); got != tc.verdict {
				t.Fatalf("verdict = %s, want %s", got, tc.verdict)
			}
			if tc.verdict == "tentative" && !strings.Contains(log, "::warning::") {
				t.Fatalf("no warning for a tentative resource: %s", log)
			}
		})
	}
}

func TestTheSummaryTable(t *testing.T) {
	tools(t)
	out := planned(t, report("no", "in-use"), errorResult("not-found"))
	if err := os.WriteFile(filepath.Join(out, "unsupported.txt"), []byte(sub+"rg/providers/microsoft.compute/disks/d-unknown\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := script(t, "policy.sh", []string{"FAIL_ON=no", "TOOL_EXIT=3"}, out); err == nil {
		t.Fatal("a no passed")
	}
	summary := read(t, filepath.Join(out, "summary.md"))
	for _, want := range []string{
		"### az-can-i-delete — pre-flight for 3 planned deletions",
		// Named by the id the tool parsed, from its own report; a row with
		// no report is named by its number (ADR-0007).
		"| `/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st-logs-prod` | delete | **no** | in-use | approved private endpoint \\| pe-sql-01 | 0 |",
		"| #2 (planned deletion 2, in plan order) | detach | not found | not-found |",
		"| #3 (planned deletion 3, in plan order) | unsupported | tentative | unsupported |",
		"Window 2026-06-23 → 2026-09-21 (90 d) · rules 2026-09-21 · fail-on: no · skipped non-ARM ids: 0",
		"never that deleting is safe",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("missing %q in:\n%s", want, summary)
		}
	}
	// The plan's own ids never reach the comment.
	if strings.Contains(summary, "nic-old-01") || strings.Contains(summary, "d-unknown") {
		t.Fatalf("a planned id reached the comment:\n%s", summary)
	}
	// Nothing the plan said is written out for upload either.
	if _, err := os.Stat(filepath.Join(out, "planned.tsv")); err == nil {
		t.Fatal("the plan's ids were written to an output file")
	}
}

// The action is what a workflow author reads. Its inputs and outputs are the
// specification's, and it never installs a moving target.
func TestTheActionDeclaresTheSpecifiedInterface(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "action.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Inputs  map[string]struct{ Default string } `yaml:"inputs"`
		Outputs map[string]any                      `yaml:"outputs"`
		Runs    struct{ Using string }              `yaml:"runs"`
	}
	if err := yaml.Unmarshal(body, &action); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"resource-ids", "terraform-plan-json", "stack-whatif-json", "arm-whatif-json", "fail-on", "window-days", "comment", "version"} {
		if _, ok := action.Inputs[input]; !ok {
			t.Errorf("missing input %s", input)
		}
	}
	for _, output := range []string{"verdict", "results-json", "summary-markdown", "ids-count", "skipped-count"} {
		if _, ok := action.Outputs[output]; !ok {
			t.Errorf("missing output %s", output)
		}
	}
	if action.Inputs["fail-on"].Default != "no" || action.Inputs["window-days"].Default != "90" || action.Inputs["version"].Default == "latest" {
		t.Errorf("defaults = %+v", action.Inputs)
	}
	if action.Runs.Using != "composite" {
		t.Errorf("runs.using = %s", action.Runs.Using)
	}
	if strings.Contains(string(body), "--exit-on-verdict") {
		t.Error("the action lets the tool's exit code decide the policy")
	}
	// ADR-0014: the action runs no other action at a moving tag.
	if strings.Contains(string(body), "uses:") {
		t.Error("the action runs another action; it would arrive unpinned and unread")
	}
}

func TestTheInstallerRefusesAnUnpinnedAction(t *testing.T) {
	tools(t)
	for _, env := range [][]string{
		{"ACTION_REF=main", "RUNNER_TEMP=" + t.TempDir()},
		{"VERSION=latest", "RUNNER_TEMP=" + t.TempDir()},
	} {
		log, err := script(t, "install.sh", env)
		if err == nil || !strings.Contains(log, "::error::") {
			t.Fatalf("%v: err %v log %s", env, err, log)
		}
	}
}
