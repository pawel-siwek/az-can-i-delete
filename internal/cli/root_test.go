package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/assess"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect/collecttest"
)

const testTarget = "/subscriptions/01234567-89ab-cdef-0123-456789abcdef/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/store"

var testCutoff = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

// testDeps runs the real command paths over fakes. No test may build a
// credential or reach Azure, so every run goes through an injected runner.
func testDeps(arm *collecttest.ARM, graph *collecttest.Graph) Dependencies {
	if arm == nil {
		arm = &collecttest.ARM{GetFunc: func(context.Context, string, string) (collect.Resource, error) {
			return collect.Resource{}, &collect.Failure{StatusCode: http.StatusNotFound, ErrorCode: "ResourceNotFound"}
		}}
	}
	if graph == nil {
		graph = &collecttest.Graph{}
	}
	return Dependencies{
		Now: func() time.Time { return testCutoff },
		Runner: func(version string, _ bool) (*assess.Runner, error) {
			clients := collecttest.Clients(arm, graph, &collecttest.Metrics{}, &collecttest.ActivityLog{}, nil)
			return assess.New(clients, version), nil
		},
	}
}

// liveDeps answer as a readable, quiet storage account would.
func liveDeps() Dependencies {
	arm := &collecttest.ARM{GetFunc: func(_ context.Context, id, _ string) (collect.Resource, error) {
		return collect.Resource{ID: id, Name: "store", Type: "Microsoft.Storage/storageAccounts",
			Properties: map[string]any{"provisioningState": "Succeeded"}}, nil
	}}
	graph := &collecttest.Graph{Answers: []collecttest.GraphAnswer{{
		Match: "where id =~", Rows: collect.Rows{Rows: []map[string]any{{"id": testTarget}}}}}}
	return testDeps(arm, graph)
}

func run(t *testing.T, deps Dependencies, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = RunWith(context.Background(), args, strings.NewReader(""), &out, &errOut, "dev", deps)
	return code, out.String(), errOut.String()
}

func TestVersion(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"version"}, {"--version"}} {
		code, out, errOut := run(t, testDeps(nil, nil), args...)
		if code != 0 || out != "az-can-i-delete dev\n" || errOut != "" {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, out, errOut)
		}
	}
}

func TestCommandHelp(t *testing.T) {
	t.Parallel()
	for _, path := range [][]string{
		{}, {"check"}, {"cordon"}, {"uncordon"}, {"status"}, {"history"},
		{"demo"}, {"patterns"}, {"patterns", "list"}, {"mcp"},
	} {
		t.Run(strings.Join(path, "/"), func(t *testing.T) {
			code, out, errOut := run(t, testDeps(nil, nil), append(append([]string(nil), path...), "--help")...)
			if code != 0 || !strings.Contains(out, "Usage:") || errOut != "" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"unknown-command"}, {"check"}, {"check", "--unknown-flag"},
		{"version", "extra"}, {"cordon"}, {"uncordon"}, {"status"},
	} {
		code, out, errOut := run(t, testDeps(nil, nil), args...)
		if code != 2 || out != "" || !strings.HasPrefix(errOut, "error: ") {
			t.Errorf("%v: code=%d stdout=%q stderr=%q", args, code, out, errOut)
		}
	}
}

func TestUnimplementedCommandsFailExplicitly(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"cordon", testTarget}, {"uncordon", testTarget},
		{"history"},
	} {
		code, out, errOut := run(t, testDeps(nil, nil), args...)
		if code != 1 || out != "" || !strings.Contains(errOut, "not implemented") {
			t.Errorf("%v: code=%d stdout=%q stderr=%q", args, code, out, errOut)
		}
	}
}

func TestTargetValidation(t *testing.T) {
	t.Parallel()
	// A parsed target reaches the runner, which answers 404 here, so exit 3
	// distinguishes "parsed and assessed" from a usage error.
	for _, command := range []string{"check", "cordon", "uncordon", "status"} {
		// status reads, so a parsed target reaches the fake and comes back
		// not found; a slot is a type the cordon gate refuses, which is usage.
		parsed, slot := 1, 1
		switch command {
		case "check":
			parsed, slot = 3, 3
		case "status":
			parsed, slot = 3, 2
		}
		for _, tc := range []struct {
			name string
			args []string
			code int
		}{
			{"invalid", []string{"/placeholder"}, 2},
			{"portal", []string{"https://portal.azure.com/#resource" + testTarget + "/overview"}, parsed},
			{"slot preserved", []string{strings.ReplaceAll(testTarget, "Microsoft.Storage/storageAccounts/store", "Microsoft.Web/sites/app/slots/staging")}, slot},
			{"subscription match", []string{testTarget, "--subscription", "01234567-89AB-CDEF-0123-456789ABCDEF"}, parsed},
			{"subscription mismatch", []string{testTarget, "--subscription", "fedcba98-7654-3210-fedc-ba9876543210"}, 2},
			{"subscription invalid", []string{testTarget, "--subscription", "not-a-guid"}, 2},
			{"subscription empty", []string{testTarget, "--subscription="}, 2},
			{"URL credentials", []string{"https://secret:password@portal.azure.com/#resource" + testTarget}, 2},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				code, _, errOut := run(t, testDeps(nil, nil), append([]string{command}, tc.args...)...)
				if code != tc.code {
					t.Fatalf("%v: code=%d, want %d (stderr %q)", tc.args, code, tc.code, errOut)
				}
				if strings.Contains(errOut, "secret") || strings.Contains(errOut, "password") {
					t.Fatalf("error echoed credentials: %s", errOut)
				}
			})
		}
	}
}

func TestUnsupportedTypeIsRefusedNotAssessed(t *testing.T) {
	t.Parallel()
	extension := testTarget + "/providers/Microsoft.Authorization/locks/L"
	code, out, errOut := run(t, testDeps(nil, nil), "check", extension)
	if code != 1 || !strings.Contains(errOut, "unsupported resource type") {
		t.Fatalf("code=%d stderr=%q, want a refusal", code, errOut)
	}
	if strings.Contains(out, "\"verdict\"") {
		t.Error("an unsupported type must not produce a verdict")
	}
}

func TestCheckMultipleTargets(t *testing.T) {
	t.Parallel()
	other := strings.ReplaceAll(testTarget, "01234567-89ab-cdef-0123-456789abcdef", "fedcba98-7654-3210-fedc-ba9876543210")
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"positional", []string{testTarget, other}, 3},
		{"space delimited ids", []string{"--ids", testTarget, other}, 3},
		{"repeated ids", []string{"--ids", testTarget, "--ids", other}, 3},
		{"invalid second positional", []string{testTarget, "/placeholder"}, 2},
		{"invalid second id", []string{"--ids", testTarget, "/placeholder"}, 2},
		{"invalid repeated id", []string{"--ids", testTarget, "--ids", "/placeholder"}, 2},
		{"empty id", []string{"--ids="}, 2},
		{"invalid id with valid positional", []string{"--ids=", testTarget}, 2},
		{"cross subscription mismatch", []string{"--ids", testTarget, other, "--subscription", "01234567-89ab-cdef-0123-456789abcdef"}, 2},
		{"same subscription", []string{"--ids", testTarget, testTarget + "2", "--subscription", "01234567-89AB-CDEF-0123-456789ABCDEF"}, 3},
		{"comma in name is not a list", []string{"--ids", testTarget + ",Another"}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut := run(t, testDeps(nil, nil), append([]string{"check"}, tc.args...)...)
			if code != tc.code {
				t.Fatalf("%v: code=%d, want %d (stderr %q)", tc.args, code, tc.code, errOut)
			}
		})
	}
}

func TestCheckRendersAnAssessment(t *testing.T) {
	t.Parallel()
	code, out, errOut := run(t, liveDeps(), "check", testTarget, "-o", "json")
	if code != 0 || errOut != "" {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("output is not a report: %v\n%s", err, out)
	}
	// The storage analyzer does not exist yet, so its Required signals are
	// missing and the honest answer is tentative, never yes.
	if report["verdict"] != "tentative" || report["reasonClass"] != "inconclusive" {
		t.Fatalf("verdict = %v/%v, want tentative/inconclusive", report["verdict"], report["reasonClass"])
	}
	if report["schemaVersion"] != "2" || report["resourceId"] == nil {
		t.Fatalf("report shape = %v", report)
	}
	if report["humanEscalation"] != true || report["requiredHumanQuestion"] == "" {
		t.Error("a tentative verdict must escalate to a human")
	}
}

func TestExitOnVerdictIsAResultNotAnError(t *testing.T) {
	t.Parallel()
	code, out, errOut := run(t, liveDeps(), "check", testTarget, "--exit-on-verdict", "-o", "json")
	if code != 11 {
		t.Fatalf("code = %d, want 11 for tentative", code)
	}
	if errOut != "" {
		t.Errorf("a verdict exit must not print an error: %q", errOut)
	}
	if !strings.Contains(out, "\"verdict\"") {
		t.Error("the report must still be printed")
	}
}

func TestWindowValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		window string
		code   int
	}{{"30d", 0}, {"7d", 0}, {"93d", 0}, {"45", 0}, {"6d", 2}, {"94d", 2}, {"soon", 2}} {
		t.Run(tc.window, func(t *testing.T) {
			code, _, errOut := run(t, liveDeps(), "check", testTarget, "--window", tc.window, "-o", "none")
			if code != tc.code {
				t.Fatalf("--window %s: code=%d, want %d (%s)", tc.window, code, tc.code, errOut)
			}
		})
	}
}

func TestIndependentCommandDefaults(t *testing.T) {
	t.Parallel()
	root := NewRootCommand("dev")
	for _, tc := range []struct {
		command, flag, want string
	}{
		{"check", "window", "30d"},
		{"cordon", "window", "7d"},
		{"mcp", "redact-tags", "true"},
		{"check", "data-plane", "false"},
	} {
		command, _, err := root.Find([]string{tc.command})
		if err != nil {
			t.Fatal(err)
		}

		flag := command.Flags().Lookup(tc.flag)
		if flag == nil || flag.DefValue != tc.want {
			t.Errorf("%s --%s: expected default %q", tc.command, tc.flag, tc.want)
		}
	}
}

func TestOutputFormatValidation(t *testing.T) {
	for _, format := range []string{"json", "jsonc", "table", "tsv", "yaml", "none", "invalid"} {
		code, _, errOut := run(t, liveDeps(), "check", testTarget, "-o", format)
		want := 0
		if format == "invalid" {
			want = 2
		}
		if code != want {
			t.Fatalf("%s: %d %s", format, code, errOut)
		}
	}
}

func TestUnsupportedQuery(t *testing.T) {
	code, _, errOut := run(t, testDeps(nil, nil), "check", testTarget, "--query", "verdict")
	if code != 2 || !strings.Contains(errOut, "query is not implemented") {
		t.Fatalf("%d %s", code, errOut)
	}
}

func TestDefaultOutputFormat(t *testing.T) {
	if defaultOutputFormat(&bytes.Buffer{}) != "json" {
		t.Fatal("non-TTY default")
	}
	if formatForTerminal(true) != "table" || formatForTerminal(false) != "json" {
		t.Fatal("terminal default")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	}()
	if defaultOutputFormat(writer) != "json" {
		t.Fatal("real pipe fd mistaken for a terminal")
	}
}

// The data-plane walk is opt-in, and the opt-in has to reach the runner: a
// flag that is accepted and then ignored is worse than one that is refused.
func TestTheDataPlaneFlagReachesTheRunner(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		args []string
		want bool
	}{
		{"off by default", []string{"check", testTarget}, false},
		{"on when asked", []string{"check", testTarget, "--data-plane"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var asked bool
			deps := testDeps(nil, nil)
			inner := deps.Runner
			deps.Runner = func(version string, dataPlane bool) (*assess.Runner, error) {
				asked = dataPlane
				return inner(version, dataPlane)
			}
			run(t, deps, test.args...)
			if asked != test.want {
				t.Errorf("the runner was built with dataPlane=%v, want %v", asked, test.want)
			}
		})
	}
}
