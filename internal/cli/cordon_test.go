package cli

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/pawel-siwek/az-can-i-delete/internal/assess"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect/collecttest"
	"github.com/pawel-siwek/az-can-i-delete/internal/cordon"
)

// account is a storage account the fake writer really changes, so the
// command's own verification reads back what it wrote.
type account struct {
	mu     sync.Mutex
	access string
	tags   map[string]string
	calls  []string
}

func (a *account) Principal(context.Context) (cordon.Principal, error) {
	return cordon.Principal{ObjectID: "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"}, nil
}

func (a *account) Patch(_ context.Context, _, _ string, body map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.access = body["properties"].(map[string]any)["publicNetworkAccess"].(string)
	a.calls = append(a.calls, "patch "+a.access)
	return nil
}

func (a *account) Action(context.Context, string, string, string) error { return nil }

func (a *account) Tags(_ context.Context, _ string, op cordon.TagOperation, tags map[string]string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, "tags "+string(op))
	for k, v := range tags {
		if op == cordon.TagMerge {
			a.tags[k] = v
		} else {
			delete(a.tags, k)
		}
	}
	return nil
}

func (a *account) CheckPolicy(context.Context, cordon.PolicyCheck) (cordon.PolicyResult, error) {
	return cordon.PolicyResult{}, nil
}

func cordonDeps(t *testing.T, a *account) Dependencies {
	t.Helper()
	t.Setenv("AZCID_HOME", t.TempDir())
	arm := &collecttest.ARM{GetFunc: func(_ context.Context, id, _ string) (collect.Resource, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		tags := map[string]string{}
		for k, v := range a.tags {
			tags[k] = v
		}
		return collect.Resource{ID: id, Name: "store", Type: "Microsoft.Storage/storageAccounts", Tags: tags,
			Properties: map[string]any{"provisioningState": "Succeeded", "publicNetworkAccess": a.access}}, nil
	}}
	graph := &collecttest.Graph{Answers: []collecttest.GraphAnswer{{
		Match: "where id =~", Rows: collect.Rows{Rows: []map[string]any{{"id": testTarget}}}}}}
	deps := testDeps(arm, graph)
	deps.Runner = func(version string, _ bool) (*assess.Runner, error) {
		return assess.New(collecttest.Clients(arm, graph, &collecttest.Metrics{}, &collecttest.ActivityLog{}, nil), version), nil
	}
	deps.Writer = func(string) (cordon.Writer, error) { return a, nil }
	return deps
}

func TestCordonShowsThePlanAndWritesNothingWithoutYes(t *testing.T) {
	a := &account{access: "Enabled", tags: map[string]string{}}
	deps := cordonDeps(t, a)
	code, out, errOut := run(t, deps, "cordon", testTarget, "--dry-run", "-o", "table")
	if code != 0 || errOut != "" || !strings.Contains(out, "CORDON PLAN (publicNetworkAccess Enabled → Disabled)\n    resource "+testTarget) || !strings.Contains(out, "nothing was written") {
		t.Fatalf("dry run: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	// Seen live: the untrusted-text filter read the timestamp's "T12:" as a
	// URL scheme and hid the whole tag. The tag is this tool's own grammar.
	if !strings.Contains(out, "state tag azcid=v=1;m=pna;t=2026-09-21T12:00:00Z;by=0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9;p=Enabled;w=7") ||
		strings.Contains(out, "URL omitted") {
		t.Fatalf("the plan did not show the tag:\n%s", out)
	}
	code, out, errOut = run(t, deps, "cordon", testTarget, "-o", "table")
	if code != 1 || !strings.Contains(out, "CORDON PLAN") || !strings.Contains(errOut, "pass --yes") {
		t.Fatalf("no --yes: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if len(a.calls) != 0 {
		t.Fatalf("a plan wrote: %v", a.calls)
	}
}

func TestCordonThenStatusThenUncordon(t *testing.T) {
	a := &account{access: "Enabled", tags: map[string]string{}}
	deps := cordonDeps(t, a)
	code, out, errOut := run(t, deps, "cordon", testTarget, "--yes", "-o", "json")
	if code != 0 || errOut != "" {
		t.Fatalf("cordon: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil || report["applied"] != true || a.access != "Disabled" {
		t.Fatalf("report %v err %v access %s", report, err, a.access)
	}
	code, out, _ = run(t, deps, "status", testTarget, "-o", "json")
	if code != 0 || !strings.Contains(out, `"cordoned":true`) {
		t.Fatalf("status: code=%d stdout=%q", code, out)
	}
	// Without --yes an uncordon only says what it would do.
	if code, _, errOut := run(t, deps, "uncordon", testTarget, "-o", "json"); code != 1 || !strings.Contains(errOut, "pass --yes") || a.access != "Disabled" {
		t.Fatalf("uncordon without --yes: code=%d stderr=%q access=%s", code, errOut, a.access)
	}
	code, out, errOut = run(t, deps, "uncordon", testTarget, "--yes", "-o", "json")
	if code != 0 || errOut != "" || a.access != "Enabled" || a.tags["azcid"] != "" {
		t.Fatalf("uncordon: code=%d stdout=%q stderr=%q access=%s tags=%v", code, out, errOut, a.access, a.tags)
	}
	want := "patch Disabled|tags Merge|patch Enabled|tags Delete"
	if strings.Join(a.calls, "|") != want {
		t.Fatalf("calls = %v", a.calls)
	}
}

func TestCordonRefusesATypeItCannotIsolate(t *testing.T) {
	a := &account{access: "Enabled", tags: map[string]string{}}
	nsg := strings.Replace(testTarget, "Microsoft.Storage/storageAccounts/store", "Microsoft.Network/networkSecurityGroups/n1", 1)
	code, _, errOut := run(t, cordonDeps(t, a), "cordon", nsg, "--yes")
	if code != 2 || !strings.Contains(errOut, "removing an NSG's associations is itself the destructive change") {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
}

func TestCordonWindowIsOneToThirtyDays(t *testing.T) {
	a := &account{access: "Enabled", tags: map[string]string{}}
	for _, window := range []string{"0d", "31d", "a week"} {
		if code, _, _ := run(t, cordonDeps(t, a), "cordon", testTarget, "--window", window); code != 2 {
			t.Errorf("--window %s: exit %d, want 2", window, code)
		}
	}
}
