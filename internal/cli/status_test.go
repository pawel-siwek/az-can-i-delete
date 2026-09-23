package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect/collecttest"
)

const statusTag = "v=1;m=pna;t=2026-09-20T10:30:00Z;by=0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9;p=Enabled;w=7"

func cordonedDeps(access string) Dependencies {
	arm := &collecttest.ARM{GetFunc: func(_ context.Context, id, _ string) (collect.Resource, error) {
		return collect.Resource{ID: id, Name: "store", Type: "Microsoft.Storage/storageAccounts",
			Tags:       map[string]string{"azcid": statusTag},
			Properties: map[string]any{"publicNetworkAccess": access}}, nil
	}}
	return testDeps(arm, nil)
}

func TestStatusPrintsTheCordonAsJSON(t *testing.T) {
	t.Parallel()
	code, out, errOut := run(t, cordonedDeps("Disabled"), "status", testTarget, "-o", "json")
	if code != 0 || errOut != "" {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	var status map[string]any
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if status["cordoned"] != true || status["mode"] != "pna" || status["prior"] != "Enabled" || status["reverted"] != false {
		t.Fatalf("status = %v", status)
	}
}

func TestStatusSaysWhenACordonWasUndone(t *testing.T) {
	t.Parallel()
	code, out, errOut := run(t, cordonedDeps("Enabled"), "status", testTarget, "-o", "table")
	if code != 0 || errOut != "" {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	for _, want := range []string{"REVERTED — store", "prior Enabled (from the tag)", "denied public requests may not be recorded"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestStatusRefusesATypeItCannotCordon(t *testing.T) {
	t.Parallel()
	disk := strings.Replace(testTarget, "Microsoft.Storage/storageAccounts/store", "Microsoft.Compute/disks/d1", 1)
	code, out, errOut := run(t, testDeps(nil, nil), "status", disk)
	if code != 2 || out != "" || !strings.Contains(errOut, "an unattached disk receives no traffic") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

func TestPatternsListPrintsTheKnowledgeBaseInMatchOrder(t *testing.T) {
	t.Parallel()
	code, out, errOut := run(t, testDeps(nil, nil), "patterns", "list", "-o", "json")
	if code != 0 || errOut != "" {
		t.Fatalf("code=%d stderr=%q", code, errOut)
	}
	var document struct {
		Count    int `json:"count"`
		Patterns []struct {
			ID        string `json:"id"`
			Regex     string `json:"regex"`
			Mechanism bool   `json:"mechanism"`
		} `json:"patterns"`
	}
	if err := json.Unmarshal([]byte(out), &document); err != nil {
		t.Fatal(err)
	}
	if document.Count != 79 || len(document.Patterns) != 79 || document.Patterns[0].ID != "container.insights-logs" {
		t.Fatalf("count %d, first %+v", document.Count, document.Patterns[0])
	}
	for _, p := range document.Patterns {
		if p.Mechanism && p.Regex != "" {
			t.Fatalf("%s prints a pattern it never matches by", p.ID)
		}
	}
	// The source links stay in kb.yaml. A confirm text may still name a URL
	// shape, such as a storageUri prefix, which is a pattern and not a link.
	if strings.Contains(out, "source_url") || strings.Contains(out, "github.com/") {
		t.Fatal("the list printed a source link")
	}
	code, out, _ = run(t, testDeps(nil, nil), "patterns", "list", "-o", "table")
	if code != 0 || !strings.Contains(out, "79 patterns") || !strings.Contains(out, "never by name") {
		t.Fatalf("table:\n%s", out)
	}
}
