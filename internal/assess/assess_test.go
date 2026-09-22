package assess_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/assess"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect/collecttest"
	"github.com/pawel-siwek/az-can-i-delete/internal/disk"
	"github.com/pawel-siwek/az-can-i-delete/internal/generic"
	"github.com/pawel-siwek/az-can-i-delete/internal/network"
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
)

const (
	diskID  = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.Compute/disks/disk1"
	otherNS = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.Sql/servers/sql1"
)

var cutoff = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

func target(t *testing.T, id string) armid.Target {
	t.Helper()
	parsed, err := armid.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func runner(arm *collecttest.ARM, graph *collecttest.Graph, log *collecttest.ActivityLog) *assess.Runner {
	if arm == nil {
		arm = &collecttest.ARM{}
	}
	if graph == nil {
		graph = &collecttest.Graph{}
	}
	if log == nil {
		log = &collecttest.ActivityLog{}
	}
	return assess.New(collecttest.Clients(arm, graph, &collecttest.Metrics{}, log, nil), "dev")
}

func options() assess.Options {
	window, _ := assess.ParseWindow("30d", cutoff)
	return assess.Options{Requested: window, Cutoff: cutoff}
}

func TestParseWindow(t *testing.T) {
	for _, tc := range []struct {
		flag string
		days int
		bad  bool
	}{
		{"", assess.DefaultWindowDays, false},
		{"30d", 30, false},
		{"45", 45, false},
		{"7d", assess.MinWindowDays, false},
		{"93d", assess.MaxWindowDays, false},
		{"6d", 0, true},
		{"94d", 0, true},
		{"a while", 0, true},
	} {
		window, err := assess.ParseWindow(tc.flag, cutoff)
		if tc.bad {
			if err == nil {
				t.Errorf("--window %q must be refused", tc.flag)
			}
			continue
		}
		if err != nil || window.Days != tc.days || window.End != cutoff ||
			window.Start != cutoff.AddDate(0, 0, -tc.days) || window.Grain != "P1D" {
			t.Errorf("--window %q = %+v, %v; want %d complete days", tc.flag, window, err, tc.days)
		}
	}
}

func TestMissingResourceIsNotAVerdict(t *testing.T) {
	arm := &collecttest.ARM{GetFunc: func(context.Context, string, string) (collect.Resource, error) {
		return collect.Resource{}, &collect.Failure{StatusCode: http.StatusNotFound, ErrorCode: "ResourceNotFound"}
	}}
	outcome, err := runner(arm, nil, nil).Check(context.Background(), target(t, diskID), options())
	if err != nil {
		t.Fatalf("a missing resource is an outcome, not an error: %v", err)
	}
	if code := output.ExitCode([]output.Outcome{outcome}, false); code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
}

func TestUnsupportedTypeIsRefused(t *testing.T) {
	arm := &collecttest.ARM{GetFunc: func(context.Context, string, string) (collect.Resource, error) {
		t.Error("an unsupported type must not be read at all")
		return collect.Resource{}, nil
	}}
	_, err := runner(arm, nil, nil).Check(context.Background(), target(t, otherNS), options())
	if !errors.Is(err, assess.ErrUnsupportedType) {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

func TestCollectionFailureIsAnErrorNotAnAssessment(t *testing.T) {
	arm := &collecttest.ARM{GetFunc: func(context.Context, string, string) (collect.Resource, error) {
		return collect.Resource{}, collecttest.Forbidden()
	}}
	outcome, err := runner(arm, nil, nil).Check(context.Background(), target(t, diskID), options())
	if err == nil {
		t.Fatal("an unreadable resource must be reported as an error")
	}
	if code := output.ExitCode([]output.Outcome{outcome}, false); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestReportCarriesTheGenericEvidenceAndCoverage(t *testing.T) {
	arm := &collecttest.ARM{GetFunc: func(_ context.Context, id, apiVersion string) (collect.Resource, error) {
		if apiVersion != "2026-03-02" {
			t.Errorf("api-version = %s, want the pinned disk version", apiVersion)
		}
		return collect.Resource{ID: id, Name: "disk1", Type: "Microsoft.Compute/disks",
			Tags:       map[string]string{"owner": "platform"},
			Properties: map[string]any{"provisioningState": "Succeeded", "diskState": "Unattached"}}, nil
	}}
	graph := &collecttest.Graph{Answers: []collecttest.GraphAnswer{{
		Match: "where id =~", Rows: collect.Rows{Rows: []map[string]any{{"id": diskID}}}}}}
	outcome, err := runner(arm, graph, nil).Check(context.Background(), target(t, diskID), options())
	if err != nil {
		t.Fatal(err)
	}
	if code := output.ExitCode([]output.Outcome{outcome}, true); code != 11 {
		t.Fatalf("exit code = %d, want 11: the disk analyzer does not exist yet, so the answer is tentative", code)
	}
	report := reportValue(t, outcome)
	// A disk is assessed by the generic layer and the disk analyzer together.
	want := len(generic.Signals) + len(disk.Signals)
	evidence, _ := report["evidence"].([]any)
	if len(evidence) != want {
		t.Fatalf("report carried %d signals, want %d", len(evidence), want)
	}
	coverage, _ := report["coverage"].(map[string]any)
	if coverage["total"] != float64(want) {
		t.Errorf("coverage = %v, want every collected signal counted", coverage)
	}
	scope, _ := report["scope"].(map[string]any)
	if scope["argVisible"] != true || scope["resourceChangesDays"] != float64(assess.ResourceChangesDays) {
		t.Errorf("scope = %v, want the disclosed collection coverage", scope)
	}
	if report["rulesDate"] == nil || report["rulesDate"] == "" {
		t.Error("a report must state the rule table it was produced under")
	}
}

func TestGraphBlindnessIsVisibleInTheReport(t *testing.T) {
	arm := &collecttest.ARM{GetFunc: func(_ context.Context, id, _ string) (collect.Resource, error) {
		return collect.Resource{ID: id, Name: "disk1", Type: "Microsoft.Compute/disks"}, nil
	}}
	outcome, err := runner(arm, &collecttest.Graph{}, nil).Check(context.Background(), target(t, diskID), options())
	if err != nil {
		t.Fatal(err)
	}
	report := reportValue(t, outcome)
	scope, _ := report["scope"].(map[string]any)
	if scope["argVisible"] != false || scope["resourceChangesDays"] != float64(0) {
		t.Errorf("scope = %v, want the blindness disclosed", scope)
	}
	coverage, _ := report["coverage"].(map[string]any)
	if coverage["criticalUnknown"] == float64(0) {
		t.Error("an unreadable hard dependency must be counted as a critical unknown")
	}
	if report["verdict"] != "tentative" {
		t.Errorf("verdict = %v, want tentative when critical signals are unknown", report["verdict"])
	}
}

// reportValue renders the outcome the way the CLI does and reads the result
// back, so a test sees exactly what a caller would.
func reportValue(t *testing.T, outcome output.Outcome) map[string]any {
	t.Helper()
	var rendered bytes.Buffer
	if err := output.Render(&rendered, "json", []output.Outcome{outcome}); err != nil {
		t.Fatal(err)
	}
	value := map[string]any{}
	if err := json.Unmarshal(rendered.Bytes(), &value); err != nil {
		t.Fatalf("rendered output is not a report: %v\n%s", err, rendered.String())
	}
	return value
}

func TestALongDetachedDiskCanReachYes(t *testing.T) {
	arm := &collecttest.ARM{GetFunc: func(_ context.Context, id, _ string) (collect.Resource, error) {
		return collect.Resource{ID: id, Name: "disk1", Type: "Microsoft.Compute/disks",
			SystemData: map[string]any{"createdAt": cutoff.AddDate(0, 0, -400).Format(time.RFC3339)},
			Properties: map[string]any{
				"provisioningState":       "Succeeded",
				"diskState":               "Unattached",
				"LastOwnershipUpdateTime": cutoff.AddDate(0, 0, -120).Format(time.RFC3339),
			}}, nil
	}}
	graph := &collecttest.Graph{Answers: []collecttest.GraphAnswer{{
		Match: "where id =~", Rows: collect.Rows{Rows: []map[string]any{{"id": diskID}}}}}}
	log := &collecttest.ActivityLog{Log: collect.ActivityLog{Days: 90}}
	outcome, err := runner(arm, graph, log).Check(context.Background(), target(t, diskID), options())
	if err != nil {
		t.Fatal(err)
	}
	report := reportValue(t, outcome)
	if report["verdict"] != "yes" || report["reasonClass"] != "no-evidence-of-use" {
		t.Fatalf("verdict = %v/%v with reasons %v, want yes/no-evidence-of-use",
			report["verdict"], report["reasonClass"], report["reasons"])
	}
	// Every `yes` carries the approved limitations verbatim and escalates
	// nothing, because there is nothing left for a human to resolve.
	if limitations, _ := report["limitations"].([]any); len(limitations) == 0 {
		t.Error("a yes must print the approved limitations")
	}
	if report["humanEscalation"] != false {
		t.Error("a yes does not escalate")
	}
	window, _ := report["window"].(map[string]any)
	effective, _ := window["effective"].(map[string]any)
	if effective["days"] != float64(30) {
		t.Errorf("effective window = %v, want the full 30 days", window)
	}
	if code := output.ExitCode([]output.Outcome{outcome}, true); code != 0 {
		t.Errorf("exit code = %d, want 0 for yes", code)
	}
}

func TestAnAttachedDiskIsBlocked(t *testing.T) {
	arm := &collecttest.ARM{GetFunc: func(_ context.Context, id, _ string) (collect.Resource, error) {
		return collect.Resource{ID: id, Name: "disk1", Type: "Microsoft.Compute/disks",
			Properties: map[string]any{"diskState": "Attached",
				"managedBy": "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.Compute/virtualMachines/vm1"}}, nil
	}}
	graph := &collecttest.Graph{Answers: []collecttest.GraphAnswer{{
		Match: "where id =~", Rows: collect.Rows{Rows: []map[string]any{{"id": diskID}}}}}}
	outcome, err := runner(arm, graph, nil).Check(context.Background(), target(t, diskID), options())
	if err != nil {
		t.Fatal(err)
	}
	report := reportValue(t, outcome)
	if report["verdict"] != "no" || report["reasonClass"] != "blocked" {
		t.Fatalf("verdict = %v/%v, want no/blocked", report["verdict"], report["reasonClass"])
	}
	if code := output.ExitCode([]output.Outcome{outcome}, true); code != 10 {
		t.Errorf("exit code = %d, want 10 for no", code)
	}
}

func TestADetachedInterfaceCanReachYes(t *testing.T) {
	nicID := "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.Network/networkInterfaces/nic1"
	arm := &collecttest.ARM{GetFunc: func(_ context.Context, id, apiVersion string) (collect.Resource, error) {
		if apiVersion != "2026-01-01" {
			t.Errorf("api-version = %s, want the pinned network version", apiVersion)
		}
		return collect.Resource{ID: id, Name: "nic1", Type: "Microsoft.Network/networkInterfaces",
			SystemData: map[string]any{"createdAt": cutoff.AddDate(0, 0, -400).Format(time.RFC3339)},
			Properties: map[string]any{"provisioningState": "Succeeded",
				"ipConfigurations": []any{map[string]any{"properties": map[string]any{"privateIPAllocationMethod": "Dynamic"}}}}}, nil
	}}
	graph := &collecttest.Graph{Answers: []collecttest.GraphAnswer{{
		Match: "where id =~", Rows: collect.Rows{Rows: []map[string]any{{"id": nicID}}}}}}
	log := &collecttest.ActivityLog{Log: collect.ActivityLog{Days: 90}}
	outcome, err := runner(arm, graph, log).Check(context.Background(), target(t, nicID), options())
	if err != nil {
		t.Fatal(err)
	}
	report := reportValue(t, outcome)
	if report["verdict"] != "yes" {
		t.Fatalf("verdict = %v with reasons %v, want yes", report["verdict"], report["reasons"])
	}
	evidence, _ := report["evidence"].([]any)
	if want := len(generic.Signals) + len(network.NICSignals); len(evidence) != want {
		t.Errorf("report carried %d signals, want %d", len(evidence), want)
	}
}
