package verdict_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/age"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

func TestEffectiveWindows(t *testing.T) {
	if verdict.DefaultRequestedDays != 30 {
		t.Fatal("product default must remain 30 days")
	}
	requested := testInput().Requested
	tests := []struct {
		name string
		age  verdict.Age
		days int
	}{
		{"verified-old", verdict.Age{Confidence: "verified", LowerBoundDays: 400}, 30},
		{"bounded-young", verdict.Age{Confidence: "bounded", LowerBoundDays: 20}, 20},
		{"verified-at-boundary", verdict.Age{Confidence: "verified", LowerBoundDays: 30}, 30},
		{"inferred-uses-requested", verdict.Age{Confidence: "inferred", LowerBoundDays: 90}, 30},
		{"unknown-zero", verdict.Age{Confidence: "unknown"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verdict.EffectiveWindow(requested, tt.age)
			want := verdict.Window{Start: requested.End.Add(-time.Duration(tt.days) * 24 * time.Hour),
				End: requested.End, Days: tt.days, Grain: requested.Grain}
			if got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestCompleteReasons(t *testing.T) {
	in := testInput()
	in.Evidence = append(in.Evidence,
		verdict.Evidence{ID: "storage.metrics.user-writes", Tier: verdict.TierLiveActivity, Status: verdict.StatusPresent},
		verdict.Evidence{ID: "storage.pe.approved", Tier: verdict.TierHardDependency, Status: verdict.StatusPresent},
		verdict.Evidence{ID: "generic.tags.protect", Tier: verdict.TierHardDependency, Status: verdict.StatusPresent},
		verdict.Evidence{ID: "generic.lock.cannotdelete", Tier: verdict.TierBlocker, Status: verdict.StatusPresent},
		verdict.Evidence{ID: "generic.deny-assignment", Tier: verdict.TierBlocker, Status: verdict.StatusPresent},
	)
	got, err := verdict.Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"generic.deny-assignment", "generic.lock.cannotdelete", "generic.tags.protect", "storage.pe.approved", "storage.metrics.user-writes"}
	if !slices.Equal(got.Reasons, want) {
		t.Fatalf("all positive tiers 1-3 must survive: %v", got.Reasons)
	}
}

func TestMultipleMissingAndUnknownReasons(t *testing.T) {
	in := testInput()
	in.Evidence = nil
	got, err := verdict.Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"required.missing:disk.ownership.age-ge-30d", "required.missing:disk.state.unattached", "required.missing:generic.arg.visible"}
	if !slices.Equal(got.Reasons, want) {
		t.Fatalf("missing reasons incomplete: %v", got.Reasons)
	}
	in.Evidence = []verdict.Evidence{
		{ID: "storage.lease.held", Tier: verdict.TierLiveActivity, Status: verdict.StatusUnknown, Critical: true},
		{ID: "storage.pe.approved", Tier: verdict.TierHardDependency, Status: verdict.StatusUnknown, Critical: true},
		{ID: "generic.lock.cannotdelete", Tier: verdict.TierBlocker, Status: verdict.StatusUnknown, Critical: true},
	}
	got, err = verdict.Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"generic.lock.cannotdelete", "storage.pe.approved", "storage.lease.held"}
	if !slices.Equal(got.Reasons, want) || !slices.Equal(got.Unknowns, want) {
		t.Fatalf("critical unknowns not ordered by tier: %+v", got)
	}
}

func TestUnsupportedNeverYieldsYes(t *testing.T) {
	in := testInput()
	in.Type = "Microsoft.KeyVault/vaults"
	in.Required = verdict.RequiredForType(in.Type)
	in.Evidence = []verdict.Evidence{{ID: "generic.never", Tier: verdict.TierObservedIdle, Status: verdict.StatusPresent}}
	got, err := verdict.Evaluate(in)
	if err != nil || got.Verdict != "tentative" || !slices.Equal(got.Reasons, []string{"generic.never"}) {
		t.Fatalf("generic.never must not become yes even if present: %+v, %v", got, err)
	}
}

func TestIdenticalDuplicatesHaveSetReasons(t *testing.T) {
	in := testInput()
	in.Evidence = append(in.Evidence, in.Evidence[0])
	got, err := verdict.Evaluate(in)
	if err != nil || got.Verdict != "yes" || len(got.Reasons) != len(in.Required) {
		t.Fatalf("identical duplicate should not conflict or repeat reasons: %+v, %v", got, err)
	}
	checkInvariants(t, in, got)
}

func TestConflictingDuplicateMetadata(t *testing.T) {
	for _, field := range []string{"tier", "critical", "details", "window", "unknown"} {
		t.Run(field, func(t *testing.T) {
			in := testInput()
			e := in.Evidence[0]
			switch field {
			case "tier":
				e.Tier = verdict.TierInfo
			case "critical":
				e.Critical = true
			case "details":
				e.Details = map[string]any{"count": 1}
			case "window":
				e.Window = &in.Requested
			case "unknown":
				e.Unknown = &verdict.Unknown{Code: verdict.UnkPartial}
			}
			in.Evidence = append(in.Evidence, e)
			got, err := verdict.Evaluate(in)
			var internal *verdict.EvaluationError
			if !errors.As(err, &internal) || got.Verdict != "" {
				t.Fatalf("conflicting copies must have no verdict: %+v, %v", got, err)
			}
		})
	}
}

func TestNormalizedShapeValidation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*verdict.Input)
	}{
		{"window-too-small", func(in *verdict.Input) { in.Requested.Days = 6 }},
		{"window-too-large", func(in *verdict.Input) { in.Requested.Days = 94 }},
		{"age-invalid", func(in *verdict.Input) { in.Age.Confidence = "certain" }},
		{"age-negative", func(in *verdict.Input) { in.Age.LowerBoundDays = -1 }},
		{"empty-id", func(in *verdict.Input) { in.Evidence[0].ID = "" }},
		{"bad-tier", func(in *verdict.Input) { in.Evidence[0].Tier = 7 }},
		{"bad-status", func(in *verdict.Input) { in.Evidence[0].Status = "empty" }},
		{"info-critical", func(in *verdict.Input) {
			in.Evidence = append(in.Evidence, verdict.Evidence{ID: "generic.arm.get", Tier: verdict.TierInfo, Status: verdict.StatusUnknown, Critical: true})
		}},
		{"required-not-silence", func(in *verdict.Input) { in.Evidence[0].Tier = verdict.TierInfo }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := testInput()
			tt.change(&in)
			got, err := verdict.Evaluate(in)
			if err == nil || !reflect.DeepEqual(got, verdict.Result{}) {
				t.Fatalf("malformed internal schema must have no verdict: %+v, %v", got, err)
			}
		})
	}
}

func TestCatalogueIntegrityDoesNotAddUsageGates(t *testing.T) {
	for _, typ := range []string{"Microsoft.Network/publicIPAddresses", "Microsoft.App/managedEnvironments", "Microsoft.Web/sites/slots"} {
		t.Run(typ, func(t *testing.T) {
			in := testInput()
			in.Type = typ
			in.Required = verdict.RequiredForType(typ)
			in.Evidence = nil
			for _, id := range in.Required {
				in.Evidence = append(in.Evidence, verdict.Evidence{ID: id, Tier: verdict.TierObservedIdle, Status: verdict.StatusPresent})
			}
			in.Evidence = append(in.Evidence, verdict.Evidence{ID: "generic.arm.get", Tier: verdict.TierInfo, Status: verdict.StatusPresent,
				Details: map[string]any{"contradiction": true}})
			got, err := verdict.Evaluate(in)
			if err != nil || got.Verdict != "yes" {
				t.Fatalf("no extra ownership/public-access/contradiction gates: %+v, %v", got, err)
			}
		})
	}
}

func TestSchemaJSONTags(t *testing.T) {
	values := []any{verdict.Evidence{}, verdict.Age{}, verdict.Input{}, verdict.Coverage{}, verdict.Result{}, verdict.Window{}, verdict.Source{}, verdict.Unknown{}, verdict.NotEvaluated{},
		age.Input{}, age.ActivityEvent{}, age.ResourceChange{}, age.Deployment{}}
	for _, value := range values {
		typ := reflect.TypeOf(value)
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			key := strings.Split(field.Tag.Get("json"), ",")[0]
			if key == "" || key[0] < 'a' || key[0] > 'z' {
				t.Errorf("%s.%s needs lower-camel JSON tag, got %q", typ.Name(), field.Name, key)
			}
		}
	}
	e := verdict.Evidence{
		ID: "generic.policy.state", Tier: verdict.TierInfo, TierName: "INFO", Family: "derived",
		ResourceType: "Microsoft.Compute/disks", Status: verdict.StatusNotEvaluated,
		Summary: "Policy compliance is not queried",
		Details: map[string]any{"count": float64(1)}, Untrusted: map[string]string{"name": "fixture"},
		Source: verdict.Source{API: "Rules", Path: "generic.policy.state"}, Confidence: "heuristic",
		NotEvaluated: &verdict.NotEvaluated{Reason: "not queried", Consequence: "unknown policy state", HowToCheck: "check policy state"},
		Related:      []string{"generic.arm.get"}, NextSteps: []string{"inspect policy state"},
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var got verdict.Evidence
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e, got) {
		t.Fatalf("evidence metadata did not round-trip: %+v", got)
	}
}
