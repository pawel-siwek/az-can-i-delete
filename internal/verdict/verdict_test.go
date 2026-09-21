package verdict_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/age"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

type fixture struct {
	Number int    `json:"number"`
	Name   string `json:"name"`
	Source struct {
		Document string `json:"document"`
		Section  string `json:"section"`
		RawRow   string `json:"rawRow"`
	} `json:"source"`
	Conventions []string       `json:"conventions"`
	RawStimuli  map[string]any `json:"rawStimuli"`
	Retained    map[string]any `json:"retained"`
	Input       verdict.Input  `json:"input"`
	AgeInput    *age.AgeInput  `json:"ageInput"`
	Expect      struct {
		Verdict         string              `json:"verdict"`
		ReasonClass     string              `json:"reasonClass"`
		Reasons         []string            `json:"reasons"`
		Effective       verdict.Window      `json:"effective"`
		Age             verdict.Age         `json:"age"`
		NextSteps       map[string][]string `json:"nextSteps"`
		CriticalUnknown int                 `json:"criticalUnknown"`
	} `json:"expect"`
}

func loadFixtures(t *testing.T) []fixture {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "[0-9][0-9]-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 66 {
		t.Fatalf("original acceptance suite must contain exactly 66 fixtures, got %d", len(paths))
	}
	root, err := os.OpenRoot("testdata")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	source, err := os.ReadFile(filepath.Join("..", "..", "docs", "architect-3.md"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []fixture
	for i, path := range paths {
		data, err := root.ReadFile(filepath.Base(path))
		if err != nil {
			t.Fatal(err)
		}
		var f fixture
		if err := json.Unmarshal(data, &f); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if f.Number != i+1 || f.Name == "" || !strings.Contains(string(source), f.Source.RawRow) {
			t.Fatalf("%s: missing original row provenance", path)
		}
		if !strings.HasPrefix(f.Source.RawRow, fmt.Sprintf("| %d | %s |", f.Number, f.Name)) {
			t.Fatalf("%s: original number/name mismatch", path)
		}
		fixtures = append(fixtures, f)
	}
	return fixtures
}

func TestOriginal66(t *testing.T) {
	for _, f := range loadFixtures(t) {
		t.Run(fmt.Sprintf("%02d/%s", f.Number, f.Name), func(t *testing.T) {
			in := f.Input
			if in.Requested.Days < 7 || in.Requested.Days > 93 ||
				in.Requested.End.Sub(in.Requested.Start) != time.Duration(in.Requested.Days)*24*time.Hour {
				t.Fatal("fixture must have a complete explicit requested window")
			}
			if f.AgeInput != nil {
				in.Age = age.ResolveAge(*f.AgeInput)
			}
			if !reflect.DeepEqual(in.Age, f.Expect.Age) {
				t.Fatalf("age = %#v, want %#v", in.Age, f.Expect.Age)
			}
			before, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			got, err := verdict.Evaluate(in)
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict != f.Expect.Verdict || got.ReasonClass != f.Expect.ReasonClass ||
				!slices.Equal(got.Reasons, f.Expect.Reasons) {
				t.Errorf("got %s / %s / %v; want %s / %s / %v", got.Verdict, got.ReasonClass,
					got.Reasons, f.Expect.Verdict, f.Expect.ReasonClass, f.Expect.Reasons)
			}
			if got.Effective != f.Expect.Effective {
				t.Errorf("effective = %+v, want %+v", got.Effective, f.Expect.Effective)
			}
			if got.Coverage.CriticalUnknown != f.Expect.CriticalUnknown {
				t.Errorf("criticalUnknown = %d, want %d", got.Coverage.CriticalUnknown, f.Expect.CriticalUnknown)
			}
			checkInvariants(t, in, got)
			if !reflect.DeepEqual(got, verdict.Decide(in)) {
				t.Error("validated pure Decide differs from Evaluate")
			}
			for id, steps := range f.Expect.NextSteps {
				found := false
				for _, e := range in.Evidence {
					if e.ID == id && slices.Equal(e.NextSteps, steps) {
						found = true
					}
				}
				if !found {
					t.Errorf("prescribed NextSteps metadata missing for %s", id)
				}
			}
			after, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Error("evaluator mutated input")
			}
			slices.Reverse(in.Evidence)
			slices.Reverse(in.Required)
			reversed, err := verdict.Evaluate(in)
			if err != nil || !reflect.DeepEqual(got, reversed) {
				t.Errorf("evidence/Required order changed result: %+v, %v", reversed, err)
			}
		})
	}
}

func TestFixtureScopeAndConventions(t *testing.T) {
	for _, f := range loadFixtures(t) {
		switch f.Number {
		case 36, 51, 52:
			refusal := "already-suspended"
			if f.Number == 52 {
				refusal = "locked-readonly"
			}
			if f.Retained["cordonRefusal"] != refusal || f.Retained["implemented"] != false {
				t.Fatalf("case%d must retain cordon expectation without implementation claim", f.Number)
			}
		case 39, 40, 41, 59:
			if len(f.RawStimuli) == 0 {
				t.Fatalf("case%d lost classifier raw stimuli", f.Number)
			}
		case 60, 61, 65:
			if f.AgeInput == nil || f.Input.Age.Confidence != "unknown" {
				t.Fatalf("case%d must exercise ResolveAge, not supply the expected Age", f.Number)
			}
		case 38, 49, 63:
			if len(f.Conventions) == 0 {
				t.Fatalf("case%d must disclose construction conventions", f.Number)
			}
		}
	}
}

func checkInvariants(t *testing.T, in verdict.Input, got verdict.Result) {
	t.Helper()
	want := verdict.Coverage{Total: len(in.Evidence), Age: in.Age}
	var unknowns, notEvaluated []string
	for _, e := range in.Evidence {
		switch e.Status {
		case verdict.StatusPresent, verdict.StatusAbsent:
			want.Evaluated++
		case verdict.StatusUnknown:
			want.Unknown++
			unknowns = append(unknowns, e.ID)
			if e.Critical {
				want.CriticalUnknown++
			}
		case verdict.StatusNotEvaluated:
			want.NotEvaluated++
			notEvaluated = append(notEvaluated, e.ID)
		}
		if e.Tier == verdict.TierInfo && slices.Contains(got.Reasons, e.ID) {
			t.Errorf("INFO reason: %s", e.ID)
		}
	}
	slices.Sort(unknowns)
	slices.Sort(notEvaluated)
	actualUnknowns := slices.Clone(got.Unknowns)
	actualNotEvaluated := slices.Clone(got.NotEvaluated)
	slices.Sort(actualUnknowns)
	slices.Sort(actualNotEvaluated)
	if !reflect.DeepEqual(want, got.Coverage) || !slices.Equal(unknowns, actualUnknowns) ||
		!slices.Equal(notEvaluated, actualNotEvaluated) {
		t.Errorf("coverage/unknowns/notEvaluated do not reflect complete evidence: %+v", got)
	}
	tentative := got.Verdict == "tentative"
	if got.HumanEscalation != tentative || (got.RequiredHumanQuestion != "") != tentative {
		t.Error("human escalation/question must occur iff tentative")
	}
}

func testInput() verdict.Input {
	end := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	in := verdict.Input{
		Type:      "Microsoft.Compute/disks",
		Age:       verdict.Age{LowerBoundDays: 60, Confidence: "verified", Source: "rp.timestamp"},
		Requested: verdict.Window{Start: end.AddDate(0, 0, -30), End: end, Days: 30, Grain: "P1D"},
		Required:  verdict.RequiredForType("Microsoft.Compute/disks"),
	}
	for _, id := range in.Required {
		in.Evidence = append(in.Evidence, verdict.Evidence{ID: id, Tier: verdict.TierObservedIdle, Status: verdict.StatusPresent})
	}
	return in
}

// These are the three G6 additions, not replacements for numbered source rows.
func TestG6Validation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*verdict.Input)
	}{
		{"empty-required", func(in *verdict.Input) { in.Required = nil }},
		{"omitted-catalogue-requirement", func(in *verdict.Input) { in.Required = in.Required[1:] }},
		{"contradictory-duplicate-evidence-id", func(in *verdict.Input) {
			e := in.Evidence[0]
			e.Status = verdict.StatusAbsent
			in.Evidence = append(in.Evidence, e)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := testInput()
			tt.change(&in)
			got, err := verdict.Evaluate(in)
			if err == nil || !strings.Contains(err.Error(), "INTERNAL ERROR") {
				t.Fatalf("expected explicit internal error, got %v", err)
			}
			if !reflect.DeepEqual(got, verdict.Result{}) {
				t.Fatalf("invalid input must return no verdict: %+v", got)
			}
		})
	}
}

func TestMissingObservationIsNotCatalogueError(t *testing.T) {
	for _, status := range []verdict.Status{"", verdict.StatusAbsent, verdict.StatusUnknown, verdict.StatusNotEvaluated} {
		t.Run(string(status), func(t *testing.T) {
			in := testInput()
			id := in.Evidence[0].ID
			if status == "" {
				in.Evidence = in.Evidence[1:]
			} else {
				in.Evidence[0].Status = status
			}
			got, err := verdict.Evaluate(in)
			if err != nil || got.Verdict != "tentative" ||
				!slices.Equal(got.Reasons, []string{"required.missing:" + id}) {
				t.Fatalf("missing observation should remain tentative: %+v, %v", got, err)
			}
		})
	}
}

func TestCoverageSurvivesEveryWinningRule(t *testing.T) {
	for _, f := range loadFixtures(t) {
		t.Run(fmt.Sprintf("%02d", f.Number), func(t *testing.T) {
			in := f.Input
			if f.AgeInput != nil {
				in.Age = age.ResolveAge(*f.AgeInput)
			}
			in.Evidence = append(in.Evidence,
				verdict.Evidence{ID: "generic.policy.state", Tier: verdict.TierInfo, Status: verdict.StatusNotEvaluated,
					NotEvaluated: &verdict.NotEvaluated{Reason: "not queried", Consequence: "compliance unknown", HowToCheck: "check policy state"}},
				verdict.Evidence{ID: "generic.deny-assignment", Tier: verdict.TierBlocker, Status: verdict.StatusUnknown,
					Unknown: &verdict.Unknown{Code: verdict.UnkPermission, Message: "not authorized"}},
			)
			got, err := verdict.Evaluate(in)
			if err != nil {
				t.Fatal(err)
			}
			checkInvariants(t, in, got)
			if got.Verdict != f.Expect.Verdict || !slices.Equal(got.Reasons, f.Expect.Reasons) {
				t.Fatal("non-critical unknown and not-evaluated changed winner")
			}
		})
	}
}

func TestRequiredCatalogue(t *testing.T) {
	types := []string{
		"Microsoft.Storage/storageAccounts", "Microsoft.Compute/disks", "Microsoft.Compute/virtualMachines",
		"Microsoft.Network/networkInterfaces", "Microsoft.Network/publicIPAddresses",
		"Microsoft.Network/networkSecurityGroups", "Microsoft.Network/virtualNetworks",
		"Microsoft.Web/sites", "Microsoft.Web/sites/slots", "Microsoft.Web/serverfarms",
		"Microsoft.App/containerApps", "Microsoft.App/jobs", "Microsoft.App/managedEnvironments",
	}
	for _, typ := range types {
		t.Run(typ, func(t *testing.T) {
			got := verdict.RequiredForType(typ)
			if len(got) < 3 || !slices.Contains(got, "generic.arg.visible") ||
				!slices.Equal(got, verdict.RequiredForType(strings.ToUpper(typ))) {
				t.Fatalf("invalid catalogue for %s: %v", typ, got)
			}
			got[0] = "mutated"
			if slices.Contains(verdict.RequiredForType(typ), "mutated") {
				t.Fatal("caller can mutate trusted catalogue")
			}
		})
	}
	pip := []string{"generic.arg.visible", "pip.structural.unassociated", "pip.unassociated.ge-30d"}
	if !slices.Equal(verdict.RequiredForType("Microsoft.Network/publicIPAddresses"), pip) {
		t.Error("public IP mapping differs from SPEC")
	}
	if !slices.Equal(verdict.RequiredForType("Microsoft.KeyVault/vaults"), []string{"generic.never"}) {
		t.Error("unsupported type lost generic.never")
	}
}
