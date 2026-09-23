package drift

import (
	"strings"
	"testing"
)

const record = `# ADR-0007: Something

- Status: accepted
- Date: 2026-09-01

## Context

c

## Decision

The thing is done this way.

## Consequences

c

## Enforcement

A test.
`

// has reports whether a rule fired, and whether it blocked.
func has(findings []Finding, rule string) (bool, bool) {
	for _, f := range findings {
		if f.Rule == rule {
			return true, f.Blocking
		}
	}
	return false, false
}

// The rule the whole arrangement rests on. Editing a record's Decision so that
// it agrees with new code is the failure that leaves no trace anywhere else.
func TestARecordEditedToAgreeWithNewCodeIsBlocked(t *testing.T) {
	edited := strings.Replace(record, "The thing is done this way.", "The thing is done the other way now.", 1)
	found, blocking := has(Check([]Change{{Path: "docs/adr/0007-something.md", Before: record, After: edited}}), "record-edited-to-fit")
	if !found || !blocking {
		t.Errorf("an edited Decision must block (found=%v blocking=%v)", found, blocking)
	}
}

// Superseding is the legitimate way to change a decision, and it has to be
// recognised or the rule would make decisions unchangeable.
func TestSupersedingARecordIsAllowed(t *testing.T) {
	retired := strings.Replace(record, "- Status: accepted", "- Status: superseded by ADR-0009", 1)
	retired = strings.Replace(retired, "The thing is done this way.", "This was replaced.", 1)
	changes := []Change{
		{Path: "docs/adr/0007-something.md", Before: record, After: retired},
		{Path: "docs/adr/0009-the-new-way.md", After: strings.Replace(record, "0007", "0009", 1)},
	}
	if found, _ := has(Check(changes), "record-edited-to-fit"); found {
		t.Error("a record superseded by one arriving in the same change is not an edit to fit")
	}
}

// A supersession that names a record nobody is adding is still an edit to fit.
func TestSupersedingByARecordThatIsNotThereIsBlocked(t *testing.T) {
	retired := strings.Replace(record, "- Status: accepted", "- Status: superseded by ADR-0042", 1)
	retired = strings.Replace(retired, "The thing is done this way.", "Changed.", 1)
	found, blocking := has(Check([]Change{{Path: "docs/adr/0007-something.md", Before: record, After: retired}}), "record-edited-to-fit")
	if !found || !blocking {
		t.Error("a supersession pointing at a record that does not arrive must still block")
	}
}

// Touching prose is not touching the decision.
func TestEditingARecordsProseIsFine(t *testing.T) {
	tidied := strings.Replace(record, "## Context\n\nc", "## Context\n\nA fuller explanation.", 1)
	if found, _ := has(Check([]Change{{Path: "docs/adr/0007-something.md", Before: record, After: tidied}}), "record-edited-to-fit"); found {
		t.Error("rewriting Context is not editing the Decision")
	}
}

func TestDeletingARecordIsBlocked(t *testing.T) {
	found, blocking := has(Check([]Change{{Path: "docs/adr/0007-something.md", Before: record}}), "record-deleted")
	if !found || !blocking {
		t.Error("deleting a record must block")
	}
}

// A status document may not start claiming a component exists while no test
// changed to back the claim.
func TestAStatusClaimWithoutTestsIsBlocked(t *testing.T) {
	before := "| `internal/thing` | **not started** | — |\n"
	after := "| `internal/thing` | complete | covered |\n"
	cases := []struct {
		name    string
		changes []Change
		want    bool
	}{
		{
			name:    "claim with no test in the change",
			changes: []Change{{Path: "IMPLEMENTATION-PLAN.md", Before: before, After: after}},
			want:    true,
		},
		{
			name: "claim alongside a test",
			changes: []Change{
				{Path: "IMPLEMENTATION-PLAN.md", Before: before, After: after},
				{Path: "internal/thing/thing_test.go", After: "package thing"},
			},
			want: false,
		},
		{
			name:    "an unrelated edit to the same document",
			changes: []Change{{Path: "IMPLEMENTATION-PLAN.md", Before: before, After: before + "\nA sentence.\n"}},
			want:    false,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			found, blocking := has(Check(test.changes), "claim-without-tests")
			if found != test.want {
				t.Errorf("fired=%v, want %v", found, test.want)
			}
			if found && !blocking {
				t.Error("a claim without tests must block")
			}
		})
	}
}

// Losing a disclosed gap is raised, but not blocked: the same edit is how a
// gap gets filled.
func TestRemovingAStubIsRaised(t *testing.T) {
	before := "a := Catalogue.NotEvaluated(SignalX)\nmore\nlines\nhere\n"
	found, blocking := has(Check([]Change{{Path: "internal/x/x.go", Before: before, After: "more\n"}}), "stub-removed")
	if !found {
		t.Fatal("removing a stub must be raised")
	}
	if blocking {
		t.Error("it must not block: filling the gap removes the stub too")
	}
	// Filling the gap grows the file, and that is not worth raising.
	grown := before + strings.Repeat("real implementation\n", 20)
	if found, _ := has(Check([]Change{{Path: "internal/x/x.go", Before: before, After: strings.Replace(grown, "a := Catalogue.NotEvaluated(SignalX)\n", "", 1)}}), "stub-removed"); found {
		t.Error("a stub replaced by an implementation is not a dropped disclosure")
	}
}

func TestANewPackageWithoutTestsIsRaised(t *testing.T) {
	found, blocking := has(Check([]Change{{Path: "internal/fresh/fresh.go", After: "package fresh"}}), "package-without-tests")
	if !found || blocking {
		t.Errorf("a new untested package is raised, not blocked (found=%v blocking=%v)", found, blocking)
	}
	if found, _ := has(Check([]Change{
		{Path: "internal/fresh/fresh.go", After: "package fresh"},
		{Path: "internal/fresh/fresh_test.go", After: "package fresh"},
	}), "package-without-tests"); found {
		t.Error("a new package with a test is not a finding")
	}
}

func TestANormativeChangeIsRaised(t *testing.T) {
	found, blocking := has(Check([]Change{{Path: "docs/SPEC.md", Before: "a", After: "b"}}), "normative-document-changed")
	if !found || blocking {
		t.Errorf("a normative change is raised for a human, not blocked (found=%v blocking=%v)", found, blocking)
	}
}

// An ordinary change disagrees with nothing.
func TestAnOrdinaryChangeIsQuiet(t *testing.T) {
	changes := []Change{
		{Path: "internal/storage/storage.go", Before: "package storage\nold\n", After: "package storage\nnew\n"},
		{Path: "internal/storage/storage_test.go", Before: "package storage_test\n", After: "package storage_test\nmore\n"},
	}
	if findings := Check(changes); len(findings) != 0 {
		t.Errorf("expected nothing to report, got %v", findings)
	}
}

// Blocking findings sort first, because that is what a reader needs to see.
func TestBlockingFindingsComeFirst(t *testing.T) {
	changes := []Change{
		{Path: "docs/SPEC.md", Before: "a", After: "b"},
		{Path: "docs/adr/0007-something.md", Before: record,
			After: strings.Replace(record, "The thing is done this way.", "Reversed.", 1)},
	}
	findings := Check(changes)
	if len(findings) < 2 || !findings[0].Blocking {
		t.Fatalf("expected a blocking finding first, got %v", findings)
	}
}
