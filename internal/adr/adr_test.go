package adr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recordsDir() string { return filepath.Join("..", "..", "docs", "adr") }

// The records in this repository are part of the review contract: CI asks an
// agent to judge a diff against them, so they have to be structurally sound
// before anyone argues about their content.
func TestCommittedRecordsAreWellFormed(t *testing.T) {
	for _, problem := range Check(recordsDir()) {
		t.Errorf("docs/adr: %s", problem)
	}
}

// Every decision names what makes it real. A record whose Enforcement section
// is empty is a wish, and the reviewer would have no way to check a diff
// against it.
func TestEveryRecordNamesItsEnforcement(t *testing.T) {
	entries, err := os.ReadDir(recordsDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".md") || name == "README.md" || strings.HasPrefix(name, "0000-") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(recordsDir(), name)) //nolint:gosec // the directory is chosen by the caller, not by input this package reads
		if err != nil {
			t.Fatal(err)
		}
		_, after, found := strings.Cut(string(body), "\n## Enforcement\n")
		if !found {
			t.Errorf("%s: no Enforcement section", name)
			continue
		}
		if len(strings.TrimSpace(after)) < 40 {
			t.Errorf("%s: the Enforcement section must name the test or the code that checks this decision", name)
		}
	}
}

// The checker earns its place only if it catches the ways a record set rots.
func TestCheckCatchesMalformedRecords(t *testing.T) {
	const good = "# ADR-0001: Something was decided\n\n- Status: accepted\n- Date: 2026-09-22\n\n## Context\n\nc\n\n## Decision\n\nd\n\n## Consequences\n\nc\n\n## Enforcement\n\ne\n"
	const index = "# Index\n\n| ADR | Decision | Status |\n| --- | --- | --- |\n| [0001](0001-a.md) | Something was decided | accepted |\n"

	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name:  "a well formed set has nothing to report",
			files: map[string]string{"0001-a.md": good, "README.md": index},
		},
		{
			name:  "a record missing a section",
			files: map[string]string{"0001-a.md": strings.Replace(good, "\n## Consequences\n\nc\n", "\n", 1), "README.md": index},
			want:  "missing the `## Consequences` section",
		},
		{
			name:  "a status nobody can act on",
			files: map[string]string{"0001-a.md": strings.Replace(good, "accepted\n- Date", "probably\n- Date", 1), "README.md": index},
			want:  `status "probably"`,
		},
		{
			name: "a supersession is a legitimate status",
			files: map[string]string{
				"0001-a.md": strings.Replace(good, "- Status: accepted", "- Status: superseded by ADR-0007", 1),
				"README.md": strings.Replace(index, "| accepted |", "| superseded by ADR-0007 |", 1),
			},
		},
		{
			name:  "a title that disagrees with the file name",
			files: map[string]string{"0002-a.md": good, "README.md": strings.ReplaceAll(index, "0001", "0002")},
			want:  "title says ADR-0001 but the file is numbered 0002",
		},
		{
			name:  "a record nobody indexed",
			files: map[string]string{"0001-a.md": good, "README.md": "# Index\n"},
			want:  "is not in the index",
		},
		{
			name:  "an index row with no record behind it",
			files: map[string]string{"0001-a.md": good, "README.md": index + "| [0009](0009-gone.md) | Vanished | accepted |\n"},
			want:  "ADR-0009 is listed but has no record",
		},
		{
			name:  "an index that stopped matching the status",
			files: map[string]string{"0001-a.md": good, "README.md": strings.Replace(index, "| accepted |", "| proposed |", 1)},
			want:  `does not show its status "accepted"`,
		},
		{
			name:  "a file name that is not a record",
			files: map[string]string{"0001-a.md": good, "notes.md": "whatever", "README.md": index},
			want:  "name must be NNNN-lower-case-slug.md",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range test.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			problems := Check(dir)
			if test.want == "" {
				if len(problems) != 0 {
					t.Fatalf("expected a clean set, got %q", problems)
				}
				return
			}
			for _, problem := range problems {
				if strings.Contains(problem, test.want) {
					return
				}
			}
			t.Fatalf("expected a problem mentioning %q, got %q", test.want, problems)
		})
	}
}

// Copilot code review works from .github/copilot-instructions.md. A record
// the brief never cites is a decision that quietly left the review's scope, so
// the two are kept in step here rather than by anybody remembering.
func TestTheReviewBriefCitesEveryRecord(t *testing.T) {
	brief, err := os.ReadFile(filepath.Join("..", "..", ".github", "copilot-instructions.md"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(recordsDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".md") || name == "README.md" || strings.HasPrefix(name, "0000-") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(recordsDir(), name)) //nolint:gosec // the directory is chosen by the caller, not by input this package reads
		if err != nil {
			t.Fatal(err)
		}
		// A record that is no longer in force needs no place in the brief.
		if !strings.Contains(string(body), "- Status: accepted") {
			continue
		}
		cited := "ADR-" + name[:4]
		if !strings.Contains(string(brief), cited) {
			t.Errorf(".github/copilot-instructions.md does not cite %s (%s), so the reviewer will not check it", cited, name)
		}
	}
}
