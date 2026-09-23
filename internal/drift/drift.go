// Package drift compares a proposed change against the documents that govern
// it, and reports where the two have come apart.
//
// The repository already checks that the code obeys its own rules
// (internal/conformance) and that the records are well formed (internal/adr).
// Neither of those reads a diff, so neither can see the failures that only
// exist between two versions: a decision record quietly edited to agree with
// new code, a status table that starts claiming a component exists, a stub
// that disappears without anything replacing it.
//
// Those are the ones worth blocking a merge over, because each is a way the
// project stops being able to say what it knows.
package drift

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Change is one file as it stands on each side of the comparison. Before is
// empty for an added file and After is empty for a deleted one.
type Change struct {
	Path   string
	Before string
	After  string
}

// Added reports a file that does not exist on the base side.
func (c Change) Added() bool { return c.Before == "" && c.After != "" }

// Deleted reports a file that does not exist on the head side.
func (c Change) Deleted() bool { return c.Before != "" && c.After == "" }

// Finding is one way the change and the documents disagree. Blocking findings
// stop the merge; the rest are raised for a human to weigh.
type Finding struct {
	Path     string
	Rule     string
	Detail   string
	Blocking bool
}

func (f Finding) String() string {
	weight := "note"
	if f.Blocking {
		weight = "blocking"
	}
	return fmt.Sprintf("[%s] %s: %s — %s", weight, f.Rule, f.Path, f.Detail)
}

// Check reports every disagreement it can establish from the change alone.
func Check(changes []Change) []Finding {
	var findings []Finding
	findings = append(findings, recordsNotEditedToFit(changes)...)
	findings = append(findings, claimsBackedByTests(changes)...)
	findings = append(findings, stubsNotSilentlyDropped(changes)...)
	findings = append(findings, newPackagesAreTested(changes)...)
	findings = append(findings, normativeChangesAreDeclared(changes)...)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Blocking != findings[j].Blocking {
			return findings[i].Blocking
		}
		return findings[i].Path < findings[j].Path
	})
	return findings
}

var (
	adrPath      = regexp.MustCompile(`^docs/adr/(\d{4})-[a-z0-9-]+\.md$`)
	supersededBy = regexp.MustCompile(`superseded by ADR-(\d{4})`)
)

// section returns the body of one `## Heading` section.
func section(body, heading string) string {
	_, rest, found := strings.Cut(body, "\n## "+heading+"\n")
	if !found {
		return ""
	}
	next, _, more := strings.Cut(rest, "\n## ")
	if more {
		return strings.TrimSpace(next)
	}
	return strings.TrimSpace(rest)
}

// recordsNotEditedToFit is the rule the whole arrangement rests on: a record is
// never edited to agree with new code. Reversing a decision means a new record
// that supersedes the old one, so the disagreement stays visible.
func recordsNotEditedToFit(changes []Change) []Finding {
	var findings []Finding
	newRecords := map[string]bool{}
	for _, c := range changes {
		if match := adrPath.FindStringSubmatch(c.Path); match != nil && c.Added() {
			newRecords[match[1]] = true
		}
	}

	for _, c := range changes {
		if adrPath.FindStringSubmatch(c.Path) == nil || c.Added() || c.Deleted() {
			if c.Deleted() && adrPath.MatchString(c.Path) {
				findings = append(findings, Finding{
					Path: c.Path, Rule: "record-deleted", Blocking: true,
					Detail: "a decision record was deleted; a decision that no longer holds is superseded, not removed, or the history of why stops existing",
				})
			}
			continue
		}
		if section(c.Before, "Decision") == section(c.After, "Decision") {
			continue
		}
		// The Decision changed. That is legitimate only when this record is
		// being retired in favour of another one arriving in the same change.
		status := supersededBy.FindStringSubmatch(section(c.After, "Status") + statusLine(c.After))
		if status != nil && newRecords[status[1]] {
			continue
		}
		findings = append(findings, Finding{
			Path: c.Path, Rule: "record-edited-to-fit", Blocking: true,
			Detail: "the Decision section changed without this record being superseded by a new one in the same change; a record is never edited to agree with new code",
		})
	}
	return findings
}

// statusLine pulls the `- Status: ...` line, which is where a supersession is
// recorded.
func statusLine(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "- Status:") {
			return line
		}
	}
	return ""
}

var (
	claimDocs  = map[string]bool{"README.md": true, "IMPLEMENTATION-PLAN.md": true}
	notBuilt   = regexp.MustCompile(`(?i)\*\*not started\*\*|not implemented|stub`)
	nowBuilt   = regexp.MustCompile(`(?i)\|\s*complete`)
	testedFile = regexp.MustCompile(`_test\.go$`)
)

// claimsBackedByTests holds the status documents to the rule that they may not
// claim a component exists before its tests do.
func claimsBackedByTests(changes []Change) []Finding {
	testsChanged := false
	for _, c := range changes {
		if testedFile.MatchString(c.Path) && !c.Deleted() {
			testsChanged = true
		}
	}
	var findings []Finding
	for _, c := range changes {
		if !claimDocs[c.Path] || c.Added() || c.Deleted() {
			continue
		}
		gained := countMatches(nowBuilt, c.After) - countMatches(nowBuilt, c.Before)
		lost := countMatches(notBuilt, c.Before) - countMatches(notBuilt, c.After)
		if gained <= 0 && lost <= 0 {
			continue
		}
		if testsChanged {
			continue
		}
		findings = append(findings, Finding{
			Path: c.Path, Rule: "claim-without-tests", Blocking: true,
			Detail: "a component's status moved towards complete while no test file changed; this document may not claim a component exists before its tests do",
		})
	}
	return findings
}

func countMatches(pattern *regexp.Regexp, body string) int {
	return len(pattern.FindAllString(body, -1))
}

var notEvaluated = regexp.MustCompile(`NotEvaluated\(`)

// stubsNotSilentlyDropped watches the honest gaps. A stub says what it does not
// evaluate and why; removing one means either the gap was filled or the
// disclosure was dropped, and only the first is acceptable.
func stubsNotSilentlyDropped(changes []Change) []Finding {
	var findings []Finding
	for _, c := range changes {
		if !strings.HasSuffix(c.Path, ".go") || c.Added() || c.Deleted() {
			continue
		}
		removed := countMatches(notEvaluated, c.Before) - countMatches(notEvaluated, c.After)
		if removed <= 0 {
			continue
		}
		// Filling a gap adds code and tests; dropping a disclosure only takes
		// lines away. Length is a blunt proxy and this is a note, not a block.
		if len(c.After) > len(c.Before) {
			continue
		}
		findings = append(findings, Finding{
			Path: c.Path, Rule: "stub-removed", Blocking: false,
			Detail: "a not_evaluated stub was removed and the file did not grow; check that the gap was filled rather than the disclosure dropped",
		})
	}
	return findings
}

// newPackagesAreTested reports a new package that arrives with no test of its
// own. Nothing in this repository is exempt, so a new one without tests is
// either unfinished or untestable, and both are worth saying out loud.
func newPackagesAreTested(changes []Change) []Finding {
	added := map[string]bool{}
	tested := map[string]bool{}
	for _, c := range changes {
		if !strings.HasSuffix(c.Path, ".go") || !c.Added() {
			continue
		}
		dir := c.Path[:strings.LastIndex(c.Path, "/")+1]
		if !strings.HasPrefix(dir, "internal/") && !strings.HasPrefix(dir, "cmd/") {
			continue
		}
		if testedFile.MatchString(c.Path) {
			tested[dir] = true
			continue
		}
		added[dir] = true
	}
	var findings []Finding
	for dir := range added {
		if tested[dir] {
			continue
		}
		findings = append(findings, Finding{
			Path: dir, Rule: "package-without-tests", Blocking: false,
			Detail: "new Go files here arrive with no test file in the same change",
		})
	}
	return findings
}

var normative = map[string]bool{"REQUIREMENTS.md": true, "docs/SPEC.md": true}

// normativeChangesAreDeclared raises any edit to a normative document. These
// are the documents everything else is measured against, so a change to one is
// never routine: it is the measuring stick moving.
func normativeChangesAreDeclared(changes []Change) []Finding {
	var findings []Finding
	for _, c := range changes {
		if !normative[c.Path] || c.Added() {
			continue
		}
		findings = append(findings, Finding{
			Path: c.Path, Rule: "normative-document-changed", Blocking: false,
			Detail: "a normative document changed; the code is measured against this, so the change needs an argument in the pull request, not just a diff",
		})
	}
	return findings
}
