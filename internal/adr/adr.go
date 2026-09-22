// Package adr checks that the architecture decision records stay readable as
// a set: numbered, structured, indexed and honest about being superseded.
//
// The agentic reviewer in CI reads the records and argues about what a diff
// means. This package is the half of that job a machine can settle on its
// own, so a missing section or an index that drifted never reaches a human
// reviewer's attention budget.
package adr

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Record is one decision record on disk.
type Record struct {
	Number int
	File   string
	Title  string
	Status string
}

// Sections every record must carry, in this order. Enforcement is last on
// purpose: a decision nothing checks is a wish, and the record has to say so.
var sections = []string{"Context", "Decision", "Consequences", "Enforcement"}

var (
	fileName     = regexp.MustCompile(`^(\d{4})-[a-z0-9]+(?:-[a-z0-9]+)*\.md$`)
	titleLine    = regexp.MustCompile(`^# ADR-(\d{4}): (\S.*\S)$`)
	statusLine   = regexp.MustCompile(`^- Status: (.+)$`)
	supersededBy = regexp.MustCompile(`^superseded by ADR-\d{4}$`)
	indexRow     = regexp.MustCompile(`^\| \[(\d{4})\]\(([^)]+)\)`)
)

// simple statuses a record may carry. Anything else must be a supersession,
// which names the record that replaced this one.
var simpleStatuses = map[string]bool{"proposed": true, "accepted": true, "rejected": true, "deprecated": true}

// Check reads the records in dir and reports everything wrong with them.
// An empty result means the set is well formed; it says nothing about whether
// the decisions are any good.
func Check(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{fmt.Sprintf("cannot read %s: %v", dir, err)}
	}

	var problems []string
	var records []Record
	seen := map[int]string{}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".md") || name == "README.md" {
			continue
		}
		match := fileName.FindStringSubmatch(name)
		if match == nil {
			problems = append(problems, fmt.Sprintf("%s: name must be NNNN-lower-case-slug.md", name))
			continue
		}
		number, _ := strconv.Atoi(match[1])

		body, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // the directory is chosen by the caller, not by input this package reads
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		record, found := parse(name, number, string(body))
		problems = append(problems, found...)
		if record == nil {
			continue
		}
		if other, clash := seen[number]; clash {
			problems = append(problems, fmt.Sprintf("%s: number %04d is already taken by %s", name, number, other))
			continue
		}
		seen[number] = name
		if number > 0 {
			records = append(records, *record)
		}
	}

	sort.Slice(records, func(i, j int) bool { return records[i].Number < records[j].Number })
	problems = append(problems, checkIndex(dir, records)...)
	sort.Strings(problems)
	return problems
}

// parse pulls the title and status out of one record and reports whatever the
// record is missing. A nil record means nothing further can be checked.
func parse(name string, number int, body string) (*Record, []string) {
	var problems []string
	lines := strings.Split(body, "\n")
	if len(lines) == 0 {
		return nil, []string{name + ": file is empty"}
	}

	title := titleLine.FindStringSubmatch(strings.TrimRight(lines[0], "\r"))
	if title == nil {
		return nil, []string{name + `: first line must read "# ADR-NNNN: <the decision>"`}
	}
	if declared, _ := strconv.Atoi(title[1]); declared != number {
		problems = append(problems, fmt.Sprintf("%s: title says ADR-%s but the file is numbered %04d", name, title[1], number))
	}

	record := Record{Number: number, File: name, Title: title[2]}
	for _, line := range lines {
		if match := statusLine.FindStringSubmatch(strings.TrimRight(line, "\r")); match != nil {
			record.Status = strings.TrimSpace(match[1])
			break
		}
	}
	switch {
	case record.Status == "":
		problems = append(problems, name+": no `- Status: ...` line")
	case simpleStatuses[record.Status]:
	case supersededBy.MatchString(record.Status):
	default:
		problems = append(problems, fmt.Sprintf("%s: status %q must be proposed, accepted, rejected, deprecated, or \"superseded by ADR-NNNN\"", name, record.Status))
	}

	if !strings.Contains(body, "- Date: ") {
		problems = append(problems, name+": no `- Date: ...` line")
	}
	for _, section := range sections {
		if !strings.Contains(body, "\n## "+section+"\n") {
			problems = append(problems, fmt.Sprintf("%s: missing the `## %s` section", name, section))
		}
	}
	return &record, problems
}

// checkIndex holds README.md to the records that exist: every record listed
// once, in order, with the link and status it actually has.
func checkIndex(dir string, records []Record) []string {
	body, err := os.ReadFile(filepath.Join(dir, "README.md")) //nolint:gosec // the directory is chosen by the caller, not by input this package reads
	if err != nil {
		return []string{fmt.Sprintf("docs/adr/README.md: %v", err)}
	}
	text := string(body)

	var problems []string
	var listed []int
	for _, line := range strings.Split(text, "\n") {
		match := indexRow.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if match == nil {
			continue
		}
		number, _ := strconv.Atoi(match[1])
		listed = append(listed, number)
		if _, err := os.Stat(filepath.Join(dir, match[2])); err != nil {
			problems = append(problems, fmt.Sprintf("docs/adr/README.md: the row for ADR-%04d links to %s, which does not exist", number, match[2]))
		}
	}

	indexed := map[int]bool{}
	for _, number := range listed {
		indexed[number] = true
	}
	for _, record := range records {
		if !indexed[record.Number] {
			problems = append(problems, fmt.Sprintf("docs/adr/README.md: ADR-%04d (%s) is not in the index", record.Number, record.File))
			continue
		}
		if !rowCarriesStatus(text, record) {
			problems = append(problems, fmt.Sprintf("docs/adr/README.md: the row for ADR-%04d does not show its status %q", record.Number, record.Status))
		}
	}
	for _, number := range listed {
		if _, ok := byNumber(records, number); !ok {
			problems = append(problems, fmt.Sprintf("docs/adr/README.md: ADR-%04d is listed but has no record", number))
		}
	}
	if !sort.IntsAreSorted(listed) {
		problems = append(problems, "docs/adr/README.md: the index must be in ascending order")
	}
	return problems
}

// rowCarriesStatus reports whether the index row for this record ends in the
// status the record itself declares.
func rowCarriesStatus(index string, record Record) bool {
	prefix := fmt.Sprintf("| [%04d](", record.Number)
	for _, line := range strings.Split(index, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		columns := strings.Split(strings.Trim(line, "|"), "|")
		return len(columns) >= 3 && strings.TrimSpace(columns[len(columns)-1]) == record.Status
	}
	return false
}

func byNumber(records []Record, number int) (Record, bool) {
	for _, record := range records {
		if record.Number == number {
			return record, true
		}
	}
	return Record{}, false
}
