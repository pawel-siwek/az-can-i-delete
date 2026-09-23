package kb

import (
	"strings"
	"testing"
)

// The counts docs/SPEC.md appendix L records for the source data. They are
// here so that losing a row during a correction is a failure rather than a
// quieter knowledge base.
func TestTheBaseIsTheWholeTable(t *testing.T) {
	entries, err := Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 79 {
		t.Errorf("the knowledge base has %d entries, and the source table has 79", len(entries))
	}
	if Date() != "2026-09-21" {
		t.Errorf("review date = %q, want the source table's 2026-09-21", Date())
	}
	status := map[string]int{}
	for _, entry := range entries {
		status[entry.Status]++
	}
	for provenance, want := range map[string]int{"VERIFIED": 51, "SOURCE": 8, "OBSERVED": 20} {
		if status[provenance] != want {
			t.Errorf("%s entries = %d, want %d", provenance, status[provenance], want)
		}
	}
}

// Every example must hold and every counterexample must not. Two kinds of
// fixture need care, and docs/SPEC.md section 9.3 says not to delete either to
// make the test pass.
//
// A tag fixture carries a value: `do-not-delete=false` is a counterexample
// whose key matches perfectly and whose value is what disqualifies it.
//
// A counterexample like `WADMetricsPT1HP10DV2S20151108` under table.wad does
// match that entry's pattern. The claim is about precedence — the name belongs
// to the specific entry that precedes it — so counterexamples are checked
// through the ordered matcher rather than against the single pattern.
func TestKBExamples(t *testing.T) {
	entries, err := Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Mechanism {
			continue // no pattern, so nothing to exemplify
		}
		for _, example := range entry.Examples {
			if entry.Kind == "tag" {
				key, value, _ := strings.Cut(example, "=")
				if !entry.Matches(key) {
					t.Errorf("%s: its own example key %q does not match %q", entry.ID, key, entry.Regex)
					continue
				}
				if confirmed, known := ValueConfirms(entry.ID, value); known && !confirmed {
					t.Errorf("%s: its own example %q has a value its confirm rule rejects", entry.ID, example)
				}
				continue
			}
			if !entry.Matches(example) {
				t.Errorf("%s: its own example %q does not match %q", entry.ID, example, entry.Regex)
			}
		}

		for _, counterexample := range entry.Counterexamples {
			if entry.Kind == "tag" {
				key, value, _ := strings.Cut(counterexample, "=")
				if !entry.Matches(key) {
					continue // the key alone already disqualifies it
				}
				confirmed, known := ValueConfirms(entry.ID, value)
				if !known {
					t.Errorf("%s: counterexample %q matches by key and no value rule rejects it", entry.ID, counterexample)
				} else if confirmed {
					t.Errorf("%s: counterexample %q is accepted by its own confirm rule", entry.ID, counterexample)
				}
				continue
			}
			matched, found, err := Lookup(entry.Kind, counterexample)
			if err != nil {
				t.Fatal(err)
			}
			if found && matched.ID == entry.ID {
				t.Errorf("%s: its own counterexample %q resolves to it", entry.ID, counterexample)
			}
		}
	}
}

// The three value rules, stated directly rather than only through fixtures.
func TestValueConfirms(t *testing.T) {
	cases := []struct {
		id, value        string
		confirmed, known bool
	}{
		{"tag.cloudshell", "azure-cloud-shell", true, true},
		{"tag.cloudshell", "something-else", false, true},
		{"tag.protect-generic", "true", true, true},
		{"tag.protect-generic", "false", false, true},
		{"tag.protect-generic", "0", false, true},
		{"tag.protect-generic", "", false, true},
		{"tag.expiry-generic", "2026-12-31", true, true},
		{"tag.expiry-generic", "2026-12-31T23:59:59Z", true, true},
		{"tag.expiry-generic", "forever", false, true},
		// Every other entry's confirm is a query against Azure, so there is no
		// value rule and the caller must not read the absence as a pass.
		{"tag.aks-created-by", "azure", false, false},
		{"container.insights-logs", "anything", false, false},
	}
	for _, test := range cases {
		confirmed, known := ValueConfirms(test.id, test.value)
		if confirmed != test.confirmed || known != test.known {
			t.Errorf("ValueConfirms(%q, %q) = (%v, %v), want (%v, %v)",
				test.id, test.value, confirmed, known, test.confirmed, test.known)
		}
	}
}

// File order is precedence. Both pairs below have a specific entry and a
// generic one that also matches; the specific must win, or a WAD metrics table
// would be reported as an unspecified WAD table.
func TestKBPrecedence(t *testing.T) {
	cases := []struct {
		kind, name, want string
	}{
		{"table", "WADMetricsPT1HP10DV2S20151108", "table.wadmetrics"},
		{"table", "LinuxSyslogVer2v0", "table.lad-syslog"},
		{"container", "insights-logs-kube-audit", "container.insights-logs"},
		{"container", "wad-iis-logfiles", "container.wad"},
	}
	for _, test := range cases {
		entry, found, err := Lookup(test.kind, test.name)
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Errorf("%s %q matched nothing, want %s", test.kind, test.name, test.want)
			continue
		}
		if entry.ID != test.want {
			t.Errorf("%s %q matched %s, want %s", test.kind, test.name, entry.ID, test.want)
		}
	}
}

// A name is weak evidence. No entry may let a name alone reach BLOCKER or
// HARD_DEPENDENCY, because that would make "this container is called
// insights-logs-x" as strong as finding the diagnostic setting that produced
// it. The exception is a tag or lock whose confirm is a check of the value the
// match already carries.
func TestKBTierSanity(t *testing.T) {
	entries, err := Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.UnconfirmedTier != "BLOCKER" && entry.UnconfirmedTier != "HARD_DEPENDENCY" {
			continue
		}
		if entry.Kind != "tag" && entry.Kind != "lockName" {
			t.Errorf("%s: a name-only match claims %s; only a tag or a lock may, and only on its value",
				entry.ID, entry.UnconfirmedTier)
			continue
		}
		if !strings.Contains(entry.Confirm, "value") && !strings.Contains(entry.Confirm, "lock level") {
			t.Errorf("%s: claims %s from a name alone without checking the value (confirm: %q)",
				entry.ID, entry.UnconfirmedTier, entry.Confirm)
		}
	}
}

// A mechanism entry is reachable only through a confirming query. If one could
// be matched by name it would match every name of its kind, which is the
// loudest possible false positive.
func TestMechanismsAreNeverNameMatched(t *testing.T) {
	entries, err := Entries()
	if err != nil {
		t.Fatal(err)
	}
	mechanisms := 0
	for _, entry := range entries {
		if !entry.Mechanism {
			continue
		}
		mechanisms++
		for _, name := range []string{"", "anything", "aksbackup", "x", strings.Repeat("a", 63)} {
			if entry.Matches(name) {
				t.Errorf("%s is a mechanism but matched the name %q", entry.ID, name)
			}
		}
		found, _, err := Lookup(entry.Kind, "aksbackup")
		if err != nil {
			t.Fatal(err)
		}
		if found.ID == entry.ID {
			t.Errorf("%s was reached by a name lookup", entry.ID)
		}
	}
	site := by(t)["share.functions-content-by-site"]
	if len(site.Examples) != 0 || len(site.Counterexamples) != 0 {
		t.Errorf("share.functions-content-by-site kept examples; docs/SPEC.md section 9.3 removes them because it became a mechanism")
	}
	if mechanisms != 6 {
		t.Errorf("mechanism entries = %d, want the six docs/SPEC.md section 9.3 names", mechanisms)
	}
	for _, kind := range []string{"container", "share", "accountName"} {
		list, err := Mechanisms(kind)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) == 0 {
			t.Errorf("no mechanism entries of kind %s, want at least one", kind)
		}
	}
}

// An unknown name is not a match, and neither is a name of the wrong kind.
func TestLookupRefusesWhatItDoesNotKnow(t *testing.T) {
	for _, test := range []struct{ kind, name string }{
		{"container", "my-holiday-photos"},
		{"container", ""},
		{"queue", "insights-logs-auditevent"}, // right name, wrong kind
		{"nonsense", "insights-logs-auditevent"},
	} {
		if _, found, err := Lookup(test.kind, test.name); err != nil || found {
			t.Errorf("Lookup(%q, %q) = %v, want no match", test.kind, test.name, found)
		}
	}
}

// The corrections docs/SPEC.md section 9.3 selects, asserted as behaviour
// rather than as a diff, so regenerating the file cannot quietly drop one.
func TestTheSelectedCorrectionsHold(t *testing.T) {
	cases := []struct {
		name          string
		kind, subject string
		want          string // entry id, or "" for no match
	}{
		{"insights-logs admits hyphenated categories", "container", "insights-logs-kube-audit", "container.insights-logs"},
		{"an AKS account name is f and 23 hex digits", "accountName", "f1a2b3c4d5e6f7a8b9c0d1e2", "accountName.aks"},
		{"a tfstate suffix needs its hyphen", "container", "tf-state-prod", "container.tfstate"},
		{"and without it is not a match", "container", "tfstatefiles-backup", ""},
		{"wad containers are hyphenated", "container", "wad-crash-dumps", "container.wad"},
		{"a bare wad name is not one", "container", "wadlogs", ""},
		{"a function content share is no longer guessed from its name", "share", "myfuncapp8f3a", ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			entry, found, err := Lookup(test.kind, test.subject)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case test.want == "" && found:
				t.Errorf("%q matched %s, want no match", test.subject, entry.ID)
			case test.want != "" && !found:
				t.Errorf("%q matched nothing, want %s", test.subject, test.want)
			case test.want != "" && entry.ID != test.want:
				t.Errorf("%q matched %s, want %s", test.subject, entry.ID, test.want)
			}
		})
	}

	entries, err := Entries()
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Entry{}
	for _, entry := range entries {
		by[entry.ID] = entry
	}
	if tier := by["tag.cloudshell"].UnconfirmedTier; tier != "INFO" {
		t.Errorf("tag.cloudshell unconfirmedTier = %s, want INFO", tier)
	}
	for _, id := range []string{"table.lad-syslog", "table.lad", "container.lad-jsonblob"} {
		if !strings.Contains(by[id].Confirm, "protectedSettings") {
			t.Errorf("%s: confirm must record that Reader cannot see LAD's account name, got %q", id, by[id].Confirm)
		}
	}
	for _, id := range []string{
		"container.webjobs-hosts", "container.webjobs-secrets", "queue.webjobs-blobtrigger",
		"queue.webjobs-host", "queue.webjobs-shared", "blobPrefix.webjobs-hosts-layout",
		"container.flex-app-package", "container.scm-releases",
	} {
		if by[id].Tier != "DESIGN_INTENT" {
			t.Errorf("%s tier = %s, want DESIGN_INTENT", id, by[id].Tier)
		}
		if !strings.Contains(by[id].Confirm, "site analyzer") {
			t.Errorf("%s: confirm must point at the site analyzer, got %q", id, by[id].Confirm)
		}
	}
	for _, id := range []string{"blobPrefix.insights-resourceid", "blobPrefix.flowlog", "blobPrefix.la-export"} {
		for _, example := range by[id].Examples {
			if strings.Contains(strings.ToLower(example), "-0000-4000-8000-") {
				continue
			}
			if strings.Count(example, "-") >= 4 {
				t.Errorf("%s: example %q does not use the mandated GUID", id, example)
			}
		}
	}
}

// by indexes the knowledge base for assertions about single rows.
func by(t *testing.T) map[string]Entry {
	t.Helper()
	entries, err := Entries()
	if err != nil {
		t.Fatal(err)
	}
	indexed := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		indexed[entry.ID] = entry
	}
	return indexed
}
