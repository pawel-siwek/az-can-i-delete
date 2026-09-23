package storage

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pawel-siwek/az-can-i-delete/internal/kb"
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The knowledge base answers a narrow question about the four child listings:
// does a container, share, queue or table name identify what produced it?
//
// It is weak evidence and stays weak. A name match reports the entry's
// unconfirmedTier and never the confirmed one, because confirming a producer
// means finding it in configuration — a flow log pointing here, a diagnostic
// setting naming this account, a function app whose content share this is —
// and those are the other storage signals' work, not this one's. The six
// mechanism entries carry no name pattern at all and are unreachable here by
// design.

// kbSignalID is the per-entry signal a match is reported under.
//
// docs/SPEC.md section 5.1 spells this `storage.kb.match:<entryId>`. That form
// cannot survive the report: REQUIREMENTS section 6 fixes the rule-id grammar
// every emitted id must satisfy, and it admits neither a colon, which reads as
// a URL scheme, nor the capital in a kind like `rgName`. The separator is a
// dot and the entry id is lower-cased; nothing else about it changes, so the
// signal still names the row it came from.
func kbSignalID(entryID string) string { return SignalKB + "." + strings.ToLower(entryID) }

// kbTiers maps the knowledge base's tier names onto the verdict's tiers.
var kbTiers = map[string]verdict.Tier{
	"BLOCKER":         verdict.TierBlocker,
	"HARD_DEPENDENCY": verdict.TierHardDependency,
	"LIVE_ACTIVITY":   verdict.TierLiveActivity,
	"DESIGN_INTENT":   verdict.TierDesignIntent,
	"OBSERVED_IDLE":   verdict.TierObservedIdle,
	"INFO":            verdict.TierInfo,
}

// kbKinds maps a child listing to the knowledge base kind that describes it.
var kbKinds = map[string]string{
	"containers": "container",
	"shares":     "share",
	"queues":     "queue",
	"tables":     "table",
}

// kbMatches reports every knowledge base entry a listed name resolves to.
//
// The base signal is reported on every run: absent when nothing matched, so a
// reader can tell "no name identified a producer" from "the knowledge base was
// not consulted". Each matching entry adds its own evidence at its own tier.
func kbMatches(lists []childList) []verdict.Evidence {
	counts := map[string]int{}
	entries := map[string]kb.Entry{}
	for _, list := range lists {
		kind, known := kbKinds[list.name]
		if !known {
			continue
		}
		for _, item := range list.items {
			entry, found, err := kb.Lookup(kind, item.Name)
			if err != nil || !found {
				continue
			}
			counts[entry.ID]++
			entries[entry.ID] = entry
		}
	}

	if len(counts) == 0 {
		return []verdict.Evidence{Catalogue.Absent(SignalKB)}
	}

	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	evidence := []verdict.Evidence{Catalogue.Present(SignalKB, map[string]any{
		"matchCount": len(ids),
	})}
	for _, id := range ids {
		evidence = append(evidence, Catalogue.Present(kbSignalID(id), map[string]any{
			"matchCount": counts[id],
			// A name match is never the confirmed tier. The detail says so
			// rather than leaving the reader to infer it from the tier.
			"confirmed": false,
		}))
	}
	return evidence
}

// kbCatalogue is the catalogue rows the knowledge base contributes, one per
// entry, each at the tier a name alone may claim.
func kbCatalogue() map[string]signal.Spec {
	entries, err := kb.Entries()
	if err != nil {
		panic(fmt.Sprintf("the embedded knowledge base is unusable: %v", err))
	}
	rows := make(map[string]signal.Spec, len(entries))
	for _, entry := range entries {
		if entry.Mechanism {
			continue // no name pattern, so this signal can never be emitted
		}
		tier, known := kbTiers[entry.UnconfirmedTier]
		if !known {
			panic(fmt.Sprintf("%s: unknown unconfirmedTier %q", entry.ID, entry.UnconfirmedTier))
		}
		rows[kbSignalID(entry.ID)] = signal.Spec{
			Tier: tier, Family: "kb", Confidence: "unknown", API: "ARM",
		}
	}
	return rows
}

// kbPolicies supplies the user-facing strings for those rows.
//
// Every string is the tool's own or the knowledge base's; none is built from
// an Azure name. What matched is reported as a count, and the producer comes
// from kb.yaml, which this repository writes and reviews.
func kbPolicies() map[string]output.SignalPolicy {
	entries, err := kb.Entries()
	if err != nil {
		panic(fmt.Sprintf("the embedded knowledge base is unusable: %v", err))
	}
	policies := make(map[string]output.SignalPolicy, len(entries))
	for _, entry := range entries {
		if entry.Mechanism {
			continue
		}
		policies[kbSignalID(entry.ID)] = output.SignalPolicy{
			Family: "kb", Confidence: "unknown",
			Details: map[string]output.DetailPolicy{
				"matchCount": {Kind: output.Number},
				"confirmed":  {Kind: output.Boolean},
			},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: kbSummary(entry),
				verdict.StatusAbsent:  "No name in this account matches " + entry.ID + ".",
			},
			APIVersions: []string{},
			NextSteps:   []string{kbNextStep(entry)},
		}
	}
	return policies
}

// kbSummary states what the match means and, just as importantly, what it does
// not: a name is a naming convention, not the producer itself.
func kbSummary(entry kb.Entry) string {
	return "A name here follows the convention of " + entry.ID +
		", which belongs to " + kbProducer(entry) +
		". The name alone is the only evidence, and the producer was not found in configuration."
}

func kbNextStep(entry kb.Entry) string {
	return "Before acting on " + entry.ID + ", confirm it - " + kbConfirm(entry)
}

// kbProducer and kbConfirm make the knowledge base's own prose safe to print.
// The text is the repository's, but it is written for human readers and
// carries backticks, arrows and the odd colon, which the report's fixed-text
// rule rejects for looking like markup or a URL scheme.
func kbProducer(entry kb.Entry) string { return kbPlain(entry.Producer) }

func kbConfirm(entry kb.Entry) string { return kbPlain(entry.Confirm) }

var kbReplacer = strings.NewReplacer(
	"`", "", "→", "then", "≤", "at most", "≥", "at least", "∉", "is not one of",
	"∧", "and", "∨", "or", "—", "-", "…", "", "://", " ", ":", " -",
)

func kbPlain(text string) string {
	return strings.Join(strings.Fields(kbReplacer.Replace(text)), " ")
}
