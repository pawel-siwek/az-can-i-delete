package verdict

import (
	"cmp"
	"slices"
	"strings"
	"time"
)

// EffectiveWindow computes the v3 silence window with the caller's cutoff.
// LIVE always uses Requested instead; fixed 30-day predicates use absolute days.
// Collectors must mark timed silence absent when this window has zero days.
func EffectiveWindow(requested Window, age Age) Window {
	effective := requested
	switch age.Confidence {
	case "verified", "bounded":
		effective.Days = max(0, min(requested.Days, age.LowerBoundDays))
	case "inferred":
		effective.Days = requested.Days
	default:
		effective.Days = 0
	}
	effective.Start = effective.End.Add(-time.Duration(effective.Days) * 24 * time.Hour)
	return effective
}

// Decide applies the original nine ordered v3 rules to ALREADY VALIDATED input.
// It deliberately preserves the original pure signature: no network, clock,
// classifier or error return. Calling it without a successful Validate is not a
// safe production entrypoint; use Evaluate instead. Evidence must already carry
// the collector's Requested LIVE and Effective timed-silence classifications.
func Decide(in Input) Result {
	out := Result{
		Effective: EffectiveWindow(in.Requested, in.Age),
		Coverage:  Coverage{Total: len(in.Evidence), Age: in.Age},
		Reasons:   []string{}, Unknowns: []string{}, NotEvaluated: []string{},
	}
	out.Coverage.Age.Caveats = slices.Clone(in.Age.Caveats)
	present := make(map[Tier][]string)
	byID := make(map[string]Evidence, len(in.Evidence))
	var criticalUnknown []string
	for _, e := range in.Evidence {
		byID[e.ID] = e
		switch e.Status {
		case StatusPresent:
			out.Coverage.Evaluated++
			present[e.Tier] = append(present[e.Tier], e.ID)
		case StatusAbsent:
			out.Coverage.Evaluated++
		case StatusUnknown:
			out.Coverage.Unknown++
			out.Unknowns = append(out.Unknowns, e.ID)
			if e.Critical {
				out.Coverage.CriticalUnknown++
				criticalUnknown = append(criticalUnknown, e.ID)
			}
		case StatusNotEvaluated:
			out.Coverage.NotEvaluated++
			out.NotEvaluated = append(out.NotEvaluated, e.ID)
		}
	}
	var missing []string
	for _, id := range in.Required {
		if byID[id].Status != StatusPresent {
			missing = append(missing, "required.missing:"+id)
		}
	}
	out.Verdict, out.ReasonClass = "tentative", "inconclusive"
	switch {
	case len(present[TierBlocker]) > 0:
		out.Verdict, out.ReasonClass = "no", "blocked"
		out.Reasons = append(out.Reasons, present[TierBlocker]...)
		out.Reasons = append(out.Reasons, present[TierHardDependency]...)
		out.Reasons = append(out.Reasons, present[TierLiveActivity]...)
	case len(present[TierHardDependency])+len(present[TierLiveActivity]) > 0:
		out.Verdict, out.ReasonClass = "no", "in-use"
		out.Reasons = append(out.Reasons, present[TierHardDependency]...)
		out.Reasons = append(out.Reasons, present[TierLiveActivity]...)
	case len(criticalUnknown) > 0:
		out.Reasons = criticalUnknown
	case len(present[TierDesignIntent]) > 0:
		out.ReasonClass = "design-intent"
		out.Reasons = present[TierDesignIntent]
	case in.Age.Confidence == "unknown":
		out.Reasons = []string{"age.unknown"}
	case in.Age.Confidence == "inferred":
		out.Reasons = []string{"age.inferred-only"}
	case out.Effective.Days < 30:
		out.Reasons = []string{"window.too-short-for-yes"}
	case slices.Contains(in.Required, "generic.never"):
		out.Reasons = []string{"generic.never"}
	case len(missing) == 0:
		out.Verdict, out.ReasonClass = "yes", "no-evidence-of-use"
		out.Reasons = slices.Clone(in.Required)
	default:
		out.Reasons = missing
	}
	out.Reasons = sortedIDs(out.Reasons, byID)
	out.Unknowns = sortedIDs(out.Unknowns, byID)
	out.NotEvaluated = sortedIDs(out.NotEvaluated, byID)
	out.HumanEscalation = out.Verdict == "tentative"
	if out.HumanEscalation {
		out.RequiredHumanQuestion = humanQuestion(out.Reasons[0])
	}
	return out
}

func sortedIDs(ids []string, evidence map[string]Evidence) []string {
	slices.SortFunc(ids, func(a, b string) int {
		ta, pa := reasonOrder(a, evidence)
		tb, pb := reasonOrder(b, evidence)
		if order := cmp.Compare(ta, tb); order != 0 {
			return order
		}
		if order := cmp.Compare(pa, pb); order != 0 {
			return order
		}
		return strings.Compare(a, b)
	})
	return slices.Compact(ids)
}

func reasonOrder(id string, evidence map[string]Evidence) (Tier, int) {
	switch {
	case strings.HasPrefix(id, "required.missing:"):
		return TierObservedIdle, 1
	case strings.HasPrefix(id, "age."):
		return TierObservedIdle, 2
	case strings.HasPrefix(id, "window."):
		return TierObservedIdle, 3
	case id == "generic.never":
		return TierObservedIdle, 4
	default:
		return evidence[id].Tier, 0
	}
}

// No per-ID question wording is supplied in the normative table. These are
// tool-owned templates, referencing the first ordered reason rather than Azure
// metadata. A later rules renderer may specialize wording without adding gates.
func humanQuestion(reason string) string {
	switch {
	case strings.HasPrefix(reason, "required.missing:"):
		return "Can a human verify the missing required observation (" + strings.TrimPrefix(reason, "required.missing:") + ") before considering deletion?"
	case strings.HasPrefix(reason, "age."):
		return "Can a human establish the current resource incarnation's age before considering deletion?"
	case strings.HasPrefix(reason, "window."):
		return "Can a human obtain at least 30 days of applicable observation before considering deletion? Do not shorten the window."
	case reason == "generic.never":
		return "Can a human assess this unsupported resource type and its consumers before considering deletion?"
	default:
		return "Can a human resolve the uncertainty or design intent reported by " + reason + " before considering deletion?"
	}
}
