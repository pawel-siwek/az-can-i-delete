package verdict

import (
	"fmt"
	"reflect"
	"slices"
)

// EvaluationError denotes malformed internal evaluation state, never an Azure
// collection failure. Callers must report the error without publishing a verdict.
type EvaluationError struct {
	Problem string
}

// Error makes the internal-error boundary explicit for CLI and API consumers.
func (e *EvaluationError) Error() string { return "INTERNAL ERROR: " + e.Problem }

func invalid(format string, args ...any) error {
	return &EvaluationError{Problem: fmt.Sprintf(format, args...)}
}

// Evaluate is the production entrypoint. It validates catalogue integrity and
// normalized input before invoking the pure Decide rules. On validation failure
// it returns a zero Result and an explicit internal error, never a verdict.
func Evaluate(in Input) (Result, error) {
	if err := Validate(in); err != nil {
		return Result{}, err
	}
	return Decide(in), nil
}

// Validate checks internal shape and the G6 integrity constraints. It does not
// require observations to exist or be present: missing, absent, unknown and
// not-evaluated observations remain inputs to the original verdict rules.
// Identical duplicate evidence is accepted; conflicting copies are rejected.
func Validate(in Input) error {
	trusted := RequiredForType(in.Type)
	if len(in.Required) == 0 || len(trusted) == 0 {
		return invalid("empty Required catalogue/list")
	}
	actual := slices.Clone(in.Required)
	slices.Sort(actual)
	slices.Sort(trusted)
	if !slices.Equal(actual, trusted) {
		return invalid("Required list differs from trusted catalogue for type %q", in.Type)
	}
	if in.Requested.Days < 7 || in.Requested.Days > 93 {
		return invalid("requested window must be between 7 and 93 days")
	}
	switch in.Age.Confidence {
	case "verified", "bounded", "inferred", "unknown":
	default:
		return invalid("invalid age confidence")
	}
	if in.Age.LowerBoundDays < 0 {
		return invalid("negative age lower bound")
	}
	seen := make(map[string]Evidence, len(in.Evidence))
	for _, e := range in.Evidence {
		if prior, ok := seen[e.ID]; ok && !reflect.DeepEqual(prior, e) {
			return invalid("contradictory duplicate evidence ID %q", e.ID)
		}
		seen[e.ID] = e
		if e.ID == "" || e.Tier < TierBlocker || e.Tier > TierInfo {
			return invalid("invalid evidence ID or tier")
		}
		switch e.Status {
		case StatusPresent, StatusAbsent, StatusUnknown, StatusNotEvaluated:
		default:
			return invalid("invalid status for evidence %q", e.ID)
		}
		if e.Tier == TierInfo && e.Critical {
			return invalid("INFO evidence cannot be critical: %q", e.ID)
		}
		if slices.Contains(trusted, e.ID) && e.ID != "generic.never" && e.Tier != TierObservedIdle {
			return invalid("Required silence evidence must be OBSERVED_IDLE: %q", e.ID)
		}
	}
	return nil
}
