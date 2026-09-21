// Package verdict implements the pure Decide v3 rules and current-incarnation
// age chain. Production callers must use Evaluate: Decide requires validated
// input. Collectors, classification, rendering and Azure access are separate.
package verdict

import "time"

// Tier is the precedence of a normalized signal, not a numeric risk score.
type Tier int

// The six tiers are ordered from a deletion blocker to descriptive information.
const (
	TierBlocker Tier = iota + 1
	TierHardDependency
	TierLiveActivity
	TierDesignIntent
	TierObservedIdle
	TierInfo
)

// Status distinguishes observations, collection failures, and unimplemented checks.
type Status string

// Evidence statuses never interpret failure or missing observations as absence.
const (
	StatusPresent      Status = "present"
	StatusAbsent       Status = "absent"
	StatusUnknown      Status = "unknown"
	StatusNotEvaluated Status = "not_evaluated"
)

// UnknownCode identifies why a signal could not be evaluated.
type UnknownCode string

// Unknown reasons preserve the acquisition failure rather than inventing silence.
const (
	UnkPermission  UnknownCode = "permission"
	UnkNetwork     UnknownCode = "network"
	UnkAuth        UnknownCode = "auth"
	UnkThrottled   UnknownCode = "throttled"
	UnkTransient   UnknownCode = "transient"
	UnkTimeout     UnknownCode = "timeout"
	UnkPartial     UnknownCode = "partial"
	UnkUnsupported UnknownCode = "unsupported"
	UnkDependency  UnknownCode = "dependency"
)

// DefaultRequestedDays is the product default, not the historical fixture window.
const DefaultRequestedDays = 30

// Unknown carries a tool-owned failure explanation; it is not evidence of disuse.
type Unknown struct {
	Code       UnknownCode `json:"code"`
	Message    string      `json:"message"`
	HTTPStatus int         `json:"httpStatus,omitempty"`
	ErrorCode  string      `json:"errorCode,omitempty"`
}

// Window is an explicit observation interval; no evaluator reads the clock.
type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Days  int       `json:"days"`
	Grain string    `json:"grain,omitempty"`
}

// Source identifies the acquisition surface for a signal.
type Source struct {
	API        string `json:"api"`
	Path       string `json:"path"`
	APIVersion string `json:"apiVersion,omitempty"`
}

// NotEvaluated explains an unperformed check and its consequences.
type NotEvaluated struct {
	Reason      string `json:"reason"`
	Consequence string `json:"consequence"`
	HowToCheck  string `json:"howToCheck"`
}

// Evidence is a normalized, tiered signal. Details must be allow-listed and
// Azure free-form strings confined to Untrusted by the output boundary.
// NextSteps is metadata for downstream rendering, not an additional verdict gate.
type Evidence struct {
	ID           string            `json:"id"`
	Tier         Tier              `json:"tier"`
	TierName     string            `json:"tierName"`
	Family       string            `json:"family"`
	ResourceType string            `json:"resourceType"`
	Status       Status            `json:"status"`
	Critical     bool              `json:"critical"`
	Summary      string            `json:"summary"`
	Details      map[string]any    `json:"details,omitempty"`
	Untrusted    map[string]string `json:"untrusted,omitempty"`
	Window       *Window           `json:"window,omitempty"`
	Source       Source            `json:"source"`
	Confidence   string            `json:"confidence"`
	Unknown      *Unknown          `json:"unknown,omitempty"`
	NotEvaluated *NotEvaluated     `json:"notEvaluated,omitempty"`
	Related      []string          `json:"related,omitempty"`
	NextSteps    []string          `json:"nextSteps,omitempty"`
}

// Age is a lower bound for the current resource incarnation, not an exact age.
type Age struct {
	LowerBoundDays int      `json:"lowerBoundDays"`
	Confidence     string   `json:"confidence"`
	Source         string   `json:"source"`
	Caveats        []string `json:"caveats"`
}

// Input separates the trusted Required definition from possibly missing evidence.
// LIVE signals must have been classified over Requested; timed OBSERVED_IDLE
// signals over EffectiveWindow. Fixed-lookback predicates keep their own periods.
type Input struct {
	Type      string     `json:"type"`
	Evidence  []Evidence `json:"evidence"`
	Age       Age        `json:"age"`
	Requested Window     `json:"requested"`
	Required  []string   `json:"required"`
}

// Coverage counts all supplied evidence independently of the winning rule.
// Evaluated counts present and absent signals; unknown and not-evaluated are
// disjoint counts. Missing observations are reflected by required.missing reasons.
type Coverage struct {
	Total           int `json:"total"`
	Evaluated       int `json:"evaluated"`
	Unknown         int `json:"unknown"`
	NotEvaluated    int `json:"notEvaluated"`
	CriticalUnknown int `json:"criticalUnknown"`
	Age             Age `json:"age"`
}

// Result preserves the A schema: Unknowns and NotEvaluated are IDs referencing
// Evidence metadata. A zero Result returned with an error is not a verdict.
type Result struct {
	Verdict               string   `json:"verdict"`
	ReasonClass           string   `json:"reasonClass"`
	Reasons               []string `json:"reasons"`
	Unknowns              []string `json:"unknowns"`
	NotEvaluated          []string `json:"notEvaluated"`
	Effective             Window   `json:"effective"`
	Coverage              Coverage `json:"coverage"`
	HumanEscalation       bool     `json:"humanEscalation"`
	RequiredHumanQuestion string   `json:"requiredHumanQuestion"`
}
