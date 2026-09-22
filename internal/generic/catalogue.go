// Package generic collects the signals SPEC section 5.0 requires on every
// supported type: existence, Resource Graph visibility, locks, deny
// assignments, resource-group ownership, tags, deployments, Activity Log
// writes, private endpoint connections, DNS and Advisor. Every signal in the
// catalogue is reported on every run as present, absent, unknown(code) or
// not_evaluated; nothing this layer cannot read is ever reported as absent.
package generic

import (
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The generic signal IDs. Analyzers reference them; the output policy supplies
// every user-facing string for them.
const (
	SignalARMGet          = "generic.arm.get"
	SignalARGVisible      = "generic.arg.visible"
	SignalLock            = "generic.lock.cannotdelete"
	SignalDenyAssignment  = "generic.deny-assignment"
	SignalRGManagedBy     = "generic.rg.managedby"
	SignalTagProtect      = "generic.tags.protect"
	SignalTagExpired      = "generic.tags.expired"
	SignalTagIntent       = "generic.tags.intent"
	SignalHiddenLink      = "generic.tags.hidden-link"
	SignalHiddenLinkDead  = "generic.tags.hidden-link-dangling"
	SignalTagOwner        = "generic.tags.owner"
	SignalDeployment      = "generic.iac.deployment"
	SignalRecentWrite     = "generic.activitylog.recent-write"
	SignalWrites          = "generic.activitylog.writes"
	SignalPEConnections   = "generic.pe.connections"
	SignalDNSRecords      = "generic.dns.records"
	SignalAdvisor         = "generic.advisor"
	SignalRoleAssignments = "generic.roleassignments.direct"
	SignalPolicyState     = "generic.policy.state"
)

// The api-versions SPEC section 5.0 pins for the generic layer.
const (
	LocksAPIVersion           = "2020-05-01"
	DenyAssignmentsAPIVersion = "2022-04-01"
	DeploymentsAPIVersion     = "2026-06-01"
)

// RecentWriteDays and WritesDays are the fixed lookbacks of the two Activity
// Log signals. They are absolute periods, not the requested window, so a short
// window can neither widen nor narrow them.
const (
	RecentWriteDays = 30
	WritesDays      = 90
)

// spec is the fixed catalogue row for one signal: what tier it carries, whether
// an unreadable answer is a critical unknown, and where it is collected from.
type spec struct {
	tier       verdict.Tier
	critical   bool
	family     string
	confidence string
	api        string
	apiVersion string
	// argBacked signals cannot be trusted when the Resource Graph probe did not
	// find the target: they become unknown rather than absent.
	argBacked bool
}

// catalogue is SPEC section 5.0, in the order every report prints. A deny
// assignment is deliberately non-critical: a 403 reading it must not by itself
// block a verdict, while an unreadable lock must.
var catalogue = map[string]spec{
	SignalARMGet:          {tier: verdict.TierInfo, family: "structural", confidence: "verified", api: "ARM"},
	SignalARGVisible:      {tier: verdict.TierObservedIdle, family: "structural", confidence: "verified", api: "ARG"},
	SignalLock:            {tier: verdict.TierBlocker, critical: true, family: "structural", confidence: "verified", api: "ARM", apiVersion: LocksAPIVersion},
	SignalDenyAssignment:  {tier: verdict.TierBlocker, family: "structural", confidence: "verified", api: "ARM", apiVersion: DenyAssignmentsAPIVersion},
	SignalRGManagedBy:     {tier: verdict.TierHardDependency, critical: true, family: "structural", confidence: "verified", api: "ARG", argBacked: true},
	SignalTagProtect:      {tier: verdict.TierHardDependency, family: "tags", confidence: "heuristic", api: "ARM"},
	SignalTagExpired:      {tier: verdict.TierObservedIdle, family: "tags", confidence: "heuristic", api: "ARM"},
	SignalTagIntent:       {tier: verdict.TierDesignIntent, family: "tags", confidence: "heuristic", api: "ARM"},
	SignalHiddenLink:      {tier: verdict.TierHardDependency, family: "tags", confidence: "verified", api: "ARG", argBacked: true},
	SignalHiddenLinkDead:  {tier: verdict.TierInfo, family: "tags", confidence: "verified", api: "ARG", argBacked: true},
	SignalTagOwner:        {tier: verdict.TierInfo, family: "tags", confidence: "heuristic", api: "ARM"},
	SignalDeployment:      {tier: verdict.TierDesignIntent, family: "activity-log", confidence: "verified", api: "ARM", apiVersion: DeploymentsAPIVersion},
	SignalRecentWrite:     {tier: verdict.TierDesignIntent, family: "activity-log", confidence: "verified", api: "ActivityLog"},
	SignalWrites:          {tier: verdict.TierInfo, family: "activity-log", confidence: "verified", api: "ActivityLog"},
	SignalPEConnections:   {tier: verdict.TierHardDependency, critical: true, family: "structural", confidence: "verified", api: "ARM"},
	SignalDNSRecords:      {tier: verdict.TierHardDependency, critical: true, family: "reverse-ref", confidence: "verified", api: "ARG", argBacked: true},
	SignalAdvisor:         {tier: verdict.TierObservedIdle, family: "derived", confidence: "heuristic", api: "Advisor", argBacked: true},
	SignalRoleAssignments: {tier: verdict.TierInfo, family: "structural", confidence: "unknown", api: "ARM"},
	SignalPolicyState:     {tier: verdict.TierInfo, family: "structural", confidence: "unknown", api: "ARM"},
}

// Signals is the catalogue order. Every run emits exactly these IDs, so a
// missing observation is visible as unknown or not_evaluated, never as nothing.
var Signals = []string{
	SignalARMGet, SignalARGVisible, SignalLock, SignalDenyAssignment, SignalRGManagedBy,
	SignalTagProtect, SignalTagExpired, SignalTagIntent, SignalHiddenLink, SignalHiddenLinkDead,
	SignalTagOwner, SignalDeployment, SignalRecentWrite, SignalWrites, SignalPEConnections,
	SignalDNSRecords, SignalAdvisor, SignalRoleAssignments, SignalPolicyState,
}

// evidence builds one catalogue-consistent observation. Only the tier, status,
// criticality and typed details come from here; every user-facing string is the
// output policy's, so no Azure text can reach a summary through this layer.
func evidence(id string, status verdict.Status, details map[string]any) verdict.Evidence {
	s := catalogue[id]
	return verdict.Evidence{
		ID: id, Tier: s.tier, Family: s.family, Status: status,
		Critical: s.critical && status != verdict.StatusNotEvaluated,
		Details:  details, Confidence: s.confidence,
		Source: verdict.Source{API: s.api, APIVersion: s.apiVersion},
	}
}

func present(id string, details map[string]any) verdict.Evidence {
	return evidence(id, verdict.StatusPresent, details)
}

func absent(id string) verdict.Evidence { return evidence(id, verdict.StatusAbsent, nil) }

func notEvaluated(id string) verdict.Evidence {
	return evidence(id, verdict.StatusNotEvaluated, nil)
}

// unknownAs preserves why an observation is missing. A signal whose acquisition
// failed keeps its catalogue criticality, which is what stops a `yes`.
func unknownAs(id string, u *verdict.Unknown) verdict.Evidence {
	e := evidence(id, verdict.StatusUnknown, nil)
	e.Unknown = u
	return e
}

func windowed(e verdict.Evidence, end time.Time, days int) verdict.Evidence {
	window := verdict.Window{Start: end.AddDate(0, 0, -days), End: end, Days: days, Grain: "P1D"}
	e.Window = &window
	return e
}
