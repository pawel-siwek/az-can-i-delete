// Package generic collects the signals SPEC section 5.0 requires on every
// supported type: existence, Resource Graph visibility, locks, deny
// assignments, resource-group ownership, tags, deployments, Activity Log
// writes, private endpoint connections, DNS and Advisor. Every signal in the
// catalogue is reported on every run as present, absent, unknown(code) or
// not_evaluated; nothing this layer cannot read is ever reported as absent.
package generic

import (
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
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

// The api-versions SPEC section 5.0 pins for the generic layer. They are read
// from the rule table rather than repeated here: two copies of a pin drift,
// and a signal collected under one version while the report names another is
// exactly the silent inconsistency docs/adr/0008 exists to prevent.
var (
	LocksAPIVersion           = rules.MustOperation("locks")
	DenyAssignmentsAPIVersion = rules.MustOperation("denyAssignments")
	DeploymentsAPIVersion     = rules.MustOperation("deployments")
)

// RecentWriteDays and WritesDays are the fixed lookbacks of the two Activity
// Log signals. They are absolute periods, not the requested window, so a short
// window can neither widen nor narrow them.
const (
	RecentWriteDays = 30
	WritesDays      = 90
)

// Catalogue is SPEC section 5.0, in the order every report prints. A deny
// assignment is deliberately non-critical: a 403 reading it must not by itself
// block a verdict, while an unreadable lock must.
var Catalogue = signal.Catalogue{
	SignalARMGet:          {Tier: verdict.TierInfo, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalARGVisible:      {Tier: verdict.TierObservedIdle, Family: "structural", Confidence: "verified", API: "ARG"},
	SignalLock:            {Tier: verdict.TierBlocker, Critical: true, Family: "structural", Confidence: "verified", API: "ARM", APIVersion: LocksAPIVersion},
	SignalDenyAssignment:  {Tier: verdict.TierBlocker, Family: "structural", Confidence: "verified", API: "ARM", APIVersion: DenyAssignmentsAPIVersion},
	SignalRGManagedBy:     {Tier: verdict.TierHardDependency, Critical: true, Family: "structural", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalTagProtect:      {Tier: verdict.TierHardDependency, Family: "tags", Confidence: "heuristic", API: "ARM"},
	SignalTagExpired:      {Tier: verdict.TierObservedIdle, Family: "tags", Confidence: "heuristic", API: "ARM"},
	SignalTagIntent:       {Tier: verdict.TierDesignIntent, Family: "tags", Confidence: "heuristic", API: "ARM"},
	SignalHiddenLink:      {Tier: verdict.TierHardDependency, Family: "tags", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalHiddenLinkDead:  {Tier: verdict.TierInfo, Family: "tags", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalTagOwner:        {Tier: verdict.TierInfo, Family: "tags", Confidence: "heuristic", API: "ARM"},
	SignalDeployment:      {Tier: verdict.TierDesignIntent, Family: "activity-log", Confidence: "verified", API: "ARM", APIVersion: DeploymentsAPIVersion},
	SignalRecentWrite:     {Tier: verdict.TierDesignIntent, Family: "activity-log", Confidence: "verified", API: "ActivityLog"},
	SignalWrites:          {Tier: verdict.TierInfo, Family: "activity-log", Confidence: "verified", API: "ActivityLog"},
	SignalPEConnections:   {Tier: verdict.TierHardDependency, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalDNSRecords:      {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalAdvisor:         {Tier: verdict.TierObservedIdle, Family: "derived", Confidence: "heuristic", API: "Advisor", ARGBacked: true},
	SignalRoleAssignments: {Tier: verdict.TierInfo, Family: "structural", Confidence: "unknown", API: "ARM"},
	SignalPolicyState:     {Tier: verdict.TierInfo, Family: "structural", Confidence: "unknown", API: "ARM"},
}

// Signals is the catalogue order. Every run emits exactly these IDs, so a
// missing observation is visible as unknown or not_evaluated, never as nothing.
var Signals = []string{
	SignalARMGet, SignalARGVisible, SignalLock, SignalDenyAssignment, SignalRGManagedBy,
	SignalTagProtect, SignalTagExpired, SignalTagIntent, SignalHiddenLink, SignalHiddenLinkDead,
	SignalTagOwner, SignalDeployment, SignalRecentWrite, SignalWrites, SignalPEConnections,
	SignalDNSRecords, SignalAdvisor, SignalRoleAssignments, SignalPolicyState,
}

func present(id string, details map[string]any) verdict.Evidence {
	return Catalogue.Present(id, details)
}

func absent(id string) verdict.Evidence { return Catalogue.Absent(id) }

func notEvaluated(id string) verdict.Evidence { return Catalogue.NotEvaluated(id) }

func unknownAs(id string, unknown *verdict.Unknown) verdict.Evidence {
	return Catalogue.Unknown(id, unknown)
}

func windowed(e verdict.Evidence, end time.Time, days int) verdict.Evidence {
	return signal.Windowed(e, end, days)
}
