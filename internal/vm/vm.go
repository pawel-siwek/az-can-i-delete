// Package vm is the analyzer for Microsoft.Compute/virtualMachines. A machine
// that nobody logs into still has a network address other things point at, a
// backup that keeps running, and a scale set or platform that owns it, so the
// analyzer asks all three questions before it asks whether the machine is
// busy. A deallocated machine is not a retired one: its disks, its address and
// its backups outlive the power state.
package vm

import (
	"context"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/generic"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// ResourceType is the type this analyzer answers for.
const ResourceType = "Microsoft.Compute/virtualMachines"

// The virtual machine signal IDs of SPEC section 5.2.
const (
	SignalScaleSet       = "vm.membership.vmss-flex"
	SignalAvailability   = "vm.membership.availabilityset"
	SignalReservation    = "vm.membership.capacity-reservation"
	SignalDedicatedHost  = "vm.membership.dedicated-host"
	SignalPlatform       = "vm.platform.owned"
	SignalBackup         = "vm.backup.protected"
	SignalBackupRetained = "vm.backup.retained"
	SignalASR            = "vm.asr.replicated"
	SignalImage          = "vm.image.source"
	SignalNetworkRefs    = "vm.network.dns-or-nexthop"
	SignalPools          = "vm.network.lb-or-agw"
	SignalAGW            = "vm.network.agw-ip-pool"
	SignalDNS            = "vm.network.dns-records"
	SignalFirewall       = "vm.network.firewall-rules"
	SignalUpdateManager  = "vm.updatemanager.assigned"
	SignalIdentityRoles  = "vm.identity.roles"
	SignalIdentityUser   = "vm.identity.user-assigned"
	SignalPower          = "vm.power.state"
	SignalStartEvents    = "vm.activitylog.start-events"
	SignalNoStartEvents  = "vm.activitylog.no-start-events"
	SignalMetrics        = "vm.metrics.activity"
	SignalMetricSilence  = "vm.metrics.silence"
	SignalDeallocated    = "vm.power.deallocated-silence"
	SignalIdle           = "vm.silence.any"
	SignalKept           = "vm.deallocated.with-reservation"
	SignalOnPremDNS      = "vm.consumers.onprem-dns"
)

// The activity thresholds of SPEC section 5.2. A machine has to clear all
// three to count as busy: idle Windows machines still burn a little CPU.
const (
	CPUPercentile   = 3.0
	FlowsPercentile = 5.0
	DailyBytesMiB   = 20.0
	DeallocatedDays = 30
	// AvailabilityCoverage is how much of the effective window the platform's
	// own availability metric must cover before silence means anything.
	AvailabilityCoverage = 0.8
)

// platformTags mark a machine a managed platform created and owns.
var platformTags = []string{"aks-managed", "hidden-devtestlabs-labuid"}

// Catalogue is SPEC section 5.2.
var Catalogue = signal.Catalogue{
	SignalScaleSet:       {Tier: verdict.TierHardDependency, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalAvailability:   {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalReservation:    {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalDedicatedHost:  {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalPlatform:       {Tier: verdict.TierHardDependency, Critical: true, Family: "kb", Confidence: "heuristic", API: "ARG", ARGBacked: true},
	SignalBackup:         {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalBackupRetained: {Tier: verdict.TierDesignIntent, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalASR:            {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalImage:          {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalNetworkRefs:    {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalPools:          {Tier: verdict.TierHardDependency, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalAGW:            {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "unknown", API: "ARG", ARGBacked: true},
	SignalDNS:            {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "unknown", API: "ARG", ARGBacked: true},
	SignalFirewall:       {Tier: verdict.TierDesignIntent, Family: "reverse-ref", Confidence: "unknown", API: "ARG"},
	SignalUpdateManager:  {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "unknown", API: "ARM"},
	SignalIdentityRoles:  {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalIdentityUser:   {Tier: verdict.TierInfo, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalPower:          {Tier: verdict.TierInfo, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalStartEvents:    {Tier: verdict.TierLiveActivity, Critical: true, Family: "activity-log", Confidence: "verified", API: "ActivityLog"},
	SignalNoStartEvents:  {Tier: verdict.TierObservedIdle, Family: "activity-log", Confidence: "verified", API: "ActivityLog"},
	SignalMetrics:        {Tier: verdict.TierLiveActivity, Critical: true, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalMetricSilence:  {Tier: verdict.TierObservedIdle, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalDeallocated:    {Tier: verdict.TierObservedIdle, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalIdle:           {Tier: verdict.TierObservedIdle, Family: "derived", Confidence: "verified", API: "Rules"},
	SignalKept:           {Tier: verdict.TierDesignIntent, Family: "derived", Confidence: "verified", API: "Rules"},
	SignalOnPremDNS:      {Tier: verdict.TierDesignIntent, Family: "reverse-ref", Confidence: "unknown", API: "ARG"},
}

// Signals is the catalogue order.
var Signals = []string{
	SignalScaleSet, SignalPlatform, SignalBackup, SignalASR, SignalImage, SignalNetworkRefs, SignalPools,
	SignalAGW, SignalDNS, SignalAvailability, SignalReservation, SignalDedicatedHost, SignalBackupRetained,
	SignalIdentityRoles, SignalFirewall, SignalUpdateManager, SignalOnPremDNS, SignalKept,
	SignalStartEvents, SignalMetrics, SignalMetricSilence, SignalDeallocated, SignalNoStartEvents,
	SignalIdle, SignalPower, SignalIdentityUser,
}

// Input is what the analyzer needs on top of the generic layer's result.
type Input struct {
	Target    armid.Target
	Resource  collect.Resource
	Requested verdict.Window
	Cutoff    time.Time
	Clients   collect.Clients
	Graph     *collect.Limiter
	Generic   generic.Result
}

func (in Input) graph() signal.Graph {
	return signal.Graph{Client: in.Clients.Graph, Limiter: in.Graph, Subscription: in.Target.SubscriptionID}
}

func (in Input) effective() verdict.Window {
	return verdict.EffectiveWindow(in.Requested, in.Generic.Age)
}

// Collect runs the virtual machine analyzer and returns its evidence in
// catalogue order.
func Collect(ctx context.Context, in Input) []verdict.Evidence {
	var references referenceGroup
	var measured metricGroup
	var network networkGroup
	outcomes := collect.Gather(ctx, []collect.Signal{
		{ID: SignalBackup, Run: references.run(in)},
		{ID: SignalMetrics, Run: measured.run(in)},
		{ID: SignalPools, Run: network.run(in)},
	})

	properties := in.Resource.Properties
	collected := map[string]verdict.Evidence{
		SignalScaleSet:      owner(SignalScaleSet, reference(properties, "virtualMachineScaleSet", "id")),
		SignalAvailability:  owner(SignalAvailability, reference(properties, "availabilitySet", "id")),
		SignalReservation:   owner(SignalReservation, capacityReservation(properties)),
		SignalDedicatedHost: owner(SignalDedicatedHost, host(properties)),
		SignalIdentityUser:  userAssigned(in.Resource),
		SignalAGW:           Catalogue.NotEvaluated(SignalAGW),
		SignalDNS:           Catalogue.NotEvaluated(SignalDNS),
		SignalFirewall:      Catalogue.NotEvaluated(SignalFirewall),
		SignalUpdateManager: Catalogue.NotEvaluated(SignalUpdateManager),
		SignalOnPremDNS:     Catalogue.NotEvaluated(SignalOnPremDNS),
	}
	for id, evidence := range activityLogSignals(in) {
		collected[id] = evidence
	}
	for _, outcome := range outcomes {
		for _, evidence := range outcome.Evidence {
			collected[evidence.ID] = evidence
		}
		if outcome.Unknown != nil {
			for _, id := range groupSignals(outcome.ID) {
				collected[id] = Catalogue.Unknown(id, outcome.Unknown)
			}
		}
	}
	power := powerState(ctx, in)
	collected[SignalPower] = power.evidence
	collected[SignalDeallocated] = deallocatedSilence(in, power)
	collected[SignalIdle] = idle(collected)
	collected[SignalKept] = keptForAReason(collected, power)

	evidence := make([]verdict.Evidence, 0, len(Signals))
	for _, id := range Signals {
		found, ok := collected[id]
		if !ok {
			found = Catalogue.Unknown(id, &verdict.Unknown{
				Code: verdict.UnkTransient, Message: "the signal produced no observation"})
		}
		evidence = append(evidence, found)
	}
	return evidence
}

func groupSignals(groupID string) []string {
	switch groupID {
	case SignalBackup:
		return []string{SignalBackup, SignalBackupRetained, SignalASR, SignalImage,
			SignalPlatform, SignalIdentityRoles}
	case SignalMetrics:
		return []string{SignalMetrics, SignalMetricSilence}
	case SignalPools:
		return []string{SignalPools, SignalNetworkRefs}
	default:
		return []string{groupID}
	}
}

func owner(id, target string) verdict.Evidence {
	if target == "" {
		return Catalogue.Absent(id)
	}
	return Catalogue.Present(id, map[string]any{"owner": target})
}

func reference(properties map[string]any, path ...string) string {
	current := properties
	for i, key := range path {
		if i == len(path)-1 {
			value, _ := current[key].(string)
			return value
		}
		next, ok := current[key].(map[string]any)
		if !ok {
			return ""
		}
		current = next
	}
	return ""
}

func capacityReservation(properties map[string]any) string {
	return reference(properties, "capacityReservation", "capacityReservationGroup", "id")
}

func host(properties map[string]any) string {
	if id := reference(properties, "host", "id"); id != "" {
		return id
	}
	return reference(properties, "hostGroup", "id")
}

// userAssigned reports identities that outlive the machine, which is why the
// report names them rather than leaving them to be cleaned up later.
func userAssigned(resource collect.Resource) verdict.Evidence {
	identity, _ := resource.Properties["identity"].(map[string]any)
	assigned, _ := identity["userAssignedIdentities"].(map[string]any)
	if len(assigned) == 0 {
		return Catalogue.Absent(SignalIdentityUser)
	}
	return Catalogue.Present(SignalIdentityUser, map[string]any{"identityCount": len(assigned)})
}

// power is the machine's reported power state and whether it could be read.
type power struct {
	state       string
	deallocated bool
	read        bool
	evidence    verdict.Evidence
}

// powerState reads the instance view. A machine whose power state cannot be
// read is not assumed to be running or stopped; the signal says so.
func powerState(ctx context.Context, in Input) power {
	version, err := apiVersion()
	if err != nil {
		return power{evidence: Catalogue.Failed(SignalPower, err)}
	}
	view, err := in.Clients.ARM.Get(ctx, in.Target.ID+"/instanceView", version)
	if err != nil {
		return power{evidence: Catalogue.Failed(SignalPower, err)}
	}
	statuses, _ := view.Properties["statuses"].([]any)
	state := ""
	for _, status := range statuses {
		body, _ := status.(map[string]any)
		code, _ := body["code"].(string)
		if value, ok := strings.CutPrefix(strings.ToLower(code), "powerstate/"); ok {
			state = value
		}
	}
	if state == "" {
		return power{read: true, evidence: Catalogue.Absent(SignalPower)}
	}
	return power{
		state: state, deallocated: state == "deallocated", read: true,
		evidence: Catalogue.Present(SignalPower, map[string]any{"powerState": canonicalPower(state)}),
	}
}

func canonicalPower(state string) string {
	for _, known := range []string{"running", "deallocated", "stopped", "starting", "deallocating", "stopping", "unknown"} {
		if state == known {
			return known
		}
	}
	return "unknown"
}

// deallocatedSilence reports a machine that has been switched off long enough
// to be a candidate. Deallocation alone proves nothing: it has to have lasted,
// and nobody may have started the machine since.
func deallocatedSilence(in Input, state power) verdict.Evidence {
	if !state.read {
		return Catalogue.Unknown(SignalDeallocated, &verdict.Unknown{
			Code: verdict.UnkDependency, Message: "the power state could not be read"})
	}
	if !state.deallocated {
		return Catalogue.Absent(SignalDeallocated)
	}
	if !in.Generic.ActivityLogRead {
		return Catalogue.Unknown(SignalDeallocated, &verdict.Unknown{
			Code: verdict.UnkDependency, Message: "the Activity Log could not be read"})
	}
	lastDeallocate, lastStart := time.Time{}, time.Time{}
	for _, event := range in.Generic.ActivityLog.Events {
		if !strings.EqualFold(event.Status, "Succeeded") {
			continue
		}
		operation := strings.ToLower(event.Operation)
		switch {
		case strings.HasSuffix(operation, "/deallocate/action") && event.Timestamp.After(lastDeallocate):
			lastDeallocate = event.Timestamp
		case strings.HasSuffix(operation, "/start/action") && event.Timestamp.After(lastStart):
			lastStart = event.Timestamp
		}
	}
	cutoff := in.Cutoff.AddDate(0, 0, -DeallocatedDays)
	longEnough := (!lastDeallocate.IsZero() && lastDeallocate.Before(cutoff) && lastStart.Before(lastDeallocate)) ||
		(lastDeallocate.IsZero() && lastStart.IsZero() && in.Generic.Age.LowerBoundDays >= DeallocatedDays &&
			in.Generic.Age.Confidence != "unknown")
	if !longEnough {
		return signal.Windowed(Catalogue.Absent(SignalDeallocated), in.Cutoff, DeallocatedDays)
	}
	days := DeallocatedDays
	if !lastDeallocate.IsZero() {
		days = int(in.Cutoff.Sub(lastDeallocate) / (24 * time.Hour))
	}
	return signal.Windowed(Catalogue.Present(SignalDeallocated,
		map[string]any{"quietDays": days}), in.Cutoff, DeallocatedDays)
}

// idle is the Required derived signal: a machine is idle when its metrics are
// silent or it has been switched off for long enough. An unknown on both
// sources is an unknown here too, never a quiet machine.
func idle(collected map[string]verdict.Evidence) verdict.Evidence {
	metrics, deallocated := collected[SignalMetricSilence], collected[SignalDeallocated]
	switch {
	case metrics.Status == verdict.StatusPresent:
		return Catalogue.Present(SignalIdle, map[string]any{"via": "metrics"})
	case deallocated.Status == verdict.StatusPresent:
		return Catalogue.Present(SignalIdle, map[string]any{"via": "deallocated"})
	case metrics.Status == verdict.StatusUnknown && deallocated.Status == verdict.StatusUnknown:
		return Catalogue.Unknown(SignalIdle, metrics.Unknown)
	default:
		return Catalogue.Absent(SignalIdle)
	}
}

// keptForAReason reports a machine that is switched off but deliberately kept:
// something still backs it up, replicates it or holds capacity for it.
func keptForAReason(collected map[string]verdict.Evidence, state power) verdict.Evidence {
	if !state.deallocated {
		return Catalogue.Absent(SignalKept)
	}
	reasons := 0
	for _, id := range []string{SignalBackup, SignalBackupRetained, SignalASR,
		SignalReservation, SignalAvailability} {
		if collected[id].Status == verdict.StatusPresent {
			reasons++
		}
	}
	if reasons == 0 {
		return Catalogue.Absent(SignalKept)
	}
	return Catalogue.Present(SignalKept, map[string]any{"reasonCount": reasons})
}

// activityLogSignals reports the operations that mean somebody is running this
// machine, and the Required silence that says nobody did.
func activityLogSignals(in Input) map[string]verdict.Evidence {
	if !in.Generic.ActivityLogRead {
		unknown := &verdict.Unknown{Code: verdict.UnkDependency, Message: "the Activity Log could not be read"}
		return map[string]verdict.Evidence{
			SignalStartEvents:   Catalogue.Unknown(SignalStartEvents, unknown),
			SignalNoStartEvents: Catalogue.Unknown(SignalNoStartEvents, unknown),
		}
	}
	effective := in.effective()
	newest, inRequested, inEffective := time.Time{}, 0, 0
	for _, event := range in.Generic.ActivityLog.Events {
		if !strings.EqualFold(event.Status, "Succeeded") || !running(event.Operation) ||
			strings.Contains(strings.ToLower(event.Caller), "azcid") {
			continue
		}
		if !event.Timestamp.Before(in.Requested.Start) {
			inRequested++
			if event.Timestamp.After(newest) {
				newest = event.Timestamp
			}
		}
		if !event.Timestamp.Before(effective.Start) {
			inEffective++
		}
	}
	out := map[string]verdict.Evidence{}
	if inRequested == 0 {
		out[SignalStartEvents] = signal.Windowed(Catalogue.Absent(SignalStartEvents), in.Cutoff, in.Requested.Days)
	} else {
		out[SignalStartEvents] = signal.Windowed(Catalogue.Present(SignalStartEvents, map[string]any{
			"eventCount": inRequested, "daysAgo": int(in.Cutoff.Sub(newest) / (24 * time.Hour))}),
			in.Cutoff, in.Requested.Days)
	}
	switch {
	case inEffective > 0:
		out[SignalNoStartEvents] = signal.Windowed(Catalogue.Absent(SignalNoStartEvents), in.Cutoff, effective.Days)
	case effective.Days == 0 || in.Generic.ActivityLog.Truncated || in.Generic.ActivityLog.Days < effective.Days:
		out[SignalNoStartEvents] = Catalogue.Unknown(SignalNoStartEvents, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the Activity Log did not cover the effective window"})
	default:
		out[SignalNoStartEvents] = signal.Windowed(Catalogue.Present(SignalNoStartEvents,
			map[string]any{"quietDays": effective.Days}), in.Cutoff, effective.Days)
	}
	return out
}

// running are the operations that mean somebody used the machine rather than
// merely changed its metadata.
func running(operation string) bool {
	operation = strings.ToLower(operation)
	for _, suffix := range []string{"/start/action", "/restart/action", "/runcommand/action", "/extensions/write"} {
		if strings.HasSuffix(operation, suffix) {
			return true
		}
	}
	return false
}
