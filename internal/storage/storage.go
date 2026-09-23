// Package storage is the analyzer for Microsoft.Storage/storageAccounts. A
// storage account is the hardest resource to be sure about: nothing has to
// reference it in the control plane for something to depend on it, so the
// analyzer combines what the account's own body says, what the Resource Graph
// says references it, what its four child listings contain, and what its
// transaction, egress and object-count metrics show over the window.
package storage

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/generic"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// ResourceType is the type this analyzer answers for.
const ResourceType = "Microsoft.Storage/storageAccounts"

// The storage signal IDs of SPEC section 5.1.
const (
	SignalImmutability    = "storage.immutability.locked"
	SignalCloudShell      = "storage.cloudshell.account"
	SignalPE              = "storage.pe.approved"
	SignalNetACL          = "storage.netacl.resource-instances"
	SignalORS             = "storage.ors.policy"
	SignalEventGrid       = "storage.eventgrid.subscriptions"
	SignalBootDiag        = "storage.bootdiag.vms"
	SignalFlowLogs        = "storage.flowlogs"
	SignalBackup          = "storage.backup.items"
	SignalBackupLock      = "storage.backup.files-lock"
	SignalReverse         = "storage.reverse.generic-has"
	SignalVMExt           = "storage.vmext.diagnostics"
	SignalFunctions       = "storage.functions.host-artefacts"
	SignalKB              = "storage.kb.match"
	SignalLists           = "storage.lists.complete"
	SignalLease           = "storage.lease.held"
	SignalAnonymous       = "storage.metrics.anonymous-success"
	SignalWrites          = "storage.metrics.user-writes"
	SignalReads           = "storage.metrics.user-reads"
	SignalQueue           = "storage.metrics.queue-polling"
	SignalQueueLow        = "storage.metrics.queue-polling-low"
	SignalCountDelta      = "storage.metrics.count-delta"
	SignalLowReads        = "storage.metrics.low-volume-reads"
	SignalDefenderShaped  = "storage.metrics.defender-shaped"
	SignalSMB             = "storage.smb.mounted"
	SignalSilence         = "storage.metrics.user-transactions-silence"
	SignalCountSilence    = "storage.metrics.count-delta-silence"
	SignalSystem          = "storage.metrics.system-transactions"
	SignalALSilence       = "storage.activitylog.control-plane-silence"
	SignalListKeys        = "storage.activitylog.listkeys"
	SignalSKUGeo          = "storage.sku.geo"
	SignalLifecycle       = "storage.policy.lifecycle"
	SignalInventory       = "storage.policy.inventory"
	SignalDefenderConfig  = "storage.policy.defender"
	SignalInventoryShaped = "storage.metrics.writes-inventory-shaped"
	SignalDataPlane       = "storage.data-plane.freshness"
	SignalSharesUsage     = "storage.shares.usage"
)

// The amended thresholds of SPEC section 3.2.
const (
	WriteFloor        = 10
	WriteFloorDays    = 2
	WriteSingleDay    = 1000
	ReadDays          = 3
	ReadFloor         = 1000
	ReadEgressMiB     = 50
	PollingLivePerDay = 1000
	PollingLiveDays   = 3
	CountDeltaDays    = 2
	BackupLockName    = "azurebackupprotectionlock"
)

// cloudShellName is the account Azure Cloud Shell keeps a user's home in.
var cloudShellName = regexp.MustCompile(`^cs[0-9a-f]{16,22}$`)

// functionsContainers are the containers a Functions host keeps its own state
// in. Under Reader the container name is all there is, so it stays intent.
var functionsContainers = []string{"azure-webjobs-hosts", "azure-webjobs-secrets", "scm-releases", "app-package-"}

// Catalogue is SPEC section 5.1.
var Catalogue = signal.Catalogue{
	SignalImmutability:    {Tier: verdict.TierBlocker, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalCloudShell:      {Tier: verdict.TierHardDependency, Family: "kb", Confidence: "heuristic", API: "ARM"},
	SignalPE:              {Tier: verdict.TierHardDependency, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalNetACL:          {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalORS:             {Tier: verdict.TierHardDependency, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalEventGrid:       {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARM"},
	SignalBootDiag:        {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalFlowLogs:        {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalBackup:          {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalBackupLock:      {Tier: verdict.TierHardDependency, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalReverse:         {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalVMExt:           {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalFunctions:       {Tier: verdict.TierDesignIntent, Family: "kb", Confidence: "heuristic", API: "ARM"},
	SignalKB:              {Tier: verdict.TierDesignIntent, Family: "kb", Confidence: "unknown", API: "ARM"},
	SignalLists:           {Tier: verdict.TierObservedIdle, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalLease:           {Tier: verdict.TierLiveActivity, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalAnonymous:       {Tier: verdict.TierLiveActivity, Critical: true, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalWrites:          {Tier: verdict.TierLiveActivity, Critical: true, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalReads:           {Tier: verdict.TierLiveActivity, Critical: true, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalQueue:           {Tier: verdict.TierLiveActivity, Critical: true, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalQueueLow:        {Tier: verdict.TierDesignIntent, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalCountDelta:      {Tier: verdict.TierLiveActivity, Critical: true, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalLowReads:        {Tier: verdict.TierDesignIntent, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalDefenderShaped:  {Tier: verdict.TierDesignIntent, Family: "metrics", Confidence: "heuristic", API: "Metrics"},
	SignalSMB:             {Tier: verdict.TierDesignIntent, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalSilence:         {Tier: verdict.TierObservedIdle, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalCountSilence:    {Tier: verdict.TierObservedIdle, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalSystem:          {Tier: verdict.TierInfo, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalALSilence:       {Tier: verdict.TierObservedIdle, Family: "activity-log", Confidence: "verified", API: "ActivityLog"},
	SignalListKeys:        {Tier: verdict.TierDesignIntent, Family: "activity-log", Confidence: "verified", API: "ActivityLog"},
	SignalSKUGeo:          {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalLifecycle:       {Tier: verdict.TierInfo, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalInventory:       {Tier: verdict.TierInfo, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalDefenderConfig:  {Tier: verdict.TierInfo, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalInventoryShaped: {Tier: verdict.TierInfo, Family: "metrics", Confidence: "unknown", API: "Metrics"},
	SignalDataPlane:       {Tier: verdict.TierInfo, Family: "data-plane", Confidence: "unknown", API: "DataPlane"},
	SignalSharesUsage:     {Tier: verdict.TierInfo, Family: "structural", Confidence: "unknown", API: "ARM"},
}

// The knowledge base contributes one catalogue row per entry, so a name match
// carries the tier that entry allows a name alone to claim.
func init() {
	for id, spec := range kbCatalogue() {
		Catalogue[id] = spec
	}
}

// Signals is the catalogue order: what holds the account, what references it,
// what it contains, what it did, and what it is configured for.
var Signals = []string{
	SignalImmutability, SignalCloudShell, SignalPE, SignalNetACL, SignalORS, SignalEventGrid,
	SignalBootDiag, SignalFlowLogs, SignalBackup, SignalBackupLock, SignalReverse, SignalVMExt,
	SignalFunctions, SignalKB, SignalLease, SignalAnonymous, SignalWrites, SignalReads,
	SignalQueue, SignalQueueLow, SignalCountDelta, SignalLowReads, SignalDefenderShaped, SignalSMB,
	SignalLists, SignalSilence, SignalCountSilence, SignalALSilence, SignalListKeys,
	SignalSystem, SignalSKUGeo, SignalLifecycle, SignalInventory, SignalDefenderConfig,
	SignalInventoryShaped, SignalDataPlane, SignalSharesUsage,
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

// effective is the window the silence signals are evaluated over: the
// requested window bounded by how long the account has demonstrably existed.
func (in Input) effective() verdict.Window {
	return verdict.EffectiveWindow(in.Requested, in.Generic.Age)
}

// Collect runs the storage analyzer and returns its evidence in catalogue
// order. Structural facts come from the account body, references from the
// Resource Graph and the child listings, and activity from the metrics.
func Collect(ctx context.Context, in Input) []verdict.Evidence {
	var children listGroup
	var references referenceGroup
	var configuration policyGroup
	var measured metricGroup
	outcomes := collect.Gather(ctx, []collect.Signal{
		{ID: SignalLists, Run: children.run(in)},
		{ID: SignalReverse, Run: references.run(in)},
		{ID: SignalLifecycle, Run: configuration.run(in)},
		{ID: SignalSilence, Run: measured.run(in)},
	})

	collected := map[string]verdict.Evidence{
		SignalPE:              privateEndpoints(in.Resource),
		SignalCloudShell:      cloudShell(in),
		SignalSKUGeo:          geoRedundant(in.Resource),
		SignalBackupLock:      backupLock(in),
		SignalDataPlane:       Catalogue.NotEvaluated(SignalDataPlane),
		SignalSharesUsage:     Catalogue.NotEvaluated(SignalSharesUsage),
		SignalInventoryShaped: Catalogue.NotEvaluated(SignalInventoryShaped),
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
	evidence := make([]verdict.Evidence, 0, len(Signals))
	for _, id := range Signals {
		found, ok := collected[id]
		if !ok {
			found = Catalogue.Unknown(id, &verdict.Unknown{
				Code: verdict.UnkTransient, Message: "the signal produced no observation"})
		}
		evidence = append(evidence, found)
	}
	// A knowledge base match is one signal per matching entry, so the number of
	// them depends on what the account contains rather than on the catalogue.
	// They follow the fixed catalogue, in a stable order of their own.
	matched := make([]string, 0, len(collected))
	for id := range collected {
		if strings.HasPrefix(id, SignalKB+".") {
			matched = append(matched, id)
		}
	}
	sort.Strings(matched)
	for _, id := range matched {
		evidence = append(evidence, collected[id])
	}
	return evidence
}

// groupSignals maps a failed collection group onto every signal it would have
// produced, so one failed call cannot silence the rest of the group.
func groupSignals(groupID string) []string {
	switch groupID {
	case SignalLists:
		return []string{SignalLists, SignalLease, SignalFunctions, SignalImmutability, SignalKB}
	case SignalReverse:
		return []string{SignalReverse, SignalNetACL, SignalBootDiag, SignalFlowLogs, SignalBackup, SignalVMExt}
	case SignalLifecycle:
		return []string{SignalLifecycle, SignalInventory, SignalORS, SignalEventGrid}
	case SignalSilence:
		return []string{SignalSilence, SignalCountSilence, SignalAnonymous, SignalWrites, SignalReads,
			SignalQueue, SignalQueueLow, SignalCountDelta, SignalLowReads, SignalDefenderShaped,
			SignalSMB, SignalSystem, SignalDefenderConfig}
	default:
		return []string{groupID}
	}
}

// privateEndpoints reports approved private endpoint connections. A body that
// does not carry the collection is not evaluated rather than reported empty.
func privateEndpoints(resource collect.Resource) verdict.Evidence {
	raw, ok := resource.Properties["privateEndpointConnections"]
	if !ok {
		return Catalogue.NotEvaluated(SignalPE)
	}
	connections, ok := raw.([]any)
	if !ok {
		return Catalogue.Unknown(SignalPE, &verdict.Unknown{
			Code: verdict.UnkUnsupported, Message: "the private endpoint collection had an unexpected shape"})
	}
	approved := 0
	for _, connection := range connections {
		body, _ := connection.(map[string]any)
		properties, _ := body["properties"].(map[string]any)
		state, _ := properties["privateLinkServiceConnectionState"].(map[string]any)
		if status, _ := state["status"].(string); strings.EqualFold(status, "Approved") {
			approved++
		}
	}
	if approved == 0 {
		return Catalogue.Absent(SignalPE)
	}
	return Catalogue.Present(SignalPE, map[string]any{"privateEndpointCount": approved})
}

// cloudShell reports the account Cloud Shell keeps a user's home directory in.
// Deleting it loses that user's files, and only its name and tags say so.
func cloudShell(in Input) verdict.Evidence {
	if tag, ok := in.Resource.Tags["ms-resource-usage"]; ok && strings.EqualFold(tag, "azure-cloud-shell") {
		return Catalogue.Present(SignalCloudShell, map[string]any{"matchedName": false})
	}
	if cloudShellName.MatchString(strings.ToLower(in.Target.Name)) &&
		strings.HasPrefix(strings.ToLower(in.Target.ResourceGroup), "cloud-shell-storage-") {
		return Catalogue.Present(SignalCloudShell, map[string]any{"matchedName": true})
	}
	return Catalogue.Absent(SignalCloudShell)
}

// geoRedundant reports a replicated SKU, which is a deliberate durability
// choice somebody made and may still be relying on.
func geoRedundant(resource collect.Resource) verdict.Evidence {
	sku, _ := resource.Properties["skuName"].(string)
	if sku == "" {
		if body, ok := resource.Properties["sku"].(map[string]any); ok {
			sku, _ = body["name"].(string)
		}
	}
	// Longest first: Standard_RAGRS ends with GRS too, and the report should
	// name the replication the account actually has.
	for _, suffix := range []string{"RAGZRS", "RAGRS", "GZRS", "GRS"} {
		if strings.HasSuffix(strings.ToUpper(sku), suffix) {
			return Catalogue.Present(SignalSKUGeo, map[string]any{"replication": strings.ToUpper(suffix)})
		}
	}
	return Catalogue.Absent(SignalSKUGeo)
}

// backupLock reports the lock Azure Backup puts on an account whose file
// shares it protects. The generic layer already read the locks.
func backupLock(in Input) verdict.Evidence {
	if !in.Generic.LocksRead {
		return Catalogue.Unknown(SignalBackupLock, &verdict.Unknown{
			Code: verdict.UnkDependency, Message: "management locks could not be read"})
	}
	for _, lock := range in.Generic.Locks {
		if strings.EqualFold(strings.ToLower(lock.Name), BackupLockName) {
			return Catalogue.Present(SignalBackupLock, map[string]any{"lockCount": 1})
		}
	}
	return Catalogue.Absent(SignalBackupLock)
}

// activityLogSignals derives the control-plane signals from the log the
// generic layer already read: key operations are design intent, and silence
// over the effective window is one of the Required signals.
func activityLogSignals(in Input) map[string]verdict.Evidence {
	if !in.Generic.ActivityLogRead {
		unknown := &verdict.Unknown{Code: verdict.UnkDependency, Message: "the Activity Log could not be read"}
		return map[string]verdict.Evidence{
			SignalALSilence: Catalogue.Unknown(SignalALSilence, unknown),
			SignalListKeys:  Catalogue.Unknown(SignalListKeys, unknown),
		}
	}
	effective := in.effective()
	keys, newestKeys := 0, time.Time{}
	controlPlane := false
	for _, event := range in.Generic.ActivityLog.Events {
		if !strings.EqualFold(event.Status, "Succeeded") ||
			strings.Contains(strings.ToLower(event.Caller), "azcid") {
			continue
		}
		operation := strings.ToLower(event.Operation)
		isKeyOperation := strings.Contains(operation, "listkeys") || strings.Contains(operation, "regeneratekey")
		if isKeyOperation && !event.Timestamp.Before(in.Requested.Start) {
			keys++
			if event.Timestamp.After(newestKeys) {
				newestKeys = event.Timestamp
			}
		}
		if event.Timestamp.Before(effective.Start) {
			continue
		}
		if strings.HasSuffix(operation, "/write") || strings.HasSuffix(operation, "/delete") || isKeyOperation {
			controlPlane = true
		}
	}
	out := map[string]verdict.Evidence{}
	switch {
	case controlPlane:
		out[SignalALSilence] = signal.Windowed(Catalogue.Absent(SignalALSilence), in.Cutoff, effective.Days)
	case effective.Days == 0 || in.Generic.ActivityLog.Truncated || in.Generic.ActivityLog.Days < effective.Days:
		out[SignalALSilence] = Catalogue.Unknown(SignalALSilence, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the Activity Log did not cover the effective window"})
	default:
		out[SignalALSilence] = signal.Windowed(
			Catalogue.Present(SignalALSilence, map[string]any{"quietDays": effective.Days}), in.Cutoff, effective.Days)
	}
	if keys == 0 {
		out[SignalListKeys] = signal.Windowed(Catalogue.Absent(SignalListKeys), in.Cutoff, in.Requested.Days)
		return out
	}
	out[SignalListKeys] = signal.Windowed(Catalogue.Present(SignalListKeys, map[string]any{
		"keyOperationCount": keys, "daysAgo": int(in.Cutoff.Sub(newestKeys) / (24 * time.Hour))}),
		in.Cutoff, in.Requested.Days)
	return out
}
