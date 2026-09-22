package network

import (
	"context"
	"regexp"
	"strings"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The network security group signal IDs of SPEC section 5.5.
const (
	SignalNSGAssociations = "nsg.associations"
	SignalNSGFlowLog      = "nsg.flowlog.configured"
	SignalNSGFlowLogs     = "nsg.flowlogs"
	SignalNSGPlatform     = "nsg.platform.owned"
	SignalNSGFree         = "nsg.structural.no-associations"
	SignalNSGIdle         = "nsg.unassociated.ge-30d"
)

// NSGCatalogue is SPEC section 5.5 with the approved G4 addition: a scale set
// whose desired network model references this group counts as an association
// even when the set has no instances running.
var NSGCatalogue = signal.Catalogue{
	SignalNSGAssociations: {Tier: verdict.TierBlocker, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalNSGFlowLog:      {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalNSGFlowLogs:     {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalNSGPlatform:     {Tier: verdict.TierHardDependency, Critical: true, Family: "kb", Confidence: "heuristic", API: "ARG", ARGBacked: true},
	SignalNSGFree:         {Tier: verdict.TierObservedIdle, Family: "structural", Confidence: "verified", API: "Rules"},
	SignalNSGIdle:         {Tier: verdict.TierObservedIdle, Family: "activity-log", Confidence: "verified", API: "ActivityLog"},
}

// NSGSignals is the catalogue order.
var NSGSignals = []string{
	SignalNSGAssociations, SignalNSGFlowLog, SignalNSGFlowLogs,
	SignalNSGPlatform, SignalNSGFree, SignalNSGIdle,
}

// vmssModelQuery is the G4 reference source: a scale set whose network profile
// names this group. A set with zero instances still owns the reference.
const vmssModelQuery = "resources | where type =~ 'microsoft.compute/virtualmachinescalesets' " +
	"| where properties has '%s' | project id"

// flowLogQuery is K7: the flow logs whose target is this group.
const flowLogQuery = "resources | where type =~ 'microsoft.network/networkwatchers/flowlogs' " +
	"| where tolower(tostring(properties.targetResourceId)) == '%s' " +
	"| project id, storage = tostring(properties.storageId), enabled = tobool(properties.enabled)"

// aksNSGName is the name Azure Kubernetes Service gives the group it manages.
var aksNSGName = regexp.MustCompile(`(?i)^aks-agentpool-.*-nsg$`)

// platformGroups are the node resource groups a managed platform owns.
var platformGroups = []string{"mc_", "databricks-rg-"}

func collectNSG(ctx context.Context, in Input) []verdict.Evidence {
	var associations, flowLogs associationGroup
	outcomes := collect.Gather(ctx, []collect.Signal{
		{ID: SignalNSGAssociations, Run: associations.runAssociations(in)},
		{ID: SignalNSGFlowLogs, Run: flowLogs.runFlowLogs(in)},
	})
	collected := map[string]verdict.Evidence{
		SignalNSGFlowLog:  flowLogConfigured(in),
		SignalNSGPlatform: platformOwned(in),
	}
	for _, outcome := range outcomes {
		for _, evidence := range outcome.Evidence {
			collected[evidence.ID] = evidence
		}
		if outcome.Unknown != nil {
			collected[outcome.ID] = NSGCatalogue.Unknown(outcome.ID, outcome.Unknown)
		}
	}
	collected[SignalNSGFree] = structural(NSGCatalogue, SignalNSGFree,
		[]verdict.Evidence{collected[SignalNSGAssociations]})
	collected[SignalNSGIdle] = idle(ctx, in, NSGCatalogue, SignalNSGIdle, "")
	return order(NSGCatalogue, NSGSignals, collected)
}

type associationGroup struct{}

// runAssociations counts the interfaces and subnets the group is applied to,
// plus the scale set models that reference it. Removing an association is
// itself the destructive change, so any association blocks.
func (associationGroup) runAssociations(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		attached := len(list(in.Resource.Properties, "networkInterfaces")) +
			len(list(in.Resource.Properties, "subnets"))
		models := 0
		if !in.Generic.ARGVisible {
			// One applicable reference source could not be read, so "no
			// associations" cannot be established at all.
			return []verdict.Evidence{NSGCatalogue.Unknown(SignalNSGAssociations, in.Generic.ARGUnknown)}, nil
		}
		rows, err := in.graph().Query(ctx, vmssModelQuery, signal.Lower(in.Target.ID))
		if err != nil {
			return nil, err
		}
		models = len(rows.Rows)
		if attached+models == 0 {
			return []verdict.Evidence{NSGCatalogue.Absent(SignalNSGAssociations)}, nil
		}
		return []verdict.Evidence{NSGCatalogue.Present(SignalNSGAssociations, map[string]any{
			"attachmentCount": attached, "scaleSetModelCount": models})}, nil
	}
}

// runFlowLogs reports an enabled flow log writing to a storage account that
// still exists. A log whose sink is gone is configuration, not a dependency.
func (associationGroup) runFlowLogs(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		if !in.Generic.ARGVisible {
			return []verdict.Evidence{NSGCatalogue.Unknown(SignalNSGFlowLogs, in.Generic.ARGUnknown)}, nil
		}
		rows, err := in.graph().Query(ctx, flowLogQuery, signal.Lower(in.Target.ID))
		if err != nil {
			return nil, err
		}
		var sinks []string
		for _, row := range rows.Rows {
			enabled, _ := row["enabled"].(bool)
			storage, _ := row["storage"].(string)
			if enabled && storage != "" {
				sinks = append(sinks, storage)
			}
		}
		if len(sinks) == 0 {
			return []verdict.Evidence{NSGCatalogue.Absent(SignalNSGFlowLogs)}, nil
		}
		existing, err := sinksExist(ctx, in, sinks)
		if err != nil {
			return nil, err
		}
		if existing == 0 {
			return []verdict.Evidence{NSGCatalogue.Absent(SignalNSGFlowLogs)}, nil
		}
		return []verdict.Evidence{NSGCatalogue.Present(SignalNSGFlowLogs,
			map[string]any{"flowLogCount": existing})}, nil
	}
}

// sinksExist resolves the storage accounts a flow log writes to.
func sinksExist(ctx context.Context, in Input, ids []string) (int, error) {
	rows, err := in.graph().Query(ctx, "resources | where id in~ (%s) | project id", signal.QuoteIDs(ids))
	if err != nil {
		return 0, err
	}
	return len(rows.Rows), nil
}

// flowLogConfigured reports the flow logs the group's own body lists, whatever
// state their sink is in.
func flowLogConfigured(in Input) verdict.Evidence {
	logs := list(in.Resource.Properties, "flowLogs")
	if len(logs) == 0 {
		return NSGCatalogue.Absent(SignalNSGFlowLog)
	}
	return NSGCatalogue.Present(SignalNSGFlowLog, map[string]any{"flowLogCount": len(logs)})
}

// platformOwned reports a group a managed platform created and maintains.
// Deleting it breaks the platform rather than a workload of the caller's.
func platformOwned(in Input) verdict.Evidence {
	named := aksNSGName.MatchString(in.Target.Name)
	group := strings.ToLower(in.Target.ResourceGroup)
	managed := false
	for _, prefix := range platformGroups {
		if strings.HasPrefix(group, prefix) && in.Generic.ManagedBy != "" {
			managed = true
		}
	}
	if !named && !managed {
		if !in.Generic.ARGVisible {
			// Ownership of the resource group is one of the two sources, and
			// it could not be read.
			return NSGCatalogue.Unknown(SignalNSGPlatform, in.Generic.ARGUnknown)
		}
		return NSGCatalogue.Absent(SignalNSGPlatform)
	}
	return NSGCatalogue.Present(SignalNSGPlatform, map[string]any{
		"matchedName": named, "managedGroup": managed})
}
