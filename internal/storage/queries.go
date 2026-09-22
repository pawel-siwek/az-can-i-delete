package storage

import (
	"context"
	"strings"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The Resource Graph queries of SPEC section 5.1, in the reference spelling of
// appendix L section 4. Each takes the target's lowercased id or its name.
const (
	// K5b: a backup instance whose data source is this account.
	backupQuery = "recoveryservicesresources " +
		"| where type =~ 'microsoft.dataprotection/backupvaults/backupinstances' " +
		"| where tolower(tostring(properties.dataSourceInfo.resourceID)) == '%s' | project id"
	// K7b: a flow log writing here.
	flowLogQuery = "resources | where type =~ 'microsoft.network/networkwatchers/flowlogs' " +
		"and tolower(tostring(properties.storageId)) == '%s' | project id"
	// K8: a virtual machine whose boot diagnostics write here.
	bootDiagnosticsQuery = "resources | where type =~ 'microsoft.compute/virtualmachines' " +
		"| where tolower(tostring(properties.diagnosticsProfile.bootDiagnostics.storageUri)) startswith 'https://%s.' " +
		"| project id"
	// K9: a virtual machine extension configured against this account.
	extensionQuery = "resources | where type =~ 'microsoft.compute/virtualmachines/extensions' " +
		"| where properties.settings has '%s' or properties has '%s.blob.core.windows.net' " +
		"| project id, publisher = tostring(properties.publisher)"
	// K6: anything else in the subscription whose configuration names this
	// account, by endpoint or by resource id.
	genericQuery = "resources | where subscriptionId == '%s' and id !startswith '%s/' and id !~ '%s' " +
		"| where properties has '%s.blob.core.windows.net' or properties has '%s.file.core.windows.net' " +
		"or properties has '%s.queue.core.windows.net' or properties has '%s.table.core.windows.net' " +
		"or properties has '%s.dfs.core.windows.net' or properties has '%s' " +
		"| project id, type, flexDeployment = tostring(properties.functionAppConfig.deployment.storage.value)"
)

// listGroup reads the four child listings. Their completeness is one of the
// Required signals: silence means nothing about an account whose contents
// could not be listed.
type listGroup struct{}

type childList struct {
	name     string
	path     string
	items    []collect.Resource
	complete bool
}

func (listGroup) run(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		version, err := rules.APIVersion(ResourceType)
		if err != nil {
			return nil, err
		}
		lists := []childList{
			{name: "containers", path: "/blobServices/default/containers"},
			{name: "shares", path: "/fileServices/default/shares"},
			{name: "queues", path: "/queueServices/default/queues"},
			{name: "tables", path: "/tableServices/default/tables"},
		}
		counts := map[string]any{}
		for i := range lists {
			items, err := in.Clients.ARM.List(ctx, in.Target.ID+lists[i].path, version)
			switch {
			case err == nil:
				lists[i].items, lists[i].complete = items, true
			case strings.Contains(err.Error(), collect.ErrTruncated.Error()):
				lists[i].items = items
			default:
				return nil, err
			}
		}
		complete := true
		for _, list := range lists {
			counts[list.name+"Count"] = len(list.items)
			complete = complete && list.complete
		}
		evidence := []verdict.Evidence{
			leaseHeld(lists), functionsArtefacts(lists), immutability(in, lists),
		}
		if !complete {
			return append(evidence, Catalogue.Unknown(SignalLists, &verdict.Unknown{
				Code: verdict.UnkPartial, Message: "a child listing was longer than the page budget"})), nil
		}
		return append(evidence, Catalogue.Present(SignalLists, counts)), nil
	}
}

// leaseHeld reports a lease, which means a process is holding a container or
// share right now.
func leaseHeld(lists []childList) verdict.Evidence {
	held := 0
	for _, list := range lists {
		for _, item := range list.items {
			if state, _ := item.Properties["leaseState"].(string); strings.EqualFold(state, "Leased") {
				held++
			}
		}
	}
	if held == 0 {
		return Catalogue.Absent(SignalLease)
	}
	return Catalogue.Present(SignalLease, map[string]any{"leaseCount": held})
}

// functionsArtefacts reports the containers a Functions host keeps its state
// in. Under Reader the name is all there is, so this stays design intent: the
// host ids inside are data-plane reads this version does not make.
func functionsArtefacts(lists []childList) verdict.Evidence {
	matched := 0
	for _, list := range lists {
		if list.name != "containers" {
			continue
		}
		for _, item := range list.items {
			name := strings.ToLower(item.Name)
			for _, artefact := range functionsContainers {
				if name == artefact || strings.HasPrefix(name, artefact) {
					matched++
				}
			}
		}
	}
	if matched == 0 {
		return Catalogue.Absent(SignalFunctions)
	}
	return Catalogue.Present(SignalFunctions, map[string]any{"containerCount": matched})
}

// immutability reports a legal hold or a locked immutability policy, at the
// account or on any container. Azure refuses the delete while one exists.
func immutability(in Input, lists []childList) verdict.Evidence {
	locked := 0
	if account, ok := in.Resource.Properties["immutableStorageWithVersioning"].(map[string]any); ok {
		if policy, ok := account["immutabilityPolicy"].(map[string]any); ok {
			if state, _ := policy["state"].(string); strings.EqualFold(state, "Locked") {
				locked++
			}
		}
	}
	for _, list := range lists {
		if list.name != "containers" {
			continue
		}
		for _, item := range list.items {
			if hold, ok := item.Properties["hasLegalHold"].(bool); ok && hold {
				locked++
			}
			if policy, ok := item.Properties["hasImmutabilityPolicy"].(bool); ok && policy {
				locked++
			}
		}
	}
	if locked == 0 {
		return Catalogue.Absent(SignalImmutability)
	}
	return Catalogue.Present(SignalImmutability, map[string]any{"holdCount": locked})
}

// referenceGroup runs the reverse-reference queries. Every one of them is
// graph-backed, so a blind probe makes all of them unknown at once.
type referenceGroup struct{}

func (referenceGroup) run(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		ids := []string{SignalReverse, SignalNetACL, SignalBootDiag, SignalFlowLogs, SignalBackup, SignalVMExt}
		if !in.Generic.ARGVisible {
			evidence := make([]verdict.Evidence, 0, len(ids))
			for _, id := range ids {
				evidence = append(evidence, Catalogue.Unknown(id, in.Generic.ARGUnknown))
			}
			return evidence, nil
		}
		graph := in.graph()
		id, name := signal.Lower(in.Target.ID), signal.Lower(in.Target.Name)
		evidence := []verdict.Evidence{}
		for _, query := range []struct {
			id   string
			text string
			args []any
		}{
			{SignalBackup, backupQuery, []any{id}},
			{SignalFlowLogs, flowLogQuery, []any{id}},
			{SignalBootDiag, bootDiagnosticsQuery, []any{name}},
			{SignalVMExt, extensionQuery, []any{name, name}},
		} {
			rows, err := graph.Query(ctx, query.text, query.args...)
			if err != nil {
				return nil, err
			}
			evidence = append(evidence, count(query.id, len(rows.Rows)))
		}
		generic, err := graph.Query(ctx, genericQuery,
			in.Target.SubscriptionID, id, id, name, name, name, name, name, id)
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, genericReference(generic))
		acl, err := resourceInstanceRules(ctx, in)
		if err != nil {
			return nil, err
		}
		return append(evidence, acl), nil
	}
}

// genericReference separates a Flex Consumption function app's deployment
// storage, which is a hard dependency, from every other configuration that
// merely names the account, which is design intent.
func genericReference(rows collect.Rows) verdict.Evidence {
	hard, soft := 0, 0
	for _, row := range rows.Rows {
		if deployment, _ := row["flexDeployment"].(string); deployment != "" {
			hard++
			continue
		}
		soft++
	}
	switch {
	case hard > 0:
		return Catalogue.Present(SignalReverse, map[string]any{"referenceCount": hard + soft, "hardReference": true})
	case soft > 0:
		evidence := Catalogue.Present(SignalReverse, map[string]any{"referenceCount": soft, "hardReference": false})
		// A configuration that names the account without a confirmed producer
		// is intent, not a dependency.
		evidence.Tier = verdict.TierDesignIntent
		evidence.Critical = false
		return evidence
	default:
		return Catalogue.Absent(SignalReverse)
	}
}

// resourceInstanceRules reports a network rule that lets another resource in.
// The rule only means something while the resource it names still exists.
func resourceInstanceRules(ctx context.Context, in Input) (verdict.Evidence, error) {
	acls, ok := in.Resource.Properties["networkAcls"].(map[string]any)
	if !ok {
		return Catalogue.Absent(SignalNetACL), nil
	}
	rules, _ := acls["resourceAccessRules"].([]any)
	var ids []string
	for _, rule := range rules {
		body, _ := rule.(map[string]any)
		if id, _ := body["resourceId"].(string); strings.HasPrefix(id, "/subscriptions/") {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return Catalogue.Absent(SignalNetACL), nil
	}
	rows, err := in.graph().Query(ctx, "resources | where id in~ (%s) | project id", signal.QuoteIDs(ids))
	if err != nil {
		return verdict.Evidence{}, err
	}
	if len(rows.Rows) == 0 {
		return Catalogue.Absent(SignalNetACL), nil
	}
	return Catalogue.Present(SignalNetACL, map[string]any{"referenceCount": len(rows.Rows)}), nil
}

func count(id string, rows int) verdict.Evidence {
	if rows == 0 {
		return Catalogue.Absent(id)
	}
	return Catalogue.Present(id, map[string]any{"referenceCount": rows})
}

// policyGroup reads the configuration an account carries: replication
// policies, Event Grid subscriptions, lifecycle and inventory policies and the
// Defender settings the read rules depend on.
type policyGroup struct{}

func (policyGroup) run(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		version, err := rules.APIVersion(ResourceType)
		if err != nil {
			return nil, err
		}
		replication, err := in.Clients.ARM.List(ctx, in.Target.ID+"/objectReplicationPolicies", version)
		if err != nil {
			return nil, err
		}
		subscriptions, err := in.Clients.ARM.List(ctx,
			in.Target.ID+"/providers/Microsoft.EventGrid/eventSubscriptions", rules.MustOperation("eventGrid"))
		if err != nil {
			return nil, err
		}
		evidence := []verdict.Evidence{
			count(SignalORS, len(replication)),
			count(SignalEventGrid, len(subscriptions)),
			optional(ctx, in, SignalLifecycle, in.Target.ID+"/managementPolicies/default", version, "ruleCount"),
			optional(ctx, in, SignalInventory, in.Target.ID+"/inventoryPolicies/default", version, "ruleCount"),
		}
		return evidence, nil
	}
}

// optional reads a policy that most accounts do not have. A 404 is the answer
// "there is none", not a failure.
func optional(ctx context.Context, in Input, id, path, version, countKey string) verdict.Evidence {
	resource, err := in.Clients.ARM.Get(ctx, path, version)
	if collect.NotFound(err) {
		return Catalogue.Absent(id)
	}
	if err != nil {
		return Catalogue.Failed(id, err)
	}
	policy, _ := resource.Properties["policy"].(map[string]any)
	rules, _ := policy["rules"].([]any)
	return Catalogue.Present(id, map[string]any{countKey: len(rules)})
}

// defenderConfiguration reads the Defender for Storage settings. The read
// rules need them, and unknown configuration stays unknown rather than
// defaulting to "the scanner could not have run".
func defenderConfiguration(ctx context.Context, in Input) verdict.Evidence {
	resource, err := in.Clients.ARM.Get(ctx,
		in.Target.ID+"/providers/Microsoft.Security/defenderForStorageSettings/current",
		rules.MustOperation("defenderForStorage"))
	if collect.NotFound(err) {
		return Catalogue.Absent(SignalDefenderConfig)
	}
	if err != nil {
		return Catalogue.Failed(SignalDefenderConfig, err)
	}
	enabled, _ := resource.Properties["isEnabled"].(bool)
	if !enabled {
		return Catalogue.Absent(SignalDefenderConfig)
	}
	scanning, _ := resource.Properties["malwareScanning"].(map[string]any)
	onUpload, _ := scanning["onUpload"].(map[string]any)
	upload, _ := onUpload["isEnabled"].(bool)
	discovery, _ := resource.Properties["sensitiveDataDiscovery"].(map[string]any)
	sdd, _ := discovery["isEnabled"].(bool)
	return Catalogue.Present(SignalDefenderConfig, map[string]any{
		"enabled": true, "onUpload": upload, "sensitiveDataDiscovery": sdd})
}
