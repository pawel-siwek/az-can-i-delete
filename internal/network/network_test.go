package network_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/age"
	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect/collecttest"
	"github.com/pawel-siwek/az-can-i-delete/internal/generic"
	"github.com/pawel-siwek/az-can-i-delete/internal/network"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

const (
	group  = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo"
	nicID  = group + "/providers/Microsoft.Network/networkInterfaces/nic1"
	pipID  = group + "/providers/Microsoft.Network/publicIPAddresses/ip1"
	nsgID  = group + "/providers/Microsoft.Network/networkSecurityGroups/nsg1"
	vmID   = group + "/providers/Microsoft.Compute/virtualMachines/vm1"
	sinkID = group + "/providers/Microsoft.Storage/storageAccounts/logs1"
)

var cutoff = time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)

type harness struct {
	id         string
	properties map[string]any
	graph      *collecttest.Graph
	metrics    *collecttest.Metrics
	log        *collecttest.ActivityLog
	generic    generic.Result
}

func newHarness(id string) *harness {
	return &harness{
		id:         id,
		properties: map[string]any{},
		graph:      &collecttest.Graph{},
		metrics:    &collecttest.Metrics{},
		log:        &collecttest.ActivityLog{},
		generic: generic.Result{
			ARGVisible: true, ActivityLogRead: true, ChangesRead: true,
			ActivityLog: collect.ActivityLog{Days: 90},
		},
	}
}

func (h *harness) run(t *testing.T, signals []string) map[string]verdict.Evidence {
	t.Helper()
	target, err := armid.Parse(h.id)
	if err != nil {
		t.Fatal(err)
	}
	window := verdict.Window{Start: cutoff.AddDate(0, 0, -30), End: cutoff, Days: 30, Grain: "P1D"}
	evidence := network.Collect(context.Background(), network.Input{
		Target:    target,
		Resource:  collect.Resource{ID: h.id, Type: target.ResourceType, Name: target.Name, Properties: h.properties},
		Requested: window,
		Cutoff:    cutoff,
		Clients:   collecttest.Clients(&collecttest.ARM{}, h.graph, h.metrics, h.log, nil),
		Graph:     collect.NewGraphLimiter(collect.SystemClock()),
		Generic:   h.generic,
	})
	var ids []string
	byID := map[string]verdict.Evidence{}
	for _, item := range evidence {
		ids = append(ids, item.ID)
		byID[item.ID] = item
	}
	if !slices.Equal(ids, signals) {
		t.Fatalf("evidence = %v, want the catalogue in order %v", ids, signals)
	}
	return byID
}

func TestSupportedTypes(t *testing.T) {
	for _, supported := range []string{network.NICType, network.PublicIPType, network.NSGType} {
		if !network.Supports(supported) {
			t.Errorf("%s must be analyzed here", supported)
		}
	}
	if network.Supports("Microsoft.Compute/disks") {
		t.Error("the disk analyzer is not in this package")
	}
}

func TestDetachedInterfaceSatisfiesItsRequiredSignals(t *testing.T) {
	evidence := newHarness(nicID).run(t, network.NICSignals)
	for _, id := range []string{network.SignalNICDetached, network.SignalNICIdle} {
		if evidence[id].Status != verdict.StatusPresent || evidence[id].Tier != verdict.TierObservedIdle {
			t.Errorf("Required %s = %+v, want a present OBSERVED_IDLE signal", id, evidence[id])
		}
	}
	for _, id := range []string{network.SignalNICVM, network.SignalNICPE, network.SignalNICPLS,
		network.SignalNICWorkloads, network.SignalNICPool, network.SignalNICStaticIP} {
		if evidence[id].Status != verdict.StatusAbsent {
			t.Errorf("%s = %+v, want absent", id, evidence[id])
		}
	}
	for _, id := range []string{network.SignalNICAGW, network.SignalNICDNS, network.SignalNICFirewall} {
		if evidence[id].Status != verdict.StatusNotEvaluated || evidence[id].Critical {
			t.Errorf("%s = %+v, want a non-critical honest stub", id, evidence[id])
		}
	}
	if required := verdict.RequiredForType(network.NICType); !slices.Contains(required, network.SignalNICDetached) ||
		!slices.Contains(required, network.SignalNICIdle) {
		t.Fatalf("the Required catalogue for an interface is %v", required)
	}
}

func TestAttachedInterfaceBlocks(t *testing.T) {
	for _, tc := range []struct {
		name, signal string
		properties   map[string]any
	}{
		{"virtual machine", network.SignalNICVM, map[string]any{"virtualMachine": map[string]any{"id": vmID}}},
		{"private endpoint", network.SignalNICPE, map[string]any{"privateEndpoint": map[string]any{"id": vmID}}},
		{"private link service", network.SignalNICPLS, map[string]any{"privateLinkService": map[string]any{"id": vmID}}},
		{"hosted workload", network.SignalNICWorkloads, map[string]any{"hostedWorkloads": []any{vmID}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(nicID)
			h.properties = tc.properties
			evidence := h.run(t, network.NICSignals)
			blocker := evidence[tc.signal]
			if blocker.Status != verdict.StatusPresent || blocker.Tier != verdict.TierBlocker || !blocker.Critical {
				t.Fatalf("%s = %+v, want a critical blocker", tc.signal, blocker)
			}
			if evidence[network.SignalNICDetached].Status != verdict.StatusAbsent {
				t.Error("an attached interface is not detached")
			}
		})
	}
}

func TestInterfaceInABackendPoolIsADependency(t *testing.T) {
	h := newHarness(nicID)
	h.properties = map[string]any{"ipConfigurations": []any{map[string]any{"properties": map[string]any{
		"privateIPAllocationMethod":       "Static",
		"loadBalancerBackendAddressPools": []any{map[string]any{"id": "/pool1"}},
		"loadBalancerInboundNatRules":     []any{map[string]any{"id": "/nat1"}},
	}}}}
	evidence := h.run(t, network.NICSignals)
	pool := evidence[network.SignalNICPool]
	if pool.Status != verdict.StatusPresent || pool.Tier != verdict.TierHardDependency || pool.Details["poolCount"] != 2 {
		t.Fatalf("pool = %+v, want both memberships as a hard dependency", pool)
	}
	if e := evidence[network.SignalNICStaticIP]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierDesignIntent {
		t.Fatalf("static ip = %+v, want design intent", e)
	}
	// A pool membership is a dependency, not an attachment: the interface is
	// still structurally detached.
	if evidence[network.SignalNICDetached].Status != verdict.StatusPresent {
		t.Error("a pooled interface with no owner is still detached")
	}
}

func TestInterfaceDetachedByADeletedVirtualMachineIsNotYetIdle(t *testing.T) {
	h := newHarness(nicID)
	// Nothing was written to the interface, but a virtual machine in the same
	// resource group was deleted nine days ago — that is how the detach
	// happened, and it is too recent to call the interface abandoned.
	h.log.EventsFunc = func(_ context.Context, id string, window verdict.Window) (collect.ActivityLog, error) {
		if id != group {
			t.Errorf("group log read for %s, want the resource group", id)
		}
		return collect.ActivityLog{Days: window.Days, Events: []collect.ActivityEvent{{
			ActivityEvent: age.ActivityEvent{ResourceID: vmID, Timestamp: cutoff.AddDate(0, 0, -9),
				Operation: "Microsoft.Compute/virtualMachines/delete", Status: "Succeeded"}}}}, nil
	}
	e := h.run(t, network.NICSignals)[network.SignalNICIdle]
	if e.Status != verdict.StatusAbsent || e.Window == nil || e.Window.Days != network.IdleDays {
		t.Fatalf("idle = %+v, want absent over the fixed 30-day period", e)
	}
}

func TestIdlenessNeedsEverySourceToHaveAnswered(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*harness)
		code   verdict.UnknownCode
	}{
		{"activity log unread", func(h *harness) { h.generic.ActivityLogRead = false }, verdict.UnkDependency},
		{"activity log truncated", func(h *harness) {
			h.generic.ActivityLog = collect.ActivityLog{Days: 90, Truncated: true}
		}, verdict.UnkPartial},
		{"activity log too short", func(h *harness) {
			h.generic.ActivityLog = collect.ActivityLog{Days: 7}
		}, verdict.UnkPartial},
		{"change history unread", func(h *harness) { h.generic.ChangesRead = false }, verdict.UnkDependency},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(pipID)
			tc.mutate(h)
			e := h.run(t, network.PublicIPSignals)[network.SignalPIPIdle]
			if e.Status != verdict.StatusUnknown || e.Unknown.Code != tc.code {
				t.Fatalf("idle = %+v, want unknown(%s)", e, tc.code)
			}
		})
	}
}

func TestARecentChangeMakesAResourceNotIdle(t *testing.T) {
	h := newHarness(pipID)
	h.generic.Changes = []age.ResourceChange{{ResourceID: pipID, Timestamp: cutoff.AddDate(0, 0, -3), ChangeType: "Update"}}
	if e := h.run(t, network.PublicIPSignals)[network.SignalPIPIdle]; e.Status != verdict.StatusAbsent {
		t.Fatalf("idle = %+v, want absent after a change three days ago", e)
	}

	// A change older than the graph's 14-day retention says nothing.
	old := newHarness(pipID)
	old.generic.Changes = []age.ResourceChange{{ResourceID: pipID, Timestamp: cutoff.AddDate(0, 0, -20), ChangeType: "Update"}}
	if e := old.run(t, network.PublicIPSignals)[network.SignalPIPIdle]; e.Status != verdict.StatusPresent {
		t.Fatalf("idle = %+v, want present when the only change predates the retention", e)
	}
}

func TestAssociatedAddressBlocksAndTrafficContradicts(t *testing.T) {
	h := newHarness(pipID)
	h.properties = map[string]any{
		"ipConfiguration":          map[string]any{"id": nicID + "/ipConfigurations/ipconfig1"},
		"publicIPAllocationMethod": "Static",
		"dnsSettings":              map[string]any{"domainNameLabel": "demo-app"},
	}
	evidence := h.run(t, network.PublicIPSignals)
	if e := evidence[network.SignalPIPAssociated]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierBlocker {
		t.Fatalf("associated = %+v, want a blocker", e)
	}
	if e := evidence[network.SignalPIPDomainLabel]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierDesignIntent {
		t.Fatalf("domain label = %+v, want design intent", e)
	}
	if evidence[network.SignalPIPUnassociated].Status != verdict.StatusAbsent {
		t.Error("an associated address is not unassociated")
	}
}

func TestTrafficOnAnUnassociatedAddressIsAContradiction(t *testing.T) {
	h := newHarness(pipID)
	h.metrics.MetricsFunc = func(_ context.Context, query collect.MetricQuery) (collect.MetricResult, error) {
		if !slices.Equal(query.Names, network.TrafficMetrics) {
			t.Errorf("metric names = %v, want the address counters", query.Names)
		}
		return collect.MetricResult{Series: []collect.MetricSeries{{Name: "ByteCount", Points: []collect.MetricPoint{
			{Timestamp: cutoff.AddDate(0, 0, -2), Value: 4096}}}}}, nil
	}
	e := h.run(t, network.PublicIPSignals)[network.SignalPIPTraffic]
	if e.Status != verdict.StatusPresent || e.Tier != verdict.TierInfo || e.Details["contradiction"] != true {
		t.Fatalf("traffic = %+v, want an informational contradiction", e)
	}
}

func TestNatGatewayHoldsAnAddress(t *testing.T) {
	h := newHarness(pipID)
	h.properties = map[string]any{"natGateway": map[string]any{"id": group + "/providers/Microsoft.Network/natGateways/nat1"}}
	evidence := h.run(t, network.PublicIPSignals)
	if e := evidence[network.SignalPIPNATGateway]; e.Status != verdict.StatusPresent || !e.Critical {
		t.Fatalf("nat gateway = %+v, want a critical blocker", e)
	}
	if evidence[network.SignalPIPUnassociated].Status != verdict.StatusAbsent {
		t.Error("an address a NAT gateway uses is not unassociated")
	}
}

func TestSecurityGroupAssociations(t *testing.T) {
	h := newHarness(nsgID)
	h.properties = map[string]any{"subnets": []any{map[string]any{"id": "/subnet1"}}}
	evidence := h.run(t, network.NSGSignals)
	e := evidence[network.SignalNSGAssociations]
	if e.Status != verdict.StatusPresent || e.Tier != verdict.TierBlocker || e.Details["attachmentCount"] != 1 {
		t.Fatalf("associations = %+v, want the subnet as a blocker", e)
	}
	if evidence[network.SignalNSGFree].Status != verdict.StatusAbsent {
		t.Error("an applied group is not association-free")
	}
}

func TestZeroInstanceScaleSetModelStillReferencesTheGroup(t *testing.T) {
	h := newHarness(nsgID)
	h.graph.Answers = []collecttest.GraphAnswer{{Match: "virtualmachinescalesets",
		Rows: collect.Rows{Rows: []map[string]any{{"id": group + "/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1"}}}}}
	evidence := h.run(t, network.NSGSignals)
	e := evidence[network.SignalNSGAssociations]
	if e.Status != verdict.StatusPresent || e.Details["scaleSetModelCount"] != 1 {
		t.Fatalf("associations = %+v, want the scale set model reference", e)
	}
	if evidence[network.SignalNSGFree].Status != verdict.StatusAbsent {
		t.Error("a group a scale set model references is not association-free")
	}
}

func TestUnreadableAssociationSourceIsUnknownNotEmpty(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*harness)
		code   verdict.UnknownCode
	}{
		{"graph blind", func(h *harness) {
			h.generic.ARGVisible = false
			h.generic.ARGUnknown = &verdict.Unknown{Code: verdict.UnkPermission, Message: "not visible"}
		}, verdict.UnkPermission},
		{"query failed", func(h *harness) {
			h.graph.Answers = []collecttest.GraphAnswer{{Match: "virtualmachinescalesets", Err: collecttest.Forbidden()}}
		}, verdict.UnkPermission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(nsgID)
			tc.mutate(h)
			evidence := h.run(t, network.NSGSignals)
			if e := evidence[network.SignalNSGAssociations]; e.Status != verdict.StatusUnknown ||
				e.Unknown.Code != tc.code || !e.Critical {
				t.Fatalf("associations = %+v, want a critical unknown(%s)", e, tc.code)
			}
			// The derived signal inherits the gap: "no associations" cannot be
			// established while an applicable source is unreadable.
			if e := evidence[network.SignalNSGFree]; e.Status != verdict.StatusUnknown {
				t.Fatalf("no-associations = %+v, want unknown", e)
			}
		})
	}
}

func TestEnabledFlowLogWithASurvivingSinkIsADependency(t *testing.T) {
	h := newHarness(nsgID)
	h.properties = map[string]any{"flowLogs": []any{map[string]any{"id": "/flowlog1"}}}
	h.graph.Answers = []collecttest.GraphAnswer{
		{Match: "networkwatchers/flowlogs", Rows: collect.Rows{Rows: []map[string]any{
			{"id": "/flowlog1", "storage": sinkID, "enabled": true}}}},
		{Match: "where id in~", Rows: collect.Rows{Rows: []map[string]any{{"id": sinkID}}}},
	}
	evidence := h.run(t, network.NSGSignals)
	if e := evidence[network.SignalNSGFlowLogs]; e.Status != verdict.StatusPresent || !e.Critical {
		t.Fatalf("flow logs = %+v, want a critical dependency", e)
	}
	if e := evidence[network.SignalNSGFlowLog]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierDesignIntent {
		t.Fatalf("flow log configuration = %+v, want design intent", e)
	}
}

func TestFlowLogWithADeadSinkIsNotADependency(t *testing.T) {
	h := newHarness(nsgID)
	h.graph.Answers = []collecttest.GraphAnswer{
		{Match: "networkwatchers/flowlogs", Rows: collect.Rows{Rows: []map[string]any{
			{"id": "/flowlog1", "storage": sinkID, "enabled": true}}}},
		{Match: "where id in~", Rows: collect.Rows{}},
	}
	if e := h.run(t, network.NSGSignals)[network.SignalNSGFlowLogs]; e.Status != verdict.StatusAbsent {
		t.Fatalf("flow logs = %+v, want absent when the storage account is gone", e)
	}
}

func TestPlatformOwnedSecurityGroup(t *testing.T) {
	h := newHarness(group[:len(group)-len("rg-demo")] + "MC_rg_aks1_westeurope/providers/Microsoft.Network/networkSecurityGroups/aks-agentpool-12345678-nsg")
	e := h.run(t, network.NSGSignals)[network.SignalNSGPlatform]
	if e.Status != verdict.StatusPresent || e.Details["matchedName"] != true || !e.Critical {
		t.Fatalf("platform = %+v, want a critical platform-owned dependency", e)
	}
}

func TestPoliciesCoverEverySignal(t *testing.T) {
	policies := network.Policies()
	all := slices.Concat(network.NICSignals, network.PublicIPSignals, network.NSGSignals)
	for _, id := range all {
		if _, ok := policies[id]; !ok {
			t.Errorf("signal %s has no output policy", id)
		}
	}
	if len(policies) != len(all) {
		t.Errorf("the policy set has %d entries for %d signals", len(policies), len(all))
	}
}
