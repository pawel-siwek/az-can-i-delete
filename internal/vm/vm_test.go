package vm_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/age"
	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect/collecttest"
	"github.com/pawel-siwek/az-can-i-delete/internal/generic"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
	"github.com/pawel-siwek/az-can-i-delete/internal/vm"
)

const (
	group = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo"
	vmID  = group + "/providers/Microsoft.Compute/virtualMachines/vm1"
	nicID = group + "/providers/Microsoft.Network/networkInterfaces/nic1"
)

var cutoff = time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)

type harness struct {
	properties map[string]any
	tags       map[string]string
	arm        *collecttest.ARM
	graph      *collecttest.Graph
	metrics    *collecttest.Metrics
	generic    generic.Result
	powerState string
	series     map[string][]float64
}

func newHarness() *harness {
	h := &harness{
		properties: map[string]any{"provisioningState": "Succeeded"},
		graph:      &collecttest.Graph{},
		metrics:    &collecttest.Metrics{},
		powerState: "PowerState/running",
		series:     map[string][]float64{},
		generic: generic.Result{
			ARGVisible: true, ActivityLogRead: true,
			ActivityLog: collect.ActivityLog{Days: 90},
			Age:         verdict.Age{LowerBoundDays: 400, Confidence: "verified", Source: "rp.timestamp"},
		},
	}
	h.arm = &collecttest.ARM{GetFunc: func(_ context.Context, id, _ string) (collect.Resource, error) {
		switch {
		case strings.HasSuffix(id, "/instanceView"):
			if h.powerState == "" {
				return collect.Resource{Properties: map[string]any{"statuses": []any{}}}, nil
			}
			return collect.Resource{Properties: map[string]any{"statuses": []any{
				map[string]any{"code": h.powerState}}}}, nil
		case id == nicID:
			return collect.Resource{ID: id, Properties: map[string]any{"ipConfigurations": []any{
				map[string]any{"properties": map[string]any{"privateIPAddress": "10.0.0.4"}}}}}, nil
		default:
			return collect.Resource{}, &collect.Failure{StatusCode: http.StatusNotFound}
		}
	}}
	return h
}

// serveMetrics answers each metric name with one point per day.
func (h *harness) serveMetrics() {
	h.metrics.MetricsFunc = func(_ context.Context, query collect.MetricQuery) (collect.MetricResult, error) {
		var out []collect.MetricSeries
		for _, name := range query.Names {
			values, ok := h.series[name]
			if !ok {
				continue
			}
			points := make([]collect.MetricPoint, 0, len(values))
			for i, value := range values {
				points = append(points, collect.MetricPoint{
					Timestamp: cutoff.AddDate(0, 0, -(i + 1)), Value: value})
			}
			out = append(out, collect.MetricSeries{Name: name, Points: points})
		}
		return collect.MetricResult{Series: out}, nil
	}
}

func (h *harness) run(t *testing.T) map[string]verdict.Evidence {
	t.Helper()
	if h.metrics.MetricsFunc == nil {
		h.serveMetrics()
	}
	target, err := armid.Parse(vmID)
	if err != nil {
		t.Fatal(err)
	}
	window := verdict.Window{Start: cutoff.AddDate(0, 0, -30), End: cutoff, Days: 30, Grain: "P1D"}
	evidence := vm.Collect(context.Background(), vm.Input{
		Target:    target,
		Resource:  collect.Resource{ID: vmID, Type: vm.ResourceType, Name: "vm1", Properties: h.properties, Tags: h.tags},
		Requested: window,
		Cutoff:    cutoff,
		Clients:   collecttest.Clients(h.arm, h.graph, h.metrics, &collecttest.ActivityLog{}, nil),
		Graph:     collect.NewGraphLimiter(collect.SystemClock()),
		Generic:   h.generic,
	})
	var ids []string
	byID := map[string]verdict.Evidence{}
	for _, item := range evidence {
		ids = append(ids, item.ID)
		byID[item.ID] = item
	}
	if !slices.Equal(ids, vm.Signals) {
		t.Fatalf("evidence = %v, want the catalogue in order %v", ids, vm.Signals)
	}
	return byID
}

// quiet fills the availability metric so silence can be established, with no
// processor, connection or traffic activity.
func (h *harness) quiet() {
	availability := make([]float64, 30)
	for i := range availability {
		availability[i] = 1
	}
	h.series["VmAvailabilityMetric"] = availability
}

func TestAnIdleMachineSatisfiesItsRequiredSignals(t *testing.T) {
	h := newHarness()
	h.quiet()
	evidence := h.run(t)
	for _, id := range verdict.RequiredForType(vm.ResourceType) {
		if id == generic.SignalARGVisible {
			continue
		}
		e := evidence[id]
		if e.Status != verdict.StatusPresent || e.Tier != verdict.TierObservedIdle {
			t.Errorf("Required %s = %+v, want a present OBSERVED_IDLE signal", id, e)
		}
	}
	if e := evidence[vm.SignalIdle]; e.Details["via"] != "metrics" {
		t.Errorf("idle = %+v, want idleness established from metrics", e)
	}
	for _, id := range []string{vm.SignalScaleSet, vm.SignalPlatform, vm.SignalBackup,
		vm.SignalASR, vm.SignalImage, vm.SignalPools, vm.SignalNetworkRefs, vm.SignalMetrics} {
		if evidence[id].Status != verdict.StatusAbsent {
			t.Errorf("%s = %+v, want absent", id, evidence[id])
		}
	}
}

func TestSilenceNeedsThePlatformAvailabilityMetric(t *testing.T) {
	// Without the availability metric, an empty answer is just an empty
	// answer: the machine may have been unreachable to monitoring.
	e := newHarness().run(t)[vm.SignalMetricSilence]
	if e.Status != verdict.StatusUnknown || e.Unknown.Code != verdict.UnkPartial {
		t.Fatalf("silence = %+v, want unknown(partial)", e)
	}
}

func TestABusyMachineNeedsAllThreeThresholds(t *testing.T) {
	busy := func() *harness {
		h := newHarness()
		h.quiet()
		cpu, flows, bytes := make([]float64, 30), make([]float64, 30), make([]float64, 30)
		for i := range cpu {
			cpu[i], flows[i], bytes[i] = 40, 50, 100*1024*1024
		}
		h.series["Percentage CPU"], h.series["Inbound Flows"] = cpu, flows
		h.series["Network In Total"] = bytes
		return h
	}
	if e := busy().run(t)[vm.SignalMetrics]; e.Status != verdict.StatusPresent || !e.Critical {
		t.Fatalf("metrics = %+v, want critical live activity", e)
	}

	// A machine burning processor with no connections and no traffic is an
	// idle Windows machine, not a busy one.
	spinning := busy()
	delete(spinning.series, "Inbound Flows")
	delete(spinning.series, "Network In Total")
	evidence := spinning.run(t)
	if evidence[vm.SignalMetrics].Status != verdict.StatusAbsent {
		t.Fatalf("metrics = %+v, want absent without connections or traffic", evidence[vm.SignalMetrics])
	}
	if evidence[vm.SignalMetricSilence].Status != verdict.StatusPresent {
		t.Errorf("silence = %+v, want present", evidence[vm.SignalMetricSilence])
	}
}

func TestStartEventsAreLiveActivity(t *testing.T) {
	h := newHarness()
	h.quiet()
	h.generic.ActivityLog = collect.ActivityLog{Days: 90, Events: []collect.ActivityEvent{{
		ActivityEvent: age.ActivityEvent{ResourceID: vmID, Timestamp: cutoff.AddDate(0, 0, -6),
			Operation: "Microsoft.Compute/virtualMachines/start/action", Status: "Succeeded"}}}}
	evidence := h.run(t)
	e := evidence[vm.SignalStartEvents]
	if e.Status != verdict.StatusPresent || e.Tier != verdict.TierLiveActivity || e.Details["daysAgo"] != 6 {
		t.Fatalf("start events = %+v, want live activity six days ago", e)
	}
	if evidence[vm.SignalNoStartEvents].Status != verdict.StatusAbsent {
		t.Error("a machine somebody started is not quiet")
	}
}

func TestDeallocatedLongEnoughIsIdleAndKeptReasonsShow(t *testing.T) {
	h := newHarness()
	h.powerState = "PowerState/deallocated"
	h.generic.ActivityLog = collect.ActivityLog{Days: 90, Events: []collect.ActivityEvent{{
		ActivityEvent: age.ActivityEvent{ResourceID: vmID, Timestamp: cutoff.AddDate(0, 0, -100),
			Operation: "Microsoft.Compute/virtualMachines/deallocate/action", Status: "Succeeded"}}}}
	h.graph.Answers = []collecttest.GraphAnswer{{Match: "protecteditems",
		Rows: collect.Rows{Rows: []map[string]any{{"id": "/b1", "state": "ProtectionStopped"}}}}}
	evidence := h.run(t)
	if e := evidence[vm.SignalDeallocated]; e.Status != verdict.StatusPresent || e.Details["quietDays"] != 100 {
		t.Fatalf("deallocated = %+v, want a hundred quiet days", e)
	}
	if e := evidence[vm.SignalIdle]; e.Status != verdict.StatusPresent || e.Details["via"] != "deallocated" {
		t.Fatalf("idle = %+v, want idleness from the power state", e)
	}
	if e := evidence[vm.SignalKept]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierDesignIntent {
		t.Fatalf("kept = %+v, want the retained backup reported as intent", e)
	}
	if evidence[vm.SignalBackupRetained].Status != verdict.StatusPresent {
		t.Error("stopped protection with retained recovery points must be reported")
	}
	if evidence[vm.SignalBackup].Status != verdict.StatusAbsent {
		t.Error("stopped protection is not active protection")
	}
}

func TestRecentlyDeallocatedIsNotYetIdle(t *testing.T) {
	h := newHarness()
	h.powerState = "PowerState/deallocated"
	h.generic.ActivityLog = collect.ActivityLog{Days: 90, Events: []collect.ActivityEvent{{
		ActivityEvent: age.ActivityEvent{ResourceID: vmID, Timestamp: cutoff.AddDate(0, 0, -5),
			Operation: "Microsoft.Compute/virtualMachines/deallocate/action", Status: "Succeeded"}}}}
	if e := h.run(t)[vm.SignalDeallocated]; e.Status != verdict.StatusAbsent {
		t.Fatalf("deallocated = %+v, want absent five days after being switched off", e)
	}
}

func TestAStartAfterTheDeallocationEndsTheSilence(t *testing.T) {
	h := newHarness()
	h.powerState = "PowerState/deallocated"
	h.generic.ActivityLog = collect.ActivityLog{Days: 90, Events: []collect.ActivityEvent{
		{ActivityEvent: age.ActivityEvent{ResourceID: vmID, Timestamp: cutoff.AddDate(0, 0, -100),
			Operation: "Microsoft.Compute/virtualMachines/deallocate/action", Status: "Succeeded"}},
		{ActivityEvent: age.ActivityEvent{ResourceID: vmID, Timestamp: cutoff.AddDate(0, 0, -40),
			Operation: "Microsoft.Compute/virtualMachines/start/action", Status: "Succeeded"}}}}
	if e := h.run(t)[vm.SignalDeallocated]; e.Status != verdict.StatusAbsent {
		t.Fatalf("deallocated = %+v, want absent after somebody started the machine", e)
	}
}

func TestMembershipsAndPlatformOwnership(t *testing.T) {
	h := newHarness()
	h.quiet()
	scaleSet := group + "/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1"
	h.properties["virtualMachineScaleSet"] = map[string]any{"id": scaleSet}
	h.properties["availabilitySet"] = map[string]any{"id": group + "/providers/Microsoft.Compute/availabilitySets/as1"}
	h.tags = map[string]string{"aks-managed-poolName": "nodepool1"}
	evidence := h.run(t)
	if e := evidence[vm.SignalScaleSet]; e.Status != verdict.StatusPresent || e.Details["owner"] != scaleSet || !e.Critical {
		t.Fatalf("scale set = %+v, want a critical dependency", e)
	}
	if e := evidence[vm.SignalAvailability]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierDesignIntent {
		t.Fatalf("availability set = %+v, want design intent", e)
	}
	if e := evidence[vm.SignalPlatform]; e.Status != verdict.StatusPresent || !e.Critical {
		t.Fatalf("platform = %+v, want a critical dependency", e)
	}
}

func TestNetworkPoolsAndRouteReferences(t *testing.T) {
	h := newHarness()
	h.quiet()
	h.properties["networkProfile"] = map[string]any{"networkInterfaces": []any{
		map[string]any{"id": nicID}}}
	h.arm.GetFunc = func(_ context.Context, id, _ string) (collect.Resource, error) {
		switch {
		case strings.HasSuffix(id, "/instanceView"):
			return collect.Resource{Properties: map[string]any{"statuses": []any{
				map[string]any{"code": "PowerState/running"}}}}, nil
		case id == nicID:
			return collect.Resource{ID: id, Properties: map[string]any{"ipConfigurations": []any{
				map[string]any{"properties": map[string]any{
					"privateIPAddress":                "10.0.0.4",
					"loadBalancerBackendAddressPools": []any{map[string]any{"id": "/pool1"}}}}}}}, nil
		default:
			return collect.Resource{}, &collect.Failure{StatusCode: http.StatusNotFound}
		}
	}
	h.graph.Answers = []collecttest.GraphAnswer{{Match: "routetables",
		Rows: collect.Rows{Rows: []map[string]any{{"id": "/route1"}}}}}
	evidence := h.run(t)
	if e := evidence[vm.SignalPools]; e.Status != verdict.StatusPresent || !e.Critical {
		t.Fatalf("pools = %+v, want a critical dependency", e)
	}
	if e := evidence[vm.SignalNetworkRefs]; e.Status != verdict.StatusPresent || !e.Critical {
		t.Fatalf("network references = %+v, want the route reported", e)
	}
}

func TestGeneralizedImageSourceIsIntentNotADependency(t *testing.T) {
	h := newHarness()
	h.quiet()
	h.graph.Answers = []collecttest.GraphAnswer{{Match: "compute/images",
		Rows: collect.Rows{Rows: []map[string]any{{"id": "/image1", "generalized": "Generalized"}}}}}
	e := h.run(t)[vm.SignalImage]
	if e.Status != verdict.StatusPresent || e.Tier != verdict.TierDesignIntent || e.Critical {
		t.Fatalf("image = %+v, want design intent for a generalized template", e)
	}
}

func TestGraphBlindnessKeepsReferencesUnknown(t *testing.T) {
	h := newHarness()
	h.quiet()
	h.generic.ARGVisible = false
	h.generic.ARGUnknown = &verdict.Unknown{Code: verdict.UnkPermission, Message: "not visible"}
	evidence := h.run(t)
	for _, id := range []string{vm.SignalBackup, vm.SignalASR, vm.SignalImage, vm.SignalPlatform} {
		e := evidence[id]
		if e.Status != verdict.StatusUnknown || e.Unknown.Code != verdict.UnkPermission {
			t.Errorf("%s = %+v, want unknown(permission)", id, e)
		}
	}
}

func TestAnUnreadablePowerStateIsNotAssumed(t *testing.T) {
	h := newHarness()
	h.quiet()
	h.arm.GetFunc = func(context.Context, string, string) (collect.Resource, error) {
		return collect.Resource{}, collecttest.Forbidden()
	}
	evidence := h.run(t)
	if e := evidence[vm.SignalPower]; e.Status != verdict.StatusUnknown {
		t.Fatalf("power = %+v, want unknown", e)
	}
	if e := evidence[vm.SignalDeallocated]; e.Status != verdict.StatusUnknown {
		t.Fatalf("deallocated = %+v, want unknown when the power state is unknown", e)
	}
	// Metric silence can still carry the verdict, which is why idle is derived
	// from both sources rather than from one.
	if evidence[vm.SignalIdle].Status != verdict.StatusPresent {
		t.Errorf("idle = %+v, want present from the metrics", evidence[vm.SignalIdle])
	}
}

func TestPoliciesCoverEverySignal(t *testing.T) {
	policies := vm.Policies()
	for _, id := range vm.Signals {
		if _, ok := policies[id]; !ok {
			t.Errorf("signal %s has no output policy", id)
		}
	}
	if len(policies) != len(vm.Signals) {
		t.Errorf("the policy set has %d entries for %d signals", len(policies), len(vm.Signals))
	}
}
