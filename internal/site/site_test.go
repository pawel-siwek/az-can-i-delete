package site_test

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
	"github.com/pawel-siwek/az-can-i-delete/internal/site"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

const (
	group  = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo"
	siteID = group + "/providers/Microsoft.Web/sites/app1"
	planID = group + "/providers/Microsoft.Web/serverfarms/plan1"
)

var cutoff = time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)

type harness struct {
	id         string
	kind       string
	properties map[string]any
	config     map[string]any
	plan       map[string]any
	functions  []collect.Resource
	slots      []collect.Resource
	slotsErr   error
	graph      *collecttest.Graph
	metrics    *collecttest.Metrics
	generic    generic.Result
	series     map[string][]float64
}

func newHarness(id string) *harness {
	return &harness{
		id:         id,
		properties: map[string]any{"provisioningState": "Succeeded", "state": "Running", "serverFarmId": planID},
		config:     map[string]any{},
		plan:       map[string]any{"sku": map[string]any{"tier": "Basic", "capacity": float64(1)}},
		graph:      &collecttest.Graph{},
		metrics:    &collecttest.Metrics{},
		series:     map[string][]float64{},
		generic: generic.Result{
			ARGVisible: true, ActivityLogRead: true,
			ActivityLog: collect.ActivityLog{Days: 90},
			Age:         verdict.Age{LowerBoundDays: 400, Confidence: "verified", Source: "rp.timestamp"},
		},
	}
}

func (h *harness) arm() *collecttest.ARM {
	return &collecttest.ARM{
		GetFunc: func(_ context.Context, id, _ string) (collect.Resource, error) {
			switch {
			case strings.HasSuffix(id, "/config/web"):
				return collect.Resource{ID: id, Properties: h.config}, nil
			case id == planID:
				return collect.Resource{ID: id, Properties: h.plan}, nil
			default:
				return collect.Resource{}, &collect.Failure{StatusCode: http.StatusNotFound}
			}
		},
		ListFunc: func(_ context.Context, path, _ string) ([]collect.Resource, error) {
			switch {
			case strings.HasSuffix(path, "/functions"):
				return h.functions, nil
			case strings.HasSuffix(path, "/slots"):
				return h.slots, h.slotsErr
			default:
				return nil, nil
			}
		},
	}
}

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
	target, err := armid.Parse(h.id)
	if err != nil {
		t.Fatal(err)
	}
	window := verdict.Window{Start: cutoff.AddDate(0, 0, -30), End: cutoff, Days: 30, Grain: "P1D"}
	evidence := site.Collect(context.Background(), site.Input{
		Target: target,
		Resource: collect.Resource{ID: h.id, Type: target.ResourceType, Name: target.Name,
			Kind: h.kind, Properties: h.properties},
		Requested: window,
		Cutoff:    cutoff,
		Clients:   collecttest.Clients(h.arm(), h.graph, h.metrics, &collecttest.ActivityLog{}, nil),
		Graph:     collect.NewGraphLimiter(collect.SystemClock()),
		Generic:   h.generic,
	})
	var ids []string
	byID := map[string]verdict.Evidence{}
	for _, item := range evidence {
		ids = append(ids, item.ID)
		byID[item.ID] = item
	}
	if !slices.Equal(ids, site.Signals(target.ResourceType)) {
		t.Fatalf("evidence = %v, want the catalogue in order %v", ids, site.Signals(target.ResourceType))
	}
	return byID
}

func TestSupportedTypes(t *testing.T) {
	for _, supported := range []string{site.SiteType, site.SlotType, site.PlanType} {
		if !site.Supports(supported) {
			t.Errorf("%s must be analyzed here", supported)
		}
	}
	if site.Supports("Microsoft.Compute/disks") {
		t.Error("the disk analyzer is not in this package")
	}
}

func TestAQuietRunningSiteSatisfiesItsRequiredSignals(t *testing.T) {
	evidence := newHarness(siteID).run(t)
	for _, id := range verdict.RequiredForType(site.SiteType) {
		if id == generic.SignalARGVisible {
			continue
		}
		e := evidence[id]
		if e.Status != verdict.StatusPresent || e.Tier != verdict.TierObservedIdle {
			t.Errorf("Required %s = %+v, want a present OBSERVED_IDLE signal", id, e)
		}
	}
	if e := evidence[site.SignalIdle]; e.Details["via"] != "metrics" {
		t.Errorf("idle = %+v, want idleness from the metrics", e)
	}
	if e := evidence[site.SignalHostingClass]; e.Details["hostingClass"] != site.ClassWindows {
		t.Errorf("hosting class = %+v, want windows for a non-reserved plan", e)
	}
}

func TestProbeTrafficIsNotRealTraffic(t *testing.T) {
	h := newHarness(siteID)
	h.config["alwaysOn"] = true
	h.config["healthCheckPath"] = "/health"
	// A worker answering its own warm-up and health probes produces about
	// 1728 requests a day; that is the site talking to itself.
	requests, success := make([]float64, 30), make([]float64, 30)
	for i := range requests {
		requests[i], success[i] = 1700, 1700
	}
	h.series["Requests"], h.series["Http2xx"] = requests, success
	evidence := h.run(t)
	if evidence[site.SignalRealTraffic].Status != verdict.StatusAbsent {
		t.Fatalf("real traffic = %+v, want absent below the site's own ceiling",
			evidence[site.SignalRealTraffic])
	}
	if evidence[site.SignalLowVolume].Status != verdict.StatusPresent {
		t.Errorf("low volume = %+v, want the requests reported as intent", evidence[site.SignalLowVolume])
	}
	if evidence[site.SignalMetricSilence].Status != verdict.StatusAbsent {
		t.Error("a site serving its own probes is not metric-silent")
	}
}

func TestTrafficAboveTheCeilingIsLive(t *testing.T) {
	h := newHarness(siteID)
	h.config["alwaysOn"] = true
	requests, success := make([]float64, 30), make([]float64, 30)
	for i := range requests {
		requests[i], success[i] = 4000, 4000
	}
	h.series["Requests"], h.series["Http2xx"] = requests, success
	e := h.run(t)[site.SignalRealTraffic]
	if e.Status != verdict.StatusPresent || !e.Critical || e.Details["liveDays"] != 30 {
		t.Fatalf("real traffic = %+v, want live traffic well above the 288-request ceiling", e)
	}
}

func TestHighVolumeAlmostAllSuccessfulTrafficIsProbeShaped(t *testing.T) {
	h := newHarness(siteID)
	requests, success := make([]float64, 30), make([]float64, 30)
	for i := range requests {
		requests[i], success[i] = 9000, 8950
	}
	h.series["Requests"], h.series["Http2xx"] = requests, success
	evidence := h.run(t)
	if e := evidence[site.SignalProbeShaped]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierDesignIntent {
		t.Fatalf("probe shaped = %+v, want design intent", e)
	}
	if evidence[site.SignalRealTraffic].Status != verdict.StatusAbsent {
		t.Error("probe-shaped traffic must not count as real traffic")
	}
}

func TestDeploymentDaysDoNotCountAsLiveTraffic(t *testing.T) {
	h := newHarness(siteID)
	requests, success := make([]float64, 30), make([]float64, 30)
	for i := range requests {
		requests[i], success[i] = 4000, 4000
	}
	h.series["Requests"], h.series["Http2xx"] = requests, success
	var events []collect.ActivityEvent
	for day := 1; day <= 30; day++ {
		events = append(events, collect.ActivityEvent{ActivityEvent: age.ActivityEvent{
			ResourceID: siteID, Timestamp: cutoff.AddDate(0, 0, -day),
			Operation: "Microsoft.Web/sites/restart/action", Status: "Succeeded"}})
	}
	h.generic.ActivityLog = collect.ActivityLog{Days: 90, Events: events}
	evidence := h.run(t)
	if evidence[site.SignalRealTraffic].Status != verdict.StatusAbsent {
		t.Fatalf("real traffic = %+v, want absent when every day was a deployment day",
			evidence[site.SignalRealTraffic])
	}
	if evidence[site.SignalNoDeploys].Status != verdict.StatusAbsent {
		t.Error("a site restarted every day is not deployment-quiet")
	}
}

func TestANonHTTPTriggerMeansTheAppRunsOnItsOwn(t *testing.T) {
	h := newHarness(siteID)
	h.kind = "functionapp"
	h.functions = []collect.Resource{
		{Name: "timer", Properties: map[string]any{"config": map[string]any{"bindings": []any{
			map[string]any{"type": "timerTrigger", "direction": "in"}}}}},
		{Name: "disabled", Properties: map[string]any{"isDisabled": true, "config": map[string]any{
			"bindings": []any{map[string]any{"type": "queueTrigger", "direction": "in"}}}}},
	}
	evidence := h.run(t)
	e := evidence[site.SignalNonHTTP]
	if e.Status != verdict.StatusPresent || !e.Critical || e.Details["triggerCount"] != 1 {
		t.Fatalf("non-HTTP triggers = %+v, want only the enabled timer", e)
	}
	if evidence[site.SignalHTTPOnly].Status != verdict.StatusAbsent {
		t.Error("an app with a timer trigger is not HTTP-only")
	}
}

func TestLinuxFunctionAppsCannotBeClearedOnExecutions(t *testing.T) {
	h := newHarness(siteID)
	h.kind = "functionapp,linux"
	h.properties["reserved"] = true
	h.plan = map[string]any{"reserved": true, "sku": map[string]any{"tier": "Dynamic", "capacity": float64(1)}}
	evidence := h.run(t)
	if e := evidence[site.SignalHostingClass]; e.Details["hostingClass"] != site.ClassConsumption {
		t.Fatalf("hosting class = %+v, want linux-consumption", e)
	}
	if e := evidence[site.SignalFunctionRuns]; e.Status != verdict.StatusUnknown ||
		e.Unknown.Code != verdict.UnkUnsupported {
		t.Fatalf("function executions = %+v, want unknown(unsupported)", e)
	}
	// Without an execution counter the site cannot be shown to have run
	// nothing, so the Required silence signal is unknown and `yes` is out.
	if e := evidence[site.SignalMetricSilence]; e.Status != verdict.StatusUnknown {
		t.Fatalf("metric silence = %+v, want unknown for a hosting class with no counter", e)
	}
}

func TestStoppedSitesAndTheirAge(t *testing.T) {
	h := newHarness(siteID)
	h.properties["state"] = "Stopped"
	h.generic.ActivityLog = collect.ActivityLog{Days: 90, Events: []collect.ActivityEvent{{
		ActivityEvent: age.ActivityEvent{ResourceID: siteID, Timestamp: cutoff.AddDate(0, 0, -200),
			Operation: "Microsoft.Web/sites/stop/action", Status: "Succeeded"}}}}
	evidence := h.run(t)
	if e := evidence[site.SignalStoppedLong]; e.Status != verdict.StatusPresent || e.Details["quietDays"] != 200 {
		t.Fatalf("stopped long = %+v, want two hundred quiet days", e)
	}
	if e := evidence[site.SignalIdle]; e.Details["via"] != "stopped" {
		t.Fatalf("idle = %+v, want idleness from the stopped state", e)
	}
	// Quiet metrics from a stopped site say nothing on their own.
	if e := evidence[site.SignalMetricSilence]; e.Status != verdict.StatusUnknown {
		t.Errorf("metric silence = %+v, want unknown while the site is stopped", e)
	}

	recent := newHarness(siteID)
	recent.properties["state"] = "Stopped"
	recent.generic.ActivityLog = collect.ActivityLog{Days: 90, Events: []collect.ActivityEvent{{
		ActivityEvent: age.ActivityEvent{ResourceID: siteID, Timestamp: cutoff.AddDate(0, 0, -4),
			Operation: "Microsoft.Web/sites/stop/action", Status: "Succeeded"}}}}
	fresh := recent.run(t)
	if fresh[site.SignalStopped].Status != verdict.StatusPresent ||
		fresh[site.SignalStoppedLong].Status != verdict.StatusAbsent {
		t.Fatalf("a site stopped four days ago must be intent, not idleness: %+v / %+v",
			fresh[site.SignalStopped], fresh[site.SignalStoppedLong])
	}
}

func TestCustomDomainsAndFronting(t *testing.T) {
	h := newHarness(siteID)
	h.properties["hostNames"] = []any{"app1.azurewebsites.net", "shop.example.com"}
	h.config["ipSecurityRestrictions"] = []any{map[string]any{
		"tag": "ServiceTag", "ipAddress": "AzureFrontDoor.Backend", "action": "Allow"}}
	evidence := h.run(t)
	if e := evidence[site.SignalCustomDomain]; e.Status != verdict.StatusPresent || !e.Critical {
		t.Fatalf("custom domain = %+v, want a critical dependency", e)
	}
	if e := evidence[site.SignalFronted]; e.Status != verdict.StatusPresent || !e.Critical {
		t.Fatalf("fronted = %+v, want a critical dependency", e)
	}
}

func TestAccessRestrictionExplainsQuietMetrics(t *testing.T) {
	h := newHarness(siteID)
	h.properties["publicNetworkAccess"] = "Disabled"
	e := h.run(t)[site.SignalAccessRestrict]
	if e.Status != verdict.StatusPresent || e.Tier != verdict.TierInfo {
		t.Fatalf("access restriction = %+v, want information", e)
	}
}

func TestPlanWithSitesIsBlockedAndEmptyPlanIsIdle(t *testing.T) {
	busy := newHarness(planID)
	busy.properties = map[string]any{"numberOfSites": float64(3)}
	evidence := busy.run(t)
	if e := evidence[site.SignalPlanSites]; e.Status != verdict.StatusPresent ||
		e.Tier != verdict.TierBlocker || e.Details["siteCount"] != 3 {
		t.Fatalf("plan sites = %+v, want a blocker", e)
	}
	if evidence[site.SignalPlanEmpty].Status != verdict.StatusAbsent {
		t.Error("a plan with sites is not empty")
	}

	empty := newHarness(planID)
	empty.properties = map[string]any{"numberOfSites": float64(0)}
	empty.graph.Answers = []collecttest.GraphAnswer{{Match: "advisorresources",
		Rows: collect.Rows{Rows: []map[string]any{{"recType": "39a8510f-1b83-4eb8-b3e2-0b5cf0b98d4c"}}}}}
	quiet := empty.run(t)
	for _, id := range verdict.RequiredForType(site.PlanType) {
		if id == generic.SignalARGVisible {
			continue
		}
		if quiet[id].Status != verdict.StatusPresent {
			t.Errorf("Required %s = %+v, want present", id, quiet[id])
		}
	}
	if quiet[site.SignalPlanAdvisor].Status != verdict.StatusPresent {
		t.Errorf("advisor = %+v, want the empty-plan recommendation", quiet[site.SignalPlanAdvisor])
	}
}

func TestAPlanThatDoesNotReportItsSiteCountIsUnknown(t *testing.T) {
	h := newHarness(planID)
	h.properties = map[string]any{}
	evidence := h.run(t)
	for _, id := range []string{site.SignalPlanSites, site.SignalPlanEmpty} {
		if evidence[id].Status != verdict.StatusUnknown {
			t.Errorf("%s = %+v, want unknown rather than an assumed empty plan", id, evidence[id])
		}
	}
}

func TestPoliciesCoverEverySignal(t *testing.T) {
	policies := site.Policies()
	all := slices.Concat(site.SiteSignals, site.PlanSignals)
	for _, id := range all {
		if _, ok := policies[id]; !ok {
			t.Errorf("signal %s has no output policy", id)
		}
	}
	if len(policies) != len(all) {
		t.Errorf("the policy set has %d entries for %d signals", len(policies), len(all))
	}
}

// Every configuration read has its own budget: the third end-to-end run lost
// nine signals to one slow call, because they were read in one sequence under
// one call budget. A failing sub-resource leaves only its own signal unknown.
func TestOneFailingConfigurationReadLeavesTheOthersRead(t *testing.T) {
	h := newHarness(siteID)
	h.slotsErr = context.DeadlineExceeded
	evidence := h.run(t)
	if got := evidence[site.SignalSlots]; got.Status != verdict.StatusUnknown || got.Unknown == nil || got.Unknown.Code != verdict.UnkTimeout {
		t.Fatalf("slots = %+v, want unknown(timeout)", got)
	}
	for _, id := range []string{site.SignalCustomDomain, site.SignalFronted, site.SignalHybrid,
		site.SignalSourceControl, site.SignalCIActive, site.SignalAccessRestrict, site.SignalHostingClass, site.SignalWebTests} {
		if evidence[id].Status == verdict.StatusUnknown {
			t.Errorf("%s = unknown(%v), want it read despite the slots failure", id, evidence[id].Unknown)
		}
	}
}
