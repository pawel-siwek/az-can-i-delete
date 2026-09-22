// Package site is the analyzer for App Service sites, their deployment slots
// and their plans. A web app is the hardest of the supported types to call
// idle, because a health probe, a scanner and a real user all arrive as HTTP
// requests. The traffic rules here compare what the site received against what
// its own configuration would produce on its own, and a site that cannot be
// told apart from its probes is reported as intent rather than as use.
package site

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

// The types this analyzer answers for.
const (
	SiteType = "Microsoft.Web/sites"
	SlotType = "Microsoft.Web/sites/slots"
	PlanType = "Microsoft.Web/serverfarms"
)

// The site signal IDs of SPEC section 5.7.
const (
	SignalHostingClass   = "site.hosting.class"
	SignalCustomDomain   = "site.customdomain"
	SignalFronted        = "site.frontdoor-or-gateway"
	SignalHybrid         = "site.hybrid-connections"
	SignalSlots          = "site.slots"
	SignalSlotsLive      = "site.slots.live"
	SignalVNet           = "site.vnet-integration"
	SignalSourceControl  = "site.sourcecontrol"
	SignalCIActive       = "site.ci.active"
	SignalNonHTTP        = "site.triggers.non-http"
	SignalHTTPOnly       = "site.triggers.http-only-or-none"
	SignalFunctionRuns   = "site.metrics.function-executions"
	SignalWorkflowRuns   = "site.metrics.workflow-runs"
	SignalRealTraffic    = "site.metrics.real-traffic"
	SignalProbeShaped    = "site.traffic.probe-shaped"
	SignalLowVolume      = "site.metrics.low-volume"
	SignalWebTests       = "site.webtests"
	SignalWebJobs        = "site.webjobs.continuous"
	SignalAccessRestrict = "site.config.access-restricted"
	SignalStopped        = "site.state.stopped"
	SignalStoppedLong    = "site.state.stopped-ge-30d"
	SignalMetricSilence  = "site.metrics.silence"
	SignalIdle           = "site.silence.any"
	SignalAppSettings    = "site.appsettings.storage-refs"
	SignalNoDeploys      = "site.activitylog.no-deploy-events"
)

// The plan signal IDs of SPEC section 5.7b.
const (
	SignalPlanSites     = "plan.structural.sites"
	SignalPlanAutoscale = "plan.autoscale"
	SignalPlanEmpty     = "plan.structural.zero-sites"
	SignalPlanAdvisor   = "plan.advisor.empty"
	SignalPlanQuiet     = "plan.activitylog.no-write-30d"
)

// The traffic rules of SPEC section 5.7. A site with Always On answers its own
// warm-up probe every five minutes, and a health check path is probed every
// minute; both produce requests nobody made.
const (
	AlwaysOnRequestsPerDay    = 288
	HealthCheckRequestsPerDay = 1440
	LiveDays                  = 3
	ProbeRequestFloor         = 5000
	ProbeSuccessRatio         = 0.98
	LiveMultiplier            = 1.25
	LiveHeadroom              = 100
	StoppedDays               = 30
	PlanQuietDays             = 30
	// EmptyPlanAdvisor is the Advisor recommendation for a plan with no sites.
	EmptyPlanAdvisor = "39a8510f"
)

// Hosting classes. The class decides which execution counter exists, which is
// why a Linux function app cannot be reported quiet on executions alone.
const (
	ClassWindows     = "windows"
	ClassFlex        = "flex"
	ClassConsumption = "linux-consumption"
	ClassDedicated   = "linux-premium-dedicated"
	ClassWorkflow    = "linux-workflow"
	ClassWeb         = "linux-web"
	ClassUnknown     = "unknown"
)

// Catalogue is SPEC sections 5.7 and 5.7b.
var Catalogue = signal.Catalogue{
	SignalHostingClass:   {Tier: verdict.TierInfo, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalCustomDomain:   {Tier: verdict.TierHardDependency, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalFronted:        {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARM"},
	SignalHybrid:         {Tier: verdict.TierHardDependency, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalSlots:          {Tier: verdict.TierInfo, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalSlotsLive:      {Tier: verdict.TierLiveActivity, Family: "metrics", Confidence: "unknown", API: "Metrics"},
	SignalVNet:           {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalSourceControl:  {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalCIActive:       {Tier: verdict.TierDesignIntent, Family: "activity-log", Confidence: "verified", API: "ARM"},
	SignalNonHTTP:        {Tier: verdict.TierDesignIntent, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalHTTPOnly:       {Tier: verdict.TierObservedIdle, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalFunctionRuns:   {Tier: verdict.TierLiveActivity, Critical: true, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalWorkflowRuns:   {Tier: verdict.TierLiveActivity, Critical: true, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalRealTraffic:    {Tier: verdict.TierLiveActivity, Critical: true, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalProbeShaped:    {Tier: verdict.TierDesignIntent, Family: "metrics", Confidence: "heuristic", API: "Metrics"},
	SignalLowVolume:      {Tier: verdict.TierDesignIntent, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalWebTests:       {Tier: verdict.TierInfo, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalWebJobs:        {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "unknown", API: "ARM"},
	SignalAccessRestrict: {Tier: verdict.TierInfo, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalStopped:        {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalStoppedLong:    {Tier: verdict.TierObservedIdle, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalMetricSilence:  {Tier: verdict.TierObservedIdle, Family: "metrics", Confidence: "verified", API: "Metrics"},
	SignalIdle:           {Tier: verdict.TierObservedIdle, Family: "derived", Confidence: "verified", API: "Rules"},
	SignalAppSettings:    {Tier: verdict.TierInfo, Family: "structural", Confidence: "unknown", API: "ARM"},
	SignalNoDeploys:      {Tier: verdict.TierObservedIdle, Family: "activity-log", Confidence: "verified", API: "ActivityLog"},

	SignalPlanSites:     {Tier: verdict.TierBlocker, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalPlanAutoscale: {Tier: verdict.TierDesignIntent, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalPlanEmpty:     {Tier: verdict.TierObservedIdle, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalPlanAdvisor:   {Tier: verdict.TierObservedIdle, Family: "derived", Confidence: "heuristic", API: "Advisor", ARGBacked: true},
	SignalPlanQuiet:     {Tier: verdict.TierObservedIdle, Family: "activity-log", Confidence: "verified", API: "ActivityLog"},
}

// SiteSignals and PlanSignals are the catalogue orders.
var (
	SiteSignals = []string{
		SignalCustomDomain, SignalFronted, SignalHybrid, SignalNonHTTP, SignalVNet,
		SignalSourceControl, SignalCIActive, SignalFunctionRuns, SignalWorkflowRuns,
		SignalRealTraffic, SignalProbeShaped, SignalLowVolume, SignalSlotsLive, SignalWebJobs,
		SignalStopped, SignalHTTPOnly, SignalStoppedLong, SignalMetricSilence, SignalIdle,
		SignalNoDeploys, SignalHostingClass, SignalSlots, SignalWebTests,
		SignalAccessRestrict, SignalAppSettings,
	}
	PlanSignals = []string{
		SignalPlanSites, SignalPlanAutoscale, SignalPlanEmpty, SignalPlanAdvisor, SignalPlanQuiet,
	}
)

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

// Supports reports whether this package analyzes a type.
func Supports(resourceType string) bool {
	switch {
	case strings.EqualFold(resourceType, SiteType),
		strings.EqualFold(resourceType, SlotType),
		strings.EqualFold(resourceType, PlanType):
		return true
	default:
		return false
	}
}

// Signals returns the catalogue order for a type.
func Signals(resourceType string) []string {
	if strings.EqualFold(resourceType, PlanType) {
		return PlanSignals
	}
	return SiteSignals
}

// Collect dispatches to the site or plan analyzer.
func Collect(ctx context.Context, in Input) []verdict.Evidence {
	if strings.EqualFold(in.Target.ResourceType, PlanType) {
		return order(PlanSignals, collectPlan(ctx, in))
	}
	return order(SiteSignals, collectSite(ctx, in))
}

func order(signals []string, collected map[string]verdict.Evidence) []verdict.Evidence {
	evidence := make([]verdict.Evidence, 0, len(signals))
	for _, id := range signals {
		found, ok := collected[id]
		if !ok {
			found = Catalogue.Unknown(id, &verdict.Unknown{
				Code: verdict.UnkTransient, Message: "the signal produced no observation"})
		}
		evidence = append(evidence, found)
	}
	return evidence
}
