package site

import (
	"context"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// collectSite runs the site analyzer. The configuration is read first because
// the traffic rules depend on it: how many requests a site makes to itself is
// decided by its own Always On and health check settings, and which execution
// counter exists is decided by its hosting class.
func collectSite(ctx context.Context, in Input) map[string]verdict.Evidence {
	var configuration configGroup
	var triggers triggerGroup
	var traffic trafficGroup
	outcomes := collect.Gather(ctx, []collect.Signal{
		{ID: SignalCustomDomain, Run: configuration.run(in)},
	})
	outcomes = append(outcomes, collect.Gather(ctx, []collect.Signal{
		{ID: SignalNonHTTP, Run: triggers.run(in)},
		{ID: SignalRealTraffic, Run: traffic.run(in, &configuration)},
	})...)

	collected := map[string]verdict.Evidence{
		SignalVNet:        vnetIntegration(in.Resource),
		SignalWebJobs:     Catalogue.NotEvaluated(SignalWebJobs),
		SignalAppSettings: Catalogue.NotEvaluated(SignalAppSettings),
		SignalSlotsLive:   Catalogue.NotEvaluated(SignalSlotsLive),
	}
	stopped, stoppedLong := stoppedState(in)
	collected[SignalStopped], collected[SignalStoppedLong] = stopped, stoppedLong
	collected[SignalNoDeploys] = deploySilence(in)
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
	collected[SignalIdle] = idle(collected)
	return collected
}

func groupSignals(groupID string) []string {
	switch groupID {
	case SignalCustomDomain:
		return []string{SignalCustomDomain, SignalFronted, SignalHybrid, SignalSourceControl,
			SignalCIActive, SignalSlots, SignalAccessRestrict, SignalHostingClass, SignalWebTests}
	case SignalNonHTTP:
		return []string{SignalNonHTTP, SignalHTTPOnly}
	case SignalRealTraffic:
		return []string{SignalRealTraffic, SignalProbeShaped, SignalLowVolume,
			SignalFunctionRuns, SignalWorkflowRuns, SignalMetricSilence}
	default:
		return []string{groupID}
	}
}

// idle is the Required derived signal: a site is idle when its metrics were
// silent or it has been stopped for long enough.
func idle(collected map[string]verdict.Evidence) verdict.Evidence {
	metrics, stopped := collected[SignalMetricSilence], collected[SignalStoppedLong]
	switch {
	case metrics.Status == verdict.StatusPresent:
		return Catalogue.Present(SignalIdle, map[string]any{"via": "metrics"})
	case stopped.Status == verdict.StatusPresent:
		return Catalogue.Present(SignalIdle, map[string]any{"via": "stopped"})
	case metrics.Status == verdict.StatusUnknown && stopped.Status != verdict.StatusPresent:
		return Catalogue.Unknown(SignalIdle, metrics.Unknown)
	default:
		return Catalogue.Absent(SignalIdle)
	}
}

func vnetIntegration(resource collect.Resource) verdict.Evidence {
	subnet, _ := resource.Properties["virtualNetworkSubnetId"].(string)
	if subnet == "" {
		return Catalogue.Absent(SignalVNet)
	}
	return Catalogue.Present(SignalVNet, map[string]any{"owner": subnet})
}

// stoppedState reports a stopped site and whether it has been stopped long
// enough to count as idle. A stop nobody reversed is the clearest evidence a
// site is unused; a recent one is not.
func stoppedState(in Input) (stopped, long verdict.Evidence) {
	state, _ := in.Resource.Properties["state"].(string)
	if !strings.EqualFold(state, "Stopped") {
		return Catalogue.Absent(SignalStopped), Catalogue.Absent(SignalStoppedLong)
	}
	if !in.Generic.ActivityLogRead {
		unknown := &verdict.Unknown{Code: verdict.UnkDependency, Message: "the Activity Log could not be read"}
		return Catalogue.Present(SignalStopped, map[string]any{"daysAgo": 0}),
			Catalogue.Unknown(SignalStoppedLong, unknown)
	}
	lastStop, lastStart := time.Time{}, time.Time{}
	for _, event := range in.Generic.ActivityLog.Events {
		if !strings.EqualFold(event.Status, "Succeeded") {
			continue
		}
		operation := strings.ToLower(event.Operation)
		switch {
		case strings.HasSuffix(operation, "/stop/action") && event.Timestamp.After(lastStop):
			lastStop = event.Timestamp
		case strings.HasSuffix(operation, "/start/action") && event.Timestamp.After(lastStart):
			lastStart = event.Timestamp
		}
	}
	cutoff := in.Cutoff.AddDate(0, 0, -StoppedDays)
	modified := lastModified(in.Resource)
	longEnough := (!lastStop.IsZero() && lastStop.Before(cutoff) && lastStart.Before(lastStop)) ||
		(lastStop.IsZero() && lastStart.IsZero() && !modified.IsZero() && modified.Before(cutoff))
	days := StoppedDays
	if !lastStop.IsZero() {
		days = int(in.Cutoff.Sub(lastStop) / (24 * time.Hour))
	} else if !modified.IsZero() {
		days = int(in.Cutoff.Sub(modified) / (24 * time.Hour))
	}
	if !longEnough {
		return Catalogue.Present(SignalStopped, map[string]any{"daysAgo": days}),
			signal.Windowed(Catalogue.Absent(SignalStoppedLong), in.Cutoff, StoppedDays)
	}
	// A site stopped long ago is reported by the idle signal rather than twice.
	return Catalogue.Absent(SignalStopped),
		signal.Windowed(Catalogue.Present(SignalStoppedLong,
			map[string]any{"quietDays": days}), in.Cutoff, StoppedDays)
}

func lastModified(resource collect.Resource) time.Time {
	value, _ := resource.Properties["lastModifiedTimeUtc"].(string)
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.9999999"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

// deploySilence is the Required signal that nobody has deployed to or
// reconfigured this site over the effective window.
func deploySilence(in Input) verdict.Evidence {
	if !in.Generic.ActivityLogRead {
		return Catalogue.Unknown(SignalNoDeploys, &verdict.Unknown{
			Code: verdict.UnkDependency, Message: "the Activity Log could not be read"})
	}
	effective := in.effective()
	for _, event := range in.Generic.ActivityLog.Events {
		if !strings.EqualFold(event.Status, "Succeeded") ||
			strings.Contains(strings.ToLower(event.Caller), "azcid") ||
			event.Timestamp.Before(effective.Start) {
			continue
		}
		if deployment(event.Operation) {
			return signal.Windowed(Catalogue.Absent(SignalNoDeploys), in.Cutoff, effective.Days)
		}
	}
	if effective.Days == 0 || in.Generic.ActivityLog.Truncated || in.Generic.ActivityLog.Days < effective.Days {
		return Catalogue.Unknown(SignalNoDeploys, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the Activity Log did not cover the effective window"})
	}
	return signal.Windowed(Catalogue.Present(SignalNoDeploys,
		map[string]any{"quietDays": effective.Days}), in.Cutoff, effective.Days)
}

// deployment are the operations that mean somebody shipped to this site or
// changed how it runs.
func deployment(operation string) bool {
	operation = strings.ToLower(operation)
	for _, marker := range []string{"/publish/action", "/slotsswap/action", "/restart/action",
		"/config/write", "/deployments/write", "/sourcecontrols/write", "/sites/write"} {
		if strings.HasSuffix(operation, marker) {
			return true
		}
	}
	return false
}

// collectPlan runs the plan analyzer. A plan with sites on it must not be
// deleted; an empty one costs money for nothing.
func collectPlan(ctx context.Context, in Input) map[string]verdict.Evidence {
	sites, hasCount := planSiteCount(in.Resource)
	collected := map[string]verdict.Evidence{}
	switch {
	case !hasCount:
		unknown := &verdict.Unknown{Code: verdict.UnkUnsupported,
			Message: "the plan did not report how many sites it hosts"}
		collected[SignalPlanSites] = Catalogue.Unknown(SignalPlanSites, unknown)
		collected[SignalPlanEmpty] = Catalogue.Unknown(SignalPlanEmpty, unknown)
	case sites > 0:
		collected[SignalPlanSites] = Catalogue.Present(SignalPlanSites, map[string]any{"siteCount": sites})
		collected[SignalPlanEmpty] = Catalogue.Absent(SignalPlanEmpty)
	default:
		collected[SignalPlanSites] = Catalogue.Absent(SignalPlanSites)
		collected[SignalPlanEmpty] = Catalogue.Present(SignalPlanEmpty, map[string]any{"siteCount": 0})
	}
	collected[SignalPlanQuiet] = planQuiet(in)
	for id, evidence := range planGraphSignals(ctx, in) {
		collected[id] = evidence
	}
	return collected
}

func planSiteCount(resource collect.Resource) (int, bool) {
	value, ok := resource.Properties["numberOfSites"]
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case float64:
		return int(typed), true
	case int:
		return typed, true
	default:
		return 0, false
	}
}

// planQuiet is the Required signal that nobody has changed the plan for the
// fixed thirty days.
func planQuiet(in Input) verdict.Evidence {
	if !in.Generic.ActivityLogRead {
		return Catalogue.Unknown(SignalPlanQuiet, &verdict.Unknown{
			Code: verdict.UnkDependency, Message: "the Activity Log could not be read"})
	}
	if in.Generic.ActivityLog.Truncated || in.Generic.ActivityLog.Days < PlanQuietDays {
		return Catalogue.Unknown(SignalPlanQuiet, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the Activity Log did not cover the fixed 30-day period"})
	}
	since := in.Cutoff.AddDate(0, 0, -PlanQuietDays)
	for _, event := range in.Generic.ActivityLog.Events {
		if event.Timestamp.Before(since) || !strings.EqualFold(event.Status, "Succeeded") ||
			strings.Contains(strings.ToLower(event.Caller), "azcid") {
			continue
		}
		if operation := strings.ToLower(event.Operation); strings.HasSuffix(operation, "/write") {
			return signal.Windowed(Catalogue.Absent(SignalPlanQuiet), in.Cutoff, PlanQuietDays)
		}
	}
	return signal.Windowed(Catalogue.Present(SignalPlanQuiet,
		map[string]any{"quietDays": PlanQuietDays}), in.Cutoff, PlanQuietDays)
}

// planGraphSignals reads the autoscale rule and the Advisor recommendation,
// both of which live in the graph.
func planGraphSignals(ctx context.Context, in Input) map[string]verdict.Evidence {
	if !in.Generic.ARGVisible {
		return map[string]verdict.Evidence{
			SignalPlanAutoscale: Catalogue.Unknown(SignalPlanAutoscale, in.Generic.ARGUnknown),
			SignalPlanAdvisor:   Catalogue.Unknown(SignalPlanAdvisor, in.Generic.ARGUnknown),
		}
	}
	graph := in.graph()
	out := map[string]verdict.Evidence{}
	rows, err := graph.Query(ctx, autoscaleQuery, signal.Lower(in.Target.ID))
	switch {
	case err != nil:
		out[SignalPlanAutoscale] = Catalogue.Failed(SignalPlanAutoscale, err)
	case len(rows.Rows) == 0:
		out[SignalPlanAutoscale] = Catalogue.Absent(SignalPlanAutoscale)
	default:
		out[SignalPlanAutoscale] = Catalogue.Present(SignalPlanAutoscale,
			map[string]any{"referenceCount": len(rows.Rows)})
	}
	advisor, err := graph.Query(ctx, advisorQuery, signal.Lower(in.Target.ID))
	if err != nil {
		out[SignalPlanAdvisor] = Catalogue.Failed(SignalPlanAdvisor, err)
		return out
	}
	for _, row := range advisor.Rows {
		if recommendation, _ := row["recType"].(string); strings.HasPrefix(
			strings.ToLower(recommendation), EmptyPlanAdvisor) {
			out[SignalPlanAdvisor] = Catalogue.Present(SignalPlanAdvisor,
				map[string]any{"recommendationCount": len(advisor.Rows)})
			return out
		}
	}
	out[SignalPlanAdvisor] = Catalogue.Absent(SignalPlanAdvisor)
	return out
}

func apiVersion() (string, error) { return rules.APIVersion(SiteType) }
