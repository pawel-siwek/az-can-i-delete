package site

import (
	"context"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The site metric names of SPEC section 5.7.
const (
	requestsMetric   = "Requests"
	http2xxMetric    = "Http2xx"
	cpuTimeMetric    = "CpuTime"
	instancesMetric  = "InstanceCount"
	executionsMetric = "FunctionExecutionCount"
	workflowsMetric  = "WorkflowRunsStarted"
)

// trafficGroup applies the request rules. The question it answers is not "did
// this site receive requests" but "did it receive more than its own
// configuration would produce": Always On and a health check path make a site
// talk to itself all day.
type trafficGroup struct{}

// day is one day of a site's metrics.
type day struct {
	requests  float64
	http2xx   float64
	cpuTime   float64
	instances float64
}

func (trafficGroup) run(in Input, config *configGroup) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		if in.Clients.Metrics == nil {
			return []verdict.Evidence{
				Catalogue.NotEvaluated(SignalRealTraffic), Catalogue.NotEvaluated(SignalProbeShaped),
				Catalogue.NotEvaluated(SignalLowVolume), Catalogue.NotEvaluated(SignalFunctionRuns),
				Catalogue.NotEvaluated(SignalWorkflowRuns), Catalogue.NotEvaluated(SignalMetricSilence),
			}, nil
		}
		days, err := requestDays(ctx, in)
		if err != nil {
			return nil, err
		}
		effective := in.effective()
		excluded := deploymentDays(in)
		class := config.class
		if !config.read {
			class = ClassUnknown
		}

		live, probe := 0, 0
		requests, cpu := float64(0), float64(0)
		peak := float64(0)
		for stamp, value := range days {
			workers := value.instances
			if workers <= 0 {
				workers = float64(max(config.capacity, 1))
			}
			ceiling := workers * float64(
				AlwaysOnRequestsPerDay*boolean(config.alwaysOn)+HealthCheckRequestsPerDay*boolean(config.healthCheck))
			probeShaped := value.requests > ProbeRequestFloor && value.http2xx >= ProbeSuccessRatio*value.requests
			if probeShaped {
				probe++
			}
			if !excluded[stamp] && !probeShaped &&
				value.http2xx > maxFloat(LiveMultiplier*ceiling, ceiling+LiveHeadroom) {
				live++
			}
			if !outside(stamp, effective) {
				requests += value.requests
				cpu += value.cpuTime
			}
			peak = maxFloat(peak, value.requests)
		}

		executions, executionCount, err := classCounter(ctx, in, class)
		if err != nil {
			return nil, err
		}
		workflows, workflowCount, err := workflowCounter(ctx, in, class)
		if err != nil {
			return nil, err
		}
		realTraffic := signal.Windowed(Catalogue.Absent(SignalRealTraffic), in.Cutoff, in.Requested.Days)
		if live >= LiveDays {
			realTraffic = signal.Windowed(Catalogue.Present(SignalRealTraffic, map[string]any{
				"liveDays": live, "peakRequests": peak}), in.Cutoff, in.Requested.Days)
		}
		probeShaped := signal.Windowed(Catalogue.Absent(SignalProbeShaped), in.Cutoff, in.Requested.Days)
		if probe >= LiveDays {
			probeShaped = signal.Windowed(Catalogue.Present(SignalProbeShaped,
				map[string]any{"probeDays": probe}), in.Cutoff, in.Requested.Days)
		}
		lowVolume := signal.Windowed(Catalogue.Absent(SignalLowVolume), in.Cutoff, in.Requested.Days)
		if total(days) > 0 && live < LiveDays {
			lowVolume = signal.Windowed(Catalogue.Present(SignalLowVolume,
				map[string]any{"requestCount": total(days)}), in.Cutoff, in.Requested.Days)
		}
		return []verdict.Evidence{
			realTraffic, probeShaped, lowVolume, executions, workflows,
			metricSilence(in, effective, requests, cpu, executionCount, workflowCount, class),
		}, nil
	}
}

// metricSilence is the Required silence signal. It needs the site to have been
// running: quiet metrics from a stopped site say nothing that the stopped
// signal does not already say better.
func metricSilence(in Input, effective verdict.Window, requests, cpu, executions, workflows float64, class string) verdict.Evidence {
	state, _ := in.Resource.Properties["state"].(string)
	if !strings.EqualFold(state, "Running") {
		return Catalogue.Unknown(SignalMetricSilence, &verdict.Unknown{
			Code:    verdict.UnkDependency,
			Message: "the site was not running, so quiet metrics do not establish that nobody wanted it"})
	}
	if effective.Days == 0 {
		return Catalogue.Unknown(SignalMetricSilence, &verdict.Unknown{
			Code: verdict.UnkPartial, Message: "the site's age leaves no effective window to observe"})
	}
	if unsupportedCounter(class) {
		return Catalogue.Unknown(SignalMetricSilence, &verdict.Unknown{
			Code:    verdict.UnkUnsupported,
			Message: "this hosting class has no execution counter, so the site cannot be shown to have run nothing"})
	}
	if requests > 0 || cpu > 0 || executions > 0 || workflows > 0 {
		return signal.Windowed(Catalogue.Absent(SignalMetricSilence), in.Cutoff, effective.Days)
	}
	return signal.Windowed(Catalogue.Present(SignalMetricSilence,
		map[string]any{"quietDays": effective.Days}), in.Cutoff, effective.Days)
}

// unsupportedCounter reports the hosting classes whose function executions
// Azure Monitor does not publish under the current rules.
func unsupportedCounter(class string) bool {
	switch class {
	case ClassConsumption, ClassDedicated, ClassWorkflow:
		return true
	default:
		return false
	}
}

// classCounter reads the execution counter that exists for this hosting class.
// For the classes that have none, the signal is unknown rather than zero, which
// is what keeps a Linux function app from being reported as idle.
func classCounter(ctx context.Context, in Input, class string) (verdict.Evidence, float64, error) {
	if !functionApp(in.Resource) {
		return Catalogue.Absent(SignalFunctionRuns), 0, nil
	}
	if unsupportedCounter(class) && class != ClassWorkflow {
		return Catalogue.Unknown(SignalFunctionRuns, &verdict.Unknown{
			Code:    verdict.UnkUnsupported,
			Message: "Azure Monitor publishes no execution counter for this hosting class"}), 0, nil
	}
	if class == ClassWorkflow {
		return Catalogue.Absent(SignalFunctionRuns), 0, nil
	}
	total, err := metricTotal(ctx, in, executionsMetric, "Total", in.Requested)
	if err != nil {
		return verdict.Evidence{}, 0, err
	}
	if total == 0 {
		return signal.Windowed(Catalogue.Absent(SignalFunctionRuns), in.Cutoff, in.Requested.Days), 0, nil
	}
	return signal.Windowed(Catalogue.Present(SignalFunctionRuns,
		map[string]any{"executionCount": total}), in.Cutoff, in.Requested.Days), total, nil
}

// workflowCounter reads the workflow run counter for a logic app.
func workflowCounter(ctx context.Context, in Input, class string) (verdict.Evidence, float64, error) {
	if !strings.Contains(strings.ToLower(in.Resource.Kind), "workflowapp") {
		return Catalogue.Absent(SignalWorkflowRuns), 0, nil
	}
	if class == ClassWorkflow {
		return Catalogue.Unknown(SignalWorkflowRuns, &verdict.Unknown{
			Code:    verdict.UnkUnsupported,
			Message: "Azure Monitor publishes no workflow counter for this hosting class"}), 0, nil
	}
	total, err := metricTotal(ctx, in, workflowsMetric, "Total", in.Requested)
	if err != nil {
		return verdict.Evidence{}, 0, err
	}
	if total == 0 {
		return signal.Windowed(Catalogue.Absent(SignalWorkflowRuns), in.Cutoff, in.Requested.Days), 0, nil
	}
	return signal.Windowed(Catalogue.Present(SignalWorkflowRuns,
		map[string]any{"runCount": total}), in.Cutoff, in.Requested.Days), total, nil
}

// requestDays reads the request, success, processor-time and instance-count
// metrics and folds them into one record per day.
func requestDays(ctx context.Context, in Input) (map[time.Time]day, error) {
	days := map[time.Time]day{}
	for _, metric := range []struct {
		name        string
		aggregation string
		assign      func(*day, float64)
	}{
		{requestsMetric, "Total", func(d *day, value float64) { d.requests += value }},
		{http2xxMetric, "Total", func(d *day, value float64) { d.http2xx += value }},
		{cpuTimeMetric, "Total", func(d *day, value float64) { d.cpuTime += value }},
		{instancesMetric, "Average", func(d *day, value float64) { d.instances = maxFloat(d.instances, value) }},
	} {
		result, err := in.Clients.Metrics.Metrics(ctx, collect.MetricQuery{
			ResourceURI: in.Target.ID, Names: []string{metric.name},
			Aggregation: metric.aggregation, Interval: "P1D", Window: in.Requested})
		if err != nil {
			return nil, err
		}
		for _, series := range result.Series {
			for _, point := range series.Points {
				stamp := point.Timestamp.UTC().Truncate(24 * time.Hour)
				value := days[stamp]
				metric.assign(&value, point.Value)
				days[stamp] = value
			}
		}
	}
	return days, nil
}

func metricTotal(ctx context.Context, in Input, name, aggregation string, window verdict.Window) (float64, error) {
	result, err := in.Clients.Metrics.Metrics(ctx, collect.MetricQuery{
		ResourceURI: in.Target.ID, Names: []string{name},
		Aggregation: aggregation, Interval: "P1D", Window: window})
	if err != nil {
		return 0, err
	}
	total := float64(0)
	for _, series := range result.Series {
		for _, point := range series.Points {
			total += point.Value
		}
	}
	return total, nil
}

// deploymentDays are the days somebody deployed, swapped or restarted. The
// traffic those days is the deployment's own, so they do not count as live.
func deploymentDays(in Input) map[time.Time]bool {
	days := map[time.Time]bool{}
	if !in.Generic.ActivityLogRead {
		return days
	}
	for _, event := range in.Generic.ActivityLog.Events {
		if strings.EqualFold(event.Status, "Succeeded") && deployment(event.Operation) {
			days[event.Timestamp.UTC().Truncate(24*time.Hour)] = true
		}
	}
	return days
}

func total(days map[time.Time]day) float64 {
	sum := float64(0)
	for _, value := range days {
		sum += value.requests
	}
	return sum
}

func outside(stamp time.Time, window verdict.Window) bool {
	return stamp.Before(window.Start.UTC().Truncate(24*time.Hour)) || stamp.After(window.End.UTC())
}

func boolean(value bool) int {
	if value {
		return 1
	}
	return 0
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
