package disk

import (
	"context"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// The Resource Graph queries of SPEC section 5.4, in the reference spelling of
// appendix L section 4. Each takes the target's lowercased ARM id.
const (
	// K5b: a Backup vault instance whose data source is this disk.
	backupQuery = "recoveryservicesresources " +
		"| where type =~ 'microsoft.dataprotection/backupvaults/backupinstances' " +
		"| where tolower(tostring(properties.dataSourceInfo.resourceID)) == '%s' " +
		"| project id, state = tostring(properties.currentProtectionState)"
	// K13: an image or gallery image version built from this disk.
	imageQuery = "resources " +
		"| where type in~ ('microsoft.compute/images','microsoft.compute/galleries/images/versions') " +
		"| where properties has '%s' | project id, type"
	// K4: Advisor's recommendations for this resource.
	advisorQuery = "advisorresources | where type =~ 'microsoft.advisor/recommendations' " +
		"| where tolower(tostring(properties.resourceMetadata.resourceId)) == '%s' " +
		"| project recType = tostring(properties.recommendationTypeId), category = tostring(properties.category)"
)

// referenceGroup runs one graph-backed signal. A graph the probe could not see
// makes the signal unknown, and no query is issued at all.
type referenceGroup struct{}

func (referenceGroup) run(in Input, query, id string) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		if !in.Generic.ARGVisible {
			return []verdict.Evidence{Catalogue.Unknown(id, in.Generic.ARGUnknown)}, nil
		}
		graph := signal.Graph{Client: in.Clients.Graph, Limiter: in.Graph, Subscription: in.Target.SubscriptionID}
		rows, err := graph.Query(ctx, query, signal.Lower(in.Target.ID))
		if err != nil {
			return nil, err
		}
		return []verdict.Evidence{classify(id, rows)}, nil
	}
}

// classify turns a graph answer into the signal's evidence. Advisor is the one
// query whose rows have to be filtered: only the unattached-disk
// recommendation corroborates idleness.
func classify(id string, rows collect.Rows) verdict.Evidence {
	if id == SignalAdvisor {
		for _, row := range rows.Rows {
			recommendation, _ := row["recType"].(string)
			if strings.HasPrefix(strings.ToLower(recommendation), UnattachedAdvisorType) {
				return Catalogue.Present(SignalAdvisor, map[string]any{"recommendationCount": len(rows.Rows)})
			}
		}
		return Catalogue.Absent(SignalAdvisor)
	}
	if len(rows.Rows) == 0 {
		return Catalogue.Absent(id)
	}
	return Catalogue.Present(id, map[string]any{"referenceCount": len(rows.Rows)})
}

// The composite disk counters. They are read only to contradict an apparently
// idle disk, never to establish that one is in use.
var ioMetrics = []string{
	"Composite Disk Read Bytes/sec",
	"Composite Disk Write Bytes/sec",
	"Composite Disk Read Operations/sec",
	"Composite Disk Write Operations/sec",
}

type metricsGroup struct{}

// run reports I/O observed after the disk's last ownership change. A disk that
// nothing is attached to should have none; if it does, the report says so
// instead of quietly calling the disk idle. The signal is information only.
func (metricsGroup) run(in Input) func(context.Context) ([]verdict.Evidence, error) {
	return func(ctx context.Context) ([]verdict.Evidence, error) {
		if in.Clients.Metrics == nil {
			return []verdict.Evidence{Catalogue.NotEvaluated(SignalIO)}, nil
		}
		result, err := in.Clients.Metrics.Metrics(ctx, collect.MetricQuery{
			ResourceURI: in.Target.ID,
			Names:       ioMetrics,
			Aggregation: "Total",
			Interval:    "P1D",
			Window:      in.Requested,
		})
		if err != nil {
			return nil, err
		}
		since, hasOwnership := ownershipTime(in.Resource)
		busy := 0
		newest := time.Time{}
		for _, series := range result.Series {
			for _, point := range series.Points {
				if point.Value <= 0 || (hasOwnership && point.Timestamp.Before(since)) {
					continue
				}
				busy++
				if point.Timestamp.After(newest) {
					newest = point.Timestamp
				}
			}
		}
		if busy == 0 {
			return []verdict.Evidence{signal.Windowed(Catalogue.Absent(SignalIO), in.Cutoff, in.Requested.Days)}, nil
		}
		evidence := Catalogue.Present(SignalIO, map[string]any{
			"busyPoints": busy, "lastIODaysAgo": int(in.Cutoff.Sub(newest) / (24 * time.Hour))})
		return []verdict.Evidence{signal.Windowed(evidence, in.Cutoff, in.Requested.Days)}, nil
	}
}
