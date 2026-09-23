package cordon

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Status is what a cordon looks like from outside: the tag, the state the
// resource is actually in, and what has happened to it since. It reads; it
// never changes anything, which is why the MCP server may serve it.
type Status struct {
	ResourceID   string `json:"resourceId"`
	ResourceType string `json:"resourceType"`
	Cordoned     bool   `json:"cordoned"`
	// Source says where the cordon state came from: the tag on the resource,
	// or this machine's history when the tag is gone.
	Source         string       `json:"source,omitempty"`
	TagCorrupt     bool         `json:"tagCorrupt,omitempty"`
	Mode           Mode         `json:"mode,omitempty"`
	Since          *time.Time   `json:"since,omitempty"`
	By             string       `json:"by,omitempty"`
	Prior          string       `json:"prior,omitempty"`
	WindowDays     int          `json:"windowDays,omitempty"`
	ElapsedHours   *int         `json:"elapsedHours,omitempty"`
	RemainingHours *int         `json:"remainingHours,omitempty"`
	CurrentState   string       `json:"currentState,omitempty"`
	Slots          []SlotStatus `json:"slots,omitempty"`
	Reverted       bool         `json:"reverted"`
	RevertedAt     *time.Time   `json:"revertedAt,omitempty"`
	// Activity is what reached the resource since the cordon started. A
	// counter that could not be read is listed under unknowns instead, never
	// reported as zero.
	Activity  []Counter         `json:"activity"`
	Unknowns  []StatusUnknown   `json:"unknowns"`
	Caveats   []string          `json:"caveats"`
	Untrusted map[string]string `json:"untrusted,omitempty"`
}

// SlotStatus is a deployment slot's recorded and current state.
type SlotStatus struct {
	Name    string `json:"name"`
	Prior   string `json:"prior"`
	Current string `json:"current,omitempty"`
}

// Counter is one metric total since the cordon started.
type Counter struct {
	Metric  string  `json:"metric"`
	Total   float64 `json:"total"`
	Meaning string  `json:"meaning"`
}

// StatusUnknown is a status input that could not be read.
type StatusUnknown struct {
	ID string `json:"id"`
	verdict.Unknown
}

// The fixed caveats. They are printed on every status for the mode, because
// the thing a scream test cannot hear is the thing most worth saying.
const (
	CaveatStorage = "denied public requests may not be recorded in metrics (unverified); private-endpoint and trusted-service traffic is not blocked"
	CaveatSite    = "nothing keeps running; Always On is ineffective while stopped and continuous WebJobs stop with the site. Callers receive HTTP 403 \"Site Disabled\"."
	CaveatOwnHour = "the hour the cordon was applied is excluded from every total: it holds this tool's own writes"
	CaveatHistory = "the azcid tag is missing; this state comes from the local history file, which only knows what this machine did"
	CaveatCorrupt = "the azcid tag does not parse, so the prior state is unknown and is not guessed; restore it by hand (az storage account update --public-network-access Enabled, or az webapp start)"
	CaveatBefore  = "metrics older than 93 days are not retained; totals cover only the retained part of the cordon"
)

// NotBlocked is printed with a cordon's plan and its status: what the
// cordon does not isolate (SPEC appendix E section 6.2, verbatim).
var NotBlocked = map[Mode]string{
	ModePNA:  "not blocked by this cordon: private endpoints, resource-instance rules (networkAcls.resourceAccessRules), trusted Azure services (networkAcls.bypass), replication and backup services. Denied public requests may not appear in metrics.",
	ModeStop: "not blocked by this cordon: nothing keeps running; note that Always On is ineffective while stopped and continuous WebJobs stop with the site. Callers receive HTTP 403 \"Site Disabled\".",
}

// Reader answers status questions. It holds only read boundaries.
type Reader struct {
	ARM         collect.ARMClient
	Metrics     collect.MetricsClient
	ActivityLog collect.ActivityLogClient
}

// StatusOptions are the per-call choices.
type StatusOptions struct {
	// Now is the observation time; this package reads no clock.
	Now time.Time
	// History is consulted only when FromHistory is set and the tag is gone.
	History     History
	FromHistory bool
}

// ErrNotFound is returned for a resource ARM does not have.
var ErrNotFound = errors.New("the resource was not found")

// metricRetention is how far back Azure Monitor keeps platform metrics.
const metricRetention = 93 * 24 * time.Hour

// Status reports the cordon on target. A type the gate refuses is a Refusal,
// exactly as cordon would print it.
func (r Reader) Status(ctx context.Context, target armid.Target, opts StatusOptions) (Status, error) {
	mode, refusal := Gate(target.ResourceType)
	if refusal != nil {
		return Status{}, refusal
	}
	version, err := rules.APIVersion(target.ResourceType)
	if err != nil {
		return Status{}, err
	}
	resource, err := r.ARM.Get(ctx, target.ID, version)
	if err != nil {
		if collect.NotFound(err) {
			return Status{}, ErrNotFound
		}
		return Status{}, fmt.Errorf("reading %s: %w", target.ResourceType, err)
	}

	status := Status{
		ResourceID: target.ID, ResourceType: target.ResourceType,
		CurrentState: CurrentState(mode, resource),
		Activity:     []Counter{}, Unknowns: []StatusUnknown{}, Caveats: []string{},
	}
	raw, tagged := TagValue(resource.Tags)
	var state State
	switch {
	case tagged:
		status.Cordoned, status.Source = true, "tag"
		parsed, parseErr := Parse(raw)
		if parseErr != nil || parsed.Mode != mode {
			status.TagCorrupt = true
			status.Untrusted = map[string]string{"tag": output.Untrusted(raw)}
			status.Caveats = append(status.Caveats, CaveatCorrupt)
			return status, nil
		}
		state = parsed
	case opts.FromHistory:
		entry, historyErr := opts.History.LatestCordon(target.ID)
		if errors.Is(historyErr, ErrNoHistory) {
			return status, nil
		}
		if historyErr != nil {
			return Status{}, historyErr
		}
		parsed, parseErr := entry.State()
		if parseErr != nil || parsed.Mode != mode {
			return Status{}, fmt.Errorf("the history entry for this resource is damaged: %w", ErrCorrupt)
		}
		status.Cordoned, status.Source = true, "history"
		status.Caveats = append(status.Caveats, CaveatHistory)
		state = parsed
	default:
		return status, nil
	}

	now := opts.Now.UTC()
	since := state.Since.UTC()
	status.Mode, status.Since, status.By, status.Prior, status.WindowDays = state.Mode, &since, state.By, state.Prior, state.WindowDays
	elapsed := int(math.Max(0, now.Sub(since).Hours()))
	remaining := int(state.Remaining(now).Hours())
	status.ElapsedHours, status.RemainingHours = &elapsed, &remaining

	if mode == ModeStop {
		status.Slots = r.slots(ctx, target, version, state, &status)
	}
	status.Reverted = status.Reverted || status.CurrentState != cordonedState(mode)
	if status.Reverted {
		r.revertedBy(ctx, target, since, now, &status)
	}
	r.activity(ctx, target, mode, since, now, &status)
	return status, nil
}

// TagValue finds the azcid tag. Azure treats tag names case-insensitively, so
// this does too.
func TagValue(tags map[string]string) (string, bool) {
	for key, value := range tags {
		if strings.EqualFold(key, TagKey) {
			return value, true
		}
	}
	return "", false
}

// CurrentState is the state a cordon changes, read from the resource body and
// held to the values this tool knows. Anything else is reported as such, never
// passed through: it is Azure's text, and it would be free-form in a typed
// field.
func CurrentState(mode Mode, resource collect.Resource) string {
	switch mode {
	case ModePNA:
		value, _ := resource.Properties["publicNetworkAccess"].(string)
		for _, known := range []string{PriorEnabled, "Disabled", PriorSecuredByPerimeter} {
			if strings.EqualFold(value, known) {
				return known
			}
		}
		if value == "" {
			// An account that never set the property is open to public
			// networks, which is what Enabled means.
			return PriorEnabled
		}
	case ModeStop:
		value, _ := resource.Properties["state"].(string)
		for _, known := range []string{Running, Stopped} {
			if strings.EqualFold(value, known) {
				return known
			}
		}
	}
	return "unrecognized"
}

func cordonedState(mode Mode) string {
	if mode == ModePNA {
		return "Disabled"
	}
	return Stopped
}

func (r Reader) slots(ctx context.Context, target armid.Target, version string, state State, status *Status) []SlotStatus {
	current := map[string]string{}
	listed, err := r.ARM.List(ctx, target.ID+"/slots", version)
	if err != nil {
		status.Unknowns = append(status.Unknowns, StatusUnknown{ID: "cordon.slots", Unknown: *collect.Classify(err)})
	}
	for _, slot := range listed {
		name := slot.Name
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		current[strings.ToLower(name)] = CurrentState(ModeStop, slot)
	}
	out := make([]SlotStatus, 0, len(state.Slots))
	for _, slot := range state.Slots {
		row := SlotStatus{Name: slot.Name, Prior: slot.State}
		if err == nil {
			row.Current = current[strings.ToLower(slot.Name)]
			if row.Current == "" {
				row.Current = "missing"
			}
		}
		if row.Current != "" && row.Current != Stopped {
			status.Reverted = true
		}
		out = append(out, row)
	}
	return out
}

// revertedBy finds the last successful write after the cordon started. The
// caller is Azure's text and goes under untrusted, sanitized.
func (r Reader) revertedBy(ctx context.Context, target armid.Target, since, now time.Time, status *Status) {
	if r.ActivityLog == nil {
		return
	}
	window := hourly(since, now)
	log, err := r.ActivityLog.Events(ctx, target.ID, window)
	if err != nil {
		status.Unknowns = append(status.Unknowns, StatusUnknown{ID: "cordon.reverted-by", Unknown: *collect.Classify(err)})
		return
	}
	var latest *collect.ActivityEvent
	for i, event := range log.Events {
		if !strings.EqualFold(event.Status, "Succeeded") || !event.Timestamp.After(since) {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(event.Operation), "/write") && !strings.HasSuffix(strings.ToLower(event.Operation), "/action") {
			continue
		}
		if latest == nil || event.Timestamp.After(latest.Timestamp) {
			latest = &log.Events[i]
		}
	}
	if latest == nil {
		return
	}
	at := latest.Timestamp.UTC()
	status.RevertedAt = &at
	if latest.Caller != "" {
		if status.Untrusted == nil {
			status.Untrusted = map[string]string{}
		}
		status.Untrusted["revertedBy"] = output.Untrusted(latest.Caller)
		status.Untrusted["revertedByClass"] = callerClass(latest.Caller)
	}
}

func callerClass(caller string) string {
	if strings.Contains(caller, "@") {
		return "user"
	}
	return "service principal"
}

// activity reads the counters of SPEC appendix E section 6.5.
func (r Reader) activity(ctx context.Context, target armid.Target, mode Mode, since, now time.Time, status *Status) {
	switch mode {
	case ModePNA:
		status.Caveats = append(status.Caveats, CaveatStorage)
	case ModeStop:
		status.Caveats = append(status.Caveats, CaveatSite)
	}
	if r.Metrics == nil {
		return
	}
	status.Caveats = append(status.Caveats, CaveatOwnHour)
	start := since
	if now.Sub(start) > metricRetention {
		start = now.Add(-metricRetention)
		status.Caveats = append(status.Caveats, CaveatBefore)
	}
	window := hourly(start, now)
	switch mode {
	case ModePNA:
		r.total(ctx, status, since, collect.MetricQuery{
			ResourceURI: target.ID, Names: []string{"Transactions"},
			Filter: "ResponseType eq '*' and TransactionType eq 'User'", Aggregation: "Total",
			Interval: "PT1H", Window: window,
		}, map[string]string{"Transactions": "user transactions since the cordon, allowed and denied"})
		r.growth(ctx, status, collect.MetricQuery{
			ResourceURI: target.ID, Names: []string{"UsedCapacity"}, Aggregation: "Average",
			Interval: "PT1H", Window: window,
		})
	case ModeStop:
		r.total(ctx, status, since, collect.MetricQuery{
			ResourceURI: target.ID, Names: []string{"Requests", "Http403", "Http5xx"}, Aggregation: "Total",
			Interval: "PT1H", Window: window,
		}, map[string]string{
			"Requests": "requests since the cordon",
			"Http403":  "callers that hit the stopped site: the screams",
			"Http5xx":  "server errors since the cordon",
		})
	}
}

// total sums each metric over the cordon, leaving out the hour the cordon was
// applied in.
func (r Reader) total(ctx context.Context, status *Status, since time.Time, query collect.MetricQuery, meanings map[string]string) {
	result, err := r.Metrics.Metrics(ctx, query)
	var unknown *verdict.Unknown
	switch {
	case err != nil:
		unknown = collect.Classify(err)
	case result.Truncated:
		// A saturated answer is a lower bound, and a lower bound printed as
		// a total is the absence-for-failure mistake in another form.
		unknown = &verdict.Unknown{Code: verdict.UnkPartial, Message: "the metric answer was truncated"}
	}
	if unknown != nil {
		for _, name := range query.Names {
			status.Unknowns = append(status.Unknowns, StatusUnknown{ID: "cordon.metric." + name, Unknown: *unknown})
		}
		return
	}
	own := since.UTC().Truncate(time.Hour)
	totals := map[string]float64{}
	for _, series := range result.Series {
		for _, point := range series.Points {
			if point.Timestamp.UTC().Truncate(time.Hour).Equal(own) {
				continue
			}
			totals[series.Name] += point.Value
		}
	}
	names := append([]string(nil), query.Names...)
	sort.Strings(names)
	for _, name := range names {
		status.Activity = append(status.Activity, Counter{Metric: name, Total: totals[name], Meaning: meanings[name]})
	}
}

// growth reports whether the account kept growing under the cordon: a
// trusted service or a private endpoint still writing.
func (r Reader) growth(ctx context.Context, status *Status, query collect.MetricQuery) {
	result, err := r.Metrics.Metrics(ctx, query)
	switch {
	case err != nil:
		status.Unknowns = append(status.Unknowns, StatusUnknown{ID: "cordon.metric.UsedCapacity", Unknown: *collect.Classify(err)})
		return
	case result.Truncated:
		// Part of a series cannot show growth or its absence.
		status.Unknowns = append(status.Unknowns, StatusUnknown{ID: "cordon.metric.UsedCapacity",
			Unknown: verdict.Unknown{Code: verdict.UnkPartial, Message: "the metric answer was truncated"}})
		return
	}
	var points []collect.MetricPoint
	for _, series := range result.Series {
		points = append(points, series.Points...)
	}
	if len(points) < 2 {
		return
	}
	sort.Slice(points, func(i, j int) bool { return points[i].Timestamp.Before(points[j].Timestamp) })
	delta := points[len(points)-1].Value - points[0].Value
	if delta > 0 {
		status.Activity = append(status.Activity, Counter{Metric: "UsedCapacity", Total: delta,
			Meaning: "bytes added since the cordon: a trusted-service or private-endpoint writer still writing"})
	}
}

func hourly(start, end time.Time) verdict.Window {
	days := int(math.Ceil(end.Sub(start).Hours() / 24))
	if days < 1 {
		days = 1
	}
	return verdict.Window{Start: start.UTC(), End: end.UTC(), Days: days, Grain: "PT1H"}
}
