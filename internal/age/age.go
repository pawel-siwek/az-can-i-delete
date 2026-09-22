// Package age resolves current-incarnation age from normalized observations
// using the pure seven-source chain in architect-3 section 2.1.
package age

import (
	"slices"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// ActivityEvent is a normalized Activity Log observation. HTTPMethod is
// descriptive only; only Succeeded events can establish or reset an age.
type ActivityEvent struct {
	ResourceID string    `json:"resourceId"`
	Timestamp  time.Time `json:"timestamp"`
	Operation  string    `json:"operation"`
	Status     string    `json:"status"`
	StatusCode string    `json:"statusCode,omitempty"`
	SubStatus  string    `json:"subStatus,omitempty"`
	HTTPMethod string    `json:"httpMethod,omitempty"`
}

// ResourceChange represents a committed Resource Changes row, not an attempted
// operation. Create and Delete describe the resource state transition itself.
type ResourceChange struct {
	ResourceID string    `json:"resourceId"`
	Timestamp  time.Time `json:"timestamp"`
	ChangeType string    `json:"changeType"`
	Operation  string    `json:"operation"`
}

// Deployment is a normalized deployment with its explicit output resource IDs.
// Failed or incomplete deployments are not current-object age witnesses.
type Deployment struct {
	Timestamp       time.Time `json:"timestamp"`
	Status          string    `json:"status"`
	OutputResources []string  `json:"outputResources"`
}

// Input contains observations and an explicit cutoff, with no client or clock.
// RPTimestamp must refer to the CURRENT object. Positive normalized observations
// may be synthetic or archived; this function makes no Azure-retention claim.
// ActivityLogDays and completion flags are required only for no-event inference.
type Input struct {
	ResourceID           string           `json:"resourceId"`
	Cutoff               time.Time        `json:"cutoff"`
	RPTimestamp          *time.Time       `json:"rpTimestamp,omitempty"`
	ActivityLog          []ActivityEvent  `json:"activityLog"`
	ResourceChanges      []ResourceChange `json:"resourceChanges"`
	Deployments          []Deployment     `json:"deployments"`
	ActivityLogSucceeded bool             `json:"activityLogSucceeded"`
	ActivityLogTruncated bool             `json:"activityLogTruncated"`
	ActivityLogDays      int              `json:"activityLogDays"`
}

// ResolveAge implements the seven-source age chain without I/O or clock reads.
// It discards sources 2-5 at or before the last same-ID successful delete; the
// current RP timestamp is exempt. Missing/truncated logs cannot infer no events.
func ResolveAge(in Input) verdict.Age {
	unknown := verdict.Age{Confidence: "unknown", Source: "none", Caveats: []string{}}
	if in.Cutoff.IsZero() || in.ResourceID == "" {
		return unknown
	}
	validTime := func(ts time.Time) bool { return !ts.IsZero() && !ts.After(in.Cutoff) }
	answer := func(ts time.Time, confidence, source string) verdict.Age {
		return verdict.Age{LowerBoundDays: int(in.Cutoff.Sub(ts) / (24 * time.Hour)), Confidence: confidence, Source: source, Caveats: []string{}}
	}
	if in.RPTimestamp != nil && validTime(*in.RPTimestamp) {
		return answer(*in.RPTimestamp, "verified", "rp.timestamp")
	}
	var deleted time.Time
	eventCount := 0
	for _, e := range in.ActivityLog {
		if !strings.EqualFold(e.ResourceID, in.ResourceID) || !validTime(e.Timestamp) {
			continue
		}
		eventCount++
		if e.Status == "Succeeded" && strings.HasSuffix(strings.ToLower(e.Operation), "/delete") && e.Timestamp.After(deleted) {
			deleted = e.Timestamp
		}
	}
	for _, e := range in.ResourceChanges {
		if strings.EqualFold(e.ResourceID, in.ResourceID) && validTime(e.Timestamp) &&
			e.ChangeType == "Delete" && e.Timestamp.After(deleted) {
			deleted = e.Timestamp
		}
	}
	applicable := func(ts time.Time) bool { return validTime(ts) && ts.After(deleted) }
	var created time.Time
	moved := false
	for _, e := range in.ResourceChanges {
		if !strings.EqualFold(e.ResourceID, in.ResourceID) || !applicable(e.Timestamp) || e.ChangeType != "Create" {
			continue
		}
		isMove := strings.Contains(strings.ToLower(e.Operation), "moveresources")
		if created.IsZero() || e.Timestamp.Before(created) {
			created, moved = e.Timestamp, isMove
		} else if e.Timestamp.Equal(created) && isMove {
			moved = true
		}
	}
	if !created.IsZero() {
		if moved {
			return answer(created, "bounded", "resourcechanges.move")
		}
		return answer(created, "verified", "resourcechanges.create")
	}
	var alCreated, oldestEvent time.Time
	for _, e := range in.ActivityLog {
		if !strings.EqualFold(e.ResourceID, in.ResourceID) || !applicable(e.Timestamp) || e.Status != "Succeeded" {
			continue
		}
		oldestEvent = earlier(oldestEvent, e.Timestamp)
		if strings.HasSuffix(strings.ToLower(e.Operation), "/write") &&
			(e.StatusCode == "Created" || e.SubStatus == "Created") {
			alCreated = earlier(alCreated, e.Timestamp)
		}
	}
	if !alCreated.IsZero() {
		return answer(alCreated, "verified", "activitylog.created")
	}
	var oldestDeployment time.Time
	for _, e := range in.Deployments {
		if applicable(e.Timestamp) && e.Status == "Succeeded" &&
			slices.ContainsFunc(e.OutputResources, func(id string) bool { return strings.EqualFold(id, in.ResourceID) }) {
			oldestDeployment = earlier(oldestDeployment, e.Timestamp)
		}
	}
	if !oldestDeployment.IsZero() {
		return answer(oldestDeployment, "bounded", "deployments")
	}
	if !oldestEvent.IsZero() {
		return answer(oldestEvent, "bounded", "activitylog.oldest-succeeded")
	}
	if in.ActivityLogSucceeded && !in.ActivityLogTruncated && in.ActivityLogDays >= 90 &&
		eventCount == 0 && deleted.IsZero() {
		return verdict.Age{LowerBoundDays: 90, Confidence: "inferred", Source: "activitylog.no-events", Caveats: []string{}}
	}
	return unknown
}

func earlier(a, b time.Time) time.Time {
	if a.IsZero() || b.Before(a) {
		return b
	}
	return a
}
