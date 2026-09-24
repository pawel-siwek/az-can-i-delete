package age

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAgeChainBoundaries(t *testing.T) {
	cutoff := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	id := "/subscriptions/aaaaaaaa-0000-4000-8000-000000000001/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic"
	at := func(days int) time.Time { return cutoff.AddDate(0, 0, -days) }
	event := func(days int, operation, status string) ActivityEvent {
		return ActivityEvent{ResourceID: id, Timestamp: at(days), Operation: "Microsoft.Network/networkInterfaces/" + operation, Status: status}
	}
	change := func(days int, kind, operation string) ResourceChange {
		return ResourceChange{ResourceID: id, Timestamp: at(days), ChangeType: kind, Operation: operation}
	}
	deployment := func(days int) Deployment {
		return Deployment{Timestamp: at(days), Status: "Succeeded", OutputResources: []string{id}}
	}
	tests := []struct {
		name               string
		modify             func(*Input)
		days               int
		confidence, source string
	}{
		{"unknown", func(*Input) {}, 0, "unknown", "none"},
		{"complete-zero-events-89", func(in *Input) { in.ActivityLogSucceeded = true; in.ActivityLogDays = 89 }, 89, "inferred", "activitylog.no-events"},
		{"complete-zero-events-93", func(in *Input) { in.ActivityLogSucceeded = true; in.ActivityLogDays = 93 }, 89, "inferred", "activitylog.no-events"},
		{"short-log-not-inferred", func(in *Input) { in.ActivityLogSucceeded = true; in.ActivityLogDays = 88 }, 0, "unknown", "none"},
		{"truncated-not-inferred", func(in *Input) {
			in.ActivityLogSucceeded = true
			in.ActivityLogDays = 90
			in.ActivityLogTruncated = true
		}, 0, "unknown", "none"},
		{"failed-call-not-inferred", func(in *Input) { in.ActivityLogDays = 90 }, 0, "unknown", "none"},
		{"failed-started-accepted-never-date", func(in *Input) {
			in.ActivityLogSucceeded = true
			in.ActivityLogDays = 90
			for _, status := range []string{"Failed", "Started", "Accepted"} {
				e := event(60, "write", status)
				e.StatusCode = "Created"
				e.HTTPMethod = "PUT"
				in.ActivityLog = append(in.ActivityLog, e)
			}
		}, 0, "unknown", "none"},
		{"put-not-created", func(in *Input) {
			e := event(3, "write", "Succeeded")
			e.HTTPMethod = "PUT"
			in.ActivityLog = []ActivityEvent{e}
		}, 3, "bounded", "activitylog.oldest-succeeded"},
		{"status-code-created", func(in *Input) {
			e := event(40, "write", "Succeeded")
			e.StatusCode = "Created"
			in.ActivityLog = []ActivityEvent{e, event(80, "read", "Succeeded")}
		}, 40, "verified", "activitylog.created"},
		{"substatus-created", func(in *Input) {
			e := event(40, "write", "Succeeded")
			e.SubStatus = "Created"
			in.ActivityLog = []ActivityEvent{e}
		}, 40, "verified", "activitylog.created"},
		{"created-on-read-not-create", func(in *Input) {
			e := event(40, "read", "Succeeded")
			e.StatusCode = "Created"
			in.ActivityLog = []ActivityEvent{e}
		}, 40, "bounded", "activitylog.oldest-succeeded"},
		{"earliest-created", func(in *Input) {
			for _, days := range []int{5, 40} {
				e := event(days, "write", "Succeeded")
				e.StatusCode = "Created"
				in.ActivityLog = append(in.ActivityLog, e)
			}
		}, 40, "verified", "activitylog.created"},
		{"rp-current-object-exempt-from-reset", func(in *Input) {
			ts := at(80)
			in.RPTimestamp = &ts
			in.ActivityLog = []ActivityEvent{event(5, "delete", "Succeeded")}
			in.ResourceChanges = []ResourceChange{change(2, "Create", "write")}
		}, 80, "verified", "rp.timestamp"},
		{"rc-before-al", func(in *Input) {
			in.ResourceChanges = []ResourceChange{change(10, "Create", "write")}
			e := event(40, "write", "Succeeded")
			e.SubStatus = "Created"
			in.ActivityLog = []ActivityEvent{e}
		}, 10, "verified", "resourcechanges.create"},
		{"move-bounded", func(in *Input) {
			in.ResourceChanges = []ResourceChange{change(45, "Create", "Microsoft.Resources/subscriptions/resourceGroups/moveResources/action")}
		}, 45, "bounded", "resourcechanges.move"},
		{"equal-create-move-is-bounded", func(in *Input) {
			in.ResourceChanges = []ResourceChange{change(45, "Create", "write"), change(45, "Create", "moveResources")}
		}, 45, "bounded", "resourcechanges.move"},
		{"oldest-deployment-before-oldest-event", func(in *Input) {
			in.Deployments = []Deployment{deployment(35), deployment(60)}
			in.ActivityLog = []ActivityEvent{event(80, "read", "Succeeded")}
		}, 60, "bounded", "deployments"},
		{"failed-deployment", func(in *Input) {
			d := deployment(60)
			d.Status = "Failed"
			in.Deployments = []Deployment{d}
			in.ActivityLog = []ActivityEvent{event(2, "write", "Succeeded")}
		}, 2, "bounded", "activitylog.oldest-succeeded"},
		{"latest-delete-resets-all-sources", func(in *Input) {
			e := event(50, "write", "Succeeded")
			e.StatusCode = "Created"
			in.ActivityLog = []ActivityEvent{event(70, "delete", "Succeeded"), e, event(2, "read", "Succeeded")}
			in.ResourceChanges = []ResourceChange{change(40, "Create", "write"), change(10, "Delete", "delete")}
			in.Deployments = []Deployment{deployment(60), deployment(10)}
		}, 2, "bounded", "activitylog.oldest-succeeded"},
		{"delete-at-boundary-excludes-create", func(in *Input) {
			in.ActivityLog = []ActivityEvent{event(10, "delete", "Succeeded")}
			in.ResourceChanges = []ResourceChange{change(10, "Create", "write")}
			in.Deployments = []Deployment{deployment(10)}
			in.ActivityLogSucceeded = true
			in.ActivityLogDays = 90
		}, 0, "unknown", "none"},
		{"failed-delete-no-reset", func(in *Input) {
			in.ActivityLog = []ActivityEvent{event(2, "delete", "Failed")}
			in.Deployments = []Deployment{deployment(60)}
		}, 60, "bounded", "deployments"},
		{"rc-delete-prevents-inference", func(in *Input) {
			in.ResourceChanges = []ResourceChange{change(5, "Delete", "delete")}
			in.ActivityLogSucceeded = true
			in.ActivityLogDays = 90
		}, 0, "unknown", "none"},
		{"different-id-ignored", func(in *Input) {
			e := event(90, "read", "Succeeded")
			e.ResourceID += "-other"
			in.ActivityLog = []ActivityEvent{e}
			d := deployment(60)
			d.OutputResources = []string{id + "-other"}
			in.Deployments = []Deployment{d}
			r := change(40, "Create", "write")
			r.ResourceID += "-other"
			in.ResourceChanges = []ResourceChange{r}
		}, 0, "unknown", "none"},
		{"case-folded-id-delete", func(in *Input) {
			e := event(5, "delete", "Succeeded")
			e.ResourceID = strings.ToUpper(id)
			in.ActivityLog = []ActivityEvent{e}
			in.Deployments = []Deployment{deployment(60)}
		}, 0, "unknown", "none"},
		{"fractional-days-floor", func(in *Input) { ts := at(30).Add(time.Hour); in.RPTimestamp = &ts }, 29, "verified", "rp.timestamp"},
		{"future-timestamps-do-not-date", func(in *Input) {
			ts := at(-1)
			in.RPTimestamp = &ts
			in.ActivityLog = []ActivityEvent{event(-1, "read", "Succeeded")}
			in.ResourceChanges = []ResourceChange{change(-1, "Create", "write")}
			in.Deployments = []Deployment{deployment(-1)}
		}, 0, "unknown", "none"},
		// Found by the first end-to-end run: a storage account created minutes
		// before the check was reported as inferred 89 days old, because the
		// log ends at the cutoff and so held nothing about it.
		{"created-after-cutoff-is-not-inferred-old", func(in *Input) {
			ts := cutoff.Add(20 * time.Hour)
			in.RPTimestamp = &ts
			in.ActivityLogSucceeded = true
			in.ActivityLogDays = LogDays
		}, 0, "unknown", "none"},
		{"change-after-cutoff-is-not-inferred-old", func(in *Input) {
			in.ResourceChanges = []ResourceChange{change(-1, "Create", "write")}
			in.ActivityLogSucceeded = true
			in.ActivityLogDays = LogDays
		}, 0, "unknown", "none"},
		{"truncated-positive-event-still-lower-bound", func(in *Input) {
			in.ActivityLogTruncated = true
			in.ActivityLog = []ActivityEvent{event(40, "read", "Succeeded")}
		}, 40, "bounded", "activitylog.oldest-succeeded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := Input{ResourceID: id, Cutoff: cutoff}
			tt.modify(&in)
			got := ResolveAge(in)
			if got.LowerBoundDays != tt.days || got.Confidence != tt.confidence || got.Source != tt.source {
				t.Fatalf("got %+v; want %d/%s/%s", got, tt.days, tt.confidence, tt.source)
			}
			if !reflect.DeepEqual(got, ResolveAge(in)) {
				t.Error("age not deterministic")
			}
			slices.Reverse(in.ActivityLog)
			slices.Reverse(in.ResourceChanges)
			slices.Reverse(in.Deployments)
			if !reflect.DeepEqual(got, ResolveAge(in)) {
				t.Error("age depends on observation ordering")
			}
		})
	}
}
