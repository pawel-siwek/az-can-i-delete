package generic_test

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
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

const (
	subscription = "00000000-0000-0000-0000-000000000001"
	diskID       = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.Compute/disks/disk1"
	otherID      = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.Compute/virtualMachines/vm1"
)

var cutoff = time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)

type harness struct {
	arm   *collecttest.ARM
	graph *collecttest.Graph
	log   *collecttest.ActivityLog
	tags  map[string]string
	props map[string]any
}

func newHarness() *harness {
	return &harness{
		arm:   &collecttest.ARM{},
		graph: &collecttest.Graph{Answers: []collecttest.GraphAnswer{visible()}},
		log:   &collecttest.ActivityLog{},
	}
}

// visible is the K0 probe answer for a resource the caller can see.
func visible() collecttest.GraphAnswer {
	return collecttest.GraphAnswer{Match: "where id =~", Rows: collect.Rows{Rows: []map[string]any{{"id": diskID}}}}
}

func (h *harness) run(t *testing.T) generic.Result {
	t.Helper()
	target, err := armid.Parse(diskID)
	if err != nil {
		t.Fatal(err)
	}
	return generic.Collect(context.Background(), generic.Input{
		Target:    target,
		Resource:  collect.Resource{ID: diskID, Type: "Microsoft.Compute/disks", Name: "disk1", Tags: h.tags, Properties: h.props},
		Requested: verdict.Window{Start: cutoff.AddDate(0, 0, -30), End: cutoff, Days: 30, Grain: "P1D"},
		Cutoff:    cutoff,
		Clients:   collecttest.Clients(h.arm, h.graph, &collecttest.Metrics{}, h.log, nil),
		Graph:     collect.NewGraphLimiter(collect.SystemClock()),
	})
}

func byID(t *testing.T, result generic.Result) map[string]verdict.Evidence {
	t.Helper()
	out := map[string]verdict.Evidence{}
	for _, e := range result.Evidence {
		if _, duplicate := out[e.ID]; duplicate {
			t.Fatalf("signal %s was reported twice", e.ID)
		}
		out[e.ID] = e
	}
	return out
}

func TestEverySignalIsReportedOnEveryRun(t *testing.T) {
	result := newHarness().run(t)
	var ids []string
	for _, e := range result.Evidence {
		ids = append(ids, e.ID)
		if e.Status == verdict.StatusUnknown && e.Unknown == nil {
			t.Errorf("%s is unknown without a reason", e.ID)
		}
		if e.Status != verdict.StatusUnknown && e.Unknown != nil {
			t.Errorf("%s carries a failure reason without being unknown", e.ID)
		}
	}
	if !slices.Equal(ids, generic.Signals) {
		t.Fatalf("evidence = %v, want the catalogue in order %v", ids, generic.Signals)
	}
}

func TestCleanResourceReportsAbsenceOnlyWhereItWasEstablished(t *testing.T) {
	h := newHarness()
	evidence := byID(t, h.run(t))
	for _, id := range []string{generic.SignalLock, generic.SignalDenyAssignment, generic.SignalRGManagedBy,
		generic.SignalTagProtect, generic.SignalTagIntent, generic.SignalHiddenLink, generic.SignalDeployment,
		generic.SignalRecentWrite, generic.SignalAdvisor} {
		if evidence[id].Status != verdict.StatusAbsent {
			t.Errorf("%s = %s, want absent when the call succeeded and found nothing", id, evidence[id].Status)
		}
	}
	if evidence[generic.SignalARGVisible].Status != verdict.StatusPresent {
		t.Error("a resource the probe found must be reported visible")
	}
	if evidence[generic.SignalPEConnections].Status != verdict.StatusNotEvaluated {
		t.Error("a body without private endpoint connections must not be reported as having none")
	}
	for _, id := range []string{generic.SignalDNSRecords, generic.SignalRoleAssignments, generic.SignalPolicyState} {
		if evidence[id].Status != verdict.StatusNotEvaluated || evidence[id].Critical {
			t.Errorf("%s must be an honest non-critical stub, got %+v", id, evidence[id])
		}
	}
	if scopes := h.arm.LockScopes(); len(scopes) != 3 {
		t.Errorf("locks must be read at all three scopes, got %v", scopes)
	}
}

func TestGraphBlindnessMakesEveryGraphSignalUnknown(t *testing.T) {
	h := newHarness()
	// A successful ARM GET with zero Resource Graph rows: the caller lacks
	// subscription-scope Reader, so nothing graph-backed may read as absent.
	h.graph.Answers = nil
	evidence := byID(t, h.run(t))
	if evidence[generic.SignalARGVisible].Status != verdict.StatusAbsent {
		t.Fatalf("arg.visible = %+v, want absent", evidence[generic.SignalARGVisible])
	}
	for _, id := range []string{generic.SignalRGManagedBy, generic.SignalAdvisor} {
		e := evidence[id]
		if e.Status != verdict.StatusUnknown || e.Unknown.Code != verdict.UnkPermission {
			t.Errorf("%s = %+v, want unknown(permission)", id, e)
		}
	}
	if !evidence[generic.SignalRGManagedBy].Critical {
		t.Error("an unreadable hard dependency must stay critical")
	}
	if queries := h.graph.Queries(); len(queries) != 1 {
		t.Errorf("no graph-backed query may be issued after a blind probe, got %d", len(queries))
	}
}

func TestUnreadableLockStaysCriticalUnknown(t *testing.T) {
	h := newHarness()
	h.arm.LocksFunc = func(context.Context, string) ([]collect.Lock, error) { return nil, collecttest.Forbidden() }
	evidence := byID(t, h.run(t))
	lock := evidence[generic.SignalLock]
	if lock.Status != verdict.StatusUnknown || lock.Unknown.Code != verdict.UnkPermission || !lock.Critical {
		t.Fatalf("lock = %+v, want a critical unknown(permission)", lock)
	}
	if evidence[generic.SignalDenyAssignment].Status != verdict.StatusAbsent {
		t.Error("one failed signal must not suppress another")
	}
}

func TestLockReportsTheStrongestScope(t *testing.T) {
	h := newHarness()
	h.arm.LocksFunc = func(_ context.Context, scope string) ([]collect.Lock, error) {
		switch scope {
		case diskID:
			return []collect.Lock{{Name: "readonly", Level: "ReadOnly"}}, nil
		case "/subscriptions/" + subscription:
			return []collect.Lock{{Name: "sub", Level: "CanNotDelete"}}, nil
		default:
			return nil, nil
		}
	}
	lock := byID(t, h.run(t))[generic.SignalLock]
	if lock.Status != verdict.StatusPresent || lock.Details["level"] != "CanNotDelete" ||
		lock.Details["scope"] != string(collect.LockScopeSubscription) || lock.Details["lockCount"] != 2 {
		t.Fatalf("lock = %+v, want the CanNotDelete lock reported with both locks counted", lock)
	}
}

func TestTagClassification(t *testing.T) {
	h := newHarness()
	h.tags = map[string]string{
		"do-not-delete": "true",
		"keep":          "false",
		"expires":       "2026-01-31",
		"ttl":           "2027-01-31",
		"managed-by":    "terraform",
		"owner":         "platform-team",
		"unrelated":     "value",
	}
	evidence := byID(t, h.run(t))
	// do-not-delete plus the future ttl protect; the past expires is an expiry
	// observation; keep=false is not a protection claim.
	if e := evidence[generic.SignalTagProtect]; e.Status != verdict.StatusPresent || e.Details["matchCount"] != 2 {
		t.Errorf("protect = %+v, want two protecting tags", e)
	}
	if e := evidence[generic.SignalTagExpired]; e.Status != verdict.StatusPresent || e.Details["expiredAt"] != "2026-01-31T00:00:00Z" {
		t.Errorf("expired = %+v, want the past expiry date", e)
	}
	for _, id := range []string{generic.SignalTagIntent, generic.SignalTagOwner} {
		if evidence[id].Status != verdict.StatusPresent {
			t.Errorf("%s = %s, want present", id, evidence[id].Status)
		}
	}
	if keys := h.run(t).Metadata.TagKeys; !slices.Contains(keys, "owner") || slices.Contains(keys, "unrelated") {
		t.Errorf("metadata tag keys = %v, want only the matched keys", keys)
	}
}

func TestHiddenLinkSeparatesLiveFromDangling(t *testing.T) {
	h := newHarness()
	h.tags = map[string]string{"hidden-link:" + otherID: "Resource", "hidden-link:" + diskID + "x": "Resource"}
	h.graph.Answers = append(h.graph.Answers, collecttest.GraphAnswer{
		Match: "where id in~", Rows: collect.Rows{Rows: []map[string]any{{"id": otherID}}}})
	evidence := byID(t, h.run(t))
	if e := evidence[generic.SignalHiddenLink]; e.Status != verdict.StatusPresent || e.Details["linkCount"] != 1 {
		t.Errorf("hidden-link = %+v, want the one existing target", e)
	}
	if e := evidence[generic.SignalHiddenLinkDead]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierInfo {
		t.Errorf("dangling = %+v, want the missing target reported as information", e)
	}
}

func TestActivityLogWritesAndAge(t *testing.T) {
	h := newHarness()
	h.log.Log = collect.ActivityLog{Days: 90, Events: []collect.ActivityEvent{
		event(cutoff.AddDate(0, 0, -3), "Microsoft.Compute/disks/write", "Succeeded", "alice", "User"),
		event(cutoff.AddDate(0, 0, -60), "Microsoft.Compute/disks/write", "Succeeded", "alice", "User"),
		event(cutoff.AddDate(0, 0, -1), "Microsoft.Resources/tags/write", "Succeeded", "azcid", "User"),
		event(cutoff.AddDate(0, 0, -2), "Microsoft.Compute/disks/write", "Failed", "alice", "User"),
	}}
	result := h.run(t)
	evidence := byID(t, result)
	recent := evidence[generic.SignalRecentWrite]
	if recent.Status != verdict.StatusPresent || recent.Details["daysAgo"] != 3 || recent.Details["callerClass"] != "user" {
		t.Fatalf("recent write = %+v, want the three-day-old user write", recent)
	}
	if e := evidence[generic.SignalWrites]; e.Details["writeCount"] != 2 {
		t.Errorf("writes = %+v, want the two successful non-cordon writes", e)
	}
	if recent.Window == nil || recent.Window.Days != generic.RecentWriteDays {
		t.Errorf("the recent-write signal must carry its fixed 30-day period: %+v", recent.Window)
	}
	// The oldest successful write bounds the age from below; it is not proof of
	// the creation date, so the chain reports it as bounded.
	if result.Age.Confidence != "bounded" || result.Age.LowerBoundDays != 60 ||
		result.Age.Source != "activitylog.oldest-succeeded" {
		t.Errorf("age = %+v, want a bounded 60-day lower bound from the oldest succeeded write", result.Age)
	}
}

func TestIncompleteActivityLogCannotEstablishSilence(t *testing.T) {
	h := newHarness()
	h.log.Log = collect.ActivityLog{Days: 7, Truncated: true}
	evidence := byID(t, h.run(t))
	for _, id := range []string{generic.SignalRecentWrite, generic.SignalWrites} {
		e := evidence[id]
		if e.Status != verdict.StatusUnknown || e.Unknown.Code != verdict.UnkPartial {
			t.Errorf("%s = %+v, want unknown(partial) rather than silence", id, e)
		}
	}
}

func TestActivityLogFailureLeavesAgeUnknown(t *testing.T) {
	h := newHarness()
	h.log.Err = collecttest.Forbidden()
	result := h.run(t)
	evidence := byID(t, result)
	for _, id := range []string{generic.SignalRecentWrite, generic.SignalWrites} {
		if evidence[id].Status != verdict.StatusUnknown {
			t.Errorf("%s must be unknown when the log could not be read", id)
		}
	}
	if result.Age.Confidence != "unknown" {
		t.Errorf("age = %+v, want unknown when no source could be read", result.Age)
	}
}

func TestApprovedPrivateEndpointIsACriticalDependency(t *testing.T) {
	h := newHarness()
	h.props = map[string]any{"privateEndpointConnections": []any{
		map[string]any{"properties": map[string]any{"privateLinkServiceConnectionState": map[string]any{"status": "Approved"}}},
		map[string]any{"properties": map[string]any{"privateLinkServiceConnectionState": map[string]any{"status": "Rejected"}}},
	}}
	e := byID(t, h.run(t))[generic.SignalPEConnections]
	if e.Status != verdict.StatusPresent || e.Details["privateEndpointCount"] != 1 || !e.Critical {
		t.Fatalf("private endpoints = %+v, want one approved connection as a critical dependency", e)
	}
}

func TestDeploymentProvenance(t *testing.T) {
	h := newHarness()
	h.arm.DeploymentsFunc = func(context.Context, string, int) ([]collect.Deployment, error) {
		return []collect.Deployment{
			{Deployment: deployment(cutoff.AddDate(0, 0, -100), "Failed", diskID)},
			{Deployment: deployment(cutoff.AddDate(0, 0, -40), "Succeeded", diskID)},
		}, nil
	}
	result := h.run(t)
	e := byID(t, result)[generic.SignalDeployment]
	if e.Status != verdict.StatusPresent || e.Details["deployedAt"] != cutoff.AddDate(0, 0, -40).Format(time.RFC3339Nano) {
		t.Fatalf("deployment = %+v, want the succeeded deployment", e)
	}
	// The deployment history is also one of the age chain's seven sources.
	if result.Age.Source != "deployments" || result.Age.Confidence != "bounded" || result.Age.LowerBoundDays != 40 {
		t.Errorf("age = %+v, want a bounded 40-day lower bound from the deployment", result.Age)
	}
}

func TestGenericEvidenceSurvivesTheOutputBoundary(t *testing.T) {
	h := newHarness()
	h.tags = map[string]string{"do-not-delete": "yes", "owner": "platform", "hidden-link:" + otherID: "Resource"}
	h.props = map[string]any{"privateEndpointConnections": []any{
		map[string]any{"properties": map[string]any{"privateLinkServiceConnectionState": map[string]any{"status": "Approved"}}}}}
	h.arm.LocksFunc = func(_ context.Context, scope string) ([]collect.Lock, error) {
		if scope == diskID {
			return []collect.Lock{{Name: "keep", Level: "CanNotDelete"}}, nil
		}
		return nil, nil
	}
	h.arm.DeploymentsFunc = func(context.Context, string, int) ([]collect.Deployment, error) {
		return []collect.Deployment{{Deployment: deployment(cutoff.AddDate(0, 0, -40), "Succeeded", diskID)}}, nil
	}
	h.log.Log = collect.ActivityLog{Days: 90, Events: []collect.ActivityEvent{
		event(cutoff.AddDate(0, 0, -2), "Microsoft.Compute/disks/write", "Succeeded", "alice", "User")}}
	h.graph.Answers = append(h.graph.Answers, collecttest.GraphAnswer{
		Match: "where id in~", Rows: collect.Rows{Rows: []map[string]any{{"id": otherID}}}})
	result := h.run(t)

	assessment := verdict.Input{
		Type:      "Microsoft.Compute/disks",
		Evidence:  result.Evidence,
		Age:       result.Age,
		Requested: verdict.Window{Start: cutoff.AddDate(0, 0, -30), End: cutoff, Days: 30, Grain: "P1D"},
		Required:  verdict.RequiredForType("Microsoft.Compute/disks"),
	}
	// The disk analyzer does not exist yet, so its own Required signals are
	// simply missing here; the generic evidence must still render completely.
	report, err := output.Build(output.Input{
		ResourceID: diskID, GeneratedAt: cutoff, Assessment: assessment,
		Metadata: output.Metadata{Name: "disk1", ResourceGroup: "rg-demo"},
		Scope:    output.Scope{ARGSubscriptionsQueried: []string{subscription}, ARGVisible: result.ARGVisible, ActivityLogDays: result.ActivityLogDays},
	}, output.Config{ToolVersion: "dev", RulesDate: "2026-09-21", Policies: generic.Policies()})
	if err != nil {
		t.Fatalf("every generic signal must be publishable: %v", err)
	}
	value, err := report.Value()
	if err != nil {
		t.Fatal(err)
	}
	evidence, ok := value["evidence"].([]any)
	if !ok || len(evidence) != len(generic.Signals) {
		t.Fatalf("report carried %d evidence entries, want %d", len(evidence), len(generic.Signals))
	}
	for _, entry := range evidence {
		row := entry.(map[string]any)
		if row["summary"] == "" || row["summary"] == nil {
			t.Errorf("%v has no summary", row["id"])
		}
		if row["id"] == generic.SignalLock && row["tierName"] != "BLOCKER" {
			t.Errorf("lock rendered as %v, want BLOCKER", row["tierName"])
		}
	}
	if value["verdict"] != "no" || value["reasonClass"] != "blocked" {
		t.Fatalf("a locked resource must render as blocked, got %v/%v", value["verdict"], value["reasonClass"])
	}
}

func TestPoliciesCoverEverySignal(t *testing.T) {
	policies := generic.Policies()
	for _, id := range generic.Signals {
		if _, ok := policies[id]; !ok {
			t.Errorf("signal %s has no output policy, so it would print a default summary", id)
		}
	}
	if len(policies) != len(generic.Signals) {
		t.Errorf("the policy set has %d entries for %d signals", len(policies), len(generic.Signals))
	}
}

func event(ts time.Time, operation, status, caller, callerType string) collect.ActivityEvent {
	return collect.ActivityEvent{
		ActivityEvent: age.ActivityEvent{ResourceID: diskID, Timestamp: ts, Operation: operation, Status: status},
		Caller:        caller, CallerType: callerType,
	}
}

func deployment(ts time.Time, status string, outputs ...string) age.Deployment {
	return age.Deployment{Timestamp: ts, Status: status, OutputResources: outputs}
}
