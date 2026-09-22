package disk_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/age"
	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect/collecttest"
	"github.com/pawel-siwek/az-can-i-delete/internal/disk"
	"github.com/pawel-siwek/az-can-i-delete/internal/generic"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

const (
	diskID    = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.Compute/disks/disk1"
	clusterID = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.ContainerService/managedClusters/aks1"
	aksDiskID = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/MC_rg_aks1_westeurope/providers/Microsoft.Compute/disks/pvc-disk"
)

var cutoff = time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)

type harness struct {
	id         string
	properties map[string]any
	tags       map[string]string
	graph      *collecttest.Graph
	metrics    *collecttest.Metrics
	generic    generic.Result
}

func newHarness() *harness {
	return &harness{
		id:         diskID,
		properties: map[string]any{"diskState": "Unattached", "LastOwnershipUpdateTime": cutoff.AddDate(0, 0, -120).Format(time.RFC3339)},
		graph:      &collecttest.Graph{},
		metrics:    &collecttest.Metrics{},
		generic:    generic.Result{ARGVisible: true, ActivityLogRead: true, ActivityLog: collect.ActivityLog{Days: 90}},
	}
}

func (h *harness) run(t *testing.T) map[string]verdict.Evidence {
	t.Helper()
	target, err := armid.Parse(h.id)
	if err != nil {
		t.Fatal(err)
	}
	window := verdict.Window{Start: cutoff.AddDate(0, 0, -30), End: cutoff, Days: 30, Grain: "P1D"}
	evidence := disk.Collect(context.Background(), disk.Input{
		Target:    target,
		Resource:  collect.Resource{ID: h.id, Type: disk.ResourceType, Properties: h.properties, Tags: h.tags},
		Requested: window,
		Cutoff:    cutoff,
		Clients:   collecttest.Clients(&collecttest.ARM{}, h.graph, h.metrics, &collecttest.ActivityLog{}, nil),
		Graph:     collect.NewGraphLimiter(collect.SystemClock()),
		Generic:   h.generic,
	})
	var ids []string
	byID := map[string]verdict.Evidence{}
	for _, item := range evidence {
		ids = append(ids, item.ID)
		byID[item.ID] = item
	}
	if !slices.Equal(ids, disk.Signals) {
		t.Fatalf("evidence = %v, want the catalogue in order %v", ids, disk.Signals)
	}
	return byID
}

func TestDetachedDiskSatisfiesItsRequiredSignals(t *testing.T) {
	evidence := newHarness().run(t)
	for _, id := range []string{disk.SignalUnattached, disk.SignalOwnership} {
		if evidence[id].Status != verdict.StatusPresent {
			t.Errorf("%s = %+v, want present", id, evidence[id])
		}
	}
	if days := evidence[disk.SignalOwnership].Details["detachedDays"]; days != 120 {
		t.Errorf("detachedDays = %v, want 120", days)
	}
	for _, id := range []string{disk.SignalAttached, disk.SignalActiveSAS, disk.SignalBackup,
		disk.SignalAKSPV, disk.SignalASRReplica, disk.SignalImage, disk.SignalGolden, disk.SignalExport} {
		if evidence[id].Status != verdict.StatusAbsent {
			t.Errorf("%s = %+v, want absent", id, evidence[id])
		}
	}
	// Required plus the generic Required signal is what a `yes` rests on.
	required := verdict.RequiredForType(disk.ResourceType)
	for _, id := range required {
		if id == generic.SignalARGVisible {
			continue
		}
		if evidence[id].Status != verdict.StatusPresent || evidence[id].Tier != verdict.TierObservedIdle {
			t.Errorf("Required %s = %+v, want a present OBSERVED_IDLE signal", id, evidence[id])
		}
	}
}

func TestAttachedDiskBlocks(t *testing.T) {
	for _, tc := range []struct {
		name       string
		properties map[string]any
	}{
		{"state", map[string]any{"diskState": "Attached"}},
		{"reserved", map[string]any{"diskState": "Reserved"}},
		{"owner only", map[string]any{"diskState": "Unattached", "managedBy": "/subscriptions/x/vm"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness()
			h.properties = tc.properties
			evidence := h.run(t)
			attached := evidence[disk.SignalAttached]
			if attached.Status != verdict.StatusPresent || attached.Tier != verdict.TierBlocker || !attached.Critical {
				t.Fatalf("attached = %+v, want a critical blocker", attached)
			}
		})
	}
}

func TestActiveExportIsLiveActivity(t *testing.T) {
	h := newHarness()
	h.properties["diskState"] = "ActiveSAS"
	evidence := h.run(t)
	if e := evidence[disk.SignalActiveSAS]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierLiveActivity {
		t.Fatalf("activesas = %+v, want live activity", e)
	}
	// ActiveSAS is use, not an attachment, and it is not the unattached state.
	if evidence[disk.SignalAttached].Status != verdict.StatusAbsent ||
		evidence[disk.SignalUnattached].Status != verdict.StatusAbsent {
		t.Error("an active export is neither an attachment nor an unattached disk")
	}
}

func TestMissingOwnershipTimestampIsUnknownNotOld(t *testing.T) {
	h := newHarness()
	delete(h.properties, "LastOwnershipUpdateTime")
	e := h.run(t)[disk.SignalOwnership]
	if e.Status != verdict.StatusUnknown || e.Unknown.Code != verdict.UnkUnsupported {
		t.Fatalf("ownership = %+v, want unknown(unsupported)", e)
	}
}

func TestRecentlyDetachedDiskIsNotYetIdle(t *testing.T) {
	h := newHarness()
	h.properties["LastOwnershipUpdateTime"] = cutoff.AddDate(0, 0, -29).Format(time.RFC3339)
	e := h.run(t)[disk.SignalOwnership]
	if e.Status != verdict.StatusAbsent || e.Window == nil || e.Window.Days != disk.OwnershipDays {
		t.Fatalf("ownership = %+v, want absent over the fixed 30-day period", e)
	}
}

func TestReverseReferencesAreCriticalDependencies(t *testing.T) {
	h := newHarness()
	h.graph.Answers = []collecttest.GraphAnswer{
		{Match: "backupvaults/backupinstances", Rows: collect.Rows{Rows: []map[string]any{{"id": "/b1", "state": "ProtectionConfigured"}}}},
		{Match: "microsoft.compute/images", Rows: collect.Rows{Rows: []map[string]any{{"id": "/i1"}}}},
	}
	evidence := h.run(t)
	for _, id := range []string{disk.SignalBackup, disk.SignalImage} {
		e := evidence[id]
		if e.Status != verdict.StatusPresent || e.Tier != verdict.TierHardDependency || !e.Critical {
			t.Errorf("%s = %+v, want a critical hard dependency", id, e)
		}
		if e.Details["referenceCount"] != 1 {
			t.Errorf("%s referenceCount = %v, want 1", id, e.Details["referenceCount"])
		}
	}
}

func TestUnreadableReferencesStayCriticalUnknowns(t *testing.T) {
	h := newHarness()
	h.graph.Answers = []collecttest.GraphAnswer{{Match: "backupvaults/backupinstances", Err: collecttest.Forbidden()}}
	e := h.run(t)[disk.SignalBackup]
	if e.Status != verdict.StatusUnknown || e.Unknown.Code != verdict.UnkPermission || !e.Critical {
		t.Fatalf("backup = %+v, want a critical unknown(permission)", e)
	}
}

func TestGraphBlindnessSkipsQueriesAndKeepsSignalsUnknown(t *testing.T) {
	h := newHarness()
	h.generic = generic.Result{
		ARGVisible:      false,
		ARGUnknown:      &verdict.Unknown{Code: verdict.UnkPermission, Message: "not visible in Resource Graph"},
		ActivityLogRead: true, ActivityLog: collect.ActivityLog{Days: 90},
	}
	evidence := h.run(t)
	for _, id := range []string{disk.SignalBackup, disk.SignalImage, disk.SignalAdvisor} {
		if evidence[id].Status != verdict.StatusUnknown || evidence[id].Unknown.Code != verdict.UnkPermission {
			t.Errorf("%s = %+v, want unknown(permission)", id, evidence[id])
		}
	}
	if queries := h.graph.Queries(); len(queries) != 0 {
		t.Errorf("no graph query may be issued when the probe was blind, got %d", len(queries))
	}
}

func TestKubernetesPersistentVolume(t *testing.T) {
	h := newHarness()
	h.id = aksDiskID
	h.tags = map[string]string{"kubernetes.io-created-for-pvc-name": "data-0"}
	h.generic.ManagedBy = clusterID
	e := h.run(t)[disk.SignalAKSPV]
	if e.Status != verdict.StatusPresent || e.Details["cluster"] != clusterID || !e.Critical {
		t.Fatalf("aks = %+v, want the owning cluster as a critical dependency", e)
	}

	// The tag alone, outside a node resource group owned by a cluster, is not
	// a dependency.
	plain := newHarness()
	plain.tags = h.tags
	if plain.run(t)[disk.SignalAKSPV].Status != verdict.StatusAbsent {
		t.Error("a persistent-volume tag outside a cluster's node resource group is not a dependency")
	}
}

func TestSiteRecoveryAndGoldenProvenance(t *testing.T) {
	h := newHarness()
	h.id = renamed(diskID, "vm1-ASRReplica")
	if e := h.run(t)[disk.SignalASRReplica]; e.Status != verdict.StatusPresent || e.Details["matchedName"] != true {
		t.Fatalf("asr = %+v, want the replica name matched", e)
	}
	golden := newHarness()
	golden.properties["creationData"] = map[string]any{"createOption": "Import"}
	golden.tags = map[string]string{"purpose": "golden"}
	e := golden.run(t)[disk.SignalGolden]
	if e.Status != verdict.StatusPresent || e.Tier != verdict.TierDesignIntent ||
		e.Details["createOption"] != "Import" || e.Details["matchedMetadata"] != true {
		t.Fatalf("golden = %+v, want imported design intent", e)
	}
}

func TestExportActivityUsesTheGenericActivityLog(t *testing.T) {
	h := newHarness()
	h.generic.ActivityLog = collect.ActivityLog{Days: 90, Events: []collect.ActivityEvent{{
		ActivityEvent: age.ActivityEvent{ResourceID: diskID, Timestamp: cutoff.AddDate(0, 0, -5),
			Operation: "Microsoft.Compute/disks/beginGetAccess/action", Status: "Succeeded"}}}}
	e := h.run(t)[disk.SignalExport]
	if e.Status != verdict.StatusPresent || e.Details["daysAgo"] != 5 {
		t.Fatalf("export = %+v, want the five-day-old export", e)
	}

	// An export older than the requested window is outside what was asked about.
	old := newHarness()
	old.generic.ActivityLog = collect.ActivityLog{Days: 90, Events: []collect.ActivityEvent{{
		ActivityEvent: age.ActivityEvent{ResourceID: diskID, Timestamp: cutoff.AddDate(0, 0, -60),
			Operation: "Microsoft.Compute/disks/beginGetAccess/action", Status: "Succeeded"}}}}
	if old.run(t)[disk.SignalExport].Status != verdict.StatusAbsent {
		t.Error("an export before the window must not be reported inside it")
	}

	unread := newHarness()
	unread.generic.ActivityLogRead = false
	if e := unread.run(t)[disk.SignalExport]; e.Status != verdict.StatusUnknown {
		t.Errorf("export = %+v, want unknown when the log was never read", e)
	}
}

func TestInputOutputAfterDetachIsReportedAsAContradiction(t *testing.T) {
	h := newHarness()
	h.metrics.MetricsFunc = func(_ context.Context, query collect.MetricQuery) (collect.MetricResult, error) {
		if query.ResourceURI != diskID || query.Interval != "P1D" {
			t.Errorf("metric query = %+v, want the target over daily buckets", query)
		}
		return collect.MetricResult{Series: []collect.MetricSeries{{
			Name: "Composite Disk Read Operations/sec",
			Points: []collect.MetricPoint{
				{Timestamp: cutoff.AddDate(0, 0, -200), Value: 900}, // before the detach
				{Timestamp: cutoff.AddDate(0, 0, -2), Value: 12},
				{Timestamp: cutoff.AddDate(0, 0, -1), Value: 0},
			}}}}, nil
	}
	e := h.run(t)[disk.SignalIO]
	if e.Status != verdict.StatusPresent || e.Tier != verdict.TierInfo || e.Critical {
		t.Fatalf("io = %+v, want a non-critical information signal", e)
	}
	if e.Details["busyPoints"] != 1 || e.Details["lastIODaysAgo"] != 2 {
		t.Fatalf("io details = %v, want only the activity after the last ownership change", e.Details)
	}
}

func TestPoliciesCoverEverySignal(t *testing.T) {
	policies := disk.Policies()
	for _, id := range disk.Signals {
		if _, ok := policies[id]; !ok {
			t.Errorf("signal %s has no output policy", id)
		}
	}
	if len(policies) != len(disk.Signals) {
		t.Errorf("the policy set has %d entries for %d signals", len(policies), len(disk.Signals))
	}
}

// renamed returns the same disk id under a different resource name.
func renamed(id, name string) string {
	return id[:len(id)-len("disk1")] + name
}
