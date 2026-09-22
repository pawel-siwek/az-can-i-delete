package storage_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/age"
	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect/collecttest"
	"github.com/pawel-siwek/az-can-i-delete/internal/generic"
	"github.com/pawel-siwek/az-can-i-delete/internal/storage"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

const (
	group     = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo"
	accountID = group + "/providers/Microsoft.Storage/storageAccounts/store1"
	vmID      = group + "/providers/Microsoft.Compute/virtualMachines/vm1"
)

var cutoff = time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)

type harness struct {
	id         string
	properties map[string]any
	tags       map[string]string
	arm        *collecttest.ARM
	graph      *collecttest.Graph
	metrics    *collecttest.Metrics
	generic    generic.Result
	points     []point
}

// point is one metric bucket a test wants the account to have served.
type point struct {
	metric    string
	api       string
	kind      string
	auth      string
	response  string
	daysAgo   int
	value     float64
	fileShare bool
}

func newHarness() *harness {
	return &harness{
		id:         accountID,
		properties: map[string]any{"provisioningState": "Succeeded"},
		arm:        &collecttest.ARM{},
		graph:      &collecttest.Graph{},
		metrics:    &collecttest.Metrics{},
		generic: generic.Result{
			ARGVisible: true, ActivityLogRead: true, LocksRead: true,
			ActivityLog: collect.ActivityLog{Days: 90},
			Age:         verdict.Age{LowerBoundDays: 400, Confidence: "verified", Source: "rp.timestamp"},
		},
	}
}

// serve makes the fake metrics client answer with the harness's points,
// matched to the call that asked for them.
func (h *harness) serve() {
	h.metrics.MetricsFunc = func(_ context.Context, query collect.MetricQuery) (collect.MetricResult, error) {
		var series []collect.MetricSeries
		for _, p := range h.points {
			if !slices.Contains(query.Names, p.metric) {
				continue
			}
			fileCall := query.ResourceURI == accountID+"/fileServices/default" && p.metric == "Transactions"
			if p.fileShare != fileCall {
				continue
			}
			dimensions := map[string]string{}
			for key, value := range map[string]string{
				"apiname": p.api, "transactiontype": p.kind,
				"authentication": p.auth, "responsetype": p.response,
			} {
				if value != "" {
					dimensions[key] = value
				}
			}
			series = append(series, collect.MetricSeries{
				Name: p.metric, Dimensions: dimensions,
				Points: []collect.MetricPoint{{
					Timestamp: cutoff.AddDate(0, 0, -p.daysAgo), Value: p.value, Dimensions: dimensions}},
			})
		}
		return collect.MetricResult{Series: series}, nil
	}
}

func (h *harness) run(t *testing.T) map[string]verdict.Evidence {
	t.Helper()
	if h.metrics.MetricsFunc == nil {
		h.serve()
	}
	target, err := armid.Parse(h.id)
	if err != nil {
		t.Fatal(err)
	}
	window := verdict.Window{Start: cutoff.AddDate(0, 0, -30), End: cutoff, Days: 30, Grain: "P1D"}
	evidence := storage.Collect(context.Background(), storage.Input{
		Target:    target,
		Resource:  collect.Resource{ID: h.id, Type: storage.ResourceType, Name: target.Name, Properties: h.properties, Tags: h.tags},
		Requested: window,
		Cutoff:    cutoff,
		Clients:   collecttest.Clients(h.arm, h.graph, h.metrics, &collecttest.ActivityLog{}, nil),
		Graph:     collect.NewGraphLimiter(collect.SystemClock()),
		Generic:   h.generic,
	})
	var ids []string
	byID := map[string]verdict.Evidence{}
	for _, item := range evidence {
		ids = append(ids, item.ID)
		byID[item.ID] = item
	}
	if !slices.Equal(ids, storage.Signals) {
		t.Fatalf("evidence = %v, want the catalogue in order %v", ids, storage.Signals)
	}
	return byID
}

func TestQuietAccountSatisfiesItsRequiredSignals(t *testing.T) {
	evidence := newHarness().run(t)
	required := verdict.RequiredForType(storage.ResourceType)
	for _, id := range required {
		if id == generic.SignalARGVisible {
			continue
		}
		e := evidence[id]
		if e.Status != verdict.StatusPresent || e.Tier != verdict.TierObservedIdle {
			t.Errorf("Required %s = %+v, want a present OBSERVED_IDLE signal", id, e)
		}
	}
	for _, id := range []string{storage.SignalImmutability, storage.SignalBackup,
		storage.SignalFlowLogs, storage.SignalBootDiag, storage.SignalVMExt, storage.SignalReverse,
		storage.SignalLease, storage.SignalWrites, storage.SignalReads, storage.SignalAnonymous} {
		if evidence[id].Status != verdict.StatusAbsent {
			t.Errorf("%s = %+v, want absent", id, evidence[id])
		}
	}
	// A body without the private endpoint collection is not evidence that the
	// account has none.
	if evidence[storage.SignalPE].Status != verdict.StatusNotEvaluated {
		t.Errorf("private endpoints = %+v, want not evaluated", evidence[storage.SignalPE])
	}
	for _, id := range []string{storage.SignalKB, storage.SignalDataPlane,
		storage.SignalSharesUsage, storage.SignalInventoryShaped} {
		if evidence[id].Status != verdict.StatusNotEvaluated || evidence[id].Critical {
			t.Errorf("%s = %+v, want an honest non-critical stub", id, evidence[id])
		}
	}
}

func TestWritesNeedToClearTheNoiseFloor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		points []point
		live   bool
	}{
		{"one small day", []point{{metric: "Transactions", api: "PutBlob", kind: "User", daysAgo: 2, value: 9}}, false},
		{"ten over one day", []point{{metric: "Transactions", api: "PutBlob", kind: "User", daysAgo: 2, value: 40}}, false},
		{"ten over two days", []point{
			{metric: "Transactions", api: "PutBlob", kind: "User", daysAgo: 2, value: 6},
			{metric: "Transactions", api: "AppendBlock", kind: "User", daysAgo: 5, value: 6}}, true},
		{"a thousand in one day", []point{
			{metric: "Transactions", api: "PutBlob", kind: "User", daysAgo: 2, value: 1500}}, true},
		{"excluded maintenance writes", []point{
			{metric: "Transactions", api: "SetBlobTier", kind: "User", daysAgo: 2, value: 900},
			{metric: "Transactions", api: "DeleteBlob", kind: "User", daysAgo: 3, value: 900}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness()
			h.points = tc.points
			evidence := h.run(t)
			want := verdict.StatusAbsent
			if tc.live {
				want = verdict.StatusPresent
			}
			if evidence[storage.SignalWrites].Status != want {
				t.Fatalf("writes = %+v, want %s", evidence[storage.SignalWrites], want)
			}
			// Whatever the write rule decides, any user transaction ends silence.
			if evidence[storage.SignalSilence].Status != verdict.StatusAbsent {
				t.Errorf("silence = %+v, want absent while the account served transactions",
					evidence[storage.SignalSilence])
			}
		})
	}
}

func TestReadsNeedDaysAndVolume(t *testing.T) {
	h := newHarness()
	for _, day := range []int{2, 3, 4} {
		h.points = append(h.points, point{metric: "Transactions", api: "GetBlob", kind: "User", daysAgo: day, value: 400})
	}
	evidence := h.run(t)
	if e := evidence[storage.SignalReads]; e.Status != verdict.StatusPresent || e.Details["readDays"] != 3 {
		t.Fatalf("reads = %+v, want live reads over three days", e)
	}

	// The same volume on two days is below the rule.
	low := newHarness()
	low.points = []point{
		{metric: "Transactions", api: "GetBlob", kind: "User", daysAgo: 2, value: 600},
		{metric: "Transactions", api: "GetBlob", kind: "User", daysAgo: 3, value: 600}}
	quiet := low.run(t)
	if quiet[storage.SignalReads].Status != verdict.StatusAbsent {
		t.Errorf("reads = %+v, want absent on two days", quiet[storage.SignalReads])
	}
	if quiet[storage.SignalLowReads].Status != verdict.StatusPresent {
		t.Errorf("low-volume reads = %+v, want the reads reported as intent", quiet[storage.SignalLowReads])
	}
}

func TestEgressCanEstablishReadsWithoutTheRequestFloor(t *testing.T) {
	h := newHarness()
	for _, day := range []int{2, 3, 4} {
		h.points = append(h.points,
			point{metric: "Transactions", api: "GetBlob", kind: "User", daysAgo: day, value: 10},
			point{metric: "Egress", daysAgo: day, value: 30 * 1024 * 1024})
	}
	e := h.run(t)[storage.SignalReads]
	if e.Status != verdict.StatusPresent {
		t.Fatalf("reads = %+v, want live reads from 90 MiB of egress", e)
	}
}

func TestDefenderScannerMakesOAuthOnlyReadsIntent(t *testing.T) {
	h := newHarness()
	h.arm.GetFunc = func(_ context.Context, path, _ string) (collect.Resource, error) {
		if !contains(path, "defenderForStorageSettings") {
			return collect.Resource{}, &collect.Failure{StatusCode: 404}
		}
		return collect.Resource{Properties: map[string]any{
			"isEnabled":              true,
			"sensitiveDataDiscovery": map[string]any{"isEnabled": true},
		}}, nil
	}
	for _, day := range []int{2, 3, 4} {
		h.points = append(h.points,
			point{metric: "Transactions", api: "GetBlob", kind: "User", daysAgo: day, value: 400},
			point{metric: "Transactions", auth: "OAuth", response: "Success", kind: "User", daysAgo: day, value: 400})
	}
	evidence := h.run(t)
	if evidence[storage.SignalReads].Status != verdict.StatusAbsent {
		t.Fatalf("reads = %+v, want the scanner's reads kept out of live activity", evidence[storage.SignalReads])
	}
	if e := evidence[storage.SignalDefenderShaped]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierDesignIntent {
		t.Fatalf("defender-shaped = %+v, want design intent", e)
	}
	if evidence[storage.SignalDefenderConfig].Status != verdict.StatusPresent {
		t.Error("the Defender configuration must be reported")
	}
}

func TestKeyAuthenticatedReadsStayLiveWithDefenderOn(t *testing.T) {
	h := newHarness()
	h.arm.GetFunc = func(_ context.Context, path, _ string) (collect.Resource, error) {
		if !contains(path, "defenderForStorageSettings") {
			return collect.Resource{}, &collect.Failure{StatusCode: 404}
		}
		return collect.Resource{Properties: map[string]any{"isEnabled": true,
			"sensitiveDataDiscovery": map[string]any{"isEnabled": true}}}, nil
	}
	for _, day := range []int{2, 3, 4} {
		h.points = append(h.points,
			point{metric: "Transactions", api: "GetBlob", kind: "User", daysAgo: day, value: 400},
			point{metric: "Transactions", auth: "AccountKey", response: "Success", kind: "User", daysAgo: day, value: 400})
	}
	if e := h.run(t)[storage.SignalReads]; e.Status != verdict.StatusPresent {
		t.Fatalf("reads = %+v, want live reads when something read with a key", e)
	}
}

func TestQueuePollingSeparatesADeployedConsumerFromOccasionalPolls(t *testing.T) {
	h := newHarness()
	for _, day := range []int{2, 3, 4} {
		h.points = append(h.points, point{metric: "Transactions", api: "GetMessages", kind: "User", daysAgo: day, value: 1200})
	}
	evidence := h.run(t)
	if e := evidence[storage.SignalQueue]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierLiveActivity {
		t.Fatalf("queue polling = %+v, want live activity", e)
	}

	quiet := newHarness()
	quiet.points = []point{{metric: "Transactions", api: "GetMessages", kind: "User", daysAgo: 2, value: 5}}
	low := quiet.run(t)
	if low[storage.SignalQueue].Status != verdict.StatusAbsent ||
		low[storage.SignalQueueLow].Status != verdict.StatusPresent {
		t.Fatalf("occasional polling must be intent, got %+v / %+v",
			low[storage.SignalQueue], low[storage.SignalQueueLow])
	}
}

func TestAnonymousSuccessIsLiveActivity(t *testing.T) {
	h := newHarness()
	h.points = []point{{metric: "Transactions", auth: "Anonymous", response: "Success", kind: "User", daysAgo: 4, value: 3}}
	e := h.run(t)[storage.SignalAnonymous]
	if e.Status != verdict.StatusPresent || !e.Critical || e.Tier != verdict.TierLiveActivity {
		t.Fatalf("anonymous = %+v, want critical live activity", e)
	}
}

func TestObjectCountGrowthIsLiveActivity(t *testing.T) {
	h := newHarness()
	h.points = []point{
		{metric: "BlobCount", daysAgo: 5, value: 100},
		{metric: "BlobCount", daysAgo: 4, value: 140},
		{metric: "BlobCount", daysAgo: 3, value: 190},
	}
	evidence := h.run(t)
	if e := evidence[storage.SignalCountDelta]; e.Status != verdict.StatusPresent || e.Details["growthDays"] != 2 {
		t.Fatalf("count delta = %+v, want growth on two days", e)
	}
	if evidence[storage.SignalCountSilence].Status != verdict.StatusAbsent {
		t.Error("counts that grew are not silent")
	}
}

func TestUnclassifiedOperationsAreNotSilence(t *testing.T) {
	h := newHarness()
	h.points = []point{{metric: "Transactions", api: "NfsRead3", kind: "User", daysAgo: 4, value: 500}}
	e := h.run(t)[storage.SignalSilence]
	if e.Status != verdict.StatusUnknown || e.Unknown.Code != verdict.UnkUnsupported {
		t.Fatalf("silence = %+v, want unknown(unsupported) for operations this version cannot classify", e)
	}
}

func TestSilenceIsJudgedOverTheEffectiveWindow(t *testing.T) {
	h := newHarness()
	// The account is only 10 days old, so the effective window is 10 days and
	// a transaction 20 days ago belongs to nothing this run can speak about.
	h.generic.Age = verdict.Age{LowerBoundDays: 10, Confidence: "verified", Source: "rp.timestamp"}
	h.points = []point{{metric: "Transactions", api: "GetBlob", kind: "User", daysAgo: 20, value: 5000}}
	evidence := h.run(t)
	e := evidence[storage.SignalSilence]
	if e.Status != verdict.StatusPresent || e.Window.Days != 10 {
		t.Fatalf("silence = %+v, want present over the ten-day effective window", e)
	}
	// Live activity is still judged over the requested window.
	if evidence[storage.SignalLowReads].Status != verdict.StatusPresent {
		t.Errorf("the older reads must still be reported: %+v", evidence[storage.SignalLowReads])
	}
}

func TestReverseReferencesAndDependencies(t *testing.T) {
	h := newHarness()
	h.graph.Answers = []collecttest.GraphAnswer{
		{Match: "backupvaults/backupinstances", Rows: collect.Rows{Rows: []map[string]any{{"id": "/b1"}}}},
		{Match: "networkwatchers/flowlogs", Rows: collect.Rows{Rows: []map[string]any{{"id": "/f1"}}}},
		{Match: "bootDiagnostics", Rows: collect.Rows{Rows: []map[string]any{{"id": vmID}}}},
		{Match: "virtualmachines/extensions", Rows: collect.Rows{Rows: []map[string]any{{"id": "/e1"}}}},
	}
	evidence := h.run(t)
	for _, id := range []string{storage.SignalBackup, storage.SignalFlowLogs,
		storage.SignalBootDiag, storage.SignalVMExt} {
		e := evidence[id]
		if e.Status != verdict.StatusPresent || e.Tier != verdict.TierHardDependency || !e.Critical {
			t.Errorf("%s = %+v, want a critical hard dependency", id, e)
		}
	}
}

func TestAFlexFunctionAppIsAHardDependencyAndOtherNamesAreIntent(t *testing.T) {
	h := newHarness()
	h.graph.Answers = []collecttest.GraphAnswer{{Match: "!startswith", Rows: collect.Rows{Rows: []map[string]any{
		{"id": "/app1", "type": "microsoft.web/sites", "flexDeployment": "https://store1.blob.core.windows.net/releases"}}}}}
	if e := h.run(t)[storage.SignalReverse]; e.Status != verdict.StatusPresent ||
		e.Tier != verdict.TierHardDependency || e.Details["hardReference"] != true {
		t.Fatalf("reverse reference = %+v, want a hard dependency", e)
	}

	soft := newHarness()
	soft.graph.Answers = []collecttest.GraphAnswer{{Match: "!startswith", Rows: collect.Rows{Rows: []map[string]any{
		{"id": "/workflow1", "type": "microsoft.logic/workflows"}}}}}
	e := soft.run(t)[storage.SignalReverse]
	if e.Status != verdict.StatusPresent || e.Tier != verdict.TierDesignIntent || e.Critical {
		t.Fatalf("reverse reference = %+v, want design intent for an unconfirmed producer", e)
	}
}

func TestGraphBlindnessMakesEveryReverseReferenceUnknown(t *testing.T) {
	h := newHarness()
	h.generic.ARGVisible = false
	h.generic.ARGUnknown = &verdict.Unknown{Code: verdict.UnkPermission, Message: "not visible"}
	evidence := h.run(t)
	for _, id := range []string{storage.SignalReverse, storage.SignalBackup, storage.SignalFlowLogs,
		storage.SignalBootDiag, storage.SignalVMExt, storage.SignalNetACL} {
		e := evidence[id]
		if e.Status != verdict.StatusUnknown || e.Unknown.Code != verdict.UnkPermission || !e.Critical {
			t.Errorf("%s = %+v, want a critical unknown(permission)", id, e)
		}
	}
	if queries := h.graph.Queries(); len(queries) != 0 {
		t.Errorf("no graph query may be issued when the probe was blind, got %d", len(queries))
	}
}

func TestChildListingsAndTheirCompleteness(t *testing.T) {
	h := newHarness()
	h.arm.ListFunc = func(_ context.Context, path, _ string) ([]collect.Resource, error) {
		switch {
		case contains(path, "/containers"):
			return []collect.Resource{
				{Name: "azure-webjobs-hosts"},
				{Name: "data", Properties: map[string]any{"leaseState": "Leased"}},
				{Name: "records", Properties: map[string]any{"hasLegalHold": true}},
			}, nil
		case contains(path, "/shares"):
			return []collect.Resource{{Name: "share1"}}, nil
		default:
			return nil, nil
		}
	}
	evidence := h.run(t)
	if e := evidence[storage.SignalLists]; e.Status != verdict.StatusPresent || e.Details["containersCount"] != 3 {
		t.Fatalf("lists = %+v, want a complete listing", e)
	}
	if e := evidence[storage.SignalLease]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierLiveActivity {
		t.Fatalf("lease = %+v, want live activity", e)
	}
	if e := evidence[storage.SignalImmutability]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierBlocker {
		t.Fatalf("immutability = %+v, want a blocker", e)
	}
	if e := evidence[storage.SignalFunctions]; e.Status != verdict.StatusPresent || e.Tier != verdict.TierDesignIntent {
		t.Fatalf("functions artefacts = %+v, want design intent", e)
	}
}

func TestAnIncompleteListingCannotEstablishWhatTheAccountHolds(t *testing.T) {
	h := newHarness()
	h.arm.ListFunc = func(_ context.Context, path, _ string) ([]collect.Resource, error) {
		if contains(path, "/containers") {
			return []collect.Resource{{Name: "one"}}, collect.ErrTruncated
		}
		return nil, nil
	}
	e := h.run(t)[storage.SignalLists]
	if e.Status != verdict.StatusUnknown || e.Unknown.Code != verdict.UnkPartial {
		t.Fatalf("lists = %+v, want unknown(partial)", e)
	}
}

func TestControlPlaneSilenceAndKeyOperations(t *testing.T) {
	h := newHarness()
	h.generic.ActivityLog = collect.ActivityLog{Days: 90, Events: []collect.ActivityEvent{{
		ActivityEvent: age.ActivityEvent{ResourceID: accountID, Timestamp: cutoff.AddDate(0, 0, -4),
			Operation: "Microsoft.Storage/storageAccounts/listKeys/action", Status: "Succeeded"},
		Caller: "alice@example.com", CallerType: "User"}}}
	evidence := h.run(t)
	if e := evidence[storage.SignalListKeys]; e.Status != verdict.StatusPresent || e.Details["daysAgo"] != 4 {
		t.Fatalf("listKeys = %+v, want the key operation reported", e)
	}
	if evidence[storage.SignalALSilence].Status != verdict.StatusAbsent {
		t.Error("an account whose keys were taken is not control-plane silent")
	}
}

func TestBackupLockAndCloudShellAndGeoRedundancy(t *testing.T) {
	h := newHarness()
	h.generic.Locks = []collect.Lock{{Name: "AzureBackupProtectionLock", Level: "CanNotDelete"}}
	h.properties["sku"] = map[string]any{"name": "Standard_RAGRS"}
	h.tags = map[string]string{"ms-resource-usage": "azure-cloud-shell"}
	evidence := h.run(t)
	if e := evidence[storage.SignalBackupLock]; e.Status != verdict.StatusPresent || !e.Critical {
		t.Fatalf("backup lock = %+v, want a critical dependency", e)
	}
	if e := evidence[storage.SignalCloudShell]; e.Status != verdict.StatusPresent {
		t.Fatalf("cloud shell = %+v, want the account recognized", e)
	}
	if e := evidence[storage.SignalSKUGeo]; e.Status != verdict.StatusPresent || e.Details["replication"] != "RAGRS" {
		t.Fatalf("sku = %+v, want the geo-redundant replication reported", e)
	}
}

func TestResourceInstanceRulesOnlyCountWhileTheirResourceExists(t *testing.T) {
	h := newHarness()
	h.properties["networkAcls"] = map[string]any{"resourceAccessRules": []any{
		map[string]any{"resourceId": vmID}}}
	h.graph.Answers = []collecttest.GraphAnswer{
		{Match: "where id in~", Rows: collect.Rows{Rows: []map[string]any{{"id": vmID}}}}}
	if e := h.run(t)[storage.SignalNetACL]; e.Status != verdict.StatusPresent || !e.Critical {
		t.Fatalf("network rule = %+v, want a critical dependency", e)
	}

	gone := newHarness()
	gone.properties["networkAcls"] = h.properties["networkAcls"]
	if e := gone.run(t)[storage.SignalNetACL]; e.Status != verdict.StatusAbsent {
		t.Fatalf("network rule = %+v, want absent when the resource is gone", e)
	}
}

func TestOperationClassification(t *testing.T) {
	for name, want := range map[string]storage.Class{
		"PutBlob":           storage.Write,
		"GetBlob":           storage.Read,
		"DeleteBlob":        storage.Delete,
		"ListBlobs":         storage.Enumerate,
		"GetBlobProperties": storage.Metadata,
		"AcquireBlobLease":  storage.Lease,
		"GetMessages":       storage.Polling,
		"GetMessageWrite":   storage.Read,
		"SessionSetup":      storage.Session,
		"NfsSomething":      storage.Other,
	} {
		if got := storage.Classify(name); got != want {
			t.Errorf("Classify(%s) = %s, want %s", name, got, want)
		}
	}
	for name, want := range map[string]bool{
		"PutBlob": true, "DeleteBlob": false, "SetBlobTier": false,
		"SetBlobTags": false, "AppendBlock": true, "DeleteEntity": true, "GetBlob": false,
	} {
		if got := storage.WritePrime(name); got != want {
			t.Errorf("WritePrime(%s) = %v, want %v", name, got, want)
		}
	}
}

func TestPoliciesCoverEverySignal(t *testing.T) {
	policies := storage.Policies()
	for _, id := range storage.Signals {
		if _, ok := policies[id]; !ok {
			t.Errorf("signal %s has no output policy", id)
		}
	}
	if len(policies) != len(storage.Signals) {
		t.Errorf("the policy set has %d entries for %d signals", len(policies), len(storage.Signals))
	}
}

func contains(value, substring string) bool { return strings.Contains(value, substring) }
