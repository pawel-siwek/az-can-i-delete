package cordon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/age"
	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect/collecttest"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

const (
	accountID = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stlogs"
	siteID    = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Web/sites/app1"
)

var (
	cordonedAt = time.Date(2026, 9, 20, 10, 30, 0, 0, time.UTC)
	now        = time.Date(2026, 9, 22, 10, 30, 0, 0, time.UTC)
	pnaTag     = "v=1;m=pna;t=2026-09-20T10:30:00Z;by=" + oid + ";p=Enabled;w=7"
)

func target(t *testing.T, id string) armid.Target {
	t.Helper()
	parsed, err := armid.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func account(tags map[string]string, access string) *collecttest.ARM {
	return &collecttest.ARM{GetFunc: func(context.Context, string, string) (collect.Resource, error) {
		return collect.Resource{ID: accountID, Type: StorageType, Name: "stlogs", Tags: tags,
			Properties: map[string]any{"publicNetworkAccess": access}}, nil
	}}
}

func hourlyPoints(values ...float64) []collect.MetricPoint {
	points := make([]collect.MetricPoint, 0, len(values))
	for i, value := range values {
		points = append(points, collect.MetricPoint{Timestamp: cordonedAt.Truncate(time.Hour).Add(time.Duration(i) * time.Hour), Value: value})
	}
	return points
}

func TestAResourceWithoutTheTagIsNotCordoned(t *testing.T) {
	status, err := Reader{ARM: account(nil, "Enabled")}.Status(context.Background(), target(t, accountID), StatusOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if status.Cordoned || status.CurrentState != "Enabled" || len(status.Activity) != 0 {
		t.Fatalf("status = %+v", status)
	}
}

// The first hour holds the cordon's own writes, so it is left out; every
// later hour is somebody else.
func TestStorageStatusCountsTheScreamsAfterTheOwnHour(t *testing.T) {
	var asked []collect.MetricQuery
	metrics := &collecttest.Metrics{MetricsFunc: func(_ context.Context, q collect.MetricQuery) (collect.MetricResult, error) {
		asked = append(asked, q)
		if q.Names[0] == "UsedCapacity" {
			return collect.MetricResult{Series: []collect.MetricSeries{{Name: "UsedCapacity", Points: hourlyPoints(100, 100, 250)}}}, nil
		}
		return collect.MetricResult{Series: []collect.MetricSeries{{Name: "Transactions", Points: hourlyPoints(900, 3, 4)}}}, nil
	}}
	status, err := Reader{ARM: account(map[string]string{"AZCID": pnaTag}, "Disabled"), Metrics: metrics}.
		Status(context.Background(), target(t, accountID), StatusOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Cordoned || status.Source != "tag" || status.Mode != ModePNA || status.Prior != "Enabled" || status.Reverted {
		t.Fatalf("status = %+v", status)
	}
	if *status.ElapsedHours != 48 || *status.RemainingHours != 5*24 {
		t.Fatalf("elapsed %d remaining %d", *status.ElapsedHours, *status.RemainingHours)
	}
	if len(status.Activity) != 2 || status.Activity[0].Metric != "Transactions" || status.Activity[0].Total != 7 {
		t.Fatalf("activity = %+v", status.Activity)
	}
	if status.Activity[1].Metric != "UsedCapacity" || status.Activity[1].Total != 150 {
		t.Fatalf("growth = %+v", status.Activity[1])
	}
	if asked[0].Filter != "ResponseType eq '*' and TransactionType eq 'User'" || asked[0].Interval != "PT1H" || !asked[0].Window.Start.Equal(time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC)) ||
		!asked[0].Window.End.Equal(time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("query = %+v", asked[0])
	}
	if !contains(status.Caveats, CaveatStorage) || !contains(status.Caveats, CaveatOwnHour) {
		t.Fatalf("caveats = %v", status.Caveats)
	}
}

// ADR-0004: a counter that could not be read is unknown, never zero screams.
func TestAnUnreadableCounterIsUnknownNotSilence(t *testing.T) {
	for name, answer := range map[string]func() (collect.MetricResult, error){
		"forbidden": func() (collect.MetricResult, error) { return collect.MetricResult{}, collecttest.Forbidden() },
		"truncated": func() (collect.MetricResult, error) {
			return collect.MetricResult{Truncated: true, Series: []collect.MetricSeries{{Name: "Requests", Points: hourlyPoints(0, 0)}}}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			arm := &collecttest.ARM{GetFunc: func(context.Context, string, string) (collect.Resource, error) {
				return collect.Resource{ID: siteID, Tags: map[string]string{TagKey: "v=1;m=stop;t=2026-09-20T10:30:00Z;by=" + oid + ";p=Running;w=7"},
					Properties: map[string]any{"state": "Stopped"}}, nil
			}}
			metrics := &collecttest.Metrics{MetricsFunc: func(context.Context, collect.MetricQuery) (collect.MetricResult, error) { return answer() }}
			status, err := Reader{ARM: arm, Metrics: metrics}.Status(context.Background(), target(t, siteID), StatusOptions{Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if len(status.Activity) != 0 || len(status.Unknowns) != 3 {
				t.Fatalf("activity %+v unknowns %+v", status.Activity, status.Unknowns)
			}
			want := verdict.UnkPermission
			if name == "truncated" {
				want = verdict.UnkPartial
			}
			if status.Unknowns[0].Code != want {
				t.Fatalf("code = %s, want %s", status.Unknowns[0].Code, want)
			}
		})
	}
}

// Part of a capacity series cannot show growth, or that there was none.
func TestATruncatedCapacitySeriesIsUnknown(t *testing.T) {
	metrics := &collecttest.Metrics{MetricsFunc: func(_ context.Context, q collect.MetricQuery) (collect.MetricResult, error) {
		if q.Names[0] == "UsedCapacity" {
			return collect.MetricResult{Truncated: true, Series: []collect.MetricSeries{{Name: "UsedCapacity", Points: hourlyPoints(100, 900)}}}, nil
		}
		return collect.MetricResult{}, nil
	}}
	status, err := Reader{ARM: account(map[string]string{TagKey: pnaTag}, "Disabled"), Metrics: metrics}.
		Status(context.Background(), target(t, accountID), StatusOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, counter := range status.Activity {
		if counter.Metric == "UsedCapacity" {
			t.Fatalf("a truncated series was reported as growth: %+v", counter)
		}
	}
	if len(status.Unknowns) != 1 || status.Unknowns[0].ID != "cordon.metric.UsedCapacity" || status.Unknowns[0].Code != verdict.UnkPartial {
		t.Fatalf("unknowns = %+v", status.Unknowns)
	}
}

// Somebody opened the account again. Who did it is Azure's text and is only
// ever printed under untrusted, cleaned.
func TestARevertedCordonNamesTheWriterUnderUntrusted(t *testing.T) {
	log := &collecttest.ActivityLog{Log: collect.ActivityLog{Events: []collect.ActivityEvent{
		{ActivityEvent: age.ActivityEvent{Operation: "Microsoft.Storage/storageAccounts/write", Status: "Succeeded", Timestamp: cordonedAt.Add(-time.Hour)}, Caller: "before@example.com"},
		{ActivityEvent: age.ActivityEvent{Operation: "Microsoft.Storage/storageAccounts/write", Status: "Succeeded", Timestamp: cordonedAt.Add(26 * time.Hour)}, Caller: "pipeline\u202egpj.exe"},
		{ActivityEvent: age.ActivityEvent{Operation: "Microsoft.Storage/storageAccounts/write", Status: "Failed", Timestamp: cordonedAt.Add(30 * time.Hour)}, Caller: "failed@example.com"},
	}}}
	status, err := Reader{ARM: account(map[string]string{TagKey: pnaTag}, "Enabled"), ActivityLog: log}.
		Status(context.Background(), target(t, accountID), StatusOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Reverted || status.RevertedAt == nil || !status.RevertedAt.Equal(cordonedAt.Add(26*time.Hour)) {
		t.Fatalf("status = %+v", status)
	}
	if status.Untrusted["revertedBy"] != "pipelinegpj.exe" || status.Untrusted["revertedByClass"] != "service principal" {
		t.Fatalf("untrusted = %q", status.Untrusted)
	}
}

func TestACorruptTagIsReportedAndNeverGuessed(t *testing.T) {
	status, err := Reader{ARM: account(map[string]string{TagKey: "v=1;m=pna;p=Enabled\u0007"}, "Disabled")}.
		Status(context.Background(), target(t, accountID), StatusOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Cordoned || !status.TagCorrupt || status.Prior != "" || status.Since != nil {
		t.Fatalf("status = %+v", status)
	}
	if status.Untrusted["tag"] != "v=1;m=pna;p=Enabled" || !contains(status.Caveats, CaveatCorrupt) {
		t.Fatalf("untrusted %q caveats %v", status.Untrusted, status.Caveats)
	}
}

// A pna tag on a site is not a stop cordon; it is a tag this tool did not
// write for this resource.
func TestATagOfTheWrongModeIsCorrupt(t *testing.T) {
	arm := &collecttest.ARM{GetFunc: func(context.Context, string, string) (collect.Resource, error) {
		return collect.Resource{ID: siteID, Tags: map[string]string{TagKey: pnaTag}, Properties: map[string]any{"state": "Stopped"}}, nil
	}}
	status, err := Reader{ARM: arm}.Status(context.Background(), target(t, siteID), StatusOptions{Now: now})
	if err != nil || !status.TagCorrupt {
		t.Fatalf("status %+v err %v", status, err)
	}
}

func TestSiteStatusReadsEverySlot(t *testing.T) {
	arm := &collecttest.ARM{
		GetFunc: func(context.Context, string, string) (collect.Resource, error) {
			return collect.Resource{ID: siteID, Tags: map[string]string{TagKey: "v=1;m=stop;t=2026-09-20T10:30:00Z;by=" + oid + ";p=Running;w=7;s=blue:Running,green:Stopped"},
				Properties: map[string]any{"state": "Stopped"}}, nil
		},
		ListFunc: func(_ context.Context, path, _ string) ([]collect.Resource, error) {
			if path != siteID+"/slots" {
				t.Fatalf("listed %s", path)
			}
			return []collect.Resource{
				{Name: "app1/blue", Properties: map[string]any{"state": "Running"}},
				{Name: "app1/green", Properties: map[string]any{"state": "Stopped"}},
			}, nil
		},
	}
	status, err := Reader{ARM: arm}.Status(context.Background(), target(t, siteID), StatusOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Slots) != 2 || status.Slots[0] != (SlotStatus{Ref: "slot1", Prior: "Running", Current: "Running"}) {
		t.Fatalf("slots = %+v", status.Slots)
	}
	// The name is Azure's text: published under untrusted only.
	if status.Untrusted["slot1"] != "blue" || status.Untrusted["slot2"] != "green" {
		t.Fatalf("untrusted = %v", status.Untrusted)
	}
	// A slot running again is a reverted cordon even while production is
	// still stopped.
	if !status.Reverted {
		t.Fatal("a restarted slot was not reported as reverted")
	}
}

func TestStatusRefusesWhatCordonRefuses(t *testing.T) {
	disk := "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Compute/disks/d1"
	_, err := Reader{ARM: &collecttest.ARM{}}.Status(context.Background(), target(t, disk), StatusOptions{Now: now})
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Code != CodeNotApplicable {
		t.Fatalf("err = %v", err)
	}
}

func TestStatusOfAMissingResourceIsNotFound(t *testing.T) {
	arm := &collecttest.ARM{GetFunc: func(context.Context, string, string) (collect.Resource, error) {
		return collect.Resource{}, &collect.Failure{StatusCode: 404, ErrorCode: "ResourceNotFound"}
	}}
	if _, err := (Reader{ARM: arm}).Status(context.Background(), target(t, accountID), StatusOptions{Now: now}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestHistoryStandsInForALostTagOnlyWhenAsked(t *testing.T) {
	history := History{Path: filepath.Join(t.TempDir(), "sub", "history.jsonl")}
	if err := history.Append(Entry{TS: cordonedAt, Action: ActionCordon, ID: accountID, Mode: ModePNA, Prior: "Enabled", OID: oid, Tag: pnaTag}); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(history.Path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("history file mode %v, %v", info.Mode(), err)
		}
	}
	reader := Reader{ARM: account(nil, "Disabled")}
	status, err := reader.Status(context.Background(), target(t, accountID), StatusOptions{Now: now, History: history})
	if err != nil || status.Cordoned {
		t.Fatalf("without --from-history: %+v %v", status, err)
	}
	status, err = reader.Status(context.Background(), target(t, strings.ToUpper(accountID[:1])+accountID[1:]), StatusOptions{Now: now, History: history, FromHistory: true})
	if err != nil || !status.Cordoned || status.Source != "history" || !contains(status.Caveats, CaveatHistory) {
		t.Fatalf("with --from-history: %+v %v", status, err)
	}

	// An uncordon closes the entry: history does not resurrect a finished
	// cordon.
	if err := history.Append(Entry{TS: now, Action: ActionUncordon, ID: strings.ToLower(accountID), Mode: ModePNA}); err != nil {
		t.Fatal(err)
	}
	if _, err := history.LatestCordon(accountID); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("after uncordon: %v", err)
	}
}

func TestADamagedHistoryLineIsSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	body := "{not json\n" + `{"ts":"2026-09-20T10:30:00Z","action":"cordon","id":"` + accountID + `","mode":"pna","prior":"Enabled","oid":"` + oid + `","tag":"` + pnaTag + `"}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	entry, err := History{Path: path}.LatestCordon(accountID)
	if err != nil || entry.Tag != pnaTag {
		t.Fatalf("entry %+v err %v", entry, err)
	}
	if _, err := (History{Path: filepath.Join(t.TempDir(), "absent")}).LatestCordon(accountID); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("absent file: %v", err)
	}
}

func TestDefaultHistoryHonoursAZCIDHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(HomeEnv, dir)
	history, err := DefaultHistory()
	if err != nil || history.Path != filepath.Join(dir, "history.jsonl") {
		t.Fatalf("history %+v err %v", history, err)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// A cordon minutes old has no whole hour after its own yet. Asking Azure
// Monitor for less than one PT1H interval is refused, which read as
// "the request was rejected" on a live account; now it says when the first
// total will exist and asks nothing.
func TestAYoungCordonAsksForNoTotalsYet(t *testing.T) {
	asked := 0
	metrics := &collecttest.Metrics{MetricsFunc: func(context.Context, collect.MetricQuery) (collect.MetricResult, error) {
		asked++
		return collect.MetricResult{}, nil
	}}
	status, err := Reader{ARM: account(map[string]string{TagKey: pnaTag}, "Disabled"), Metrics: metrics}.
		Status(context.Background(), target(t, accountID), StatusOptions{Now: cordonedAt.Add(50 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if asked != 0 || len(status.Unknowns) != 0 || len(status.Activity) != 0 {
		t.Fatalf("asked %d, status %+v", asked, status)
	}
	want := "the first is readable after 2026-09-20T12:00:00Z"
	found := false
	for _, caveat := range status.Caveats {
		found = found || strings.Contains(caveat, want)
	}
	if !found {
		t.Fatalf("caveats = %v", status.Caveats)
	}
}
