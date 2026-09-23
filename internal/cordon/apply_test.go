package cordon

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/age"
	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect/collecttest"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// cloud is one resource, its slots and its tags, changed only by the fake
// writer below — so every verification in the code under test reads back
// what the writes actually did.
type cloud struct {
	mu        sync.Mutex
	id        string
	kind      string
	property  string // publicNetworkAccess or state
	value     string
	tags      map[string]string
	slots     map[string]string
	shares    []collect.Resource
	sharesErr error
	locks     map[string][]collect.Lock
	lockErr   error
	events    []collect.ActivityEvent
	eventsErr error

	calls []string
	// Hooks let a test make one write misbehave.
	failPatch   func(body map[string]any) error
	ignorePatch bool
	failAction  func(id, action string) error
	failTags    func(op TagOperation) error
	afterTags   func(c *cloud)
	policy      PolicyResult
	policyErr   error
	principal   Principal
}

func storageCloud() *cloud {
	return &cloud{id: accountID, property: "publicNetworkAccess", value: "Enabled", tags: map[string]string{"env": "prod"},
		principal: Principal{ObjectID: oid, AppID: "11111111-1111-1111-1111-111111111111"}}
}

func siteCloud(slots map[string]string) *cloud {
	return &cloud{id: siteID, property: "state", value: Running, tags: map[string]string{}, slots: slots,
		principal: Principal{ObjectID: oid}}
}

func (c *cloud) log(format string, args ...any) {
	c.calls = append(c.calls, fmt.Sprintf(format, args...))
}

func (c *cloud) arm() *collecttest.ARM {
	return &collecttest.ARM{
		GetFunc: func(_ context.Context, id, _ string) (collect.Resource, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			tags := map[string]string{}
			for k, v := range c.tags {
				tags[k] = v
			}
			return collect.Resource{ID: id, Kind: c.kind, Location: "westeurope", Tags: tags,
				Properties: map[string]any{c.property: c.value}}, nil
		},
		ListFunc: func(_ context.Context, path, _ string) ([]collect.Resource, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			if strings.HasSuffix(path, "/shares") {
				return c.shares, c.sharesErr
			}
			var out []collect.Resource
			for name, state := range c.slots {
				out = append(out, collect.Resource{Name: "app1/" + name, Properties: map[string]any{"state": state}})
			}
			return out, nil
		},
		LocksFunc: func(_ context.Context, scope string) ([]collect.Lock, error) {
			if c.lockErr != nil {
				return nil, c.lockErr
			}
			return c.locks[scope], nil
		},
	}
}

func (c *cloud) Principal(context.Context) (Principal, error) { return c.principal, nil }

func (c *cloud) Patch(_ context.Context, id, _ string, body map[string]any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	value := body["properties"].(map[string]any)["publicNetworkAccess"].(string)
	c.log("PATCH %s publicNetworkAccess=%s", id, value)
	if c.failPatch != nil {
		if err := c.failPatch(body); err != nil {
			return err
		}
	}
	if !c.ignorePatch {
		c.value = value
	}
	return nil
}

func (c *cloud) Action(_ context.Context, id, action, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log("POST %s/%s", strings.TrimPrefix(id, c.id), action)
	if c.failAction != nil {
		if err := c.failAction(id, action); err != nil {
			return err
		}
	}
	state := map[string]string{"stop": Stopped, "start": Running}[action]
	if id == c.id {
		c.value = state
		return nil
	}
	c.slots[id[strings.LastIndex(id, "/")+1:]] = state
	return nil
}

func (c *cloud) Tags(_ context.Context, _ string, op TagOperation, tags map[string]string) error {
	c.mu.Lock()
	c.log("TAGS %s", op)
	if c.failTags != nil {
		if err := c.failTags(op); err != nil {
			c.mu.Unlock()
			return err
		}
	}
	for k, v := range tags {
		if op == TagMerge {
			c.tags[k] = v
		} else {
			delete(c.tags, k)
		}
	}
	c.mu.Unlock()
	if c.afterTags != nil {
		c.afterTags(c)
	}
	return nil
}

func (c *cloud) CheckPolicy(_ context.Context, check PolicyCheck) (PolicyResult, error) {
	c.log("POLICY %s field=%s", check.Content["type"], check.Field)
	return c.policy, c.policyErr
}

type fixture struct {
	cloud    *cloud
	cordoner Cordoner
	report   map[string]any
}

func setup(t *testing.T, c *cloud) *fixture {
	t.Helper()
	f := &fixture{cloud: c, report: map[string]any{"verdict": "yes", "reasonClass": "no-evidence-of-use", "evidence": []any{}}}
	f.cordoner = Cordoner{
		Reader: Reader{ARM: c.arm(), ActivityLog: &collecttest.ActivityLog{EventsFunc: func(context.Context, string, verdict.Window) (collect.ActivityLog, error) {
			return collect.ActivityLog{Events: c.events, Days: 30}, c.eventsErr
		}}},
		Writer:  c,
		Assess:  func(context.Context, armid.Target, int) (map[string]any, error) { return f.report, nil },
		History: History{Path: filepath.Join(t.TempDir(), "history.jsonl")},
		Now:     func() time.Time { return now },
	}
	return f
}

func refusalCode(err error) string {
	var refusal *Refusal
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

func TestPreflightProducesTheTagAndWritesNothing(t *testing.T) {
	f := setup(t, storageCloud())
	plan, err := f.cordoner.Preflight(context.Background(), target(t, accountID), Options{Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Tag != "v=1;m=pna;t=2026-09-22T10:30:00Z;by="+oid+";p=Enabled;w=7" {
		t.Fatalf("tag = %s", plan.Tag)
	}
	for _, call := range f.cloud.calls {
		if !strings.HasPrefix(call, "POLICY") {
			t.Fatalf("pre-flight wrote: %s", call)
		}
	}
	if len(f.cloud.calls) != 1 || !strings.Contains(f.cloud.calls[0], "field="+pnaPolicyAlias) {
		t.Fatalf("policy was not asked about the uncordon: %v", f.cloud.calls)
	}
}

func TestWithoutYesThePlanIsShownAndRefused(t *testing.T) {
	f := setup(t, storageCloud())
	plan, err := f.cordoner.Preflight(context.Background(), target(t, accountID), Options{})
	if refusalCode(err) != CodeConfirmation || plan.Tag == "" {
		t.Fatalf("plan %+v err %v", plan, err)
	}
	if plan, err := f.cordoner.Preflight(context.Background(), target(t, accountID), Options{DryRun: true}); err != nil || plan.Tag == "" {
		t.Fatalf("dry run: %+v %v", plan, err)
	}
}

func TestPreflightRefusals(t *testing.T) {
	sp := func(appID string, at time.Time) collect.ActivityEvent {
		return collect.ActivityEvent{ActivityEvent: age.ActivityEvent{Operation: "Microsoft.Storage/storageAccounts/write",
			Status: "Succeeded", Timestamp: at}, CallerType: "servicePrincipal", AppID: appID}
	}
	cases := []struct {
		name    string
		mutate  func(f *fixture)
		opts    Options
		code    string
		message string
	}{
		{"verdict no", func(f *fixture) { f.report["verdict"], f.report["reasonClass"] = "no", "in-use" }, Options{Yes: true}, CodeVerdictNo,
			"cordon: verdict is no (in-use); pass --force to cordon anyway (this does not make deletion safe)"},
		{"already disabled", func(f *fixture) { f.cloud.value = "Disabled" }, Options{Yes: true}, CodeAlreadyIsolated, ""},
		{"behind a perimeter", func(f *fixture) { f.cloud.value = "SecuredByPerimeter" }, Options{Yes: true}, CodeAlreadyIsolated, ""},
		{"cloud shell", func(f *fixture) {
			f.report["evidence"] = []any{map[string]any{"id": "storage.cloudshell.account", "status": "present", "tier": float64(4)}}
		}, Options{Yes: true}, CodeCloudShellAccount, ""},
		{"NFS without yes", func(f *fixture) {
			f.cloud.shares = []collect.Resource{{Properties: map[string]any{"enabledProtocols": "NFS"}}}
		}, Options{DryRun: true}, CodeNFSOrPremiumFiles, "cordon: nfs-or-premium-files: SMB/NFS mounts drop immediately; pass --yes"},
		{"premium files without yes", func(f *fixture) { f.cloud.kind = "FileStorage" }, Options{DryRun: true}, CodeNFSOrPremiumFiles, ""},
		{"unlisted shares without yes", func(f *fixture) { f.cloud.sharesErr = collecttest.Forbidden() }, Options{DryRun: true}, CodeNFSOrPremiumFiles, ""},
		{"read-only lock on the group", func(f *fixture) {
			f.cloud.locks = map[string][]collect.Lock{"/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg": {{Name: "freeze", Level: "ReadOnly"}}}
		}, Options{Yes: true}, CodeLockedReadOnly, "cordon: a ReadOnly lock on the resource group prevents state changes; az lock list --resource " + accountID},
		{"unreadable locks", func(f *fixture) { f.cloud.lockErr = collecttest.Forbidden() }, Options{Yes: true}, CodeLocksUnreadable, ""},
		{"already cordoned", func(f *fixture) { f.cloud.tags[TagKey] = pnaTag }, Options{Yes: true}, CodeAlreadyCordoned,
			"cordon: already cordoned by " + oid + " at 2026-09-20T10:30:00Z (mode pna)"},
		{"damaged marker", func(f *fixture) { f.cloud.tags["AzCid"] = "v=9" }, Options{Yes: true}, CodeStateTagCorrupt, ""},
		{"automation writer", func(f *fixture) {
			f.cloud.events = []collect.ActivityEvent{sp("22222222-2222-2222-2222-222222222222", now.AddDate(0, 0, -3))}
		}, Options{DryRun: true}, CodeAutomationWriter,
			"cordon: automation writer appId 22222222-2222-2222-2222-222222222222 last wrote 2026-09-19T10:30:00Z; an IaC apply will revert the cordon and delete its state tag. Pass --yes to proceed."},
		{"unreadable activity log", func(f *fixture) { f.cloud.eventsErr = collecttest.Forbidden() }, Options{DryRun: true}, CodeAutomationWriter, ""},
		{"policy would block the uncordon", func(f *fixture) { f.cloud.policy = PolicyResult{Restricted: true, Effects: []string{"Deny"}} },
			Options{Yes: true}, CodePolicyRestricted, ""},
		{"policy unknown", func(f *fixture) { f.cloud.policyErr = collecttest.Forbidden() }, Options{Yes: true}, CodePolicyUnknown, ""},
		{"window", func(*fixture) {}, Options{Yes: true, WindowDays: 31}, "usage", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, storageCloud())
			tc.mutate(f)
			_, err := f.cordoner.Preflight(context.Background(), target(t, accountID), tc.opts)
			if refusalCode(err) != tc.code {
				t.Fatalf("err = %v, want %s", err, tc.code)
			}
			if tc.message != "" && err.Error() != tc.message {
				t.Fatalf("\n got %s\nwant %s", err, tc.message)
			}
			for _, call := range f.cloud.calls {
				if !strings.HasPrefix(call, "POLICY") {
					t.Fatalf("a refused pre-flight wrote: %s", call)
				}
			}
		})
	}
}

func TestWhatYesAndForceAcknowledgeIsWrittenDown(t *testing.T) {
	f := setup(t, storageCloud())
	f.report["verdict"] = "no"
	f.report["evidence"] = []any{map[string]any{"id": "storage.pe.approved", "status": "present", "tier": float64(2)}}
	f.cloud.shares = []collect.Resource{{Properties: map[string]any{"enabledProtocols": "NFS"}}}
	f.cloud.events = []collect.ActivityEvent{
		{ActivityEvent: age.ActivityEvent{Operation: "x/write", Status: "Succeeded", Timestamp: now.AddDate(0, 0, -1)}, CallerType: "servicePrincipal", AppID: f.cloud.principal.AppID},
	}
	f.cloud.policyErr = collecttest.Forbidden()
	plan, err := f.cordoner.Preflight(context.Background(), target(t, accountID), Options{Yes: true, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Forced) != 1 || plan.Forced[0] != "storage.pe.approved" {
		t.Fatalf("forced = %v", plan.Forced)
	}
	// The caller's own application is not an automation writer to warn about.
	if len(plan.Acknowledged) != 1 || !strings.HasPrefix(plan.Acknowledged[0], CodeNFSOrPremiumFiles) {
		t.Fatalf("acknowledged = %v", plan.Acknowledged)
	}
	if len(plan.Notes) != 1 || !strings.Contains(plan.Notes[0], "not evaluated") {
		t.Fatalf("notes = %v", plan.Notes)
	}
}

func TestSitePreflightRecordsEverySlotInNameOrder(t *testing.T) {
	f := setup(t, siteCloud(map[string]string{"zeta": Running, "alpha": Stopped}))
	plan, err := f.cordoner.Preflight(context.Background(), target(t, siteID), Options{Yes: true, WindowDays: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(plan.Tag, ";p=Running;w=3;s=alpha:Stopped,zeta:Running") {
		t.Fatalf("tag = %s", plan.Tag)
	}
	for name, mutate := range map[string]func(*cloud){
		CodeAlreadyStopped: func(c *cloud) { c.value = Stopped },
		CodeTooManySlots: func(c *cloud) {
			for _, n := range []string{"a", "b", "c", "d", "e"} {
				c.slots[n] = Running
			}
		},
		CodeStateTooLarge: func(c *cloud) {
			c.slots = map[string]string{strings.Repeat("a", 40): Running, strings.Repeat("b", 40): Running, strings.Repeat("c", 40): Running}
		},
	} {
		c := siteCloud(map[string]string{})
		mutate(c)
		f := setup(t, c)
		if _, err := f.cordoner.Preflight(context.Background(), target(t, siteID), Options{Yes: true}); refusalCode(err) != name {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestTheGateAnswersWhenCheckCannot(t *testing.T) {
	f := setup(t, storageCloud())
	f.cordoner.Assess = func(context.Context, armid.Target, int) (map[string]any, error) {
		return nil, errors.New("unsupported resource type")
	}
	job := "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.App/jobs/j1"
	_, err := f.cordoner.Preflight(context.Background(), target(t, job), Options{Yes: true})
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Exit != 2 || refusal.Code != CodeNotYetSupported {
		t.Fatalf("err = %v", err)
	}
}

func plan(t *testing.T, f *fixture, id string) Plan {
	t.Helper()
	p, err := f.cordoner.Preflight(context.Background(), target(t, id), Options{Yes: true})
	if err != nil {
		t.Fatal(err)
	}
	f.cloud.calls = nil
	return p
}

func TestApplyChangesStateThenTagsThenRemembers(t *testing.T) {
	f := setup(t, storageCloud())
	p := plan(t, f, accountID)
	applied, err := f.cordoner.Apply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PATCH " + accountID + " publicNetworkAccess=Disabled", "TAGS Merge"}
	if strings.Join(f.cloud.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v", f.cloud.calls)
	}
	if f.cloud.tags[TagKey] != p.Tag || f.cloud.tags["env"] != "prod" {
		t.Fatalf("tags = %v", f.cloud.tags)
	}
	entry, err := f.cordoner.History.LatestCordon(accountID)
	if err != nil || entry.Tag != p.Tag || entry.Prior != "Enabled" {
		t.Fatalf("history %+v %v", entry, err)
	}
	if applied.Uncordon != "az-can-i-delete uncordon "+accountID {
		t.Fatalf("uncordon = %s", applied.Uncordon)
	}
}

func TestApplyUndoesOnlyWhatItDid(t *testing.T) {
	cases := []struct {
		name  string
		setup func(c *cloud)
		code  string
		calls []string
		value string
	}{
		{"the tag cannot be written", func(c *cloud) {
			c.failTags = func(TagOperation) error { return collecttest.Forbidden() }
		}, CodeTagWriteFailed, []string{"PATCH " + accountID + " publicNetworkAccess=Disabled", "TAGS Merge", "PATCH " + accountID + " publicNetworkAccess=Enabled"}, "Enabled"},
		{"a policy removes the tag", func(c *cloud) {
			c.afterTags = func(c *cloud) { delete(c.tags, TagKey) }
		}, CodeStateTagRejected, []string{"PATCH " + accountID + " publicNetworkAccess=Disabled", "TAGS Merge", "PATCH " + accountID + " publicNetworkAccess=Enabled"}, "Enabled"},
		{"somebody else cordoned it at the same moment", func(c *cloud) {
			c.afterTags = func(c *cloud) {
				c.tags[TagKey] = "v=1;m=pna;t=2026-09-22T10:30:02Z;by=ffffffff-4e5f-6071-8293-a4b5c6d7e8f9;p=Enabled;w=7"
			}
		}, CodeConcurrentCordon, []string{"PATCH " + accountID + " publicNetworkAccess=Disabled", "TAGS Merge"}, "Disabled"},
		{"the state change does not finish", func(c *cloud) {
			c.failPatch = func(map[string]any) error { return ErrStillRunning }
		}, CodeStillRunning, []string{"PATCH " + accountID + " publicNetworkAccess=Disabled"}, "Enabled"},
		{"the tag write does not finish", func(c *cloud) {
			c.failTags = func(TagOperation) error { return ErrStillRunning }
		}, CodeStillRunning, []string{"PATCH " + accountID + " publicNetworkAccess=Disabled", "TAGS Merge"}, "Disabled"},
		{"a policy puts the state back", func(c *cloud) {
			c.afterTags = func(c *cloud) {
				if _, ok := c.tags[TagKey]; ok {
					c.value = "Enabled"
				}
			}
		}, CodeStateNotApplied, []string{"PATCH " + accountID + " publicNetworkAccess=Disabled", "TAGS Merge", "TAGS Delete"}, "Enabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, storageCloud())
			p := plan(t, f, accountID)
			tc.setup(f.cloud)
			_, err := f.cordoner.Apply(context.Background(), p)
			if refusalCode(err) != tc.code {
				t.Fatalf("err = %v, want %s", err, tc.code)
			}
			if strings.Join(f.cloud.calls, "|") != strings.Join(tc.calls, "|") {
				t.Fatalf("calls:\n got %v\nwant %v", f.cloud.calls, tc.calls)
			}
			if f.cloud.value != tc.value {
				t.Fatalf("publicNetworkAccess = %s, want %s", f.cloud.value, tc.value)
			}
		})
	}
}

func TestTheConcurrentCordonIsRecordedWithItsOwner(t *testing.T) {
	f := setup(t, storageCloud())
	p := plan(t, f, accountID)
	f.cloud.afterTags = func(c *cloud) {
		c.tags[TagKey] = "v=1;m=pna;t=2026-09-22T10:30:02Z;by=ffffffff-4e5f-6071-8293-a4b5c6d7e8f9;p=Enabled;w=7"
	}
	if _, err := f.cordoner.Apply(context.Background(), p); refusalCode(err) != CodeConcurrentCordon {
		t.Fatal(err)
	}
	entry, err := f.cordoner.History.LatestCordon(accountID)
	if err != nil || entry.TagOwner != "ffffffff-4e5f-6071-8293-a4b5c6d7e8f9" {
		t.Fatalf("entry %+v err %v", entry, err)
	}
}

func TestASlotThatWillNotStopRestartsWhatThisRunStopped(t *testing.T) {
	f := setup(t, siteCloud(map[string]string{"alpha": Running, "beta": Stopped, "gamma": Running}))
	p := plan(t, f, siteID)
	f.cloud.failAction = func(id, action string) error {
		if strings.HasSuffix(id, "/gamma") && action == "stop" {
			return collecttest.Forbidden()
		}
		return nil
	}
	if _, err := f.cordoner.Apply(context.Background(), p); refusalCode(err) != CodeSlotStopFailed {
		t.Fatalf("err = %v", err)
	}
	want := []string{"POST /stop", "POST /slots/alpha/stop", "POST /slots/beta/stop", "POST /slots/gamma/stop",
		"POST /slots/alpha/start", "POST /start"}
	if strings.Join(f.cloud.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls:\n got %v\nwant %v", f.cloud.calls, want)
	}
	// beta was stopped before the cordon, so it stays stopped.
	if f.cloud.slots["beta"] != Stopped || f.cloud.slots["alpha"] != Running || f.cloud.value != Running {
		t.Fatalf("state %s slots %v", f.cloud.value, f.cloud.slots)
	}
	if _, tagged := f.cloud.tags[TagKey]; tagged {
		t.Fatal("a failed cordon was tagged")
	}
}

func TestApplyRefusesAResourceThatMovedSincePreflight(t *testing.T) {
	f := setup(t, storageCloud())
	p := plan(t, f, accountID)
	f.cloud.value = "Disabled"
	if _, err := f.cordoner.Apply(context.Background(), p); refusalCode(err) != CodeStateChanged || len(f.cloud.calls) != 0 {
		t.Fatalf("err %v calls %v", err, f.cloud.calls)
	}
}

func cordoned(t *testing.T, c *cloud, id string) *fixture {
	t.Helper()
	f := setup(t, c)
	if _, err := f.cordoner.Apply(context.Background(), plan(t, f, id)); err != nil {
		t.Fatal(err)
	}
	f.cloud.calls = nil
	return f
}

func TestUncordonRestoresVerifiesAndThenRemovesTheTag(t *testing.T) {
	f := cordoned(t, storageCloud(), accountID)
	restored, err := f.cordoner.Uncordon(context.Background(), target(t, accountID), UncordonOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PATCH " + accountID + " publicNetworkAccess=Enabled", "TAGS Delete"}
	if strings.Join(f.cloud.calls, "|") != strings.Join(want, "|") || f.cloud.value != "Enabled" || restored.Source != "tag" {
		t.Fatalf("calls %v value %s restored %+v", f.cloud.calls, f.cloud.value, restored)
	}
	if _, err := f.cordoner.History.LatestCordon(accountID); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("history still holds the cordon: %v", err)
	}
}

func TestUncordonStartsRunningSlotsBeforeProduction(t *testing.T) {
	f := cordoned(t, siteCloud(map[string]string{"alpha": Running, "beta": Stopped}), siteID)
	if _, err := f.cordoner.Uncordon(context.Background(), target(t, siteID), UncordonOptions{}); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /slots/alpha/start", "POST /start", "TAGS Delete"}
	if strings.Join(f.cloud.calls, "|") != strings.Join(want, "|") || f.cloud.slots["beta"] != Stopped {
		t.Fatalf("calls %v slots %v", f.cloud.calls, f.cloud.slots)
	}
}

func TestUncordonKeepsTheTagWhenTheRestoreDidNotTake(t *testing.T) {
	f := cordoned(t, storageCloud(), accountID)
	// Accepted and silently not applied: a Modify policy holding the account
	// closed. The tag is the only record of the prior, so it stays.
	f.cloud.ignorePatch = true
	_, err := f.cordoner.Uncordon(context.Background(), target(t, accountID), UncordonOptions{})
	if refusalCode(err) != CodeRestoreNotApplied || strings.Contains(strings.Join(f.cloud.calls, "|"), "TAGS Delete") {
		t.Fatalf("err %v calls %v", err, f.cloud.calls)
	}
	if f.cloud.tags[TagKey] == "" {
		t.Fatal("the tag was removed")
	}
}

func TestUncordonWithoutAnyStateSaysHowToRestoreByHand(t *testing.T) {
	f := setup(t, storageCloud())
	f.cloud.value = "Disabled"
	_, err := f.cordoner.Uncordon(context.Background(), target(t, accountID), UncordonOptions{})
	if refusalCode(err) != CodeNoState || !strings.Contains(err.Error(), "az storage account update") {
		t.Fatalf("err = %v", err)
	}
}

func TestUncordonFromHistoryAndPriorNeedYes(t *testing.T) {
	f := cordoned(t, storageCloud(), accountID)
	delete(f.cloud.tags, TagKey) // an IaC apply took the tag away
	for _, opts := range []UncordonOptions{{FromHistory: true}, {Prior: "Enabled"}} {
		if _, err := f.cordoner.Uncordon(context.Background(), target(t, accountID), opts); refusalCode(err) != CodeConfirmation {
			t.Fatalf("%+v: err = %v", opts, err)
		}
	}
	if _, err := f.cordoner.Uncordon(context.Background(), target(t, accountID), UncordonOptions{Prior: "Running", Yes: true}); refusalCode(err) != CodeBadPrior {
		t.Fatalf("bad prior: %v", err)
	}
	restored, err := f.cordoner.Uncordon(context.Background(), target(t, accountID), UncordonOptions{FromHistory: true, Yes: true})
	if err != nil || restored.Source != "history" || f.cloud.value != "Enabled" {
		t.Fatalf("restored %+v err %v value %s", restored, err, f.cloud.value)
	}
}

func TestUncordonLeavesSomebodyElsesTag(t *testing.T) {
	f := cordoned(t, storageCloud(), accountID)
	f.cloud.principal = Principal{ObjectID: "ffffffff-4e5f-6071-8293-a4b5c6d7e8f9"}
	restored, err := f.cordoner.Uncordon(context.Background(), target(t, accountID), UncordonOptions{})
	if err != nil || !restored.TagKept || f.cloud.tags[TagKey] == "" {
		t.Fatalf("restored %+v err %v tags %v", restored, err, f.cloud.tags)
	}
}
