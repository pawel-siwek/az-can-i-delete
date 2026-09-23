package cordon

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
)

// The apply failure codes of SPEC appendix E section 6.3.
const (
	CodeStateChanged       = "state-changed"
	CodeSlotStopFailed     = "slot-stop-failed"
	CodeStateNotApplied    = "state-not-applied"
	CodeStillRunning       = "operation-still-running"
	CodeConcurrentCordon   = "concurrent-cordon"
	CodeStateTagRejected   = "state-tag-rejected"
	CodeTagWriteFailed     = "tag-write-failed"
	CodeRevertFailed       = "revert-failed"
	CodeHistoryWriteFailed = "history-write-failed"
)

// Applied is a cordon that is in place and verified.
type Applied struct {
	Plan Plan
	// Uncordon is the command that undoes it.
	Uncordon string
}

// Apply performs the plan: the state change first, then the tag, then a GET
// that verifies both. It undoes only what it did itself, and never another
// writer's change.
func (c Cordoner) Apply(ctx context.Context, plan Plan) (Applied, error) {
	target := plan.Target
	version, err := rules.APIVersion(target.ResourceType)
	if err != nil {
		return Applied{}, err
	}

	// 1. The resource must still be what pre-flight saw.
	resource, err := c.Reader.ARM.Get(ctx, target.ID, version)
	if err != nil {
		return Applied{}, fmt.Errorf("reading %s: %w", target.ResourceType, err)
	}
	if CurrentState(plan.Mode, resource) != plan.State.Prior {
		return Applied{}, refuse(CodeStateChanged, "the resource changed state after pre-flight; nothing was written. Run cordon again.")
	}
	if _, tagged := TagValue(resource.Tags); tagged {
		return Applied{}, refuse(CodeStateChanged, "an azcid tag appeared after pre-flight; nothing was written. Run status to see whose it is.")
	}

	// 2. The state change.
	if err := c.change(ctx, plan, version); err != nil {
		return Applied{}, err
	}

	// 3. Verify it took.
	if err := c.verifyCordoned(ctx, plan, version); err != nil {
		return Applied{}, err
	}

	// 4. The tag.
	if err := c.Writer.Tags(ctx, target.ID, TagMerge, map[string]string{TagKey: plan.Tag}); err != nil {
		if errors.Is(err, ErrStillRunning) {
			// The tag may or may not land. The state is cordoned either way,
			// and history keeps the prior so status and uncordon can find it.
			_ = c.record(plan, "")
			return Applied{}, refuse(CodeStillRunning, "the tag write did not finish within five minutes; the resource is cordoned and the tag may still appear. Nothing was reverted. Check with status, or uncordon --from-history --yes.")
		}
		return Applied{}, c.undo(ctx, plan, version, refuse(CodeTagWriteFailed,
			"the azcid tag could not be written, so the cordon was reverted (Tag Contributor is needed as well as the write on the resource)"))
	}

	// 5. Verify the tag, and that the state survived it.
	after, err := c.Reader.ARM.Get(ctx, target.ID, version)
	if err != nil {
		_ = c.record(plan, "")
		return Applied{}, fmt.Errorf("verifying the cordon: %w", err)
	}
	raw, tagged := TagValue(after.Tags)
	switch {
	case !tagged:
		// A Modify policy removed it. A cordon without a tag cannot be found
		// or restored by anybody else, so it is undone.
		return Applied{}, c.undo(ctx, plan, version, refuse(CodeStateTagRejected,
			"the azcid tag was removed after it was written (a Modify policy?), so the cordon was reverted"))
	case raw == plan.Tag:
	default:
		other, parseErr := Parse(raw)
		if parseErr != nil {
			_ = c.record(plan, "")
			return Applied{}, refuse(CodeStateTagCorrupt, "the azcid tag reads back as something else that does not parse; nothing was reverted, and `az-can-i-delete status %s` shows it. %s",
				target.ID, manual(plan.Mode, target.ID))
		}
		// Somebody else cordoned it at the same moment. Their cordon is not
		// ours to undo.
		_ = c.record(plan, other.By)
		note := ""
		if other.Since.Before(plan.State.Since) {
			note = " Their cordon pre-dates this run (pre-flight missed it by < 5 s)."
		}
		return Applied{}, refuse(CodeConcurrentCordon, "another cordon by %s raced this one; it was not reverted.%s", other.By, note)
	}
	if CurrentState(plan.Mode, after) != cordonedState(plan.Mode) {
		// The state went back while the tag was written: a policy or another
		// writer. The tag would now lie, so it goes.
		_ = c.Writer.Tags(ctx, target.ID, TagDelete, map[string]string{TagKey: ""})
		return Applied{}, refuse(CodeStateNotApplied, "the state was changed back after the cordon was applied (a Modify policy or another writer); the tag was removed")
	}

	// 6. History.
	if err := c.record(plan, ""); err != nil {
		return Applied{Plan: plan, Uncordon: "az-can-i-delete uncordon " + target.ID},
			refuse(CodeHistoryWriteFailed, "the cordon is in place and tagged, but the local history could not be written: %v", err)
	}
	return Applied{Plan: plan, Uncordon: "az-can-i-delete uncordon " + target.ID}, nil
}

// change performs step 2. For a site, production stops first and then each
// slot in name order; a slot that fails restarts exactly what this run
// stopped.
func (c Cordoner) change(ctx context.Context, plan Plan, version string) error {
	target := plan.Target
	switch plan.Mode {
	case ModePNA:
		err := c.Writer.Patch(ctx, target.ID, version, map[string]any{"properties": map[string]any{"publicNetworkAccess": "Disabled"}})
		if errors.Is(err, ErrStillRunning) {
			// It may yet finish, so the prior is kept where uncordon can use it.
			_ = c.record(plan, "")
			return refuse(CodeStillRunning, "disabling public network access did not finish within five minutes; nothing was reverted and no tag was written. The prior is in the local history: check the account, then uncordon --from-history --yes.")
		}
		if err != nil {
			return fmt.Errorf("disabling public network access: %w", err)
		}
	case ModeStop:
		if err := c.Writer.Action(ctx, target.ID, "stop", version); err != nil {
			if errors.Is(err, ErrStillRunning) {
				_ = c.record(plan, "")
				return refuse(CodeStillRunning, "stopping the site did not finish within five minutes; nothing was reverted and no tag was written. The prior is in the local history: check the site, then uncordon --from-history --yes.")
			}
			return fmt.Errorf("stopping the site: %w", err)
		}
		var stopped []string
		for i, slot := range plan.State.Slots {
			if err := c.Writer.Action(ctx, slotID(target, slot.Name), "stop", version); err != nil {
				restart := c.restartSlots(ctx, target, stopped, version)
				startErr := c.Writer.Action(ctx, target.ID, "start", version)
				if restart != nil || startErr != nil {
					return refuse(CodeRevertFailed, "a slot failed to stop and restarting what this run stopped also failed; %s",
						manual(ModeStop, target.ID))
				}
				// Slots are named by position: a name is somebody's text.
				return refuse(CodeSlotStopFailed, "deployment slot %d (in name order) did not stop; production and every slot this run stopped were started again, and no tag was written", i+1)
			}
			// Only a slot that was running is this run's to start again.
			if slot.State == Running {
				stopped = append(stopped, slot.Name)
			}
		}
	}
	return nil
}

func (c Cordoner) restartSlots(ctx context.Context, target armid.Target, names []string, version string) error {
	var errs []error
	for _, name := range names {
		errs = append(errs, c.Writer.Action(ctx, slotID(target, name), "start", version))
	}
	return errors.Join(errs...)
}

// verifyCordoned is step 3: every state this run changed reads back changed.
func (c Cordoner) verifyCordoned(ctx context.Context, plan Plan, version string) error {
	target := plan.Target
	resource, err := c.Reader.ARM.Get(ctx, target.ID, version)
	if err != nil {
		// The state may well be changed; history keeps the prior so the
		// cordon can still be found and undone.
		_ = c.record(plan, "")
		return fmt.Errorf("verifying the state change (the prior is in the local history): %w", err)
	}
	if CurrentState(plan.Mode, resource) != cordonedState(plan.Mode) {
		return c.undo(ctx, plan, version, refuse(CodeStateNotApplied, "the state change reads back unchanged (a Modify policy or another writer?); what this run changed was restored and no tag was written"))
	}
	if plan.Mode != ModeStop || len(plan.State.Slots) == 0 {
		return nil
	}
	listed, err := c.Reader.ARM.List(ctx, target.ID+"/slots", version)
	if err != nil {
		_ = c.record(plan, "")
		return fmt.Errorf("verifying the slots (the prior is in the local history): %w", err)
	}
	states := slotStates(listed)
	for i, slot := range plan.State.Slots {
		if states[strings.ToLower(slot.Name)] != Stopped {
			return c.undo(ctx, plan, version, refuse(CodeStateNotApplied, "deployment slot %d (in name order) reads back as not stopped; what this run changed was restored and no tag was written", i+1))
		}
	}
	return nil
}

// undo reverses this run's state change and returns the reason it had to.
// It restores the recorded prior, and for a site only the slots that were
// running before, because those are the only ones this run stopped.
func (c Cordoner) undo(ctx context.Context, plan Plan, version string, reason *Refusal) error {
	if err := c.restore(ctx, plan.Target, plan.State, version); err != nil {
		return refuse(CodeRevertFailed, "%s, and the revert also failed; %s", strings.TrimPrefix(reason.Message, "cordon: "+reason.Code+": "), manual(plan.Mode, plan.Target.ID))
	}
	return reason
}

// restore applies a recorded state: the inverse of a cordon.
func (c Cordoner) restore(ctx context.Context, target armid.Target, state State, version string) error {
	switch state.Mode {
	case ModePNA:
		return c.Writer.Patch(ctx, target.ID, version, map[string]any{"properties": map[string]any{"publicNetworkAccess": state.Prior}})
	case ModeStop:
		var errs []error
		for _, slot := range state.Slots {
			if slot.State == Running {
				errs = append(errs, c.Writer.Action(ctx, slotID(target, slot.Name), "start", version))
			}
		}
		if state.Prior == Running {
			errs = append(errs, c.Writer.Action(ctx, target.ID, "start", version))
		}
		return errors.Join(errs...)
	}
	return fmt.Errorf("unknown mode %q", state.Mode)
}

func (c Cordoner) record(plan Plan, owner string) error {
	slots := map[string]string{}
	for _, slot := range plan.State.Slots {
		slots[slot.Name] = slot.State
	}
	if len(slots) == 0 {
		slots = nil
	}
	return c.History.Append(Entry{
		TS: c.Now().UTC(), Action: ActionCordon, ID: plan.Target.ID, Mode: plan.Mode, Prior: plan.State.Prior,
		OID: plan.State.By, Slots: slots, Tag: plan.Tag, TagOwner: owner,
	})
}

func slotID(target armid.Target, name string) string { return target.ID + "/slots/" + name }

func slotStates(listed []collect.Resource) map[string]string {
	states := map[string]string{}
	for _, slot := range listed {
		name := slot.Name
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		states[strings.ToLower(name)] = CurrentState(ModeStop, slot)
	}
	return states
}
