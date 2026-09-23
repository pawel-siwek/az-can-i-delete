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

// The uncordon failure codes of SPEC appendix E section 6.6.
const (
	CodeNoState           = "no-state"
	CodeRestoreNotApplied = "restore-not-applied"
	CodeBadPrior          = "bad-prior"
	CodeTagDeleteFailed   = "tag-delete-failed"
)

// UncordonOptions are uncordon's flags.
type UncordonOptions struct {
	FromHistory bool
	// Prior is an explicit prior state for a lost tag.
	Prior string
	Yes   bool
}

// Restored is an uncordon that took.
type Restored struct {
	Target armid.Target
	State  State
	Source string
	// TagKept is set when the tag was somebody else's and was left alone.
	TagKept bool
	Notes   []string
}

// Uncordon restores the recorded prior state, verifies it, and only then
// removes the tag.
func (c Cordoner) Uncordon(ctx context.Context, target armid.Target, opts UncordonOptions) (Restored, error) {
	mode, refusal := Gate(target.ResourceType)
	if refusal != nil {
		return Restored{}, refusal
	}
	version, err := rules.APIVersion(target.ResourceType)
	if err != nil {
		return Restored{}, err
	}

	// 1. The resource, and its locks again: one may have appeared since.
	resource, err := c.Reader.ARM.Get(ctx, target.ID, version)
	if err != nil {
		if collect.NotFound(err) {
			return Restored{}, ErrNotFound
		}
		return Restored{}, fmt.Errorf("reading %s: %w", target.ResourceType, err)
	}
	if err := c.locks(ctx, target, Options{}); err != nil {
		return Restored{}, err
	}

	// 2. Where the prior state comes from.
	restored := Restored{Target: target}
	raw, tagged := TagValue(resource.Tags)
	var state State
	switch {
	case opts.Prior != "":
		if !opts.Yes {
			return Restored{}, &Refusal{Code: CodeConfirmation, Exit: 1, Message: "uncordon: --prior restores a state nobody recorded; pass --yes to confirm it"}
		}
		if !validPrior(mode, opts.Prior) {
			return Restored{}, &Refusal{Code: CodeBadPrior, Exit: 2, Message: fmt.Sprintf("uncordon: --prior %q is not a state mode %s can restore", opts.Prior, mode)}
		}
		state = State{Mode: mode, Prior: opts.Prior}
		restored.Source = "--prior"
		if mode == ModeStop {
			restored.Notes = append(restored.Notes, "the slots' prior states were not given; only production is started")
		}
	case opts.FromHistory:
		if !opts.Yes {
			return Restored{}, &Refusal{Code: CodeConfirmation, Exit: 1, Message: "uncordon: --from-history restores what this machine recorded; pass --yes to confirm it"}
		}
		entry, historyErr := c.History.LatestCordon(target.ID)
		if errors.Is(historyErr, ErrNoHistory) {
			return Restored{}, &Refusal{Code: CodeNoState, Exit: 1, Message: "uncordon: no-state: the local history has no cordon for this resource. " + manual(mode, target.ID)}
		}
		if historyErr != nil {
			return Restored{}, historyErr
		}
		parsed, parseErr := entry.State()
		if parseErr != nil || parsed.Mode != mode {
			return Restored{}, &Refusal{Code: CodeStateTagCorrupt, Exit: 1, Message: "uncordon: the history entry for this resource is damaged. " + manual(mode, target.ID)}
		}
		state = parsed
		restored.Source = "history"
	case tagged:
		parsed, parseErr := Parse(raw)
		if parseErr != nil || parsed.Mode != mode {
			return Restored{}, &Refusal{Code: CodeStateTagCorrupt, Exit: 1, Message: fmt.Sprintf(
				"uncordon: state-tag-corrupt: the azcid tag does not parse, and its prior state is not guessed; `az-can-i-delete status %s` shows it. Use --prior with --yes, or %s",
				target.ID, manual(mode, target.ID))}
		}
		state = parsed
		restored.Source = "tag"
	default:
		return Restored{}, &Refusal{Code: CodeNoState, Exit: 1, Message: "uncordon: no-state: the resource carries no azcid tag. Use --from-history --yes if this machine cordoned it, or " + manual(mode, target.ID)}
	}
	restored.State = state

	// A restore is a state change like the cordon was, and is confirmed the
	// same way (ADR-0005): without --yes it says what it would do and does
	// nothing.
	if !opts.Yes {
		return restored, &Refusal{Code: CodeConfirmation, Exit: 1, Message: fmt.Sprintf(
			"uncordon: would restore %s (mode %s, from the %s); pass --yes to apply it", state.Prior, state.Mode, restored.Source)}
	}

	// 3. Restore.
	if err := c.restore(ctx, target, state, version); err != nil {
		if errors.Is(err, ErrStillRunning) {
			return Restored{}, &Refusal{Code: CodeStillRunning, Exit: 1, Message: "uncordon: operation-still-running: the restore did not finish within five minutes; the tag was kept. Run status, then uncordon again."}
		}
		return Restored{}, fmt.Errorf("restoring the prior state: %w", err)
	}

	// 4. Verify before the tag goes: the tag is the only record of the prior.
	if err := c.verifyRestored(ctx, target, state, version); err != nil {
		return Restored{}, err
	}

	// 5. The tag goes only when it was ours, or a human vouched for the
	// source with --yes.
	if tagged {
		principal, principalErr := c.Writer.Principal(ctx)
		ours := principalErr == nil && strings.EqualFold(principal.ObjectID, state.By)
		if ours || ((opts.FromHistory || opts.Prior != "") && opts.Yes) {
			if err := c.Writer.Tags(ctx, target.ID, TagDelete, map[string]string{TagKey: ""}); err != nil {
				return restored, &Refusal{Code: CodeTagDeleteFailed, Exit: 1, Message: "uncordon: the prior state is restored, but the azcid tag could not be removed; az tag update --resource-id " + target.ID + " --operation Delete --tags azcid"}
			}
		} else {
			restored.TagKept = true
			restored.Notes = append(restored.Notes, "the azcid tag was written by "+state.By+", not by the signed-in principal, so it was left in place")
		}
	}

	// 6. History.
	if err := c.History.Append(Entry{TS: c.Now().UTC(), Action: ActionUncordon, ID: target.ID, Mode: mode, Prior: state.Prior, OID: state.By}); err != nil {
		restored.Notes = append(restored.Notes, "the local history could not be written")
	}
	return restored, nil
}

func (c Cordoner) verifyRestored(ctx context.Context, target armid.Target, state State, version string) error {
	mismatch := &Refusal{Code: CodeRestoreNotApplied, Exit: 1, Message: fmt.Sprintf(
		"uncordon: restore-not-applied: a Modify policy or another writer changed it back; check az policy assignment list --scope /subscriptions/%s/resourceGroups/%s. The tag was kept.",
		target.SubscriptionID, target.ResourceGroup)}
	resource, err := c.Reader.ARM.Get(ctx, target.ID, version)
	if err != nil {
		return fmt.Errorf("verifying the restore: %w", err)
	}
	if CurrentState(state.Mode, resource) != state.Prior {
		return mismatch
	}
	running := 0
	for _, slot := range state.Slots {
		if slot.State == Running {
			running++
		}
	}
	if state.Mode != ModeStop || running == 0 {
		return nil
	}
	listed, err := c.Reader.ARM.List(ctx, target.ID+"/slots", version)
	if err != nil {
		return fmt.Errorf("verifying the slots: %w", err)
	}
	states := slotStates(listed)
	for _, slot := range state.Slots {
		if slot.State == Running && states[strings.ToLower(slot.Name)] != Running {
			return mismatch
		}
	}
	return nil
}
