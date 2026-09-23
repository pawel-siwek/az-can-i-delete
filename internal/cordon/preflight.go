package cordon

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Assessor runs check for the first pre-flight step and returns the report
// document. A resource that does not exist is ErrNotFound.
type Assessor func(ctx context.Context, target armid.Target, windowDays int) (map[string]any, error)

// Cordoner runs the scream test. It is the only type here that holds a Writer.
type Cordoner struct {
	Reader  Reader
	Writer  Writer
	Assess  Assessor
	History History
	// Now is the only clock the cordon reads.
	Now func() time.Time
}

// Options are a cordon's flags.
type Options struct {
	WindowDays int
	// Force overrides a `no` verdict and an unreadable policy pre-flight.
	// It says so in the plan; it never makes deletion safe.
	Force bool
	// Yes confirms the plan, and acknowledges each warning that asks for it.
	Yes    bool
	DryRun bool
}

// Plan is everything pre-flight established. Nothing has been written.
type Plan struct {
	Target      armid.Target
	Mode        Mode
	State       State
	Tag         string
	Principal   Principal
	Verdict     string
	ReasonClass string
	// Forced lists the tier 1-3 signals a --force walked past.
	Forced []string
	// Consumers are the present tier 2-4 signals: what might scream.
	Consumers []string
	// Acknowledged are the warnings --yes accepted.
	Acknowledged []string
	Notes        []string
	NotBlocked   string
	// resource is the body pre-flight read, kept to check nothing moved
	// between the plan and the change.
	resource collect.Resource
}

// The pre-flight refusal codes of SPEC appendix E section 6.1.
const (
	CodeVerdictNo          = "verdict-no"
	CodeAlreadyIsolated    = "already-isolated"
	CodeCloudShellAccount  = "cloudshell-account"
	CodeNFSOrPremiumFiles  = "nfs-or-premium-files"
	CodeAlreadyStopped     = "already-stopped"
	CodeTooManySlots       = "too-many-slots"
	CodeLockedReadOnly     = "locked-readonly"
	CodeLocksUnreadable    = "locks-unreadable"
	CodeAlreadyCordoned    = "already-cordoned"
	CodeStateTagCorrupt    = "state-tag-corrupt"
	CodeAutomationWriter   = "automation-writer"
	CodePolicyRestricted   = "policy-restricted"
	CodePolicyUnknown      = "policy-unknown"
	CodeStateTooLarge      = "state-too-large"
	CodeStateUnknown       = "state-unknown"
	CodeConfirmation       = "confirmation-required"
	cloudShellSignal       = "storage.cloudshell.account"
	automationLookbackDays = 30
	pnaPolicyAlias         = "Microsoft.Storage/storageAccounts/publicNetworkAccess"
)

func refuse(code, format string, args ...any) *Refusal {
	return &Refusal{Code: code, Exit: 1, Message: fmt.Sprintf("cordon: "+code+": "+format, args...)}
}

// Preflight runs the nine steps in the order SPEC appendix E section 6.1 gives
// them. A Refusal means nothing was written and nothing will be.
func (c Cordoner) Preflight(ctx context.Context, target armid.Target, opts Options) (Plan, error) {
	if opts.WindowDays == 0 {
		opts.WindowDays = DefaultWindowDays
	}
	if opts.WindowDays < MinWindowDays || opts.WindowDays > MaxWindowDays {
		return Plan{}, &Refusal{Code: "usage", Exit: 2, Message: fmt.Sprintf("cordon: window must be between %dd and %dd", MinWindowDays, MaxWindowDays)}
	}
	plan := Plan{Target: target}

	// 1. check. The cordon window is the check window, raised to the shortest
	// window check accepts.
	report, err := c.Assess(ctx, target, max(opts.WindowDays, 7))
	if err != nil {
		if _, refusal := Gate(target.ResourceType); refusal != nil {
			return Plan{}, refusal
		}
		return Plan{}, err
	}
	plan.Verdict, _ = report["verdict"].(string)
	plan.ReasonClass, _ = report["reasonClass"].(string)
	decisive := presentSignals(report, verdict.TierBlocker, verdict.TierLiveActivity)
	plan.Consumers = presentSignals(report, verdict.TierHardDependency, verdict.TierDesignIntent)
	if plan.Verdict == "no" {
		if !opts.Force {
			return Plan{}, &Refusal{Code: CodeVerdictNo, Exit: 1, Message: fmt.Sprintf(
				"cordon: verdict is no (%s); pass --force to cordon anyway (this does not make deletion safe)", plan.ReasonClass)}
		}
		plan.Forced = decisive
	}

	// 2. The type gate.
	mode, refusal := Gate(target.ResourceType)
	if refusal != nil {
		return Plan{}, refusal
	}
	plan.Mode, plan.NotBlocked = mode, NotBlocked[mode]

	// 3. Mode-specific refusals.
	version, err := rules.APIVersion(target.ResourceType)
	if err != nil {
		return Plan{}, err
	}
	resource, err := c.Reader.ARM.Get(ctx, target.ID, version)
	if err != nil {
		if collect.NotFound(err) {
			return Plan{}, ErrNotFound
		}
		return Plan{}, fmt.Errorf("reading %s: %w", target.ResourceType, err)
	}
	plan.resource = resource
	current := CurrentState(mode, resource)
	var slots []Slot
	switch mode {
	case ModePNA:
		if err := c.storageRefusals(ctx, target, version, resource, current, report, opts, &plan); err != nil {
			return Plan{}, err
		}
	case ModeStop:
		if slots, err = c.siteRefusals(ctx, target, version, current); err != nil {
			return Plan{}, err
		}
	}

	// 4. Locks at every scope that can hold one.
	if err := c.locks(ctx, target, opts); err != nil {
		return Plan{}, err
	}

	// 5. The marker.
	if raw, tagged := TagValue(resource.Tags); tagged {
		if existing, parseErr := Parse(raw); parseErr == nil {
			return Plan{}, &Refusal{Code: CodeAlreadyCordoned, Exit: 1, Message: fmt.Sprintf(
				"cordon: already cordoned by %s at %s (mode %s)", existing.By, existing.Since.Format(timeLayout), existing.Mode)}
		}
		// The raw value is somebody's text; status prints it, labelled.
		return Plan{}, refuse(CodeStateTagCorrupt, "the azcid tag does not parse, and its prior state is not guessed; `az-can-i-delete status %s` shows it. %s",
			target.ID, manual(mode, target.ID))
	}

	// 6. Automation writers.
	principal, err := c.Writer.Principal(ctx)
	if err != nil {
		return Plan{}, fmt.Errorf("identifying the signed-in principal: %w", err)
	}
	plan.Principal = principal
	if err := c.automationWriters(ctx, target, principal, opts, &plan); err != nil {
		return Plan{}, err
	}

	// 7. Policy, asked with the uncordon body: a cordon that cannot be undone
	// is not a scream test.
	if err := c.policy(ctx, target, mode, current, resource, opts, &plan); err != nil {
		return Plan{}, err
	}

	// 8. The state tag, rendered and measured before anything is changed.
	plan.State = State{Mode: mode, Since: c.Now().UTC().Truncate(time.Second), By: principal.ObjectID,
		Prior: current, WindowDays: opts.WindowDays, Slots: slots}
	tag, err := plan.State.Format()
	if err != nil {
		if strings.Contains(err.Error(), "longer than") {
			return Plan{}, refuse(CodeStateTooLarge, "the azcid tag would exceed %d bytes; fewer or shorter slot names are needed", MaxTagBytes)
		}
		return Plan{}, refuse(CodeStateUnknown, "the state to record does not fit the azcid grammar")
	}
	plan.Tag = tag

	// 9. Confirmation. A dry run is a complete plan that writes nothing.
	if !opts.Yes && !opts.DryRun {
		return plan, &Refusal{Code: CodeConfirmation, Exit: 1, Message: "cordon: pass --yes to apply this plan, or --dry-run to only print it"}
	}
	return plan, nil
}

// presentSignals lists the ids of present evidence between two tiers.
func presentSignals(report map[string]any, from, to verdict.Tier) []string {
	var ids []string
	evidence, _ := report["evidence"].([]any)
	for _, item := range evidence {
		row, _ := item.(map[string]any)
		tier := tierOf(row["tier"])
		if row["status"] != string(verdict.StatusPresent) || tier < from || tier > to {
			continue
		}
		if id, ok := row["id"].(string); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

func tierOf(value any) verdict.Tier {
	switch v := value.(type) {
	case float64:
		return verdict.Tier(v)
	case int:
		return verdict.Tier(v)
	case interface{ Int64() (int64, error) }:
		n, _ := v.Int64()
		return verdict.Tier(n)
	}
	return 0
}

func (c Cordoner) storageRefusals(ctx context.Context, target armid.Target, version string, resource collect.Resource, current string, report map[string]any, opts Options, plan *Plan) error {
	switch current {
	case "Disabled", PriorSecuredByPerimeter:
		return refuse(CodeAlreadyIsolated, "publicNetworkAccess is already %s; there is nothing to cordon", current)
	case PriorEnabled:
	default:
		return refuse(CodeStateUnknown, "publicNetworkAccess is not a value this tool knows, so the prior state cannot be recorded")
	}
	if slices.Contains(presentSignals(report, verdict.TierBlocker, verdict.TierInfo), cloudShellSignal) {
		return refuse(CodeCloudShellAccount, "this account holds a Cloud Shell file share; cordoning it breaks Cloud Shell for its owner")
	}
	nfs, known := c.fileShares(ctx, target, version, resource)
	if nfs || !known {
		text := "SMB/NFS mounts drop immediately; pass --yes"
		if !known {
			text = "the file shares could not be listed, so NFS mounts cannot be ruled out; SMB/NFS mounts drop immediately; pass --yes"
		}
		if !opts.Yes {
			return refuse(CodeNFSOrPremiumFiles, "%s", text)
		}
		plan.Acknowledged = append(plan.Acknowledged, CodeNFSOrPremiumFiles+": "+text)
	}
	return nil
}

// fileShares reports whether the account is premium file storage or serves a
// share over NFS. known is false when the listing failed: an unread listing
// is not a listing without NFS.
func (c Cordoner) fileShares(ctx context.Context, target armid.Target, version string, resource collect.Resource) (nfs, known bool) {
	if strings.EqualFold(resource.Kind, "FileStorage") {
		return true, true
	}
	shares, err := c.Reader.ARM.List(ctx, target.ID+"/fileServices/default/shares", version)
	if err != nil {
		return false, false
	}
	for _, share := range shares {
		if protocols, _ := share.Properties["enabledProtocols"].(string); strings.EqualFold(protocols, "NFS") {
			return true, true
		}
	}
	return false, true
}

func (c Cordoner) siteRefusals(ctx context.Context, target armid.Target, version, current string) ([]Slot, error) {
	switch current {
	case Stopped:
		return nil, refuse(CodeAlreadyStopped, "the site is already stopped; there is nothing to cordon")
	case Running:
	default:
		return nil, refuse(CodeStateUnknown, "the site's state is not one this tool knows, so the prior state cannot be recorded")
	}
	listed, err := c.Reader.ARM.List(ctx, target.ID+"/slots", version)
	if err != nil {
		return nil, refuse(CodeStateUnknown, "the deployment slots could not be listed, so their states cannot be recorded")
	}
	if len(listed) > MaxSlots {
		return nil, refuse(CodeTooManySlots, "the site has %d deployment slots; a cordon records at most %d", len(listed), MaxSlots)
	}
	slots := make([]Slot, 0, len(listed))
	for _, slot := range listed {
		name := slot.Name
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		state := CurrentState(ModeStop, slot)
		if !slotNamePattern.MatchString(name) || (state != Running && state != Stopped) {
			return nil, refuse(CodeStateUnknown, "a deployment slot's name or state does not fit the azcid grammar")
		}
		slots = append(slots, Slot{Name: name, State: state})
	}
	slices.SortFunc(slots, func(a, b Slot) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return slots, nil
}

func (c Cordoner) locks(ctx context.Context, target armid.Target, opts Options) error {
	subscription := "/subscriptions/" + target.SubscriptionID
	for _, scope := range []string{target.ID, subscription + "/resourceGroups/" + target.ResourceGroup, subscription} {
		locks, err := c.Reader.ARM.Locks(ctx, scope)
		if err != nil {
			// An unread lock is not an absent one. A ReadOnly lock would make
			// the write fail rather than do harm, so this may be forced.
			if opts.Force {
				continue
			}
			return refuse(CodeLocksUnreadable, "the management locks at %s could not be read; pass --force to try anyway", scopeName(scope, target))
		}
		for _, lock := range locks {
			if strings.EqualFold(lock.Level, "ReadOnly") {
				// SPEC names the lock in this sentence. Its name is free text
				// anybody with lock rights chose (ADR-0007), so the sentence
				// says where it is and the command lists it.
				return &Refusal{Code: CodeLockedReadOnly, Exit: 1, Message: fmt.Sprintf(
					"cordon: a ReadOnly lock on %s prevents state changes; az lock list --resource %s", scopeName(scope, target), target.ID)}
			}
		}
	}
	return nil
}

func scopeName(scope string, target armid.Target) string {
	switch scope {
	case target.ID:
		return "the resource"
	case "/subscriptions/" + target.SubscriptionID:
		return "the subscription"
	}
	return "the resource group"
}

func (c Cordoner) automationWriters(ctx context.Context, target armid.Target, principal Principal, opts Options, plan *Plan) error {
	now := c.Now().UTC()
	log, err := c.Reader.ActivityLog.Events(ctx, target.ID, verdict.Window{
		Start: now.AddDate(0, 0, -automationLookbackDays), End: now, Days: automationLookbackDays, Grain: "P1D"})
	var line string
	switch {
	case err != nil:
		line = "cordon: automation writers could not be read from the Activity Log; an IaC apply may revert the cordon and delete its state tag. Pass --yes to proceed."
	default:
		var latest *collect.ActivityEvent
		for i, event := range log.Events {
			op := strings.ToLower(event.Operation)
			if !strings.EqualFold(event.Status, "Succeeded") || event.CallerType != "servicePrincipal" ||
				(!strings.HasSuffix(op, "/write") && !strings.HasSuffix(op, "/action")) ||
				event.AppID == "" || event.AppID == principal.AppID {
				continue
			}
			if latest == nil || event.Timestamp.After(latest.Timestamp) {
				latest = &log.Events[i]
			}
		}
		if latest != nil {
			line = fmt.Sprintf("cordon: automation writer appId %s last wrote %s; an IaC apply will revert the cordon and delete its state tag. Pass --yes to proceed.",
				latest.AppID, latest.Timestamp.UTC().Format(time.RFC3339))
		}
	}
	if line == "" {
		return nil
	}
	if !opts.Yes {
		return &Refusal{Code: CodeAutomationWriter, Exit: 1, Message: line}
	}
	plan.Acknowledged = append(plan.Acknowledged, strings.TrimPrefix(line, "cordon: "))
	return nil
}

// UncordonBody is what an uncordon would send, which is what policy is asked
// about.
func UncordonBody(mode Mode, prior string, resource collect.Resource) (map[string]any, string) {
	content := map[string]any{"location": resource.Location}
	if resource.Kind != "" {
		content["kind"] = resource.Kind
	}
	switch mode {
	case ModePNA:
		content["type"] = StorageType
		content["properties"] = map[string]any{"publicNetworkAccess": prior}
		return content, pnaPolicyAlias
	default:
		content["type"] = SiteType
		content["properties"] = map[string]any{"state": Running}
		return content, ""
	}
}

func (c Cordoner) policy(ctx context.Context, target armid.Target, mode Mode, prior string, resource collect.Resource, opts Options, plan *Plan) error {
	version, err := rules.APIVersion(target.ResourceType)
	if err != nil {
		return err
	}
	content, field := UncordonBody(mode, prior, resource)
	scope := "/subscriptions/" + target.SubscriptionID + "/resourceGroups/" + target.ResourceGroup
	result, err := c.Writer.CheckPolicy(ctx, PolicyCheck{Scope: scope, Content: content, APIVersion: version, Field: field})
	if err != nil {
		// Not knowing is not permission (SPEC section 4).
		if !opts.Force {
			return refuse(CodePolicyUnknown, "policy restrictions for the uncordon could not be evaluated, so it cannot be shown to work; pass --force to proceed anyway")
		}
		plan.Notes = append(plan.Notes, "policy pre-flight: not evaluated (the request failed); proceeding under --force, and GET-verify will detect a Deny or Modify after the fact")
		return nil
	}
	if result.Restricted {
		return refuse(CodePolicyRestricted, "a %s policy would stop the uncordon from restoring the resource; az policy assignment list --scope %s",
			strings.Join(result.Effects, "/"), scope)
	}
	plan.Notes = append(plan.Notes, "policy pre-flight: no Deny or Modify affects the uncordon")
	return nil
}

// manual is the by-hand restore for a cordon this tool cannot restore itself.
func manual(mode Mode, id string) string {
	if mode == ModePNA {
		return "Restore by hand: az storage account update --ids " + id + " --public-network-access Enabled; then az tag update --resource-id " + id + " --operation Delete --tags azcid"
	}
	return "Restore by hand: az webapp start --ids " + id + " (and each slot that was running); then az tag update --resource-id " + id + " --operation Delete --tags azcid"
}
