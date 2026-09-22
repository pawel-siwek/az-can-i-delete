// Package disk is the analyzer for Microsoft.Compute/disks. A managed disk is
// the cheapest resource to be sure about: its own body says whether anything
// is attached to it, and the Resource Graph says whether a backup, an image or
// a cluster still references it. Everything this layer cannot read stays
// unknown, so an unreadable reference never reads as a free disk.
package disk

import (
	"context"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/armid"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/generic"
	"github.com/pawel-siwek/az-can-i-delete/internal/signal"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// ResourceType is the only type this analyzer answers for.
const ResourceType = "Microsoft.Compute/disks"

// The disk signal IDs of SPEC section 5.4.
const (
	SignalAttached   = "disk.state.attached"
	SignalActiveSAS  = "disk.state.activesas"
	SignalBackup     = "disk.backup.instance"
	SignalAKSPV      = "disk.aks.pv"
	SignalASRReplica = "disk.asr.replica"
	SignalImage      = "disk.image.source"
	SignalGolden     = "disk.provenance.golden"
	SignalExport     = "disk.activitylog.export"
	SignalUnattached = "disk.state.unattached"
	SignalOwnership  = "disk.ownership.age-ge-30d"
	SignalAdvisor    = "disk.advisor.unattached"
	SignalIO         = "disk.metrics.io"
)

// OwnershipDays is the fixed detachment period the Required ownership signal
// asks about. It is an absolute period, not the requested window.
const OwnershipDays = 30

// UnattachedAdvisorType is the Advisor recommendation for an unattached disk.
const UnattachedAdvisorType = "48eda464"

// attachedStates are the disk states that mean something holds the disk. Only
// Unattached and ActiveSAS are not in this set: ActiveSAS is live use rather
// than an attachment, and it is reported by its own signal.
var attachedStates = []string{"attached", "reserved", "frozen", "activesasfrozen", "activeupload", "readytoupload"}

// goldenCreateOptions mean the disk's content came from somewhere else, which
// is design intent rather than use.
var goldenCreateOptions = []string{"import", "importsecure", "upload"}

// Catalogue is SPEC section 5.4. An unreadable reverse reference is critical:
// a disk whose backup or image references could not be read must not be
// reported as free.
var Catalogue = signal.Catalogue{
	SignalAttached:   {Tier: verdict.TierBlocker, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalActiveSAS:  {Tier: verdict.TierLiveActivity, Critical: true, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalBackup:     {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalAKSPV:      {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "heuristic", API: "ARG", ARGBacked: true},
	SignalASRReplica: {Tier: verdict.TierHardDependency, Critical: true, Family: "kb", Confidence: "heuristic", API: "ARM"},
	SignalImage:      {Tier: verdict.TierHardDependency, Critical: true, Family: "reverse-ref", Confidence: "verified", API: "ARG", ARGBacked: true},
	SignalGolden:     {Tier: verdict.TierDesignIntent, Family: "structural", Confidence: "heuristic", API: "ARM"},
	SignalExport:     {Tier: verdict.TierDesignIntent, Family: "activity-log", Confidence: "verified", API: "ActivityLog"},
	SignalUnattached: {Tier: verdict.TierObservedIdle, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalOwnership:  {Tier: verdict.TierObservedIdle, Family: "structural", Confidence: "verified", API: "ARM"},
	SignalAdvisor:    {Tier: verdict.TierObservedIdle, Family: "derived", Confidence: "heuristic", API: "Advisor", ARGBacked: true},
	SignalIO:         {Tier: verdict.TierInfo, Family: "metrics", Confidence: "sampled", API: "Metrics"},
}

// Signals is the catalogue order. Every run emits all of them.
var Signals = []string{
	SignalAttached, SignalActiveSAS, SignalBackup, SignalAKSPV, SignalASRReplica, SignalImage,
	SignalGolden, SignalExport, SignalUnattached, SignalOwnership, SignalAdvisor, SignalIO,
}

// Input is what the analyzer needs on top of the generic layer's result, which
// it reuses rather than collecting the Activity Log or the graph probe again.
type Input struct {
	Target    armid.Target
	Resource  collect.Resource
	Requested verdict.Window
	Cutoff    time.Time
	Clients   collect.Clients
	Graph     *collect.Limiter
	Generic   generic.Result
}

// Collect runs the disk analyzer and returns its evidence in catalogue order.
func Collect(ctx context.Context, in Input) []verdict.Evidence {
	state := diskState(in.Resource)
	managedBy, _ := in.Resource.Properties["managedBy"].(string)

	var backup, image, advisor referenceGroup
	var io metricsGroup
	outcomes := collect.Gather(ctx, []collect.Signal{
		{ID: SignalBackup, Run: backup.run(in, backupQuery, SignalBackup)},
		{ID: SignalImage, Run: image.run(in, imageQuery, SignalImage)},
		{ID: SignalAdvisor, Run: advisor.run(in, advisorQuery, SignalAdvisor)},
		{ID: SignalIO, Run: io.run(in)},
	})

	collected := map[string]verdict.Evidence{
		SignalAttached:   attachedEvidence(state, managedBy),
		SignalActiveSAS:  activeSASEvidence(state),
		SignalAKSPV:      aksEvidence(in),
		SignalASRReplica: asrEvidence(in.Target.Name, in.Resource.Tags),
		SignalGolden:     goldenEvidence(in.Resource),
		SignalExport:     exportEvidence(in),
		SignalUnattached: unattachedEvidence(state),
		SignalOwnership:  ownershipEvidence(in.Resource, in.Cutoff),
	}
	for _, outcome := range outcomes {
		for _, evidence := range outcome.Evidence {
			collected[evidence.ID] = evidence
		}
		if outcome.Unknown != nil {
			collected[outcome.ID] = Catalogue.Unknown(outcome.ID, outcome.Unknown)
		}
	}
	evidence := make([]verdict.Evidence, 0, len(Signals))
	for _, id := range Signals {
		found, ok := collected[id]
		if !ok {
			found = Catalogue.Unknown(id, &verdict.Unknown{
				Code: verdict.UnkTransient, Message: "the signal produced no observation"})
		}
		evidence = append(evidence, found)
	}
	return evidence
}

func diskState(resource collect.Resource) string {
	state, _ := resource.Properties["diskState"].(string)
	return state
}

// attachedEvidence reports anything holding the disk. managedBy is decisive on
// its own: a disk owned by a VM is attached whatever its reported state says.
func attachedEvidence(state, managedBy string) verdict.Evidence {
	if !contains(attachedStates, state) && managedBy == "" {
		return Catalogue.Absent(SignalAttached)
	}
	details := map[string]any{"attachedByOwner": managedBy != ""}
	if canonical := canonicalState(state); canonical != "" {
		details["diskState"] = canonical
	}
	return Catalogue.Present(SignalAttached, details)
}

func activeSASEvidence(state string) verdict.Evidence {
	if !strings.EqualFold(state, "ActiveSAS") {
		return Catalogue.Absent(SignalActiveSAS)
	}
	return Catalogue.Present(SignalActiveSAS, map[string]any{"diskState": "ActiveSAS"})
}

func unattachedEvidence(state string) verdict.Evidence {
	if !strings.EqualFold(state, "Unattached") {
		return Catalogue.Absent(SignalUnattached)
	}
	return Catalogue.Present(SignalUnattached, map[string]any{"diskState": "Unattached"})
}

// ownershipEvidence answers the fixed 30-day detachment question. A disk whose
// resource provider does not report the ownership timestamp is unknown, not
// long-detached: this is one of the Required signals for a `yes`.
func ownershipEvidence(resource collect.Resource, cutoff time.Time) verdict.Evidence {
	changed, ok := ownershipTime(resource)
	if !ok {
		return Catalogue.Unknown(SignalOwnership, &verdict.Unknown{
			Code:    verdict.UnkUnsupported,
			Message: "the resource provider did not report the last ownership change"})
	}
	days := int(cutoff.Sub(changed) / (24 * time.Hour))
	if days < OwnershipDays {
		return signal.Windowed(Catalogue.Absent(SignalOwnership), cutoff, OwnershipDays)
	}
	evidence := Catalogue.Present(SignalOwnership, map[string]any{
		"detachedDays": days, "lastOwnershipChange": signal.Timestamp(changed)})
	return signal.Windowed(evidence, cutoff, OwnershipDays)
}

// ownershipTime reads LastOwnershipUpdateTime, whose spelling differs between
// api-versions; a value in the future is not a usable observation.
func ownershipTime(resource collect.Resource) (time.Time, bool) {
	for _, key := range []string{"LastOwnershipUpdateTime", "lastOwnershipUpdateTime"} {
		value, ok := resource.Properties[key].(string)
		if !ok {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			continue
		}
		return parsed.UTC(), true
	}
	return time.Time{}, false
}

// aksEvidence reports a disk that is a Kubernetes persistent volume. The tag
// alone is not enough: the cluster's node resource group must still be owned
// by a cluster, and an unresolved owner keeps the signal unknown.
func aksEvidence(in Input) verdict.Evidence {
	if !hasPVCTag(in.Resource.Tags) {
		return Catalogue.Absent(SignalAKSPV)
	}
	if !in.Generic.ARGVisible {
		return Catalogue.Unknown(SignalAKSPV, in.Generic.ARGUnknown)
	}
	if !strings.HasPrefix(strings.ToUpper(in.Target.ResourceGroup), "MC_") || in.Generic.ManagedBy == "" {
		return Catalogue.Absent(SignalAKSPV)
	}
	return Catalogue.Present(SignalAKSPV, map[string]any{"cluster": in.Generic.ManagedBy})
}

func hasPVCTag(tags map[string]string) bool {
	for key := range tags {
		if strings.Contains(strings.ToLower(key), "kubernetes.io-created-for-pvc-name") {
			return true
		}
	}
	return false
}

// asrEvidence reports a Site Recovery replica or seed disk, which is named and
// tagged by the service rather than referenced from another resource.
func asrEvidence(name string, tags map[string]string) verdict.Evidence {
	lower := strings.ToLower(name)
	named := strings.HasSuffix(lower, "-asrreplica") ||
		strings.HasPrefix(lower, "ms-asr-") || strings.HasPrefix(lower, "asrseeddisk-")
	tagged := false
	for key := range tags {
		if key := strings.ToLower(key); strings.Contains(key, "asr-replicadisk") || strings.Contains(key, "rsvaultbackup") {
			tagged = true
		}
	}
	if !named && !tagged {
		return Catalogue.Absent(SignalASRReplica)
	}
	return Catalogue.Present(SignalASRReplica, map[string]any{"matchedName": named, "matchedMetadata": tagged})
}

// goldenEvidence reports a disk whose content was imported or uploaded, or
// which is tagged as an image or template. It is design intent, never use.
func goldenEvidence(resource collect.Resource) verdict.Evidence {
	creation, _ := resource.Properties["creationData"].(map[string]any)
	createOption, _ := creation["createOption"].(string)
	imported := contains(goldenCreateOptions, createOption)
	tagged := false
	for key, value := range resource.Tags {
		for _, term := range []string{"image", "golden", "template"} {
			if strings.Contains(strings.ToLower(key), term) || strings.Contains(strings.ToLower(value), term) {
				tagged = true
			}
		}
	}
	if !imported && !tagged {
		return Catalogue.Absent(SignalGolden)
	}
	details := map[string]any{"matchedMetadata": tagged}
	if imported {
		details["createOption"] = canonicalCreateOption(createOption)
	}
	return Catalogue.Present(SignalGolden, details)
}

// exportEvidence reports an export SAS issued inside the requested window. It
// reuses the Activity Log the generic layer already read; an unread log keeps
// the signal unknown rather than reporting that no export happened.
func exportEvidence(in Input) verdict.Evidence {
	if !in.Generic.ActivityLogRead {
		return Catalogue.Unknown(SignalExport, &verdict.Unknown{
			Code: verdict.UnkDependency, Message: "the Activity Log could not be read"})
	}
	newest := time.Time{}
	for _, event := range in.Generic.ActivityLog.Events {
		if !strings.EqualFold(event.Status, "Succeeded") ||
			!strings.Contains(strings.ToLower(event.Operation), "begingetaccess") {
			continue
		}
		if event.Timestamp.After(newest) && !event.Timestamp.Before(in.Requested.Start) {
			newest = event.Timestamp
		}
	}
	if newest.IsZero() {
		if in.Generic.ActivityLog.Truncated || in.Generic.ActivityLog.Days < in.Requested.Days {
			return signal.Windowed(Catalogue.Unknown(SignalExport, &verdict.Unknown{
				Code: verdict.UnkPartial, Message: "the Activity Log did not cover the requested window"}),
				in.Cutoff, in.Requested.Days)
		}
		return signal.Windowed(Catalogue.Absent(SignalExport), in.Cutoff, in.Requested.Days)
	}
	evidence := Catalogue.Present(SignalExport, map[string]any{
		"daysAgo": int(in.Cutoff.Sub(newest) / (24 * time.Hour))})
	return signal.Windowed(evidence, in.Cutoff, in.Requested.Days)
}

func canonicalState(state string) string {
	for _, known := range []string{"Attached", "Unattached", "Reserved", "Frozen",
		"ActiveSAS", "ActiveSASFrozen", "ActiveUpload", "ReadyToUpload"} {
		if strings.EqualFold(state, known) {
			return known
		}
	}
	return ""
}

func canonicalCreateOption(option string) string {
	for _, known := range []string{"Import", "ImportSecure", "Upload"} {
		if strings.EqualFold(option, known) {
			return known
		}
	}
	return ""
}

func contains(values []string, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
