package disk

import (
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Policies supplies every user-facing string and every publishable detail for
// the disk signals. Nothing here is built from Azure text.
func Policies() map[string]output.SignalPolicy {
	diskStates := []string{"Attached", "Unattached", "Reserved", "Frozen",
		"ActiveSAS", "ActiveSASFrozen", "ActiveUpload", "ReadyToUpload"}
	return map[string]output.SignalPolicy{
		SignalAttached: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{
				"diskState":       {Kind: output.Enum, Values: diskStates},
				"attachedByOwner": {Kind: output.Boolean},
			},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "Something is holding this disk, so it cannot be deleted while that lasts.",
				verdict.StatusAbsent:  "Nothing holds this disk and no owner is recorded on it.",
				verdict.StatusUnknown: "The disk's attachment state could not be read.",
			},
			NextSteps: []string{"Detach the disk from its owner, or delete the owner instead."},
		},
		SignalActiveSAS: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"diskState": {Kind: output.Enum, Values: diskStates}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "An export shared access signature is active on this disk right now, so somebody is reading or writing it.",
				verdict.StatusAbsent:  "No export is active on this disk.",
				verdict.StatusUnknown: "The disk's export state could not be read.",
			},
		},
		SignalBackup: {
			Family: "reverse-ref", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"referenceCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A backup instance protects this disk; deleting it ends that protection.",
				verdict.StatusAbsent:  "No backup instance references this disk.",
				verdict.StatusUnknown: "Backup instances could not be read, so protection cannot be ruled out.",
			},
			NextSteps: []string{"Stop protection on the backup instance before deleting the disk."},
		},
		SignalAKSPV: {
			Family: "reverse-ref", Confidence: "heuristic",
			Details: map[string]output.DetailPolicy{"cluster": {Kind: output.ARMID}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "This disk is a Kubernetes persistent volume of a cluster that still exists; a pod mounting it loses its storage.",
				verdict.StatusAbsent:  "This disk is not a persistent volume of an existing cluster.",
				verdict.StatusUnknown: "Cluster ownership could not be established.",
			},
			NextSteps: []string{"Delete the persistent volume claim in the cluster instead of the disk."},
		},
		SignalASRReplica: {
			Family: "kb", Confidence: "heuristic",
			Details: map[string]output.DetailPolicy{
				"matchedName": {Kind: output.Boolean}, "matchedMetadata": {Kind: output.Boolean}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "This disk is named or tagged as a Site Recovery replica or seed disk; deleting it breaks replication.",
				verdict.StatusAbsent:  "This disk is not a Site Recovery replica or seed disk.",
				verdict.StatusUnknown: "The disk's name and tags could not be read.",
			},
			NextSteps: []string{"Disable replication for the protected item instead of deleting the disk."},
		},
		SignalImage: {
			Family: "reverse-ref", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"referenceCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "An image or gallery image version was built from this disk and still references it.",
				verdict.StatusAbsent:  "No image references this disk.",
				verdict.StatusUnknown: "Image references could not be read.",
			},
		},
		SignalGolden: {
			Family: "structural", Confidence: "heuristic",
			Details: map[string]output.DetailPolicy{
				"createOption":    {Kind: output.Enum, Values: []string{"Import", "ImportSecure", "Upload"}},
				"matchedMetadata": {Kind: output.Boolean},
			},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "This disk's content was imported or uploaded, or it is tagged as an image or template, which is deliberate intent rather than use.",
				verdict.StatusAbsent:  "Nothing marks this disk as an imported or golden image.",
				verdict.StatusUnknown: "The disk's provenance could not be read.",
			},
			NextSteps: []string{"Check whether a rebuild still depends on this content before deleting."},
		},
		SignalExport: {
			Family: "activity-log", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"daysAgo": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "An export shared access signature was issued for this disk inside the observation window.",
				verdict.StatusAbsent:  "No export was issued inside the observation window.",
				verdict.StatusUnknown: "Export activity could not be established from the Activity Log.",
			},
		},
		SignalUnattached: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"diskState": {Kind: output.Enum, Values: diskStates}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "The disk is unattached.",
				verdict.StatusAbsent:  "The disk is not unattached.",
				verdict.StatusUnknown: "The disk's attachment state could not be read.",
			},
		},
		SignalOwnership: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{
				"detachedDays":        {Kind: output.Number},
				"lastOwnershipChange": {Kind: output.Timestamp},
			},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "The disk's owner last changed at least 30 days ago.",
				verdict.StatusAbsent:  "The disk's owner changed within the last 30 days, which is too recent to call it abandoned.",
				verdict.StatusUnknown: "The resource provider did not report when the disk's owner last changed, so how long it has been detached is unknown.",
			},
			NextSteps: []string{"Wait until the disk has been detached for at least 30 days, or confirm with its owner."},
		},
		SignalAdvisor: {
			Family: "derived", Confidence: "heuristic",
			Details: map[string]output.DetailPolicy{"recommendationCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "Azure Advisor also reports this disk as unattached. This corroborates idleness and never establishes it on its own.",
				verdict.StatusAbsent:  "Azure Advisor has no unattached-disk recommendation for this disk.",
				verdict.StatusUnknown: "Azure Advisor recommendations could not be read.",
			},
		},
		SignalIO: {
			Family: "metrics", Confidence: "sampled",
			Details: map[string]output.DetailPolicy{
				"busyPoints": {Kind: output.Number}, "lastIODaysAgo": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "Disk input and output was recorded after the last ownership change, which contradicts an idle disk. This is information; it does not decide the verdict.",
				verdict.StatusAbsent:  "No disk input or output was recorded after the last ownership change.",
				verdict.StatusUnknown: "Disk input and output counters could not be read.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "disk input and output counters were not collected in this run",
				Consequence: "activity on an apparently detached disk would not be reported as a contradiction",
				HowToCheck:  "az monitor metrics list --resource <id> --metric 'Composite Disk Read Operations/sec'",
			},
		},
	}
}
