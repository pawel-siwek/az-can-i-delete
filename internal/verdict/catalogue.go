package verdict

import (
	"slices"
	"strings"
)

// RequiredForType returns a fresh copy of the trusted Required catalogue.
// Types are case-insensitive full ARM types, including sites/slots. Extended
// types remain here for the original acceptance suite, not CLI analyzer support.
// Unknown types deliberately retain the generic.never fallback.
func RequiredForType(resourceType string) []string {
	var required []string
	switch strings.ToLower(resourceType) {
	case "microsoft.storage/storageaccounts":
		required = []string{"generic.arg.visible", "storage.metrics.user-transactions-silence",
			"storage.metrics.count-delta-silence", "storage.activitylog.control-plane-silence", "storage.lists.complete"}
	case "microsoft.compute/virtualmachines":
		required = []string{"generic.arg.visible", "vm.silence.any", "vm.activitylog.no-start-events"}
	case "microsoft.compute/disks":
		required = []string{"generic.arg.visible", "disk.state.unattached", "disk.ownership.age-ge-30d"}
	case "microsoft.network/networkinterfaces":
		required = []string{"generic.arg.visible", "nic.structural.detached", "nic.detached.ge-30d"}
	case "microsoft.network/publicipaddresses":
		required = []string{"generic.arg.visible", "pip.structural.unassociated", "pip.unassociated.ge-30d"}
	case "microsoft.network/networksecuritygroups":
		required = []string{"generic.arg.visible", "nsg.structural.no-associations", "nsg.unassociated.ge-30d"}
	case "microsoft.network/virtualnetworks":
		required = []string{"generic.arg.visible", "vnet.structural.empty", "vnet.activitylog.no-write-30d"}
	case "microsoft.web/sites", "microsoft.web/sites/slots":
		required = []string{"generic.arg.visible", "site.silence.any",
			"site.triggers.http-only-or-none", "site.activitylog.no-deploy-events"}
	case "microsoft.web/serverfarms":
		required = []string{"generic.arg.visible", "plan.structural.zero-sites", "plan.activitylog.no-write-30d"}
	case "microsoft.app/containerapps":
		required = []string{"generic.arg.visible", "aca.silence.any", "aca.scale.http-only", "aca.revisions.no-activity"}
	case "microsoft.app/jobs":
		required = []string{"generic.arg.visible", "job.executions.none", "job.trigger.manual"}
	case "microsoft.app/managedenvironments":
		required = []string{"generic.arg.visible", "env.structural.empty", "env.activitylog.no-write-30d"}
	default:
		required = []string{"generic.never"}
	}
	return slices.Clone(required)
}
