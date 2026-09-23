package cordon

import (
	"fmt"
	"strings"
)

// Refusal is a cordon, uncordon or status request this tool declines, with the
// exit code and the exact message SPEC appendix E section 4.3 gives it.
type Refusal struct {
	Code    string
	Exit    int
	Message string
}

func (r *Refusal) Error() string { return r.Message }

// The refusal codes of the type gate.
const (
	CodeNotApplicable   = "not-applicable"
	CodeNotYetSupported = "not-yet-supported"
	CodeUnsupportedType = "unsupported-type"
)

// The two resource types a v0.1 cordon can act on.
const (
	StorageType = "Microsoft.Storage/storageAccounts"
	SiteType    = "Microsoft.Web/sites"
)

// Gate returns the mode for a resource type, or the refusal for it. Every
// command in this package passes the same gate, so status and uncordon print
// exactly what cordon would have.
func Gate(resourceType string) (Mode, *Refusal) {
	switch strings.ToLower(resourceType) {
	case strings.ToLower(StorageType):
		return ModePNA, nil
	case strings.ToLower(SiteType):
		return ModeStop, nil
	case "microsoft.compute/virtualmachines":
		return "", notYet(resourceType, "az vm deallocate --ids <id>")
	case "microsoft.app/containerapps":
		return "", notYet(resourceType, "az containerapp update --ids <id> --min-replicas 0 --max-replicas 0")
	case "microsoft.app/jobs":
		return "", notYet(resourceType, "az containerapp job update --ids <id> --trigger-type Manual")
	case "microsoft.network/publicipaddresses":
		// Not in the source table. SPEC section 4 asks for a scoped
		// counterpart rather than mutation support: dissociating an address is
		// the change being tested for, and it is not reversible to the same
		// consumer set.
		return "", &Refusal{Code: CodeNotYetSupported, Exit: 2, Message: fmt.Sprintf(
			"cordon: %s is not supported in this version; releasing or dissociating an address is not reversibly isolated. "+
				"Use: az network public-ip show --ids <id> --query ipConfiguration.id", resourceType)}
	case "microsoft.network/networkinterfaces":
		return "", notApplicable("cordon: a detached NIC has no state to isolate; its verdict is structural. If it is attached, cordon the VM instead.")
	case "microsoft.network/networksecuritygroups":
		return "", notApplicable("cordon: removing an NSG's associations is itself the destructive change; there is no reversible isolation. Its verdict is structural.")
	case "microsoft.network/virtualnetworks":
		return "", notApplicable("cordon: a VNet cannot be isolated without breaking every subnet consumer; its verdict is structural.")
	case "microsoft.compute/disks":
		return "", notApplicable("cordon: an unattached disk receives no traffic; nothing to isolate. Its verdict is structural (diskState, LastOwnershipUpdateTime).")
	case "microsoft.web/serverfarms":
		return "", notApplicable("cordon: a plan with zero sites has no traffic; a plan with sites must not be deleted (BLOCKER). Cordon the sites instead.")
	case "microsoft.app/managedenvironments":
		return "", notApplicable("cordon: an environment with members is a BLOCKER; an empty one has nothing to isolate.")
	}
	return "", &Refusal{Code: CodeUnsupportedType, Exit: 2,
		Message: fmt.Sprintf("cordon: %s is not a supported type.", resourceType)}
}

func notYet(resourceType, manual string) *Refusal {
	return &Refusal{Code: CodeNotYetSupported, Exit: 2, Message: fmt.Sprintf(
		"cordon: %s is not supported in this version (planned: deallocate / stop / suspend). Use: %s", resourceType, manual)}
}

func notApplicable(message string) *Refusal {
	return &Refusal{Code: CodeNotApplicable, Exit: 2, Message: message}
}
