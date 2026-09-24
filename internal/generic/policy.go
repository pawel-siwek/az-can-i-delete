package generic

import (
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Policies is the output policy for every generic signal: the fixed summaries,
// the typed details a report may publish and the verbatim not-evaluated strings
// of SPEC section 4.4. Nothing here is built from Azure text, which is what
// keeps a resource name or a caller out of a summary line.
func Policies() map[string]output.SignalPolicy {
	return map[string]output.SignalPolicy{
		SignalARMGet: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"provisioningState": {Kind: output.Enum,
				Values: []string{"Succeeded", "Failed", "Canceled", "Creating", "Updating", "Deleting"}}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "The resource exists and was read through Azure Resource Manager.",
				verdict.StatusUnknown: "The resource could not be read through Azure Resource Manager.",
			},
		},
		SignalARGVisible: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"rowCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "The resource is visible in Azure Resource Graph.",
				verdict.StatusAbsent:  "The resource is not visible in Azure Resource Graph, so every graph-backed signal is unknown. The caller may lack subscription-scope Reader, or the resource may be newer than the graph's ingestion delay.",
				verdict.StatusUnknown: "The Resource Graph visibility probe could not be completed.",
			},
			NextSteps: []string{"Grant the caller Reader at subscription scope and run the check again."},
		},
		SignalLock: {
			Family: "structural", Confidence: "verified",
			APIVersions: []string{LocksAPIVersion},
			Details: map[string]output.DetailPolicy{
				"level":     {Kind: output.Enum, Values: []string{"CanNotDelete", "ReadOnly"}},
				"scope":     {Kind: output.Enum, Values: []string{"resource", "resourceGroup", "subscription"}},
				"lockCount": {Kind: output.Number},
			},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A management lock blocks deletion until it is removed.",
				verdict.StatusAbsent:  "No management lock was found at resource, resource group or subscription scope.",
				verdict.StatusUnknown: "Management locks could not be read, so a lock cannot be ruled out.",
			},
			NextSteps: []string{"Remove the lock, or confirm with its owner why it exists, before deleting."},
		},
		SignalDenyAssignment: {
			Family: "structural", Confidence: "verified",
			APIVersions: []string{DenyAssignmentsAPIVersion},
			Details:     map[string]output.DetailPolicy{"denyAssignmentCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A deny assignment blocks deletion of this resource.",
				verdict.StatusAbsent:  "No deny assignment covering deletion was found.",
				verdict.StatusUnknown: "Deny assignments could not be read.",
			},
		},
		SignalRGManagedBy: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"managedBy": {Kind: output.ARMID}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "The resource group is managed by another resource, which owns everything inside it.",
				verdict.StatusAbsent:  "The resource group is not managed by another resource.",
				verdict.StatusUnknown: "Resource group ownership could not be established.",
			},
			NextSteps: []string{"Delete or reconfigure the managing resource instead of this one."},
		},
		SignalTagProtect: {
			Family: "tags", Confidence: "heuristic",
			Details: map[string]output.DetailPolicy{"matchCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A tag marks this resource as protected or not yet expired.",
				verdict.StatusAbsent:  "No protection tag was found.",
				verdict.StatusUnknown: "Tags could not be read.",
			},
			NextSteps: []string{"Confirm with the tag's owner before deleting."},
		},
		SignalTagExpired: {
			Family: "tags", Confidence: "heuristic",
			Details: map[string]output.DetailPolicy{
				"matchCount": {Kind: output.Number}, "expiredAt": {Kind: output.Timestamp}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "An expiry tag on this resource is in the past.",
				verdict.StatusAbsent:  "No expired tag was found.",
				verdict.StatusUnknown: "Tags could not be read.",
			},
		},
		SignalTagIntent: {
			Family: "tags", Confidence: "heuristic",
			Details: map[string]output.DetailPolicy{"matchCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A tag indicates deliberate design intent, such as disaster recovery, a golden image or infrastructure as code.",
				verdict.StatusAbsent:  "No design-intent tag was found.",
				verdict.StatusUnknown: "Tags could not be read.",
			},
			NextSteps: []string{"Check whether the resource is a standby, template or managed copy before deleting."},
		},
		SignalHiddenLink: {
			Family: "tags", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"linkCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A hidden-link tag points at a resource that still exists.",
				verdict.StatusAbsent:  "No hidden-link tag points at an existing resource.",
				verdict.StatusUnknown: "Hidden-link targets could not be resolved.",
			},
		},
		SignalHiddenLinkDead: {
			Family: "tags", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"linkCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A hidden-link tag points at a resource that no longer exists.",
				verdict.StatusAbsent:  "No dangling hidden-link tag was found.",
				verdict.StatusUnknown: "Hidden-link targets could not be resolved.",
			},
		},
		SignalTagOwner: {
			Family: "tags", Confidence: "heuristic",
			Details: map[string]output.DetailPolicy{"matchCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "An ownership tag names a person or team to ask.",
				verdict.StatusAbsent:  "No ownership tag was found.",
				verdict.StatusUnknown: "Tags could not be read.",
			},
		},
		SignalDeployment: {
			Family: "activity-log", Confidence: "verified",
			APIVersions: []string{DeploymentsAPIVersion},
			Details:     map[string]output.DetailPolicy{"deployedAt": {Kind: output.Timestamp}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A successful deployment in this resource group created the resource, so redeploying the template may recreate it.",
				verdict.StatusAbsent:  "No deployment in the sampled history lists this resource as an output.",
				verdict.StatusUnknown: "The deployment history could not be read completely.",
			},
			NextSteps: []string{"Remove the resource from its template as well, or the next deployment will recreate it."},
		},
		SignalRecentWrite: {
			Family: "activity-log", Confidence: "verified",
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "Somebody or something changed this resource in the last 30 days.",
				verdict.StatusAbsent:  "No successful control-plane write was recorded in the last 30 days.",
				verdict.StatusUnknown: "The Activity Log could not establish whether recent writes occurred.",
			},
			Details: map[string]output.DetailPolicy{
				"daysAgo":     {Kind: output.Number},
				"callerClass": {Kind: output.Enum, Values: []string{"user", "servicePrincipal", "managedIdentity", "unknown"}},
			},
			NextSteps: []string{"Ask the caller who made the change why the resource is still being maintained."},
		},
		SignalWrites: {
			Family: "activity-log", Confidence: "verified",
			Details: map[string]output.DetailPolicy{
				"writeCount": {Kind: output.Number}, "lastWriteDaysAgo": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "Control-plane writes were recorded in the last 89 days.",
				verdict.StatusAbsent:  "No control-plane write was recorded in the last 89 days.",
				verdict.StatusUnknown: "The 89-day write history could not be read completely.",
			},
		},
		SignalPEConnections: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"privateEndpointCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "An approved private endpoint connects to this resource.",
				verdict.StatusAbsent:  "No approved private endpoint connection was found.",
				verdict.StatusUnknown: "Private endpoint connections could not be read.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "this resource type does not expose private endpoint connections in its resource body",
				Consequence: "a private endpoint reaching this resource through another object is not reported",
				HowToCheck:  "az network private-endpoint-connection list --id <id>",
			},
			NextSteps: []string{"Delete or repoint the private endpoint first."},
		},
		SignalDNSRecords: {
			Family: "reverse-ref", Confidence: "unknown",
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A DNS record points at this resource.",
				verdict.StatusAbsent:  "No DNS record pointing at this resource was found.",
				verdict.StatusUnknown: "DNS records could not be read.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "the DNS reverse-reference query contract is not part of the committed specification, so no query is issued in this version",
				Consequence: "a DNS record pointing at this resource is not reported, and clients resolving that name break after deletion",
				HowToCheck:  "az network dns record-set list -g <rg> -z <zone> and search for this resource's address or hostname",
			},
		},
		SignalAdvisor: {
			Family: "derived", Confidence: "heuristic",
			Details: map[string]output.DetailPolicy{"recommendationCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "Azure Advisor recommends acting on the cost of this resource. This corroborates idleness and never establishes it on its own.",
				verdict.StatusAbsent:  "Azure Advisor has no cost recommendation for this resource.",
				verdict.StatusUnknown: "Azure Advisor recommendations could not be read.",
			},
		},
		SignalRoleAssignments: {
			Family: "structural", Confidence: "unknown",
			Summaries: map[verdict.Status]string{
				verdict.StatusNotEvaluated: "Role assignments on this resource are not listed in this version.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "role assignments on the resource are not listed",
				Consequence: "principals granted access directly on this resource are not shown",
				HowToCheck:  "az role assignment list --scope <id>",
			},
		},
		SignalPolicyState: {
			Family: "structural", Confidence: "unknown",
			Summaries: map[verdict.Status]string{
				verdict.StatusNotEvaluated: "Policy compliance state is not queried in this version.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "policy compliance state is not queried",
				Consequence: "non-compliant policy states are not shown",
				HowToCheck:  "az policy state list --resource <id>",
			},
		},
	}
}
