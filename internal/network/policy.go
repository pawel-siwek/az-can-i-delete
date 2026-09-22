package network

import (
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Policies supplies every user-facing string and publishable detail for the
// three network analyzers. The two reverse-reference queries the specification
// names but does not define are honest not-evaluated stubs, with the check a
// person can run instead.
func Policies() map[string]output.SignalPolicy {
	count := map[string]output.DetailPolicy{"attachmentCount": {Kind: output.Number}}
	policies := map[string]output.SignalPolicy{
		SignalNICVM: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"owner": {Kind: output.ARMID}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "This interface is attached to a virtual machine, which ARM will not let you delete it out from under.",
				verdict.StatusAbsent:  "No virtual machine holds this interface.",
				verdict.StatusUnknown: "The interface's attachment could not be read.",
			},
			NextSteps: []string{"Delete the virtual machine, or detach the interface from it first."},
		},
		SignalNICPE: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"owner": {Kind: output.ARMID}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "This is the interface of a private endpoint. ARM refuses to delete it directly.",
				verdict.StatusAbsent:  "This interface does not belong to a private endpoint.",
				verdict.StatusUnknown: "The interface's owner could not be read.",
			},
			NextSteps: []string{"Delete the private endpoint instead; its interface goes with it."},
		},
		SignalNICPLS: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"owner": {Kind: output.ARMID}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "This interface belongs to a private link service.",
				verdict.StatusAbsent:  "This interface does not belong to a private link service.",
				verdict.StatusUnknown: "The interface's owner could not be read.",
			},
			NextSteps: []string{"Delete or reconfigure the private link service instead."},
		},
		SignalNICWorkloads: {
			Family: "structural", Confidence: "verified", Details: count,
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A hosted workload, such as a container group, holds this interface.",
				verdict.StatusAbsent:  "No hosted workload holds this interface.",
				verdict.StatusUnknown: "Hosted workloads could not be read.",
			},
			NextSteps: []string{"Delete the workload that hosts this interface instead."},
		},
		SignalNICPool: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"poolCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "This interface is a backend of a load balancer, a NAT rule or an application gateway, which is still serving traffic to it.",
				verdict.StatusAbsent:  "This interface is not in any backend pool.",
				verdict.StatusUnknown: "Backend pool membership could not be read.",
			},
			NextSteps: []string{"Remove the backend from the pool before deleting the interface."},
		},
		SignalNICAGW: {
			Family: "reverse-ref", Confidence: "unknown",
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "An application gateway backend pool contains this interface's address.",
				verdict.StatusAbsent:  "No application gateway pool contains this address.",
				verdict.StatusUnknown: "Application gateway pools could not be read.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "the application gateway address-pool query contract is not part of the committed specification, so no query is issued in this version",
				Consequence: "a gateway that reaches this address by IP rather than by resource reference is not reported",
				HowToCheck:  "az network application-gateway address-pool list --gateway-name <gateway> -g <rg>",
			},
		},
		SignalNICDNS:      dnsStub("interface"),
		SignalNICFirewall: firewallStub(),
		SignalNICStaticIP: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"staticAddressCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "This interface has a static private address, which somebody may have written into a firewall rule or an allow list this tool cannot see.",
				verdict.StatusAbsent:  "This interface has no static private address.",
				verdict.StatusUnknown: "The address allocation could not be read.",
			},
			NextSteps: []string{"Search firewall rules, allow lists and on-premises configuration for this address."},
		},
		SignalNICDetached: {
			Family: "structural", Confidence: "verified", Details: count,
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "Nothing is attached to this interface.",
				verdict.StatusAbsent:  "Something is attached to this interface.",
				verdict.StatusUnknown: "Whether anything is attached could not be established, because one of the attachment sources could not be read.",
			},
		},
		SignalNICIdle: idlePolicy("interface", "It may have been detached when a virtual machine was deleted, which is not always written to the interface itself."),
		SignalPIPAssociated: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"owner": {Kind: output.ARMID}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "This address is associated with something that is using it, whether an interface, a load balancer, a gateway, a bastion, an application gateway or a firewall.",
				verdict.StatusAbsent:  "No configuration is associated with this address.",
				verdict.StatusUnknown: "The address's association could not be read.",
			},
			NextSteps: []string{"Dissociate the address from its consumer before deleting it."},
		},
		SignalPIPNATGateway: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"owner": {Kind: output.ARMID}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A NAT gateway uses this address for outbound traffic.",
				verdict.StatusAbsent:  "No NAT gateway uses this address.",
				verdict.StatusUnknown: "NAT gateway use could not be read.",
			},
			NextSteps: []string{"Remove the address from the NAT gateway first; outbound connectivity depends on it."},
		},
		SignalPIPDNS: dnsStub("address"),
		SignalPIPDomainLabel: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{
				"allocation": {Kind: output.Enum, Values: []string{"Static"}}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "This is a static address with a published domain label, which is a deliberate, stable name somebody may be using.",
				verdict.StatusAbsent:  "This address has no static domain label.",
				verdict.StatusUnknown: "The address's allocation and label could not be read.",
			},
		},
		SignalPIPTraffic: {
			Family: "metrics", Confidence: "sampled",
			Details: map[string]output.DetailPolicy{
				"busyPoints": {Kind: output.Number}, "contradiction": {Kind: output.Boolean}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "Traffic was recorded on this address inside the window. On an address nothing is associated with, that is a contradiction worth explaining. This is information; it does not decide the verdict.",
				verdict.StatusAbsent:  "No traffic was recorded on this address inside the window.",
				verdict.StatusUnknown: "The address's traffic counters could not be read.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "the address's traffic counters were not collected in this run",
				Consequence: "traffic on an apparently unassociated address would not be reported as a contradiction",
				HowToCheck:  "az monitor metrics list --resource <id> --metric ByteCount",
			},
		},
		SignalPIPUnassociated: {
			Family: "structural", Confidence: "verified", Details: count,
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "Nothing is associated with this address.",
				verdict.StatusAbsent:  "Something is associated with this address.",
				verdict.StatusUnknown: "Whether anything is associated could not be established, because one of the association sources could not be read.",
			},
		},
		SignalPIPIdle: idlePolicy("address", ""),
		SignalNSGAssociations: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{
				"attachmentCount": {Kind: output.Number}, "scaleSetModelCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "This group is applied to interfaces, subnets or a scale set's network model. Removing an association is itself the destructive change, so the group is blocked while any remains.",
				verdict.StatusAbsent:  "Every applicable association source was read and none references this group.",
				verdict.StatusUnknown: "One of the association sources could not be read, so associations cannot be ruled out.",
			},
			NextSteps: []string{"Reassign or remove the association at the interface, subnet or scale set first."},
		},
		SignalNSGFlowLog: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"flowLogCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A flow log is configured on this group, whatever state its storage sink is in.",
				verdict.StatusAbsent:  "No flow log is configured on this group.",
				verdict.StatusUnknown: "Flow log configuration could not be read.",
			},
		},
		SignalNSGFlowLogs: {
			Family: "reverse-ref", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"flowLogCount": {Kind: output.Number}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "An enabled flow log writes this group's traffic to a storage account that still exists; deleting the group ends that record.",
				verdict.StatusAbsent:  "No enabled flow log with a surviving storage account writes this group's traffic.",
				verdict.StatusUnknown: "Flow logs could not be read.",
			},
			NextSteps: []string{"Disable the flow log, or confirm its records are no longer needed."},
		},
		SignalNSGPlatform: {
			Family: "kb", Confidence: "heuristic",
			Details: map[string]output.DetailPolicy{
				"matchedName": {Kind: output.Boolean}, "managedGroup": {Kind: output.Boolean}},
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "A managed platform created and maintains this group; deleting it breaks the platform rather than a workload of yours.",
				verdict.StatusAbsent:  "No managed platform appears to own this group.",
				verdict.StatusUnknown: "Platform ownership could not be established.",
			},
			NextSteps: []string{"Change the platform's configuration instead of deleting its group."},
		},
		SignalNSGFree: {
			Family: "structural", Confidence: "verified", Details: count,
			Summaries: map[verdict.Status]string{
				verdict.StatusPresent: "Every applicable association source was read and this group is applied to nothing.",
				verdict.StatusAbsent:  "This group is still applied to something.",
				verdict.StatusUnknown: "Whether the group is applied to anything could not be established.",
			},
		},
		SignalNSGIdle: idlePolicy("group", ""),
	}
	return policies
}

// idlePolicy is the shared wording of the three detachment-age signals.
func idlePolicy(noun, caveat string) output.SignalPolicy {
	absent := "This " + noun + " was written to inside the last 30 days, which is too recent to call it abandoned."
	if caveat != "" {
		absent += " " + caveat
	}
	return output.SignalPolicy{
		Family: "activity-log", Confidence: "verified",
		Details: map[string]output.DetailPolicy{"quietDays": {Kind: output.Number}},
		Summaries: map[verdict.Status]string{
			verdict.StatusPresent: "Nothing has written to this " + noun + " for at least 30 days.",
			verdict.StatusAbsent:  absent,
			verdict.StatusUnknown: "How long this " + noun + " has been untouched could not be established, because the Activity Log or the change history could not be read completely.",
		},
	}
}

// dnsStub is the honest gap where the specification names a DNS
// reverse-reference query but does not define one.
func dnsStub(noun string) output.SignalPolicy {
	return output.SignalPolicy{
		Family: "reverse-ref", Confidence: "unknown",
		Summaries: map[verdict.Status]string{
			verdict.StatusPresent: "A DNS record points at this " + noun + ".",
			verdict.StatusAbsent:  "No DNS record pointing at this " + noun + " was found.",
			verdict.StatusUnknown: "DNS records could not be read.",
		},
		NotEvaluated: &verdict.NotEvaluated{
			Reason:      "the DNS reverse-reference query contract is not part of the committed specification, so no query is issued in this version",
			Consequence: "a DNS record pointing here is not reported, and clients resolving that name break after deletion",
			HowToCheck:  "az network dns record-set list -g <rg> -z <zone> and search for this resource's address",
		},
	}
}

// firewallStub carries the SPEC section 4.4 strings verbatim.
func firewallStub() output.SignalPolicy {
	return output.SignalPolicy{
		Family: "reverse-ref", Confidence: "unknown",
		Summaries: map[verdict.Status]string{
			verdict.StatusNotEvaluated: "Azure Firewall rules are not searched for this address in this version.",
		},
		NotEvaluated: &verdict.NotEvaluated{
			Reason:      "Azure Firewall rule references to this IP are not queried",
			Consequence: "firewall rules naming the IP are not reported",
			HowToCheck:  "az network firewall policy rule-collection-group list and search for the IP",
		},
	}
}
