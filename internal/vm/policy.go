package vm

import (
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Policies supplies every user-facing string and publishable detail for the
// virtual machine signals.
func Policies() map[string]output.SignalPolicy {
	say := func(present, absent, unknown string) map[verdict.Status]string {
		return map[verdict.Status]string{
			verdict.StatusPresent: present, verdict.StatusAbsent: absent, verdict.StatusUnknown: unknown,
		}
	}
	owner := func(present, absent, unknown string, next ...string) output.SignalPolicy {
		return output.SignalPolicy{
			Family: "structural", Confidence: "verified",
			Details:   map[string]output.DetailPolicy{"owner": {Kind: output.ARMID}},
			Summaries: say(present, absent, unknown), NextSteps: next,
		}
	}
	reference := func(family, present, absent, unknown string, next ...string) output.SignalPolicy {
		return output.SignalPolicy{
			Family: family, Confidence: "verified",
			Details:   map[string]output.DetailPolicy{"referenceCount": {Kind: output.Number}},
			Summaries: say(present, absent, unknown), NextSteps: next,
		}
	}
	quiet := func(noun string) map[string]output.DetailPolicy {
		_ = noun
		return map[string]output.DetailPolicy{"quietDays": {Kind: output.Number}}
	}
	return map[string]output.SignalPolicy{
		SignalScaleSet: owner(
			"This machine is a member of a scale set, which owns and recreates it.",
			"This machine is not a member of a scale set.",
			"Scale set membership could not be read.",
			"Change the scale set's capacity instead of deleting the machine."),
		SignalAvailability: owner(
			"This machine is in an availability set, which is a deliberate placement decision.",
			"This machine is not in an availability set.",
			"Availability set membership could not be read."),
		SignalReservation: owner(
			"This machine uses a capacity reservation, which somebody is paying to keep.",
			"This machine does not use a capacity reservation.",
			"Capacity reservation membership could not be read."),
		SignalDedicatedHost: owner(
			"This machine runs on a dedicated host, which is a deliberate placement decision.",
			"This machine does not run on a dedicated host.",
			"Dedicated host placement could not be read."),
		SignalPlatform: {
			Family: "kb", Confidence: "heuristic",
			Details: map[string]output.DetailPolicy{"matchedName": {Kind: output.Boolean}},
			Summaries: say(
				"A managed platform created and owns this machine, so deleting it breaks the platform rather than a workload of yours.",
				"No managed platform appears to own this machine.",
				"Platform ownership could not be established."),
			NextSteps: []string{"Scale or reconfigure the platform instead of deleting its machine."},
		},
		SignalBackup: reference("reverse-ref",
			"Azure Backup is protecting this machine, so somebody expects to be able to restore it.",
			"No active backup protects this machine.",
			"Backup protection could not be read.",
			"Stop protection in the vault before deleting, and decide what happens to the recovery points."),
		SignalBackupRetained: reference("reverse-ref",
			"Backup protection was stopped but the recovery points are kept, which is a deliberate decision somebody made.",
			"No retained backup was found.",
			"Backup protection could not be read."),
		SignalASR: reference("reverse-ref",
			"Site Recovery replicates this machine; deleting it breaks the replication.",
			"No Site Recovery item replicates this machine.",
			"Site Recovery items could not be read.",
			"Disable replication for the protected item first."),
		SignalImage: reference("reverse-ref",
			"An image or gallery image version was built from this machine. A generalized source machine is a template rather than a dependency.",
			"No image references this machine.",
			"Image references could not be read."),
		SignalNetworkRefs: reference("reverse-ref",
			"This machine's private address is wired into the network itself, as a route's next hop or a virtual network's DNS server. Those keep pointing at an address that will stop answering.",
			"No route or DNS setting points at this machine's address.",
			"Network references could not be read.",
			"Repoint the route or the DNS server before deleting."),
		SignalPools: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"referenceCount": {Kind: output.Number}},
			Summaries: say(
				"This machine is a backend of a load balancer, a NAT rule or an application gateway, which is still sending traffic to it.",
				"This machine is not in any backend pool.",
				"Backend pool membership could not be read."),
			NextSteps: []string{"Remove the backend from the pool before deleting."},
		},
		SignalAGW: {
			Family: "reverse-ref", Confidence: "unknown",
			Summaries: say(
				"An application gateway pool contains this machine's address.",
				"No application gateway pool contains this address.",
				"Application gateway pools could not be read."),
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "the application gateway address-pool query contract is not part of the committed specification, so no query is issued in this version",
				Consequence: "a gateway that reaches this machine by IP rather than by resource reference is not reported",
				HowToCheck:  "az network application-gateway address-pool list --gateway-name <gateway> -g <rg>",
			},
		},
		SignalDNS: {
			Family: "reverse-ref", Confidence: "unknown",
			Summaries: say(
				"A DNS record points at this machine.",
				"No DNS record pointing at this machine was found.",
				"DNS records could not be read."),
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "the DNS reverse-reference query contract is not part of the committed specification, so no query is issued in this version",
				Consequence: "a DNS record pointing here is not reported, and clients resolving that name break after deletion",
				HowToCheck:  "az network dns record-set list -g <rg> -z <zone> and search for this machine's address",
			},
		},
		SignalFirewall: {
			Family: "reverse-ref", Confidence: "unknown",
			Summaries: map[verdict.Status]string{
				verdict.StatusNotEvaluated: "Azure Firewall rules are not searched for this address in this version.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "Azure Firewall rule references to this IP are not queried",
				Consequence: "firewall rules naming the IP are not reported",
				HowToCheck:  "az network firewall policy rule-collection-group list and search for the IP",
			},
		},
		SignalUpdateManager: {
			Family: "structural", Confidence: "unknown",
			Summaries: map[verdict.Status]string{
				verdict.StatusNotEvaluated: "Update Manager assignments are not queried in this version.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "Update Manager maintenance assignments are not queried",
				Consequence: "a scheduled patch assignment is not reported",
				HowToCheck:  "az maintenance assignment list --resource-type virtualMachines --resource-name <vm> -g <rg> --provider-name Microsoft.Compute",
			},
		},
		SignalOnPremDNS: {
			Family: "reverse-ref", Confidence: "unknown",
			Summaries: map[verdict.Status]string{
				verdict.StatusNotEvaluated: "On-premises name resolution is not visible to this tool.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "on-premises DNS or hosts entries pointing at this VM's IP are not detectable",
				Consequence: "on-premises clients resolving to this IP break",
				HowToCheck:  "search on-premises DNS zones for the IP",
			},
		},
		SignalIdentityRoles: reference("structural",
			"This machine's own identity holds role assignments elsewhere, so something it does depends on those grants.",
			"This machine's identity holds no role assignments.",
			"Role assignments could not be read.",
			"Check what the machine does with those roles before deleting it."),
		SignalIdentityUser: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"identityCount": {Kind: output.Number}},
			Summaries: say(
				"A user-assigned identity is attached to this machine. The identity outlives the machine and stays behind.",
				"No user-assigned identity is attached.",
				"Identities could not be read."),
		},
		SignalPower: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"powerState": {Kind: output.Enum,
				Values: []string{"running", "deallocated", "stopped", "starting", "deallocating", "stopping", "unknown"}}},
			Summaries: say(
				"The machine's current power state.",
				"The machine reported no power state.",
				"The power state could not be read."),
		},
		SignalStartEvents: {
			Family: "activity-log", Confidence: "verified",
			Details: map[string]output.DetailPolicy{
				"eventCount": {Kind: output.Number}, "daysAgo": {Kind: output.Number}},
			Summaries: say(
				"Somebody started, restarted or ran a command on this machine inside the window, so it is being operated.",
				"Nobody started, restarted or ran a command on this machine inside the window.",
				"Operations on this machine could not be read."),
			NextSteps: []string{"Ask the caller who started it what it is for."},
		},
		SignalNoStartEvents: {
			Family: "activity-log", Confidence: "verified", Details: quiet("machine"),
			Summaries: say(
				"Nobody started, restarted or ran a command on this machine over the effective window.",
				"The machine was operated inside the effective window.",
				"Operations could not be established from the Activity Log."),
		},
		SignalMetrics: {
			Family: "metrics", Confidence: "verified",
			Details: map[string]output.DetailPolicy{
				"cpuPercentile": {Kind: output.Number}, "flowsPercentile": {Kind: output.Number},
				"dailyBytes": {Kind: output.Number}},
			Summaries: say(
				"This machine is doing work, because its processor, its connections and its network traffic all clear the idle thresholds.",
				"This machine's metrics stay below the thresholds that mean it is doing work.",
				"The machine's metrics could not be read."),
			NextSteps: []string{"Find out what it is running before switching it off."},
		},
		SignalMetricSilence: {
			Family: "metrics", Confidence: "verified", Details: quiet("machine"),
			Summaries: say(
				"The machine's metrics were idle across the effective window, and the platform's own availability metric covered enough of that window for the silence to mean something.",
				"The machine's metrics were not idle.",
				"Silence could not be established, because the platform's availability metric did not cover enough of the window."),
		},
		SignalDeallocated: {
			Family: "structural", Confidence: "verified", Details: quiet("machine"),
			Summaries: say(
				"The machine has been deallocated for at least 30 days and nobody has started it since.",
				"The machine is running, or it was switched off too recently to say it has been abandoned.",
				"How long the machine has been switched off could not be established."),
		},
		SignalIdle: {
			Family: "derived", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"via": {Kind: output.Enum,
				Values: []string{"metrics", "deallocated"}}},
			Summaries: say(
				"The machine is idle, either because its metrics were silent or because it has been switched off long enough.",
				"The machine is not idle.",
				"Whether the machine is idle could not be established."),
		},
		SignalKept: {
			Family: "derived", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"reasonCount": {Kind: output.Number}},
			Summaries: say(
				"The machine is switched off but deliberately kept, because something still backs it up, replicates it, or holds capacity or placement for it. Deallocation is not retirement.",
				"Nothing indicates the machine is being kept on purpose.",
				"Whether the machine is being kept on purpose could not be established."),
			NextSteps: []string{"Ask whoever configured the backup, replication or reservation whether it is still wanted."},
		},
	}
}
