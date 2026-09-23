package storage

import (
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Policies supplies every user-facing string and publishable detail for the
// storage signals. The stubs carry the SPEC section 4.4 strings verbatim.
func Policies() map[string]output.SignalPolicy {
	number := func(keys ...string) map[string]output.DetailPolicy {
		details := map[string]output.DetailPolicy{}
		for _, key := range keys {
			details[key] = output.DetailPolicy{Kind: output.Number}
		}
		return details
	}
	say := func(present, absent, unknown string) map[verdict.Status]string {
		return map[verdict.Status]string{
			verdict.StatusPresent: present, verdict.StatusAbsent: absent, verdict.StatusUnknown: unknown,
		}
	}
	reference := func(present, absent, unknown string, next ...string) output.SignalPolicy {
		return output.SignalPolicy{
			Family: "reverse-ref", Confidence: "verified",
			Details: number("referenceCount"), Summaries: say(present, absent, unknown), NextSteps: next,
		}
	}
	policies := map[string]output.SignalPolicy{
		SignalImmutability: {
			Family: "structural", Confidence: "verified", Details: number("holdCount"),
			Summaries: say(
				"A legal hold or a locked immutability policy protects data here; Azure refuses to delete it.",
				"No legal hold or locked immutability policy was found.",
				"Immutability could not be read, so a hold cannot be ruled out."),
			NextSteps: []string{"Release the hold or let the policy expire; a locked policy cannot be removed."},
		},
		SignalCloudShell: {
			Family: "kb", Confidence: "heuristic",
			Details: map[string]output.DetailPolicy{"matchedName": {Kind: output.Boolean}},
			Summaries: say(
				"This is a Cloud Shell home account; deleting it loses that user's files and their shell history.",
				"This is not a Cloud Shell home account.",
				"Whether this is a Cloud Shell account could not be established."),
			NextSteps: []string{"Ask the user whose Cloud Shell home this is before deleting."},
		},
		SignalPE: {
			Family: "structural", Confidence: "verified", Details: number("privateEndpointCount"),
			Summaries: say(
				"An approved private endpoint connects to this account, so a private network still reaches it.",
				"No approved private endpoint connection was found.",
				"Private endpoint connections could not be read."),
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "this account body does not expose private endpoint connections",
				Consequence: "a private endpoint reaching this account is not reported",
				HowToCheck:  "az network private-endpoint-connection list --id <id>",
			},
			NextSteps: []string{"Delete or repoint the private endpoint first."},
		},
		SignalNetACL: reference(
			"A network rule lets another Azure resource into this account, and that resource still exists.",
			"No resource-instance network rule points at an existing resource.",
			"Resource-instance rules could not be resolved.",
			"Remove the resource-instance rule, or check what that resource does with this account."),
		SignalORS: reference(
			"An object replication policy copies data to or from this account.",
			"No object replication policy is configured.",
			"Object replication policies could not be read.",
			"Delete the replication policy on both accounts before deleting either."),
		SignalEventGrid: reference(
			"An Event Grid subscription delivers this account's events somewhere, so a handler is wired to it.",
			"No Event Grid subscription is registered on this account.",
			"Event Grid subscriptions could not be read.",
			"Delete the event subscription, or repoint it at another source."),
		SignalBootDiag: reference(
			"A virtual machine writes its boot diagnostics here; deleting the account breaks its serial console.",
			"No virtual machine writes boot diagnostics here.",
			"Boot diagnostics references could not be read.",
			"Point the machine's boot diagnostics at another account first."),
		SignalFlowLogs: reference(
			"A network flow log writes here; deleting the account ends that record.",
			"No flow log writes here.",
			"Flow log references could not be read.",
			"Repoint or disable the flow log first."),
		SignalBackup: reference(
			"A backup instance protects this account's file shares.",
			"No backup instance protects this account.",
			"Backup instances could not be read.",
			"Stop protection on the backup instance before deleting the account."),
		SignalBackupLock: {
			Family: "structural", Confidence: "verified", Details: number("lockCount"),
			Summaries: say(
				"Azure Backup has locked this account because it protects its file shares.",
				"No Azure Backup protection lock was found.",
				"Management locks could not be read."),
			NextSteps: []string{"Stop protection in the Recovery Services vault; the lock goes with it."},
		},
		SignalReverse: {
			Family: "reverse-ref", Confidence: "verified",
			Details: map[string]output.DetailPolicy{
				"referenceCount": {Kind: output.Number}, "hardReference": {Kind: output.Boolean}},
			Summaries: say(
				"Another resource's configuration names this account. A Flex Consumption function app's deployment storage is a hard dependency; anything else names it without a confirmed producer and is reported as intent.",
				"No other resource in this subscription names this account.",
				"References from other resources could not be read."),
			NextSteps: []string{"Open the referencing resource and check what it uses this account for."},
		},
		SignalVMExt: reference(
			"A virtual machine extension is configured against this account, such as a diagnostics agent.",
			"No virtual machine extension names this account.",
			"Virtual machine extensions could not be read.",
			"Reconfigure the extension before deleting the account."),
		SignalFunctions: {
			Family: "kb", Confidence: "heuristic", Details: number("containerCount"),
			Summaries: say(
				"This account holds Functions host containers, so a function app may be using it as its host storage. Confirming which app would need a data-plane read this version does not make.",
				"No Functions host containers are present.",
				"The container listing could not be read."),
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "host ids under `azure-webjobs-hosts/` are not read (data plane); the container match alone is reported as design intent",
				Consequence: "a live Function App using this account as host storage is reported as `tentative`, not `no`",
				HowToCheck:  "az storage blob directory list -c azure-webjobs-hosts --account-name <sa> --auth-mode login and compare with function app names",
			},
			NextSteps: []string{"Check the function apps in this subscription for this account's name in their host storage setting."},
		},
		SignalKB: {
			Family: "kb", Confidence: "unknown",
			Details: number("matchCount"),
			Summaries: say(
				"Names in this account follow the conventions of known Azure producers; each match is reported as its own signal.",
				"No container, share, queue or table name matches a known producer's naming convention.",
				"The child listings could not be read, so no name could be matched."),
			Caveats: []string{
				"A name match is a naming convention, not the producer itself. It is reported at the tier a name alone may claim, and only finding the producer in configuration would raise it.",
			},
		},
		SignalLists: {
			Family: "structural", Confidence: "verified",
			Details: number("containersCount", "sharesCount", "queuesCount", "tablesCount"),
			Summaries: say(
				"The containers, shares, queues and tables were all listed completely, so what the account holds is known.",
				"A listing came back empty in a way that could not be confirmed as complete.",
				"A listing could not be completed, so what this account holds is not fully known."),
		},
		SignalLease: {
			Family: "structural", Confidence: "verified", Details: number("leaseCount"),
			Summaries: say(
				"A lease is held right now, which means a process has this container or share open.",
				"No lease is held.",
				"Leases could not be read."),
			NextSteps: []string{"Find the process holding the lease; it is using this account now."},
		},
		SignalAnonymous: {
			Family: "metrics", Confidence: "verified", Details: number("requestCount"),
			Summaries: say(
				"Anonymous requests succeeded against this account inside the window, so something reads it without credentials.",
				"No successful anonymous request was recorded.",
				"The authentication breakdown could not be read."),
			NextSteps: []string{"Find the public consumer before removing the account or its public access."},
		},
		SignalWrites: {
			Family: "metrics", Confidence: "verified", Details: number("writeCount", "writeDays"),
			Summaries: say(
				"Data was written to this account inside the window, above the noise floor, so somebody is using it.",
				"No qualifying user writes were recorded inside the window.",
				"The transaction metric could not be read."),
			NextSteps: []string{"Find the writer before deleting; its next write will fail."},
		},
		SignalReads: {
			Family: "metrics", Confidence: "verified", Details: number("readCount", "readDays", "egressMiB"),
			Summaries: say(
				"Data was read out of this account inside the window, above the noise floor, so somebody is using it.",
				"No qualifying user reads were recorded inside the window.",
				"The reads could not be attributed, so they may or may not be a person's."),
			NextSteps: []string{"Find the reader before deleting; its next read will fail."},
		},
		SignalQueue: {
			Family: "metrics", Confidence: "verified", Details: number("pollCount", "pollDays"),
			Summaries: say(
				"A consumer is polling a queue in this account at production rates, so a deployed system depends on it even though the queue is empty.",
				"No high-volume queue polling was recorded.",
				"Queue operations could not be read."),
			NextSteps: []string{"Find the consumer, which will fail when the account is gone."},
		},
		SignalQueueLow: {
			Family: "metrics", Confidence: "verified", Details: number("pollCount", "pollDays"),
			Summaries: say(
				"Something polls a queue in this account occasionally, below the rate that means a deployed consumer.",
				"No queue polling was recorded.",
				"Queue operations could not be read."),
		},
		SignalCountDelta: {
			Family: "metrics", Confidence: "verified", Details: number("growthDays", "objectDelta"),
			Summaries: say(
				"The number of objects in this account grew on more than one day, so data is still arriving.",
				"The object counts did not grow inside the window.",
				"The object counters could not be read."),
		},
		SignalLowReads: {
			Family: "metrics", Confidence: "verified", Details: number("readCount", "readDays"),
			Summaries: say(
				"Some reads were recorded, below the threshold that means live use.",
				"No reads were recorded.",
				"The transaction metric could not be read."),
		},
		SignalDefenderShaped: {
			Family: "metrics", Confidence: "heuristic", Details: number("readCount"),
			Summaries: say(
				"Every successful read was Entra-authenticated while a Defender for Storage scanner could have been running. The scanner's reads cannot be separated from a person's with these metrics, so they are reported as intent rather than as live use.",
				"The reads do not have the shape of scanner-only traffic.",
				"The scanner configuration could not be read."),
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "per-ApiName Defender scanner shaping is not implemented; only the OAuth-only-reads rule is applied",
				Consequence: "reads by Defender and by managed identities are not separated",
				HowToCheck:  "StorageBlobLogs | where RequesterObjectId != \"\" | summarize count() by RequesterObjectId, OperationName",
			},
		},
		SignalSMB: {
			Family: "metrics", Confidence: "verified", Details: number("sessionCount"),
			Summaries: say(
				"A client mounted a file share from this account inside the window.",
				"No SMB session was recorded.",
				"File service operations could not be read."),
			NextSteps: []string{"Find the machine with the share mounted before deleting."},
		},
		SignalSilence: {
			Family: "metrics", Confidence: "verified", Details: number("quietDays"),
			Summaries: say(
				"No user transaction of any kind was recorded over the effective window.",
				"User transactions were recorded over the effective window.",
				"Silence could not be established, because either the metric was unreadable, the account is younger than the window, or it served operations this version cannot classify."),
		},
		SignalCountSilence: {
			Family: "metrics", Confidence: "verified", Details: number("quietDays"),
			Summaries: say(
				"The object counts did not grow over the effective window.",
				"The object counts grew over the effective window.",
				"The object counters could not establish silence."),
		},
		SignalSystem: {
			Family: "metrics", Confidence: "verified", Details: number("transactionCount"),
			Summaries: say(
				"The platform itself made transactions against this account, such as lifecycle management. This is not somebody using it.",
				"No platform transactions were recorded.",
				"The transaction metric could not be read."),
		},
		SignalALSilence: {
			Family: "activity-log", Confidence: "verified", Details: number("quietDays"),
			Summaries: say(
				"No control-plane write or key operation was recorded over the effective window.",
				"The account was written to, or its keys were used, inside the effective window.",
				"The Activity Log could not establish control-plane silence."),
		},
		SignalListKeys: {
			Family: "activity-log", Confidence: "verified", Details: number("keyOperationCount", "daysAgo"),
			Summaries: say(
				"Somebody listed or regenerated this account's keys inside the window, which usually means a client is being configured against it.",
				"No key operation was recorded inside the window.",
				"Key operations could not be read."),
			NextSteps: []string{"Ask the caller who took the keys what they connected to this account."},
		},
		SignalSKUGeo: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"replication": {Kind: output.Enum,
				Values: []string{"GRS", "GZRS", "RAGRS", "RAGZRS"}}},
			Summaries: say(
				"This account is geo-redundant, which is a deliberate durability choice somebody made for the data in it.",
				"This account is not geo-redundant.",
				"The account's replication could not be read."),
		},
		SignalLifecycle: {
			Family: "structural", Confidence: "verified", Details: number("ruleCount"),
			Summaries: say(
				"A lifecycle management policy moves or deletes data here on a schedule, which is why some activity is the platform's rather than a person's.",
				"No lifecycle management policy is configured.",
				"The lifecycle policy could not be read."),
		},
		SignalInventory: {
			Family: "structural", Confidence: "verified", Details: number("ruleCount"),
			Summaries: say(
				"An inventory policy writes reports into this account on a schedule, which produces writes nobody is making by hand.",
				"No inventory policy is configured.",
				"The inventory policy could not be read."),
		},
		SignalDefenderConfig: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{
				"enabled": {Kind: output.Boolean}, "onUpload": {Kind: output.Boolean},
				"sensitiveDataDiscovery": {Kind: output.Boolean}},
			Summaries: say(
				"Defender for Storage is enabled on this account, so some reads may be the scanner's rather than a person's.",
				"Defender for Storage is not enabled on this account.",
				"The Defender for Storage configuration could not be read."),
		},
		SignalInventoryShaped: {
			Family: "metrics", Confidence: "unknown",
			Summaries: map[verdict.Status]string{
				verdict.StatusNotEvaluated: "Inventory-report writes are not separated from other writes in this version.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "inventory-report write carve-out is not implemented; the inventory policy is reported as INFO",
				Consequence: "an account whose only writes are inventory reports may be reported `no` instead of `tentative`",
				HowToCheck:  "compare `PutBlob` counts with the inventory schedule (`az storage account blob-inventory-policy show`)",
			},
		},
		SignalDataPlane: {
			Family: "data-plane", Confidence: "verified",
			Details: map[string]output.DetailPolicy{
				"lastWrite":         {Kind: output.Timestamp},
				"containersWalked":  {Kind: output.Number},
				"partitionDepth":    {Kind: output.Number},
				"withinFreshWindow": {Kind: output.Boolean},
				"complete":          {Kind: output.Boolean},
			},
			Summaries: say(
				"A sample of this account's containers was walked and something was written inside one of them.",
				"The sampled containers had no dated partitions to walk, so nothing was written where the walk could see it.",
				"The data-plane walk could not complete, so the last write inside this account is unknown."),
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "the data-plane walk was not requested, so nothing inside the containers was read",
				Consequence: "last-write dates inside containers are unknown, and freshness rests on the account metrics alone",
				HowToCheck:  "run this again with --data-plane, or az storage blob list --account-name <sa> -c <container> --auth-mode login",
			},
			Caveats: []string{
				"The data-plane walk samples at most five containers and stops after twelve calls or three seconds in each. It can show that something was written; it cannot show that nothing was.",
			},
			NextSteps: []string{
				"Treat the walk as a sample. A date it did not find is not a date that does not exist.",
			},
		},
		SignalSharesUsage: {
			Family: "structural", Confidence: "unknown",
			Summaries: map[verdict.Status]string{
				verdict.StatusNotEvaluated: "Per-share usage is not collected in this version.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "per-share usage statistics are not collected in this version",
				Consequence: "how much data each file share holds is not shown, so an empty share cannot be told from a full one here",
				HowToCheck:  "az storage share-rm show --storage-account <sa> -n <share> --expand stats",
			},
		},
	}
	for id, policy := range kbPolicies() {
		policies[id] = policy
	}
	return policies
}
