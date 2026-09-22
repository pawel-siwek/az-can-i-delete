package site

import (
	"github.com/pawel-siwek/az-can-i-delete/internal/output"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Policies supplies every user-facing string and publishable detail for the
// site, slot and plan signals.
func Policies() map[string]output.SignalPolicy {
	say := func(present, absent, unknown string) map[verdict.Status]string {
		return map[verdict.Status]string{
			verdict.StatusPresent: present, verdict.StatusAbsent: absent, verdict.StatusUnknown: unknown,
		}
	}
	number := func(keys ...string) map[string]output.DetailPolicy {
		details := map[string]output.DetailPolicy{}
		for _, key := range keys {
			details[key] = output.DetailPolicy{Kind: output.Number}
		}
		return details
	}
	return map[string]output.SignalPolicy{
		SignalHostingClass: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"hostingClass": {Kind: output.Enum,
				Values: []string{ClassWindows, ClassFlex, ClassConsumption, ClassDedicated,
					ClassWorkflow, ClassWeb, ClassUnknown}}},
			Summaries: say(
				"The hosting class this site runs under, which decides which counters exist for it.",
				"The hosting class could not be determined from the site and its plan.",
				"The hosting class could not be read."),
		},
		SignalCustomDomain: {
			Family: "structural", Confidence: "verified", Details: number("referenceCount"),
			Summaries: say(
				"A custom domain points at this site. Somebody published that name, and this tool cannot see who resolves it.",
				"Only the default azurewebsites.net hostname points at this site.",
				"The site's hostnames could not be read."),
			NextSteps: []string{"Repoint or retire the domain before deleting the site."},
		},
		SignalFronted: {
			Family: "reverse-ref", Confidence: "verified", Details: number("referenceCount"),
			Summaries: say(
				"Something stands in front of this site, such as Front Door or an application gateway, and its access restrictions say so.",
				"No fronting service was found in this site's access restrictions.",
				"The site's access restrictions could not be read."),
			NextSteps: []string{"Repoint the fronting service's backend before deleting the site."},
		},
		SignalHybrid: {
			Family: "structural", Confidence: "verified", Details: number("referenceCount"),
			Summaries: say(
				"A hybrid connection reaches from this site into another network, so something on the other side is wired to it.",
				"No hybrid connection is configured.",
				"Hybrid connections could not be read."),
			NextSteps: []string{"Check what the hybrid connection reaches before deleting."},
		},
		SignalSlots: {
			Family: "structural", Confidence: "verified",
			Details: number("slotCount"),
			Summaries: say(
				"This site has deployment slots. Each is a site of its own and is checked separately.",
				"This site has no deployment slots.",
				"Deployment slots could not be listed."),
			NextSteps: []string{"Run check on each slot id as well."},
		},
		SignalSlotsLive: {
			Family: "metrics", Confidence: "unknown",
			Summaries: map[verdict.Status]string{
				verdict.StatusNotEvaluated: "Slot traffic is not folded into this site's verdict.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "deployment slots are listed, not evaluated",
				Consequence: "live traffic on a slot is not detected",
				HowToCheck:  "run `check` on each slot id (`…/sites/<site>/slots/<slot>`)",
			},
		},
		SignalVNet: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"owner": {Kind: output.ARMID}},
			Summaries: say(
				"This site is integrated into a virtual network, which is a deliberate networking decision somebody made.",
				"This site is not integrated into a virtual network.",
				"Virtual network integration could not be read."),
		},
		SignalSourceControl: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"configured": {Kind: output.Boolean}},
			Summaries: say(
				"This site is wired to a source repository, so a repository somewhere still expects to deploy here.",
				"No source control is configured.",
				"Source control could not be read."),
		},
		SignalCIActive: {
			Family: "activity-log", Confidence: "verified", Details: number("daysAgo"),
			Summaries: say(
				"Something deployed to this site inside the last 30 days, so a pipeline is still shipping to it.",
				"Nothing deployed to this site inside the last 30 days.",
				"Deployments could not be read."),
			NextSteps: []string{"Find the pipeline that deploys here before deleting the site."},
		},
		SignalNonHTTP: {
			Family: "structural", Confidence: "verified", Details: number("triggerCount"),
			Summaries: say(
				"This app has enabled triggers that fire without a request, such as a timer or a queue. It runs whether or not anybody calls it.",
				"This app has no enabled non-HTTP trigger.",
				"The app's triggers could not be listed."),
			NextSteps: []string{"Check what the trigger consumes before deleting the app."},
		},
		SignalHTTPOnly: {
			Family: "structural", Confidence: "verified", Details: number("triggerCount"),
			Summaries: say(
				"The trigger list was read and nothing fires this app on its own.",
				"This app has a trigger that fires without a request.",
				"The app's triggers could not be listed, so what starts it is unknown."),
		},
		SignalFunctionRuns: {
			Family: "metrics", Confidence: "verified", Details: number("executionCount"),
			Summaries: say(
				"This function app executed functions inside the window, so something is calling it.",
				"No function executions were recorded inside the window.",
				"Azure Monitor publishes no execution counter for this hosting class, so whether the app ran cannot be established here."),
			NextSteps: []string{"Find the caller before deleting the app."},
		},
		SignalWorkflowRuns: {
			Family: "metrics", Confidence: "verified", Details: number("runCount"),
			Summaries: say(
				"This logic app ran workflows inside the window.",
				"No workflow runs were recorded inside the window.",
				"Azure Monitor publishes no workflow counter for this hosting class."),
		},
		SignalRealTraffic: {
			Family: "metrics", Confidence: "verified", Details: number("liveDays", "peakRequests"),
			Summaries: say(
				"This site served more successful requests than its own probes and warm-up would produce, on enough days to mean real callers.",
				"This site never served meaningfully more traffic than its own configuration produces.",
				"The site's request metrics could not be read."),
			NextSteps: []string{"Find out who is calling it before deleting."},
		},
		SignalProbeShaped: {
			Family: "metrics", Confidence: "heuristic", Details: number("probeDays"),
			Summaries: say(
				"The traffic has the shape of a prober rather than of people, which is high volume and almost entirely successful. An external monitor may be calling this site on a schedule.",
				"The traffic does not have a probe shape.",
				"The site's request metrics could not be read."),
			NextSteps: []string{"Find the monitor or scanner that produces this traffic and decide whether it is still wanted."},
		},
		SignalLowVolume: {
			Family: "metrics", Confidence: "verified", Details: number("requestCount"),
			Summaries: say(
				"Some requests arrived, below the floor that means real use.",
				"No requests arrived inside the window.",
				"The site's request metrics could not be read."),
		},
		SignalWebTests: {
			Family: "reverse-ref", Confidence: "verified", Details: number("referenceCount"),
			Summaries: say(
				"An availability test calls this site on a schedule. Its requests are not a person's.",
				"No availability test calls this site.",
				"Availability tests could not be read."),
		},
		SignalWebJobs: {
			Family: "structural", Confidence: "unknown",
			Summaries: map[verdict.Status]string{
				verdict.StatusNotEvaluated: "Continuous WebJobs are not enumerated in this version.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "continuous WebJobs are not enumerated",
				Consequence: "a running WebJob stops when the site is deleted or cordoned",
				HowToCheck:  "az webapp webjob continuous list -n <site> -g <rg>",
			},
		},
		SignalAccessRestrict: {
			Family: "structural", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"how": {Kind: output.Enum,
				Values: []string{"publicNetworkAccess", "ipRestriction"}}},
			Summaries: say(
				"This site is not reachable from the internet, which explains quiet request metrics without meaning nobody wants it.",
				"This site is reachable from the internet.",
				"The site's access configuration could not be read."),
		},
		SignalStopped: {
			Family: "structural", Confidence: "verified", Details: number("daysAgo"),
			Summaries: say(
				"The site is stopped, but too recently to treat that as abandonment.",
				"The site is not stopped, or it has been stopped long enough to count as idle.",
				"The site's state could not be read."),
		},
		SignalStoppedLong: {
			Family: "structural", Confidence: "verified", Details: number("quietDays"),
			Summaries: say(
				"The site has been stopped for at least 30 days and nobody has started it since. A stop nobody reversed is the clearest evidence a site is unwanted.",
				"The site is running, or it was stopped too recently.",
				"How long the site has been stopped could not be established."),
		},
		SignalMetricSilence: {
			Family: "metrics", Confidence: "verified", Details: number("quietDays"),
			Summaries: say(
				"The site was running and served no requests and no processor time over the effective window.",
				"The site served requests or used processor time over the effective window.",
				"Silence could not be established, either because the site was not running, because its age leaves no window, or because its hosting class publishes no execution counter."),
		},
		SignalIdle: {
			Family: "derived", Confidence: "verified",
			Details: map[string]output.DetailPolicy{"via": {Kind: output.Enum,
				Values: []string{"metrics", "stopped"}}},
			Summaries: say(
				"The site is idle, either because its metrics were silent while it ran or because it has been stopped long enough.",
				"The site is not idle.",
				"Whether the site is idle could not be established."),
		},
		SignalAppSettings: {
			Family: "structural", Confidence: "unknown",
			Summaries: map[verdict.Status]string{
				verdict.StatusNotEvaluated: "Application settings are not read in this version.",
			},
			NotEvaluated: &verdict.NotEvaluated{
				Reason:      "application settings are not read, because listing them needs a permission beyond Reader and their values must never be printed",
				Consequence: "a storage account, a queue or another service this site depends on through a setting is not reported",
				HowToCheck:  "az webapp config appsettings list -n <site> -g <rg> --query \"[].name\"",
			},
		},
		SignalNoDeploys: {
			Family: "activity-log", Confidence: "verified", Details: number("quietDays"),
			Summaries: say(
				"Nobody deployed to, swapped, restarted or reconfigured this site over the effective window.",
				"Somebody deployed to or reconfigured this site inside the effective window.",
				"Deployments could not be established from the Activity Log."),
		},
		SignalPlanSites: {
			Family: "structural", Confidence: "verified", Details: number("siteCount"),
			Summaries: say(
				"Sites run on this plan. Deleting the plan takes them with it, so the plan cannot go while they are there.",
				"No site runs on this plan.",
				"How many sites run on this plan could not be read."),
			NextSteps: []string{"Move or delete the sites first, then the plan."},
		},
		SignalPlanAutoscale: {
			Family: "reverse-ref", Confidence: "verified", Details: number("referenceCount"),
			Summaries: say(
				"An autoscale setting drives this plan, which is a deliberate configuration somebody made.",
				"No autoscale setting targets this plan.",
				"Autoscale settings could not be read."),
		},
		SignalPlanEmpty: {
			Family: "structural", Confidence: "verified", Details: number("siteCount"),
			Summaries: say(
				"This plan hosts no sites and is being paid for anyway.",
				"This plan hosts sites.",
				"How many sites run on this plan could not be read."),
		},
		SignalPlanAdvisor: {
			Family: "derived", Confidence: "heuristic", Details: number("recommendationCount"),
			Summaries: say(
				"Azure Advisor also reports this plan as empty. This corroborates idleness and never establishes it on its own.",
				"Azure Advisor has no empty-plan recommendation for this plan.",
				"Azure Advisor recommendations could not be read."),
		},
		SignalPlanQuiet: {
			Family: "activity-log", Confidence: "verified", Details: number("quietDays"),
			Summaries: say(
				"Nobody changed this plan in the last 30 days.",
				"Somebody changed this plan inside the last 30 days.",
				"Changes to this plan could not be established from the Activity Log."),
		},
	}
}
