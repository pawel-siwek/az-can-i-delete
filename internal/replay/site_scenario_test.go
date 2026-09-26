package replay_test

import "fmt"

const (
	siteID = resourceGroupID + "/providers/Microsoft.Web/sites/fn-demo"
	planID = resourceGroupID + "/providers/Microsoft.Web/serverfarms/plan-demo"
)

// siteTentativeLinuxConsumption is the scenario about a limit of the platform
// rather than of this tool.
//
// A Linux consumption function app has no execution counter. Every other signal
// here is quiet — no custom domain, no source control, no hybrid connection, no
// requests — and the one measurement that would settle whether the code ever
// ran does not exist for this hosting class. So the answer is `tentative`, and
// it says which question could not be asked rather than treating the absent
// metric as an absence of executions.
func siteTentativeLinuxConsumption() answers {
	return answers{
		title: "A Linux consumption function app, quiet everywhere, whose hosting class has no execution counter to clear it with",
		id:    siteID,
		now:   cutoff,
		bodies: append([]answer{
			{match: "/sites/fn-demo", body: fmt.Sprintf(`{
  "id": %q, "name": "fn-demo", "type": "Microsoft.Web/sites",
  "location": "westeurope", "kind": "functionapp,linux",
  "properties": {
    "state": "Running",
    "enabled": true,
    "reserved": true,
    "serverFarmId": %q,
    "defaultHostName": "fn-demo.azurewebsites.net",
    "hostNames": ["fn-demo.azurewebsites.net"],
    "enabledHostNames": ["fn-demo.azurewebsites.net"],
    "hostNameSslStates": [
      {"name": "fn-demo.azurewebsites.net", "hostType": "Standard"},
      {"name": "fn-demo.scm.azurewebsites.net", "hostType": "Repository"}
    ],
    "httpsOnly": true,
    "clientAffinityEnabled": false
  }
}`, siteID, planID)},
			// The plan is what makes this the consumption class: Dynamic tier,
			// Linux. Without it the site would be read as dedicated and the
			// execution counter would exist.
			{match: "/serverfarms/plan-demo", body: fmt.Sprintf(`{
  "id": %q, "name": "plan-demo", "type": "Microsoft.Web/serverfarms",
  "location": "westeurope", "kind": "functionapp",
  "sku": {"name": "Y1", "tier": "Dynamic", "size": "Y1", "capacity": 0},
  "properties": {"reserved": true, "sku": {"tier": "Dynamic", "capacity": 0}, "numberOfSites": 1}
}`, planID)},
			{match: "/sites/fn-demo/config/web", body: `{
  "properties": {
    "alwaysOn": false,
    "linuxFxVersion": "Python|3.12",
    "ipSecurityRestrictions": [{"ipAddress": "Any", "action": "Allow", "priority": 2147483647, "name": "Allow all"}],
    "vnetName": ""
  }
}`},
			{match: "/sites/fn-demo/functions", body: `{"value": []}`},
			{match: "/sites/fn-demo/slots", body: `{"value": []}`},
			{match: "/sites/fn-demo/deployments", body: `{"value": []}`},
			{match: "/sites/fn-demo/hybridconnectionrelays", body: `{"value": []}`},
			{match: "/sites/fn-demo/sourcecontrols/web", body: `{"properties": {"repoUrl": "", "branch": ""}}`},
			// Answered, and each one nothing. The execution counter is not in
			// this list, because for this hosting class there is none to ask
			// for, which is the whole point of the scenario.
			{match: "/microsoft.insights/metrics", query: "Requests", body: quiet("Requests", "Total")},
			{match: "/microsoft.insights/metrics", query: "Http2xx", body: quiet("Http2xx", "Total")},
			{match: "/microsoft.insights/metrics", query: "CpuTime", body: quiet("CpuTime", "Total")},
			{match: "/microsoft.insights/metrics", query: "InstanceCount", body: quiet("InstanceCount", "Average")},
			{match: "/microsoft.insights/metrics", body: quiet("Requests", "Total")},
		}, generic(siteID, resourceGroupID, 300, "")...),
	}
}
