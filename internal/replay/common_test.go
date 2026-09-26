package replay_test

import "fmt"

// Every scenario answers the same generic questions: is the target visible in
// Resource Graph, who manages its resource group, what changed, is anything
// locked, what does the Activity Log say. Stating them once leaves each
// scenario file saying only what that scenario is for, which is the point of
// having scenarios rather than one big fixture.
//
// A scenario overrides any of these by listing its own answer first: the
// handler takes the first match.
func generic(id, resourceGroupID string, createdDaysAgo int, tags string) []answer {
	if tags == "" {
		tags = "{}"
	}
	return []answer{
		{match: "/providers/microsoft.resourcegraph/resources", contains: "project id, type, tags, systemData",
			body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"id": %q, "type": "x", "tags": %s, "systemData": {"createdAt": %q}}]
}`, id, tags, ago(createdDaysAgo))},
		{match: "/providers/microsoft.resourcegraph/resources", contains: "resourcecontainers",
			body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"id": %q, "managedBy": "", "tags": {}}]
}`, resourceGroupID)},
		{match: "/providers/microsoft.resourcegraph/resources", contains: "resourcechanges",
			body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"ts": %q, "changeType": "Create", "op": "Create"}]
}`, ago(createdDaysAgo))},
		// The rest of what Resource Graph is asked, one entry per question,
		// each answering that nothing was found. A scenario that wants one of
		// them to find something lists its own answer above this line.
		//
		// These are enumerated rather than caught by one fallback on purpose.
		// A fallback answers a question nobody wrote an answer for, and the
		// answer it gives is "nothing found" — which is the difference between
		// a signal that was read and found empty and a signal nobody asked
		// about, the difference ADR-0004 exists to keep. Adding a signal that
		// asks a new question should fail every recording until somebody says
		// what Azure answers, and with a fallback here it would not.
		empty("advisorresources"),                    // Advisor recommendations
		empty("backupvaults/backupinstances"),        // Backup vault instances
		empty("protectioncontainers/protecteditems"), // Recovery Services protected items
		empty("replicationprotecteditems"),           // Site Recovery replication
		empty("!startswith"),                         // anything else in the subscription naming this resource
		empty("bootDiagnostics.storageUri"),          // machines writing boot diagnostics here
		empty("virtualmachines/extensions"),          // extensions configured with this name
		empty("insights/webtests"),                   // availability tests calling this host
		empty("networkwatchers/flowlogs"),            // Network Watcher writing flow logs here
		empty("network/routetables"),                 // routes pointing at this address
		empty("dhcpOptions.dnsServers"),              // networks using this address as a resolver
		empty("compute/galleries/images/versions"),   // images built from this resource
		// ARM's resource list with $expand=createdTime. A site, a plan or a
		// network resource carries no systemData on its GET, so this is the
		// only age source some types have; answering it here means a scenario
		// does not have to know which types need it.
		{match: "/resources", query: "createdTime",
			body: fmt.Sprintf(`{"value": [{"id": %q, "createdTime": %q}]}`, id, ago(createdDaysAgo))},
		{match: "/microsoft.resources/deployments", body: `{"value": []}`},
		{match: "/microsoft.insights/eventtypes/management/values", body: `{"value": []}`},
		{match: "/microsoft.authorization/denyassignments", body: `{"value": []}`},
		{match: "/microsoft.authorization/locks", body: `{"value": []}`},
	}
}

// quiet is a metrics answer with a single zero in it: the service answered, and
// what it reported was nothing. An empty `value` would mean the metric does not
// exist, which is a different thing and reads as unknown.
func quiet(name, aggregation string) string {
	field := "total"
	if aggregation == "Average" {
		field = "average"
	}
	return fmt.Sprintf(`{
  "timespan": "%s/%s", "interval": "P1D",
  "value": [{"name": {"value": %q}, "unit": "Count",
             "timeseries": [{"data": [{"timeStamp": %q, %q: 0}]}]}]
}`, ago(30), ago(0), name, ago(29), field)
}

// empty is one Resource Graph question answered with an empty page: the query
// was run and matched nothing. `question` is the fragment of the KQL that tells
// this question apart from the others on the same path, so a query whose
// wording changes stops matching and the recording says so.
func empty(question string) answer {
	return answer{match: "/providers/microsoft.resourcegraph/resources", contains: question,
		body: `{"totalRecords": 0, "count": 0, "resultTruncated": "false", "data": []}`}
}
