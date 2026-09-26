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
		// Everything else Resource Graph is asked — advisor, backups, other
		// references, boot diagnostics, extensions, flow logs — is nothing,
		// unless a scenario says otherwise above this line. An empty page is
		// an answer; a missing one would be a fixture miss.
		{match: "/providers/microsoft.resourcegraph/resources",
			body: `{"totalRecords": 0, "count": 0, "resultTruncated": "false", "data": []}`},
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
