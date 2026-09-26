package replay_test

import "fmt"

const diskID = resourceGroupID + "/providers/Microsoft.Compute/disks/disk-orphan"

// diskYesUnattached is the demo's third beat: a disk nothing holds, old enough
// for the window to mean something, with no activity anybody recorded.
func diskYesUnattached() answers {
	return answers{
		title: "A managed disk detached 400 days ago, with nothing found in any signal this tool can read",
		id:    diskID,
		now:   cutoff,
		bodies: []answer{
			{match: "/disks/disk-orphan", body: fmt.Sprintf(`{
  "id": %q,
  "name": "disk-orphan",
  "type": "Microsoft.Compute/disks",
  "location": "westeurope",
  "sku": {"name": "Premium_LRS", "tier": "Premium"},
  "tags": {"owner": "platform-team", "costCentre": "4711"},
  "properties": {
    "timeCreated": %q,
    "diskState": "Unattached",
    "diskSizeGB": 128,
    "provisioningState": "Succeeded",
    "lastOwnershipUpdateTime": %q,
    "networkAccessPolicy": "DenyAll",
    "publicNetworkAccess": "Disabled"
  }
}`, diskID, ago(400), ago(380))},
			// Resource Graph answers several different questions on one path,
			// so each is matched by the query it asks.
			{match: "/providers/microsoft.resourcegraph/resources", contains: "project id, type, tags, systemData",
				body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"id": %q, "type": "microsoft.compute/disks",
            "tags": {"owner": "platform-team", "costCentre": "4711"},
            "systemData": {"createdAt": %q}}]
}`, diskID, ago(400))},
			{match: "/providers/microsoft.resourcegraph/resources", contains: "resourcecontainers",
				body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"id": %q, "managedBy": "", "tags": {}}]
}`, resourceGroupID)},
			{match: "/providers/microsoft.resourcegraph/resources", contains: "resourcechanges",
				body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"ts": %q, "changeType": "Create", "op": "Create"}]
}`, ago(400))},
			// Nothing recommends it, nothing backs it up, no image was built
			// from it. An empty Resource Graph page is an answer, not a
			// failure to ask.
			{match: "/providers/microsoft.resourcegraph/resources",
				body: `{"totalRecords": 0, "count": 0, "resultTruncated": "false", "data": []}`},
			// The resource group is deployed from a template; this disk is not
			// one of its outputs. That is deliberate and it is what makes the
			// scenario a `yes`: a deployment listing the disk would establish
			// its age and, by the same condition, make it IaC-managed, which
			// is a DESIGN_INTENT reason to leave it alone. The two cannot be
			// demonstrated at once — see the note under docs/SPEC.md 7.6.
			{match: "/microsoft.resources/deployments", body: fmt.Sprintf(`{
  "value": [{
    "id": "%[1]s/providers/Microsoft.Resources/deployments/platform-2025",
    "name": "platform-2025",
    "properties": {
      "timestamp": %[2]q,
      "provisioningState": "Succeeded",
      "outputResources": [{"id": "%[1]s/providers/Microsoft.Network/virtualNetworks/vnet-demo"}]
    }
  }]
}`, resourceGroupID, ago(402))},
			{match: "/microsoft.insights/eventtypes/management/values", body: `{"value": []}`},
			{match: "/microsoft.authorization/denyassignments", body: `{"value": []}`},
			{match: "/microsoft.authorization/locks", body: `{"value": []}`},
			{match: "/microsoft.insights/metrics", query: "metricnames=Composite Disk Read Bytes/sec", body: fmt.Sprintf(`{
  "timespan": "%s/%s",
  "interval": "P1D",
  "value": [
    {"name": {"value": "Composite Disk Read Bytes/sec"}, "unit": "BytesPerSecond",
     "timeseries": [{"data": [{"timeStamp": %q, "total": 0}]}]},
    {"name": {"value": "Composite Disk Write Bytes/sec"}, "unit": "BytesPerSecond",
     "timeseries": [{"data": [{"timeStamp": %q, "total": 0}]}]},
    {"name": {"value": "Composite Disk Read Operations/sec"}, "unit": "CountPerSecond",
     "timeseries": [{"data": [{"timeStamp": %q, "total": 0}]}]},
    {"name": {"value": "Composite Disk Write Operations/sec"}, "unit": "CountPerSecond",
     "timeseries": [{"data": [{"timeStamp": %q, "total": 0}]}]}
  ]
}`, ago(30), ago(0), ago(29), ago(29), ago(29), ago(29))},
		},
	}
}
