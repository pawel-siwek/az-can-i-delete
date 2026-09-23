package replay_test

import (
	"fmt"
	"testing"
	"time"
)

const (
	subscription = "00000000-0000-0000-0000-000000000001"
	diskID       = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.Compute/disks/disk-orphan"
)

// cutoff is the same instant for every scenario, so a recorded window and a
// recorded timestamp can be read against each other by eye.
var cutoff = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func ago(days int) string { return cutoff.AddDate(0, 0, -days).Format(time.RFC3339) }

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
  "data": [{"id": "/subscriptions/%s/resourceGroups/rg-demo", "managedBy": "", "tags": {}}]
}`, subscription)},
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
    "id": "/subscriptions/%s/resourceGroups/rg-demo/providers/Microsoft.Resources/deployments/platform-2025",
    "name": "platform-2025",
    "properties": {
      "timestamp": %q,
      "provisioningState": "Succeeded",
      "outputResources": [{"id": "/subscriptions/%s/resourceGroups/rg-demo/providers/Microsoft.Network/virtualNetworks/vnet-demo"}]
    }
  }]
}`, subscription, ago(402), subscription)},
			{match: "/microsoft.insights/eventtypes/management/values", body: `{"value": []}`},
			{match: "/microsoft.authorization/denyassignments", body: `{"value": []}`},
			{match: "/microsoft.authorization/locks", body: `{"value": []}`},
			{match: "/microsoft.insights/metrics", body: fmt.Sprintf(`{
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

func TestRecordScenarios(t *testing.T) {
	if !*update {
		t.Skip("run with -update to re-record the embedded scenarios")
	}
	for slug, scenario := range map[string]answers{
		"disk-yes-unattached": diskYesUnattached(),
		"nic-yes-detached":    nicYesDetached(),
		"vm-no-backup":        vmNoBackup(),
	} {
		t.Run(slug, func(t *testing.T) { record(t, slug, scenario) })
	}
}
