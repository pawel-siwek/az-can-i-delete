package replay_test

import "fmt"

const nicID = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-demo/providers/Microsoft.Network/networkInterfaces/nic-orphan"

// nicYesDetached is the scenario the specification names for demo beat 3 when
// no live `yes` can be found: an interface nothing is attached to.
func nicYesDetached() answers {
	return answers{
		title: "A network interface attached to nothing, with no configuration and no event pointing at it",
		id:    nicID,
		now:   cutoff,
		bodies: []answer{
			{match: "/networkinterfaces/nic-orphan", body: fmt.Sprintf(`{
  "id": %q,
  "name": "nic-orphan",
  "type": "Microsoft.Network/networkInterfaces",
  "location": "westeurope",
  "tags": {"owner": "platform-team"},
  "properties": {
    "provisioningState": "Succeeded",
    "enableAcceleratedNetworking": false,
    "ipConfigurations": [{
      "name": "ipconfig1",
      "properties": {
        "privateIPAddress": "10.0.1.4",
        "privateIPAllocationMethod": "Dynamic",
        "primary": true,
        "subnet": {"id": "/subscriptions/%s/resourceGroups/rg-demo/providers/Microsoft.Network/virtualNetworks/vnet-demo/subnets/default"}
      }
    }]
  }
}`, nicID, subscription)},
			{match: "/providers/microsoft.resourcegraph/resources", contains: "project id, type, tags, systemData",
				body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"id": %q, "type": "microsoft.network/networkinterfaces",
            "tags": {"owner": "platform-team"},
            "systemData": {"createdAt": %q}}]
}`, nicID, ago(410))},
			{match: "/providers/microsoft.resourcegraph/resources", contains: "resourcecontainers",
				body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"id": "/subscriptions/%s/resourceGroups/rg-demo", "managedBy": "", "tags": {}}]
}`, subscription)},
			{match: "/providers/microsoft.resourcegraph/resources", contains: "resourcechanges",
				body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"ts": %q, "changeType": "Create", "op": "Create"}]
}`, ago(410))},
			{match: "/providers/microsoft.resourcegraph/resources",
				body: `{"totalRecords": 0, "count": 0, "resultTruncated": "false", "data": []}`},
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
}`, subscription, ago(412), subscription)},
			{match: "/microsoft.insights/eventtypes/management/values", body: `{"value": []}`},
			{match: "/microsoft.authorization/denyassignments", body: `{"value": []}`},
			{match: "/microsoft.authorization/locks", body: `{"value": []}`},
			{match: "/microsoft.insights/metrics", body: `{"value": []}`},
		},
	}
}
