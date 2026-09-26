package replay_test

import "fmt"

const vmID = resourceGroupID + "/providers/Microsoft.Compute/virtualMachines/vm-quiet"

// vmNoBackup is the scenario that matters most to show, because it is the one
// a reader would otherwise get wrong: a machine that has been switched off for
// months looks abandoned, and something is still protecting it. Being quiet is
// not the same as being unused.
func vmNoBackup() answers {
	return answers{
		title: "A virtual machine deallocated for months that a backup vault is still protecting",
		id:    vmID,
		now:   cutoff,
		bodies: []answer{
			// Deallocated for four months. Quiet, and not the point.
			{match: "/virtualmachines/vm-quiet/instanceview", body: `{
  "statuses": [
    {"code": "ProvisioningState/succeeded", "level": "Info", "displayStatus": "Provisioning succeeded"},
    {"code": "PowerState/deallocated", "level": "Info", "displayStatus": "VM deallocated"}
  ]
}`},
			{match: "/virtualmachines/vm-quiet", body: fmt.Sprintf(`{
  "id": %q,
  "name": "vm-quiet",
  "type": "Microsoft.Compute/virtualMachines",
  "location": "westeurope",
  "tags": {"owner": "finance-reporting"},
  "properties": {
    "provisioningState": "Succeeded",
    "timeCreated": %q,
    "hardwareProfile": {"vmSize": "Standard_D2s_v5"},
    "storageProfile": {"osDisk": {"name": "vm-quiet-os", "managedDisk": {"id": "/subscriptions/%s/resourceGroups/rg-demo/providers/Microsoft.Compute/disks/vm-quiet-os"}}},
    "networkProfile": {"networkInterfaces": [{"id": "/subscriptions/%s/resourceGroups/rg-demo/providers/Microsoft.Network/networkInterfaces/vm-quiet-nic"}]}
  }
}`, vmID, ago(500), subscription, subscription)},
			{match: "/providers/microsoft.resourcegraph/resources", contains: "project id, type, tags, systemData",
				body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"id": %q, "type": "microsoft.compute/virtualmachines",
            "tags": {"owner": "finance-reporting"}, "systemData": {"createdAt": %q}}]
}`, vmID, ago(500))},
			{match: "/providers/microsoft.resourcegraph/resources", contains: "resourcecontainers",
				body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"id": "/subscriptions/%s/resourceGroups/rg-demo", "managedBy": "", "tags": {}}]
}`, subscription)},
			{match: "/providers/microsoft.resourcegraph/resources", contains: "resourcechanges",
				body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"ts": %q, "changeType": "Update", "op": "Deallocate"}]
}`, ago(120))},
			// Nothing replicates it. Site Recovery asks its question on the
			// same table as backup, so it is answered first and narrowly.
			{match: "/providers/microsoft.resourcegraph/resources", contains: "replicationprotecteditems",
				body: `{"totalRecords": 0, "count": 0, "resultTruncated": "false", "data": []}`},
			// This is the finding. A vault still holds a protected item, so
			// the machine is not free to delete however quiet it has been.
			{match: "/providers/microsoft.resourcegraph/resources", contains: "protectioncontainers/protecteditems",
				body: fmt.Sprintf(`{
  "totalRecords": 1, "count": 1, "resultTruncated": "false",
  "data": [{"id": "/subscriptions/%s/resourceGroups/rg-backup/providers/Microsoft.RecoveryServices/vaults/vault-prod/backupFabrics/Azure/protectionContainers/iaasvmcontainer;vm-quiet/protectedItems/vm;vm-quiet",
            "state": "ProtectionConfigured"}]
}`, subscription)},
			{match: "/providers/microsoft.resourcegraph/resources",
				body: `{"totalRecords": 0, "count": 0, "resultTruncated": "false", "data": []}`},
			{match: "/networkinterfaces/vm-quiet-nic", body: fmt.Sprintf(`{
  "id": "/subscriptions/%s/resourceGroups/rg-demo/providers/Microsoft.Network/networkInterfaces/vm-quiet-nic",
  "name": "vm-quiet-nic",
  "type": "Microsoft.Network/networkInterfaces",
  "location": "westeurope",
  "properties": {
    "provisioningState": "Succeeded",
    "virtualMachine": {"id": %q},
    "ipConfigurations": [{"name": "ipconfig1", "properties": {
      "privateIPAddress": "10.0.1.9", "privateIPAllocationMethod": "Dynamic", "primary": true,
      "subnet": {"id": "/subscriptions/%s/resourceGroups/rg-demo/providers/Microsoft.Network/virtualNetworks/vnet-demo/subnets/default"}
    }}]
  }
}`, subscription, vmID, subscription)},
			{match: "/microsoft.resources/deployments", body: `{"value": []}`},
			{match: "/microsoft.insights/eventtypes/management/values", body: fmt.Sprintf(`{
  "value": [{
    "eventTimestamp": %q,
    "resourceId": %q,
    "caller": "someone@example.test",
    "operationName": {"value": "Microsoft.Compute/virtualMachines/deallocate/action"},
    "status": {"value": "Succeeded"},
    "subStatus": {"value": "OK"},
    "httpRequest": {"method": "POST"},
    "properties": {},
    "claims": {"appid": "00000000-0000-0000-0000-00000000dead"}
  }]
}`, ago(120), vmID)},
			{match: "/microsoft.authorization/denyassignments", body: `{"value": []}`},
			{match: "/microsoft.authorization/locks", body: `{"value": []}`},
			{match: "/microsoft.insights/metrics", body: `{"value": []}`},
		},
	}
}
