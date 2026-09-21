package armid

import (
	"net/url"
	"strings"
	"testing"
)

const (
	subscription = "01234567-89ab-cdef-0123-456789abcdef"
	rgID         = "/subscriptions/" + subscription + "/resourceGroups/MyRG"
	storageID    = rgID + "/providers/Microsoft.Storage/storageAccounts/MyStore"
	portal       = "https://portal.azure.com/"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, input, id, resourceType, resourceGroup, resourceName string
	}{
		{"raw", storageID, storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"mixed case", "/SUBSCRIPTIONS/" + strings.ToUpper(subscription) + "/RESOURCEGROUPS/MyRG/PROVIDERS/MICROSOFT.STORAGE/STORAGEACCOUNTS/MyStore", storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"lower resourcegroups", strings.ReplaceAll(storageID, "resourceGroups", "resourcegroups"), storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"resource group", rgID, rgID, "Microsoft.Resources/resourceGroups", "MyRG", "MyRG"},
		{"subscription scope", "/subscriptions/" + subscription + "/providers/Microsoft.Compute/disks/Disk", "/subscriptions/" + subscription + "/providers/Microsoft.Compute/disks/Disk", "Microsoft.Compute/disks", "", "Disk"},
		{"trailing slash", storageID + "/", storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"REST query", storageID + "?api-version=2026-04-01", storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"query after slash", storageID + "/?a=b", storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"child container", storageID + "/blobServices/default/containers/X", storageID + "/blobServices/default/containers/X", "Microsoft.Storage/storageAccounts/blobServices/containers", "MyRG", "X"},
		{"slot", rgID + "/providers/microsoft.web/SITES/App/SLOTS/Staging", rgID + "/providers/Microsoft.Web/sites/App/slots/Staging", "Microsoft.Web/sites/slots", "MyRG", "Staging"},
		{"extension lock", storageID + "/providers/microsoft.authorization/LOCKS/L1", storageID + "/providers/Microsoft.Authorization/locks/L1", "Microsoft.Authorization/locks", "MyRG", "L1"},
		{"extension diagnostics", storageID + "/providers/Microsoft.Insights/diagnosticSettings/Diag", storageID + "/providers/Microsoft.Insights/diagnosticSettings/Diag", "Microsoft.Insights/diagnosticSettings", "MyRG", "Diag"},
		{"RG extension", rgID + "/providers/Microsoft.Authorization/locks/L1", rgID + "/providers/Microsoft.Authorization/locks/L1", "Microsoft.Authorization/locks", "MyRG", "L1"},
		{"nested extension", storageID + "/providers/Microsoft.Insights/diagnosticSettings/D/providers/Microsoft.Authorization/locks/L", storageID + "/providers/Microsoft.Insights/diagnosticSettings/D/providers/Microsoft.Authorization/locks/L", "Microsoft.Authorization/locks", "MyRG", "L"},
		{"subscription resource extension", "/subscriptions/" + subscription + "/providers/Microsoft.Compute/disks/D/providers/Microsoft.Authorization/locks/L", "/subscriptions/" + subscription + "/providers/Microsoft.Compute/disks/D/providers/Microsoft.Authorization/locks/L", "Microsoft.Authorization/locks", "", "L"},
		{"VMSS nested public IP", rgID + "/providers/Microsoft.Compute/virtualMachineScaleSets/S/virtualMachines/V/networkInterfaces/N/ipConfigurations/C/publicIPAddresses/P", rgID + "/providers/Microsoft.Compute/virtualMachineScaleSets/S/virtualMachines/V/networkInterfaces/N/ipConfigurations/C/publicIPAddresses/P", "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/networkInterfaces/ipConfigurations/publicIPAddresses", "MyRG", "P"},
		{"unknown type", rgID + "/providers/Contoso.Service/widgets/W/parts/P", rgID + "/providers/Contoso.Service/widgets/W/parts/P", "Contoso.Service/widgets/parts", "MyRG", "P"},
		{"raw overview name", rgID + "/providers/Microsoft.Web/sites/overview", rgID + "/providers/Microsoft.Web/sites/overview", "Microsoft.Web/sites", "MyRG", "overview"},
		{"raw tags name", rgID + "/providers/Microsoft.Web/sites/tags", rgID + "/providers/Microsoft.Web/sites/tags", "Microsoft.Web/sites", "MyRG", "tags"},
		{"portal no tenant", portal + "#resource" + storageID, storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"portal GUID tenant", portal + "#@" + strings.ToUpper(subscription) + "/resource" + storageID, storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"portal domain tenant", portal + "#@contoso.onmicrosoft.com/resource" + storageID, storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"portal custom domain", portal + "#@Example.COM/resource" + storageID, storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"portal overview", portal + "#resource" + storageID + "/overview", storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"portal tags slash query", portal + "#resource" + storageID + "/tags/?a=b", storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"portal RG overview", portal + "#resource" + rgID + "/overview", rgID, "Microsoft.Resources/resourceGroups", "MyRG", "MyRG"},
		{"portal encoded fragment", portal + "#" + url.PathEscape("resource"+storageID+"/overview"), storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"portal view id", portal + "#view/Extension/ResourceBlade/id/" + url.PathEscape(storageID), storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"portal view resourceId", portal + "#view/Extension/ResourceBlade/resourceId/" + url.PathEscape(storageID) + "/tags", storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"portal tenant view", portal + "#@contoso.com/view/Extension/ResourceBlade/id/" + url.PathEscape(storageID), storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"portal query separate", portal + "?l=en#resource" + storageID, storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"portal host case", "https://PORTAL.AZURE.COM/#resource" + storageID, storageID, "Microsoft.Storage/storageAccounts", "MyRG", "MyStore"},
		{"portal overview is name", portal + "#resource" + rgID + "/providers/Microsoft.Web/sites/overview", rgID + "/providers/Microsoft.Web/sites/overview", "Microsoft.Web/sites", "MyRG", "overview"},
		{"portal tags is child name", portal + "#resource" + rgID + "/providers/Microsoft.Web/sites/App/slots/tags", rgID + "/providers/Microsoft.Web/sites/App/slots/tags", "Microsoft.Web/sites/slots", "MyRG", "tags"},
		{"portal true child pair", portal + "#resource" + storageID + "/tags/Child", storageID + "/tags/Child", "Microsoft.Storage/storageAccounts/tags", "MyRG", "Child"},
		{"portal child overview", portal + "#resource" + storageID + "/blobServices/default/containers/X/overview", storageID + "/blobServices/default/containers/X", "Microsoft.Storage/storageAccounts/blobServices/containers", "MyRG", "X"},
		{"portal extension tags", portal + "#resource" + storageID + "/providers/Microsoft.Authorization/locks/L/tags", storageID + "/providers/Microsoft.Authorization/locks/L", "Microsoft.Authorization/locks", "MyRG", "L"},
		{"literal plus raw", storageID + "+Name", storageID + "+Name", "Microsoft.Storage/storageAccounts", "MyRG", "MyStore+Name"},
		{"literal plus portal", portal + "#resource" + storageID + "+Name", storageID + "+Name", "Microsoft.Storage/storageAccounts", "MyRG", "MyStore+Name"},
		{"encoded plus portal", portal + "#resource" + storageID + "%2BName", storageID + "+Name", "Microsoft.Storage/storageAccounts", "MyRG", "MyStore+Name"},
		{"encoded name portal", portal + "#resource" + storageID + "%20Name", storageID + " Name", "Microsoft.Storage/storageAccounts", "MyRG", "MyStore Name"},
		{"unicode name", storageID + "日本", storageID + "日本", "Microsoft.Storage/storageAccounts", "MyRG", "MyStore日本"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != tc.id || got.SubscriptionID != subscription || got.ResourceType != tc.resourceType || got.ResourceGroup != tc.resourceGroup || got.Name != tc.resourceName {
				t.Fatalf("Parse() = %+v; want id=%q type=%q group=%q name=%q", got, tc.id, tc.resourceType, tc.resourceGroup, tc.resourceName)
			}
		})
	}
}

func TestCanonicalShippingAndExtendedTypes(t *testing.T) {
	t.Parallel()
	for _, resourceType := range []string{
		"Microsoft.Storage/storageAccounts", "Microsoft.Compute/disks",
		"Microsoft.Network/networkInterfaces", "Microsoft.Network/publicIPAddresses",
		"Microsoft.Network/networkSecurityGroups", "Microsoft.Compute/virtualMachines",
		"Microsoft.Web/sites", "Microsoft.Web/serverfarms", "Microsoft.Network/virtualNetworks",
		"Microsoft.App/containerApps", "Microsoft.App/jobs", "Microsoft.App/managedEnvironments",
	} {
		t.Run(resourceType, func(t *testing.T) {
			parts := strings.Split(resourceType, "/")
			got, err := Parse(rgID + "/providers/" + strings.ToUpper(parts[0]) + "/" + strings.ToUpper(parts[1]) + "/OriginalName")
			if err != nil {
				t.Fatal(err)
			}
			if got.ResourceType != resourceType || got.ID != rgID+"/providers/"+resourceType+"/OriginalName" || got.Name != "OriginalName" {
				t.Fatalf("unexpected canonical target: %+v", got)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, input string }{
		{"empty", ""},
		{"placeholder", "/placeholder"},
		{"missing leading slash", strings.TrimPrefix(storageID, "/")},
		{"subscription only", "/subscriptions/" + subscription},
		{"invalid GUID", strings.ReplaceAll(storageID, subscription, "not-a-guid")},
		{"braced GUID", strings.ReplaceAll(storageID, subscription, "{"+subscription+"}")},
		{"compact GUID", strings.ReplaceAll(storageID, subscription, strings.ReplaceAll(subscription, "-", ""))},
		{"nonhex GUID", strings.ReplaceAll(storageID, subscription, "g1234567-89ab-cdef-0123-456789abcdef")},
		{"empty RG", "/subscriptions/" + subscription + "/resourceGroups//providers/Microsoft.Web/sites/X"},
		{"missing RG", "/subscriptions/" + subscription + "/resourceGroups"},
		{"missing provider", rgID + "/Microsoft.Web/sites/X"},
		{"missing namespace", rgID + "/providers//sites/X"},
		{"missing type", rgID + "/providers/Microsoft.Web"},
		{"missing name", rgID + "/providers/Microsoft.Web/sites"},
		{"missing child name", storageID + "/blobServices"},
		{"empty child name", storageID + "/blobServices//containers/X"},
		{"missing extension name", storageID + "/providers/Microsoft.Authorization/locks"},
		{"dot name", storageID + "/children/."},
		{"dot dot name", storageID + "/children/.."},
		{"double slash", storageID + "//"},
		{"backslash", storageID + `\child`},
		{"raw overview action", storageID + "/overview"},
		{"raw tags action", storageID + "/tags"},
		{"raw fragment", storageID + "#anything"},
		{"malformed raw escape", storageID + "%2X"},
		{"ambiguous raw escaping", storageID + "%2FChild"},
		{"malformed query escape", storageID + "?a=%GG"},
		{"newline", storageID + "\n"},
		{"format control", storageID + "\u202e"},
		{"invalid UTF8", storageID + "\xff"},
		{"leading whitespace", " " + storageID},
		{"trailing whitespace", storageID + " "},
		{"two raw IDs", storageID + storageID},
		{"http", "http://portal.azure.com/#resource" + storageID},
		{"management URL", "https://management.azure.com" + storageID},
		{"sovereign US", "https://portal.azure.us/#resource" + storageID},
		{"sovereign China", "https://portal.azure.cn/#resource" + storageID},
		{"lookalike", "https://portal.azure.com.evil.example/#resource" + storageID},
		{"suffix host", "https://evilportal.azure.com/#resource" + storageID},
		{"trailing dot host", "https://portal.azure.com./#resource" + storageID},
		{"port", "https://portal.azure.com:443/#resource" + storageID},
		{"userinfo", "https://secret:password@portal.azure.com/#resource" + storageID},
		{"host as userinfo", "https://portal.azure.com@evil.example/#resource" + storageID},
		{"wrong path", portal + "other#resource" + storageID},
		{"missing fragment", portal},
		{"query only target", portal + "?id=" + url.QueryEscape(storageID)},
		{"raw fragment ID", portal + "#" + storageID},
		{"browse view", portal + "#view/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts"},
		{"browse blade", portal + "#blade/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts"},
		{"KQL blade", portal + "#blade/HubsExtension/ArgQueryBlade/query/" + url.PathEscape("resources | where id == '"+storageID+"'")},
		{"KQL view", portal + "#view/HubsExtension/ArgQueryBlade/query/" + url.PathEscape(storageID)},
		{"browse with id", portal + "#view/HubsExtension/BrowseResource/id/" + url.PathEscape(storageID)},
		{"KQL with id", portal + "#view/HubsExtension/ArgQueryBlade/id/" + url.PathEscape(storageID)},
		{"wrong view key", portal + "#view/Ext/Blade/other/" + url.PathEscape(storageID)},
		{"empty view extension", portal + "#view//Blade/id/" + url.PathEscape(storageID)},
		{"empty view blade", portal + "#view/Ext//id/" + url.PathEscape(storageID)},
		{"double encoded", portal + "#view/Ext/Blade/id/" + url.PathEscape(url.PathEscape(storageID))},
		{"double encoded name", portal + "#resource" + storageID + "%252FChild"},
		{"malformed fragment escape", portal + "#resource" + storageID + "%2"},
		{"malformed portal query", portal + "?q=%XX#resource" + storageID},
		{"encoded control", portal + "#resource" + storageID + "%0A"},
		{"encoded fragment", portal + "#resource" + storageID + "%23secret"},
		{"unknown blade suffix", portal + "#resource" + storageID + "/delete"},
		{"multiple IDs", portal + "#resource" + storageID + "/resourceId/" + storageID},
		{"multiple IDs in query", portal + "#resource" + storageID + "?other=" + storageID},
		{"missing tenant", portal + "#@/resource" + storageID},
		{"tenant hint only", portal + "#@contoso.onmicrosoft.com"},
		{"tenant not GUID or domain", portal + "#@not-a-tenant/resource" + storageID},
		{"tenant invalid GUID", portal + "#@g1234567-89ab-cdef-0123-456789abcdef/resource" + storageID},
		{"tenant empty label", portal + "#@contoso..com/resource" + storageID},
		{"tenant leading hyphen", portal + "#@-contoso.com/resource" + storageID},
		{"tenant trailing hyphen", portal + "#@contoso-.com/resource" + storageID},
		{"tenant underscore", portal + "#@con_toso.com/resource" + storageID},
		{"tenant userinfo", portal + "#@user@contoso.com/resource" + storageID},
		{"tenant port", portal + "#@contoso.com:443/resource" + storageID},
		{"tenant IP address", portal + "#@127.0.0.1/resource" + storageID},
		{"tenant long label", portal + "#@" + strings.Repeat("a", 64) + ".com/resource" + storageID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.input)
			if err == nil {
				t.Fatalf("Parse() unexpectedly accepted %+v", got)
			}
			if got != (Target{}) {
				t.Fatalf("Parse() returned a partial target on error: %+v", got)
			}
			for _, sensitive := range []string{"secret", "password", tc.input} {
				if sensitive != "" && strings.Contains(err.Error(), sensitive) {
					t.Fatalf("error echoed untrusted input: %s", err)
				}
			}
		})
	}
}

func TestTargetComparisonAndSubscription(t *testing.T) {
	t.Parallel()
	target, err := Parse(storageID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Parse(strings.ToLower(storageID))
	if err != nil {
		t.Fatal(err)
	}
	if !target.Equal(other) {
		t.Fatal("target comparison must be case-insensitive")
	}
	child, err := Parse(storageID + "/blobServices/default")
	if err != nil {
		t.Fatal(err)
	}
	if target.Equal(child) {
		t.Fatal("child is not equal to parent")
	}
	for _, tc := range []struct {
		subscription string
		wantError    bool
	}{
		{"", false}, {subscription, false}, {strings.ToUpper(subscription), false},
		{"fedcba98-7654-3210-fedc-ba9876543210", true}, {"name-not-id", true},
	} {
		if err := target.ValidateSubscription(tc.subscription); (err != nil) != tc.wantError {
			t.Errorf("ValidateSubscription(%q) = %v, wantError %v", tc.subscription, err, tc.wantError)
		}
	}
}
