// Package armid parses resource targets without resolving them or contacting Azure.
// Parsing a type does not imply analyzer or mutation support for that type.
package armid

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Target retains the exact child or extension resource identity, never its parent.
// Name and ResourceGroup preserve input spelling and are not sanitized display text.
type Target struct {
	ID             string
	SubscriptionID string
	ResourceGroup  string
	ResourceType   string
	Name           string
}

var errInvalidID = errors.New("invalid ARM resource ID")

// Parse accepts an ARM ID or a public Azure portal resource URL. It removes query
// strings and one trailing slash. Only portal targets may have an unpaired
// overview/tags suffix; resource names and complete child pairs are preserved.
// Portal fragments are decoded once with path semantics (a literal + stays +).
// Remaining percent escapes in an ID are rejected rather than decoded again.
// Tenant hints are syntax-checked only and never select authentication context.
func Parse(input string) (Target, error) {
	if input == "" || input != strings.TrimSpace(input) || unsafeText(input) || !validEscapes(input) {
		return Target{}, errors.New("invalid target syntax")
	}
	path := input
	isPortal := !strings.HasPrefix(input, "/")
	if isPortal {
		var err error
		path, err = portalResource(input)
		if err != nil {
			return Target{}, err
		}
	} else if strings.Contains(input, "#") {
		return Target{}, errInvalidID
	}
	if strings.Count(strings.ToLower(path), "/subscriptions/") != 1 {
		return Target{}, errors.New("target must identify exactly one resource")
	}
	path, _, _ = strings.Cut(path, "?")
	path = strings.TrimSuffix(path, "/")
	target, err := parseARM(path)
	if err == nil || !isPortal {
		return target, err
	}
	base, suffix, found := cutLast(path)
	if found && (suffix == "overview" || suffix == "tags") {
		return parseARM(base)
	}
	return Target{}, err
}

// Equal compares the complete identities, including every child and extension.
func (t Target) Equal(other Target) bool {
	return t.ID != "" && other.ID != "" && strings.EqualFold(t.ID, other.ID)
}

// ValidateSubscription constrains a parsed target; it never reroutes it.
// An empty expected value means no explicit subscription was supplied.
func (t Target) ValidateSubscription(expected string) error {
	if expected == "" {
		return nil
	}
	if !validGUID(expected) {
		return errors.New("subscription must be a GUID")
	}
	if !strings.EqualFold(t.SubscriptionID, expected) {
		return errors.New("target subscription does not match --subscription")
	}
	return nil
}

func portalResource(input string) (string, error) {
	u, err := url.Parse(input)
	if err != nil {
		// net/url errors can include the entire URL, including user information.
		return "", errors.New("invalid portal URL")
	}
	if u.User != nil {
		return "", errors.New("portal URL must not contain user information")
	}
	if !strings.EqualFold(u.Scheme, "https") || !strings.EqualFold(u.Host, "portal.azure.com") {
		return "", errors.New("public cloud only: expected https://portal.azure.com")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("not a resource URL")
	}
	// URL.Parse already unescapes Fragment exactly once; do not unescape it again.
	fragment := u.Fragment
	if unsafeText(fragment) {
		return "", errors.New("invalid portal fragment")
	}
	if strings.HasPrefix(fragment, "@") {
		tenant, rest, found := strings.Cut(fragment[1:], "/")
		if !found || !validTenant(tenant) {
			return "", errors.New("invalid portal tenant hint")
		}
		fragment = rest
	}
	if strings.HasPrefix(fragment, "resource/") {
		return strings.TrimPrefix(fragment, "resource"), nil
	}
	parts := strings.SplitN(fragment, "/", 5)
	if len(parts) != 5 || parts[0] != "view" || !validToken(parts[1]) || !validToken(parts[2]) ||
		(strings.EqualFold(parts[2], "BrowseResource") || strings.EqualFold(parts[2], "ArgQueryBlade")) ||
		(parts[3] != "id" && parts[3] != "resourceId") || !strings.HasPrefix(parts[4], "/") {
		return "", errors.New("not a resource URL")
	}
	return parts[4], nil
}

func parseARM(path string) (Target, error) {
	parts := strings.Split(path, "/")
	if len(parts) < 5 || parts[0] != "" || !strings.EqualFold(parts[1], "subscriptions") || !validGUID(parts[2]) {
		return Target{}, errInvalidID
	}
	for _, part := range parts[1:] {
		if !validName(part) {
			return Target{}, errInvalidID
		}
	}
	parts[1] = "subscriptions"
	parts[2] = strings.ToLower(parts[2])
	target := Target{SubscriptionID: parts[2]}
	i := 3
	if strings.EqualFold(parts[i], "resourceGroups") {
		parts[i] = "resourceGroups"
		target.ResourceGroup = parts[i+1]
		target.Name = parts[i+1]
		target.ResourceType = "Microsoft.Resources/resourceGroups"
		i += 2
	}
	for i < len(parts) {
		if !strings.EqualFold(parts[i], "providers") || i+3 >= len(parts) || !validNamespace(parts[i+1]) {
			return Target{}, errInvalidID
		}
		parts[i] = "providers"
		namespace := canonicalNamespace(parts[i+1])
		parts[i+1] = namespace
		resourceType := namespace
		i += 2
		for {
			if i+1 >= len(parts) || !validToken(parts[i]) {
				return Target{}, errInvalidID
			}
			resourceType += "/" + parts[i]
			if canonical, ok := canonicalTypes[strings.ToLower(resourceType)]; ok {
				resourceType = canonical
				_, parts[i], _ = cutLast(canonical)
			}
			target.Name = parts[i+1]
			i += 2
			if i == len(parts) || strings.EqualFold(parts[i], "providers") {
				break
			}
		}
		target.ResourceType = resourceType
	}
	if target.ResourceType == "" {
		return Target{}, errInvalidID
	}
	target.ID = strings.Join(parts, "/")
	return target, nil
}

func validGUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := range len(value) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if value[i] != '-' {
				return false
			}
		} else if !hex(value[i]) {
			return false
		}
	}
	return true
}

func validTenant(value string) bool {
	if validGUID(value) {
		return true
	}
	if len(value) > 253 || !strings.Contains(value, ".") || net.ParseIP(value) != nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			if !asciiLetter(label[i]) && (label[i] < '0' || label[i] > '9') && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func validName(value string) bool {
	return strings.TrimSpace(value) != "" && value != "." && value != ".." &&
		!strings.ContainsAny(value, `\%?#`) && !unsafeText(value)
}

func validNamespace(value string) bool {
	if !strings.Contains(value, ".") {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if !validToken(part) {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if value == "" || !asciiLetter(value[0]) {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if !asciiLetter(c) && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func unsafeText(value string) bool {
	if !utf8.ValidString(value) {
		return true
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

func validEscapes(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == '%' {
			if i+2 >= len(value) || !hex(value[i+1]) || !hex(value[i+2]) {
				return false
			}
			i += 2
		}
	}
	return true
}

func hex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func asciiLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func cutLast(value string) (string, string, bool) {
	i := strings.LastIndexByte(value, '/')
	if i < 0 {
		return "", "", false
	}
	return value[:i], value[i+1:], true
}

func canonicalNamespace(namespace string) string {
	for _, resourceType := range canonicalTypes {
		canonical, _, _ := strings.Cut(resourceType, "/")
		if strings.EqualFold(namespace, canonical) {
			return canonical
		}
	}
	return namespace
}

// Unknown types keep their spelling. Dispatch must use the exact parsed type,
// case-insensitively, rather than silently falling back to a supported ancestor.
var canonicalTypes = map[string]string{
	"microsoft.resources/resourcegroups":                        "Microsoft.Resources/resourceGroups",
	"microsoft.storage/storageaccounts":                         "Microsoft.Storage/storageAccounts",
	"microsoft.storage/storageaccounts/blobservices":            "Microsoft.Storage/storageAccounts/blobServices",
	"microsoft.storage/storageaccounts/blobservices/containers": "Microsoft.Storage/storageAccounts/blobServices/containers",
	"microsoft.compute/virtualmachines":                         "Microsoft.Compute/virtualMachines",
	"microsoft.compute/disks":                                   "Microsoft.Compute/disks",
	"microsoft.network/networkinterfaces":                       "Microsoft.Network/networkInterfaces",
	"microsoft.network/publicipaddresses":                       "Microsoft.Network/publicIPAddresses",
	"microsoft.network/networksecuritygroups":                   "Microsoft.Network/networkSecurityGroups",
	"microsoft.network/virtualnetworks":                         "Microsoft.Network/virtualNetworks",
	"microsoft.web/sites":                                       "Microsoft.Web/sites",
	"microsoft.web/sites/slots":                                 "Microsoft.Web/sites/slots",
	"microsoft.web/serverfarms":                                 "Microsoft.Web/serverfarms",
	"microsoft.app/containerapps":                               "Microsoft.App/containerApps",
	"microsoft.app/jobs":                                        "Microsoft.App/jobs",
	"microsoft.app/managedenvironments":                         "Microsoft.App/managedEnvironments",
	"microsoft.authorization/locks":                             "Microsoft.Authorization/locks",
	"microsoft.authorization/roleassignments":                   "Microsoft.Authorization/roleAssignments",
	"microsoft.insights/diagnosticsettings":                     "Microsoft.Insights/diagnosticSettings",
	"microsoft.security/defenderforstoragesettings":             "Microsoft.Security/defenderForStorageSettings",
}
