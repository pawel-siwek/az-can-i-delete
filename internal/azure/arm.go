package azure

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/age"
	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/rules"
)

type armClient struct{ client *Client }

// Get reads one resource at its pinned api-version. A 404 is reported as such
// so the caller can end the run with "resource not found" rather than guessing.
// A sub-resource whose body is the payload itself, such as a virtual machine's
// instance view, keeps that payload under Properties.
func (c *armClient) Get(ctx context.Context, resourceID, apiVersion string) (collect.Resource, error) {
	if apiVersion == "" {
		return collect.Resource{}, &collect.Failure{ErrorCode: "NoSupportedApiVersion",
			Message: "no pinned api-version for this resource type"}
	}
	var raw map[string]any
	if err := c.client.get(ctx, resourceID, url.Values{"api-version": {apiVersion}}, &raw); err != nil {
		return collect.Resource{}, err
	}
	resource := fromBody(raw)
	if resource.ID == "" {
		resource.ID = resourceID
	}
	return resource, nil
}

// fromBody normalizes an ARM payload. Most bodies wrap their payload in
// properties; a few sub-resources are the payload, and losing those would mean
// reporting a check as absent that was never read.
func fromBody(raw map[string]any) collect.Resource {
	properties, wrapped := raw["properties"].(map[string]any)
	if !wrapped {
		properties = map[string]any{}
		for key, value := range raw {
			properties[key] = value
		}
	}
	text := func(key string) string {
		value, _ := raw[key].(string)
		return value
	}
	tags := map[string]string{}
	if raw, ok := raw["tags"].(map[string]any); ok {
		for key, value := range raw {
			if text, ok := value.(string); ok {
				tags[key] = text
			}
		}
	}
	state, _ := properties["provisioningState"].(string)
	systemData, _ := raw["systemData"].(map[string]any)
	resource := collect.Resource{
		ID: text("id"), Name: text("name"), Type: text("type"), Location: text("location"),
		Kind: text("kind"), ProvisioningState: state, Properties: properties, SystemData: systemData,
	}
	if len(tags) > 0 {
		resource.Tags = tags
	}
	if sku, ok := raw["sku"].(map[string]any); ok {
		resource.Properties["sku"] = sku
	}
	return resource
}

// List reads a child collection, for example a storage account's containers.
func (c *armClient) List(ctx context.Context, path, apiVersion string) ([]collect.Resource, error) {
	bodies, complete, err := list[map[string]any](ctx, c.client, path, url.Values{"api-version": {apiVersion}})
	if err != nil {
		return nil, err
	}
	resources := make([]collect.Resource, 0, len(bodies))
	for _, body := range bodies {
		resources = append(resources, fromBody(body))
	}
	if !complete {
		return resources, collect.ErrTruncated
	}
	return resources, nil
}

type lockBody struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		Level string `json:"level"`
	} `json:"properties"`
}

// Locks lists the management locks at one scope. The caller asks at all three
// scopes; an inherited lock blocks a delete exactly like a local one.
func (c *armClient) Locks(ctx context.Context, scope string) ([]collect.Lock, error) {
	query := url.Values{"api-version": {rules.MustOperation("locks")}}
	bodies, complete, err := list[lockBody](ctx, c.client, scope+"/providers/Microsoft.Authorization/locks", query)
	if err != nil {
		return nil, err
	}
	locks := make([]collect.Lock, 0, len(bodies))
	for _, body := range bodies {
		locks = append(locks, collect.Lock{ID: body.ID, Name: body.Name, Level: body.Properties.Level})
	}
	if !complete {
		return locks, collect.ErrTruncated
	}
	return locks, nil
}

type denyBody struct {
	ID         string `json:"id"`
	Properties struct {
		DenyAssignmentName string `json:"denyAssignmentName"`
		Permissions        []struct {
			Actions       []string `json:"actions"`
			NotActions    []string `json:"notActions"`
			DataActions   []string `json:"dataActions"`
			NotDataAction []string `json:"notDataActions"`
		} `json:"permissions"`
		DoNotApplyToChildScopes bool `json:"doNotApplyToChildScopes"`
	} `json:"properties"`
}

// blocksDelete reports whether an assignment denies this resource's deletion.
// An action is matched by its documented wildcard form; a matching notAction
// exempts it again.
func (b denyBody) blocksDelete() bool {
	for _, permission := range b.Properties.Permissions {
		denied := false
		for _, action := range permission.Actions {
			if deleteAction(action) {
				denied = true
			}
		}
		for _, action := range permission.NotActions {
			if deleteAction(action) {
				denied = false
			}
		}
		if denied {
			return true
		}
	}
	return false
}

// deleteAction reports whether an action covers a delete. The listing is
// already filtered to assignments covering this scope, so a wildcard action
// here does cover this resource's deletion.
func deleteAction(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	return action == "*" || strings.HasSuffix(action, "/delete") || strings.HasSuffix(action, "/*")
}

// DenyAssignments lists the deny assignments covering a scope.
func (c *armClient) DenyAssignments(ctx context.Context, scope string) ([]collect.DenyAssignment, error) {
	query := url.Values{
		"api-version": {rules.MustOperation("denyAssignments")},
		"$filter":     {"atScope()"},
	}
	bodies, complete, err := list[denyBody](ctx, c.client, scope+"/providers/Microsoft.Authorization/denyAssignments", query)
	if err != nil {
		return nil, err
	}
	assignments := make([]collect.DenyAssignment, 0, len(bodies))
	for _, body := range bodies {
		assignments = append(assignments, collect.DenyAssignment{
			ID: body.ID, Name: body.Properties.DenyAssignmentName, BlocksDelete: body.blocksDelete()})
	}
	if !complete {
		return assignments, collect.ErrTruncated
	}
	return assignments, nil
}

type deploymentBody struct {
	Name       string `json:"name"`
	Properties struct {
		Timestamp         time.Time `json:"timestamp"`
		ProvisioningState string    `json:"provisioningState"`
		OutputResources   []struct {
			ID string `json:"id"`
		} `json:"outputResources"`
	} `json:"properties"`
}

// Deployments lists the most recent deployments of a resource group, bounded
// by top. A history longer than the page budget is reported as truncated, which
// the signal layer turns into unknown(partial).
func (c *armClient) Deployments(ctx context.Context, resourceGroupID string, top int) ([]collect.Deployment, error) {
	query := url.Values{"api-version": {rules.MustOperation("deployments")}}
	if top > 0 {
		query.Set("$top", strconv.Itoa(top))
	}
	bodies, complete, err := list[deploymentBody](ctx, c.client, resourceGroupID+"/providers/Microsoft.Resources/deployments", query)
	if err != nil {
		return nil, err
	}
	deployments := make([]collect.Deployment, 0, len(bodies))
	for _, body := range bodies {
		outputs := make([]string, 0, len(body.Properties.OutputResources))
		for _, output := range body.Properties.OutputResources {
			outputs = append(outputs, output.ID)
		}
		deployments = append(deployments, collect.Deployment{
			Deployment: age.Deployment{
				Timestamp:       body.Properties.Timestamp,
				Status:          body.Properties.ProvisioningState,
				OutputResources: outputs,
			},
			Name: body.Name,
		})
	}
	if !complete {
		return deployments, collect.ErrTruncated
	}
	return deployments, nil
}

type createdBody struct {
	ID          string `json:"id"`
	CreatedTime string `json:"createdTime"`
}

// CreatedTime asks ARM's resource list for the resource's creation time. A GET
// of a site, a plan or a network resource carries no systemData, but the list
// with $expand=createdTime answers for every type; without it such a resource
// had no age source at all when the Activity Log held nothing about it.
func (c *armClient) CreatedTime(ctx context.Context, resourceID string) (*time.Time, error) {
	group, name, ok := groupAndName(resourceID)
	if !ok {
		return nil, nil
	}
	query := url.Values{
		"api-version": {rules.MustOperation("resources")},
		"$filter":     {"name eq '" + strings.ReplaceAll(name, "'", "''") + "'"},
		"$expand":     {"createdTime"},
	}
	bodies, _, err := list[createdBody](ctx, c.client, group+"/resources", query)
	if err != nil {
		return nil, err
	}
	for _, body := range bodies {
		if !strings.EqualFold(body.ID, resourceID) {
			continue
		}
		created, err := time.Parse(time.RFC3339, body.CreatedTime)
		if err != nil {
			// A value that cannot be read is not an absent one.
			return nil, &collect.Failure{ErrorCode: "UnreadableCreatedTime",
				Message: "ARM returned a createdTime that is not an RFC 3339 time"}
		}
		created = created.UTC()
		return &created, nil
	}
	return nil, nil
}

// groupAndName splits an ARM id into its resource group and the name the
// resource list uses, which for a child resource joins the names with a slash
// (a slot is "site/slot").
func groupAndName(resourceID string) (string, string, bool) {
	parts := strings.Split(strings.Trim(resourceID, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if !strings.EqualFold(parts[i], "providers") || i < 4 || i+3 >= len(parts) {
			continue
		}
		var names []string
		for j := i + 3; j < len(parts); j += 2 {
			names = append(names, parts[j])
		}
		return "/" + strings.Join(parts[:4], "/"), strings.Join(names, "/"), true
	}
	return "", "", false
}
