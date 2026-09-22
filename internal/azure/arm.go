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

// resourceBody is the shared envelope of an ARM resource. Properties stays
// free-form: the analyzers read documented paths out of it and the output
// boundary decides what may be printed.
type resourceBody struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Location   string            `json:"location"`
	Kind       string            `json:"kind"`
	Tags       map[string]string `json:"tags"`
	Properties map[string]any    `json:"properties"`
	SystemData map[string]any    `json:"systemData"`
}

func (b resourceBody) normalize() collect.Resource {
	state, _ := b.Properties["provisioningState"].(string)
	return collect.Resource{
		ID: b.ID, Name: b.Name, Type: b.Type, Location: b.Location, Kind: b.Kind,
		ProvisioningState: state, Tags: b.Tags, Properties: b.Properties, SystemData: b.SystemData,
	}
}

// Get reads one resource at its pinned api-version. A 404 is reported as such
// so the caller can end the run with "resource not found" rather than guessing.
func (c *armClient) Get(ctx context.Context, resourceID, apiVersion string) (collect.Resource, error) {
	if apiVersion == "" {
		return collect.Resource{}, &collect.Failure{ErrorCode: "NoSupportedApiVersion",
			Message: "no pinned api-version for this resource type"}
	}
	var body resourceBody
	if err := c.client.get(ctx, resourceID, url.Values{"api-version": {apiVersion}}, &body); err != nil {
		return collect.Resource{}, err
	}
	if body.ID == "" {
		body.ID = resourceID
	}
	return body.normalize(), nil
}

// List reads a child collection, for example a storage account's containers.
func (c *armClient) List(ctx context.Context, path, apiVersion string) ([]collect.Resource, error) {
	bodies, complete, err := list[resourceBody](ctx, c.client, path, url.Values{"api-version": {apiVersion}})
	if err != nil {
		return nil, err
	}
	resources := make([]collect.Resource, 0, len(bodies))
	for _, body := range bodies {
		resources = append(resources, body.normalize())
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
