// Package collect defines the five client boundaries every analyzer collects
// through, the shared budgets and the failure classification that turns a
// transport or service error into a tool-owned unknown code. Nothing in this
// package talks to Azure: an SDK adapter, a fake and a recorded fixture all
// satisfy the same interfaces, so no analyzer test needs a live tenant. A
// failure never becomes silence; it becomes unknown(code) for the signal layer.
package collect

import (
	"context"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/age"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// Resource is a normalized control-plane object. Properties stays free-form
// because the analyzers read documented paths out of it; the output boundary,
// not this package, decides what may be printed.
type Resource struct {
	ID                string            `json:"id"`
	Type              string            `json:"type"`
	Name              string            `json:"name"`
	Location          string            `json:"location,omitempty"`
	Kind              string            `json:"kind,omitempty"`
	ProvisioningState string            `json:"provisioningState,omitempty"`
	Tags              map[string]string `json:"tags,omitempty"`
	Properties        map[string]any    `json:"properties,omitempty"`
	SystemData        map[string]any    `json:"systemData,omitempty"`
}

// LockScope names the scope a management lock was read at. All three scopes are
// collected because an inherited lock blocks a delete exactly like a local one.
type LockScope string

// The three lock scopes of the generic layer, in inheritance order.
const (
	LockScopeResource      LockScope = "resource"
	LockScopeResourceGroup LockScope = "resourceGroup"
	LockScopeSubscription  LockScope = "subscription"
)

// Lock is a management lock. Level is CanNotDelete or ReadOnly; both block.
type Lock struct {
	ID    string    `json:"id"`
	Name  string    `json:"name"`
	Level string    `json:"level"`
	Scope LockScope `json:"scope"`
}

// DenyAssignment is an Azure deny assignment. BlocksDelete is decided by the
// adapter from the assignment's actions and exclusions, not by name.
type DenyAssignment struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	BlocksDelete bool   `json:"blocksDelete"`
}

// Query is one Resource Graph request. Subscriptions is the explicit scope;
// an empty scope is a caller error, never an invitation to query the tenant.
type Query struct {
	Text          string   `json:"text"`
	Subscriptions []string `json:"subscriptions"`
	Top           int      `json:"top,omitempty"`
	SkipToken     string   `json:"skipToken,omitempty"`
}

// Rows is a Resource Graph page. Truncated or a non-empty SkipToken means the
// answer is incomplete: callers must page or degrade to unknown(partial).
type Rows struct {
	Rows      []map[string]any `json:"rows"`
	Truncated bool             `json:"truncated"`
	SkipToken string           `json:"skipToken,omitempty"`
}

// MetricQuery is one Azure Monitor metrics request over an explicit window.
// ResourceURI may address a sub-service such as {sa}/blobServices/default.
type MetricQuery struct {
	ResourceURI string         `json:"resourceUri"`
	Names       []string       `json:"names"`
	Filter      string         `json:"filter,omitempty"`
	Aggregation string         `json:"aggregation"`
	Interval    string         `json:"interval"`
	Top         int            `json:"top,omitempty"`
	OrderBy     string         `json:"orderBy,omitempty"`
	Window      verdict.Window `json:"window"`
}

// MetricPoint is one aggregated value with its dimension values.
type MetricPoint struct {
	Timestamp  time.Time         `json:"timestamp"`
	Value      float64           `json:"value"`
	Dimensions map[string]string `json:"dimensions,omitempty"`
}

// MetricSeries is one metric name and dimension combination.
type MetricSeries struct {
	Name       string            `json:"name"`
	Unit       string            `json:"unit,omitempty"`
	Dimensions map[string]string `json:"dimensions,omitempty"`
	Points     []MetricPoint     `json:"points"`
}

// MetricResult carries the series and whether the response saturated a cap.
// Saturation is unknown(partial) at the signal layer, never zero activity.
type MetricResult struct {
	Series    []MetricSeries `json:"series"`
	Truncated bool           `json:"truncated"`
}

// ActivityLog is a normalized Activity Log page with the coverage it actually
// achieved. Days and Truncated feed the age chain's no-event inference, which
// refuses to infer anything from an incomplete log.
type ActivityLog struct {
	Events    []age.ActivityEvent `json:"events"`
	Days      int                 `json:"days"`
	Truncated bool                `json:"truncated"`
}

// Container is a listed blob container or file share. A lease held on one is
// live activity, so the lease state travels with the name.
type Container struct {
	Name       string `json:"name"`
	LeaseState string `json:"leaseState,omitempty"`
}

// PrefixBudget bounds the opt-in data-plane walk: SPEC section 3.2 allows at
// most 12 calls and 3 seconds per container over at most 5 containers.
type PrefixBudget struct {
	MaxCalls int           `json:"maxCalls"`
	MaxTime  time.Duration `json:"maxTime"`
}

// Prefix is the deepest y=/m=/d=/h= partition reached and its last write, if
// the walk completed within budget. An exhausted budget is unknown(partial).
type Prefix struct {
	Path      string    `json:"path"`
	LastWrite time.Time `json:"lastWrite"`
	Complete  bool      `json:"complete"`
}

// ARMClient is the control-plane boundary: GETs, child lists, management
// locks at three scopes, deny assignments and resource-group deployments.
// Implementations must return a *Failure (or wrap one) for every service error.
type ARMClient interface {
	Get(ctx context.Context, resourceID, apiVersion string) (Resource, error)
	List(ctx context.Context, path, apiVersion string) ([]Resource, error)
	Locks(ctx context.Context, scope string) ([]Lock, error)
	DenyAssignments(ctx context.Context, scope string) ([]DenyAssignment, error)
	Deployments(ctx context.Context, resourceGroupID string, top int) ([]age.Deployment, error)
}

// GraphClient is the Azure Resource Graph boundary. Every ARG-backed signal
// depends on the K0 visibility probe having found the target first.
type GraphClient interface {
	Query(ctx context.Context, query Query) (Rows, error)
}

// MetricsClient is the Azure Monitor metrics boundary.
type MetricsClient interface {
	Metrics(ctx context.Context, query MetricQuery) (MetricResult, error)
}

// ActivityLogClient is the Azure Monitor Activity Log boundary.
type ActivityLogClient interface {
	Events(ctx context.Context, resourceID string, window verdict.Window) (ActivityLog, error)
}

// DataPlaneClient is the opt-in OAuth-only storage data-plane boundary. No
// implementation may acquire account keys, list keys or fall back to SAS.
type DataPlaneClient interface {
	Containers(ctx context.Context, accountID string, limit int) ([]Container, error)
	PrefixWalk(ctx context.Context, accountID, container string, budget PrefixBudget) (Prefix, error)
}

// Clients is the complete set of boundaries an analyzer may use. DataPlane is
// nil unless --data-plane was passed, which keeps the opt-in explicit.
type Clients struct {
	ARM         ARMClient
	Graph       GraphClient
	Metrics     MetricsClient
	ActivityLog ActivityLogClient
	DataPlane   DataPlaneClient
}
