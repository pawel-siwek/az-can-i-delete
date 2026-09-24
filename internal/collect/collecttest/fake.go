// Package collecttest provides fakes for the five client boundaries so every
// analyzer can be tested without a live tenant. A fake answers exactly what a
// test hands it: a nil hook means "the call succeeded and found nothing", and
// an error hook is how a test reproduces a 403, a throttle or a timeout.
package collecttest

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/pawel-siwek/az-can-i-delete/internal/collect"
	"github.com/pawel-siwek/az-can-i-delete/internal/verdict"
)

// ARM is a fake control-plane client.
type ARM struct {
	GetFunc         func(ctx context.Context, resourceID, apiVersion string) (collect.Resource, error)
	ListFunc        func(ctx context.Context, path, apiVersion string) ([]collect.Resource, error)
	LocksFunc       func(ctx context.Context, scope string) ([]collect.Lock, error)
	DenyFunc        func(ctx context.Context, scope string) ([]collect.DenyAssignment, error)
	DeploymentsFunc func(ctx context.Context, resourceGroupID string, top int) ([]collect.Deployment, error)
	CreatedFunc     func(ctx context.Context, resourceID string) (*time.Time, error)

	mu     sync.Mutex
	scopes []string
}

// Get returns the configured resource, or an empty one.
func (c *ARM) Get(ctx context.Context, resourceID, apiVersion string) (collect.Resource, error) {
	if c.GetFunc == nil {
		return collect.Resource{ID: resourceID}, nil
	}
	return c.GetFunc(ctx, resourceID, apiVersion)
}

// List returns the configured children, or none.
func (c *ARM) List(ctx context.Context, path, apiVersion string) ([]collect.Resource, error) {
	if c.ListFunc == nil {
		return nil, nil
	}
	return c.ListFunc(ctx, path, apiVersion)
}

// Locks records the scope it was asked for so a test can assert that all three
// lock scopes were actually read.
func (c *ARM) Locks(ctx context.Context, scope string) ([]collect.Lock, error) {
	c.mu.Lock()
	c.scopes = append(c.scopes, scope)
	c.mu.Unlock()
	if c.LocksFunc == nil {
		return nil, nil
	}
	return c.LocksFunc(ctx, scope)
}

// LockScopes returns the scopes Locks was called with, in call order.
func (c *ARM) LockScopes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.scopes...)
}

// DenyAssignments returns the configured deny assignments, or none.
func (c *ARM) DenyAssignments(ctx context.Context, scope string) ([]collect.DenyAssignment, error) {
	if c.DenyFunc == nil {
		return nil, nil
	}
	return c.DenyFunc(ctx, scope)
}

// Deployments returns the configured deployment history, or none.
func (c *ARM) Deployments(ctx context.Context, resourceGroupID string, top int) ([]collect.Deployment, error) {
	if c.DeploymentsFunc == nil {
		return nil, nil
	}
	return c.DeploymentsFunc(ctx, resourceGroupID, top)
}

// CreatedTime returns the configured creation time. Unlike the other hooks, a
// nil one is not "found nothing": the live client never answers without a
// time for a resource that exists (SPEC section 2.1), so an unconfigured fake
// answers the way a failed read does.
func (c *ARM) CreatedTime(ctx context.Context, resourceID string) (*time.Time, error) {
	if c.CreatedFunc == nil {
		return nil, &collect.Failure{ErrorCode: "CreatedTimeNotReturned",
			Message: "the fake was given no creation time"}
	}
	return c.CreatedFunc(ctx, resourceID)
}

// GraphAnswer is one canned Resource Graph reply. Match is a substring of the
// query text, so a test names the query it is answering instead of repeating
// the whole KQL.
type GraphAnswer struct {
	Match string
	Rows  collect.Rows
	Err   error
}

// Graph is a fake Resource Graph client that records every query it received.
type Graph struct {
	Answers []GraphAnswer

	mu      sync.Mutex
	queries []collect.Query
}

// Query answers with the first matching canned reply, or with no rows.
func (c *Graph) Query(_ context.Context, query collect.Query) (collect.Rows, error) {
	c.mu.Lock()
	c.queries = append(c.queries, query)
	c.mu.Unlock()
	for _, answer := range c.Answers {
		if strings.Contains(query.Text, answer.Match) {
			return answer.Rows, answer.Err
		}
	}
	return collect.Rows{}, nil
}

// Queries returns every query the collector issued, in call order.
func (c *Graph) Queries() []collect.Query {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]collect.Query(nil), c.queries...)
}

// Metrics is a fake Azure Monitor metrics client.
type Metrics struct {
	MetricsFunc func(ctx context.Context, query collect.MetricQuery) (collect.MetricResult, error)
}

// Metrics answers with the configured series, or with none.
func (c *Metrics) Metrics(ctx context.Context, query collect.MetricQuery) (collect.MetricResult, error) {
	if c.MetricsFunc == nil {
		return collect.MetricResult{}, nil
	}
	return c.MetricsFunc(ctx, query)
}

// ActivityLog is a fake Activity Log client. Days defaults to the window asked
// for so a test that does not care about coverage gets a complete log.
type ActivityLog struct {
	Log        collect.ActivityLog
	Err        error
	EventsFunc func(ctx context.Context, resourceID string, window verdict.Window) (collect.ActivityLog, error)
}

// Events answers with the configured log.
func (c *ActivityLog) Events(ctx context.Context, resourceID string, window verdict.Window) (collect.ActivityLog, error) {
	if c.EventsFunc != nil {
		return c.EventsFunc(ctx, resourceID, window)
	}
	if c.Err != nil {
		return collect.ActivityLog{}, c.Err
	}
	log := c.Log
	if log.Days == 0 {
		log.Days = window.Days
	}
	return log, nil
}

// DataPlane is a fake OAuth-only storage data-plane client. It holds no
// credential of any kind, which is the point: no fake may model account keys.
type DataPlane struct {
	ContainersFunc func(ctx context.Context, accountID string, limit int) ([]collect.Container, error)
	PrefixFunc     func(ctx context.Context, accountID, container string, budget collect.PrefixBudget) (collect.Prefix, error)
}

// Containers answers with the configured containers, or with none.
func (c *DataPlane) Containers(ctx context.Context, accountID string, limit int) ([]collect.Container, error) {
	if c.ContainersFunc == nil {
		return nil, nil
	}
	return c.ContainersFunc(ctx, accountID, limit)
}

// PrefixWalk answers with the configured walk result, or with an empty one.
func (c *DataPlane) PrefixWalk(ctx context.Context, accountID, container string, budget collect.PrefixBudget) (collect.Prefix, error) {
	if c.PrefixFunc == nil {
		return collect.Prefix{}, nil
	}
	return c.PrefixFunc(ctx, accountID, container, budget)
}

// Clients wires the five fakes together for a collector under test.
func Clients(arm *ARM, graph *Graph, metrics *Metrics, log *ActivityLog, dataPlane *DataPlane) collect.Clients {
	clients := collect.Clients{ARM: arm, Graph: graph, Metrics: metrics, ActivityLog: log}
	if dataPlane != nil {
		clients.DataPlane = dataPlane
	}
	return clients
}

// Forbidden is the 403 a caller without Reader sees.
func Forbidden() error {
	return &collect.Failure{StatusCode: 403, ErrorCode: "AuthorizationFailed", Message: "forbidden"}
}
