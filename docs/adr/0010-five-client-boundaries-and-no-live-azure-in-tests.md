# ADR-0010: Five client boundaries, and no live Azure in tests

- Status: accepted
- Date: 2026-09-21
- Source: REQUIREMENTS.md section 7, docs/SPEC.md section 10

## Context

Analyzers that reach for an SDK client directly cannot be tested without a
subscription, and a test suite that needs a tenant is a test suite that stops
being run.

## Decision

All Azure access goes through five interfaces — ARM, Resource Graph,
Metrics, Activity Log and data plane — defined in `internal/collect`. Every
analyzer depends on the interfaces, never on the SDK. `collecttest` provides
a fake for each, and the whole suite runs offline.

## Consequences

A new capability means a new method on a boundary and a fake to match, which
is friction in proportion to the risk. CI needs no Azure credentials at all.

## Enforcement

`internal/collect/collecttest` fakes every boundary; analyzer packages
import `collect`, not `azure`. CI runs `go test -race ./...` with no Azure
secrets configured.
