# ADR-0009: Collection runs inside a budget, and adapters never self-retry

- Status: accepted
- Date: 2026-09-21
- Source: REQUIREMENTS.md section 7, docs/SPEC.md section 3

## Context

A resource with many reverse dependencies can fan out into hundreds of
calls. Unbounded, the tool throttles the subscription it is inspecting, and
an SDK that retries on its own multiplies the damage while hiding how long a
signal actually took.

## Decision

Collection runs under one budget: concurrency limited to 6, an ARG token
bucket of 15 calls per 5 seconds, 20 seconds per call, 60 seconds per run,
at most 3 retries that honour `Retry-After`. Retry and rate limiting live in
`internal/collect`; the Azure SDK pipeline is configured with retries
disabled so an adapter never retries behind the budget's back. A signal that
runs out of time is `unknown(timeout)`, and an exhausted budget is
`unknown`, never `absent` (see ADR-0004).

## Consequences

Large resources produce more unknowns rather than longer runs. The budget is
one place to reason about load on a subscription.

## Enforcement

`internal/collect` (`Limiter`, `Retry`, `Gather`, `ErrBudgetExhausted`) and
`internal/azure` configuring `policy.RetryOptions{MaxRetries: -1}`.
