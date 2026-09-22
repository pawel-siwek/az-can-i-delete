# ADR-0004: A failure to observe is never evidence of absence

- Status: accepted
- Date: 2026-09-21
- Source: docs/SPEC.md sections 2 and 3, REQUIREMENTS.md section 8

## Context

The dangerous failure mode of a deletion assistant is a permission error
that reads as silence. Reader cannot see the Activity Log, the log comes
back empty, the tool reports no activity, somebody deletes a resource that
was in use an hour ago.

## Decision

Every unreadable signal is reported as `unknown(reason)` with the reason
carried through to the output: `permission`, `timeout`, `network`,
`throttled`, `unsupported`. An `unknown` on a critical signal makes `yes`
impossible. Empty results from a query the caller was not allowed to run
are `unknown(permission)`, not `absent` — Resource Graph in particular is
probed first, and zero rows alongside a successful ARM GET turns every ARG
signal to `unknown(permission)`.

Collection errors never become evidence. When collection cannot complete,
the run is an error, not an assessment.

## Consequences

Under-permissioned runs produce `tentative` a lot, and that is the correct
answer. The caller is told which grant would turn the unknown into an
observation.

## Enforcement

`TestGraphBlindnessIsVisibleInTheReport`,
`TestCollectionFailureIsAnErrorNotAnAssessment` in `internal/assess`;
`internal/collect.Classify` maps transport and status failures onto reasons;
`internal/verdict` refuses `yes` with any critical unknown.
