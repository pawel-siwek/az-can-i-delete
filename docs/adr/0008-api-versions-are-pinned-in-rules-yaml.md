# ADR-0008: Every Azure api-version is pinned in rules.yaml

- Status: accepted
- Date: 2026-09-21
- Source: REQUIREMENTS.md section 7, docs/SPEC.md section 10

## Context

An api-version scattered across call sites drifts. A response shape changing
under the tool would move a verdict without any commit explaining why, which
is indistinguishable from a bug in the rules.

## Decision

All api-versions live in `internal/rules/rules.yaml`, one pin per operation,
alongside a `rulesDate` recording when the set was last reviewed. Call sites
read the pin; none carries a literal version. Changing a pin is a reviewable
diff with a reason.

## Consequences

Upgrading means editing one file and re-reading what changed in that API.
The review date makes a stale rule set visible.

## Enforcement

`internal/rules` tests `TestPinnedVersions`, `TestOperationVersions`,
`TestEveryPinIsAnAPIVersion` and `TestRulesCarryAReviewDate`.
