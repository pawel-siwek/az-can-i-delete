# ADR-0002: Tiered evidence, never a numeric score

- Status: accepted
- Date: 2026-09-21
- Source: REQUIREMENTS.md section 3, docs/SPEC.md section 2

## Context

A "risk score" of 0.82 invites exactly the behaviour this tool exists to
prevent: the reader stops looking at what was observed and starts comparing
the number to a threshold they invented. Scores also hide their own
composition — a strong dependency and three weak hints can produce the same
figure.

## Decision

Evidence is ordered into tiers, `BLOCKER -> HARD_DEPENDENCY ->
LIVE_ACTIVITY -> DESIGN_INTENT -> OBSERVED_IDLE -> INFO`, and the highest
tier with present evidence decides. Display verdicts are `yes | no |
tentative` with a `reasonClass`. No number expresses confidence anywhere in
the report, the table view, the JSON schema or the MCP surface.

Every signal in the catalogue is emitted on every run with a status of
`present`, `absent`, `unknown(reason)` or `not_evaluated` — a signal is
never silently dropped because it did not fire.

## Consequences

The report is longer than a score would be, and a reader can see which
single observation moved the verdict. Adding a signal means placing it in a
tier, which is a design decision reviewers can contest.

## Enforcement

`internal/verdict` (the 66-case acceptance suite, `TestOriginal66`) and
`TestCoverageSurvivesEveryWinningRule`. The JSON schema carries no numeric
confidence field; `internal/output` tests assert the emitted shape, and
`TestNoNumericConfidenceReachesTheVerdict` in `internal/conformance` fails on
a numeric score, weight or confidence field appearing in either package.
