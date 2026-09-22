# ADR-0012: The 66-case table is the contract, and fixtures cite their source

- Status: accepted
- Date: 2026-09-21
- Source: REQUIREMENTS.md section 3, docs/SPEC.md appendix B

## Context

The verdict engine is the part of this tool that can be wrong quietly. A
rule change that flips one historical case is invisible unless the cases are
a fixed, reviewed set rather than tests written alongside the code they
test.

## Decision

The 66 acceptance cases are the contract for `internal/verdict`. Each
fixture keeps citing its origin (architect-3 section 2.7), and the rows are
carried verbatim in `docs/SPEC.md` appendix B, which is the committed source
the suite reads. A change to `Decide()` that alters any expected result is a
specification change first and a code change second.

## Consequences

The suite cannot be tidied up to match new behaviour. Rows for types the CLI
does not expose stay in the suite; that is provenance, not scope.

## Enforcement

`TestOriginal66`, `TestFixtureScopeAndConventions`,
`TestSourceDerivedFixtureMappings` and `TestG6Validation` in
`internal/verdict`.
