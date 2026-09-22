# ADR-0001: One static binary, and no model inside the engine

- Status: accepted
- Date: 2026-09-21
- Source: REQUIREMENTS.md section 1, docs/SPEC.md section 1

## Context

The tool answers one question about one Azure resource, and the answer is
used to decide whether something gets deleted. Two properties follow from
that: a run has to be reproducible from its inputs, and the thing has to be
runnable wherever an engineer already is — a laptop, a pipeline, or Cloud
Shell, where nothing outside `$HOME` survives.

A language model in the decision path would break the first property. Two
runs over identical evidence could disagree, and neither could be defended
in a review.

## Decision

`az-can-i-delete` is a single `CGO_ENABLED=0` Go binary. The verdict is
produced by rules over collected evidence; no component of the engine calls
a model, and no dependency is loaded at runtime. The same evidence always
produces the same verdict.

## Consequences

Every rule has to be written down, which is slower than prompting a model
and is the point: a rule can be cited, tested and argued with. Coverage
grows one analyzer at a time, and a type nobody has modelled is refused
outright rather than guessed at.

An agent may drive this tool, but the tool never drives a model.

## Enforcement

The build in `.goreleaser.yaml` and CI pins `CGO_ENABLED=0`. No module in
`go.mod` is a model client. `internal/verdict` takes evidence in and gives a
verdict out with no I/O of any kind.
`TestNoModelClientIsADependency` in `internal/conformance` reads the
dependency list.
