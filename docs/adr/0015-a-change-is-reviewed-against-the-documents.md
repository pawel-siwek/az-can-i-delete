# ADR-0015: A change is reviewed against the documents, and that review blocks

- Status: accepted
- Date: 2026-09-23
- Source: REQUIREMENTS.md section 7, docs/adr/0013

## Context

ADR-0013 split conformance into what a machine can settle and what needs
judgement, and gave the judgement half to Copilot code review. Copilot
comments; it cannot hold a check red. So the only thing that could actually
stop a merge was the test suite, and the test suite reads the source, never a
diff.

That leaves a gap with a specific shape. Every check in this repository asks
"is the code right?" — none asks "did this change quietly move the thing the
code is measured against?" A decision record edited so it agrees with new
code passes every test, reads fine in a diff, and removes the only record of
why the constraint existed. So does a status table that starts calling a
component complete, and a disclosed gap that disappears without being filled.

Each of those is the project losing its ability to say what it knows, which
is the one thing it exists to do.

The obvious answer was a model reading the diff against the records. GitHub
Models, the free inference path in Actions, was retired in July 2026, and the
alternatives need a paid credential. A review that only runs when somebody is
paying is not a review anybody should rely on.

## Decision

The blocking review is deterministic and needs no credential.

`internal/drift` compares the proposed change against its base and reports
where the change and the documents disagree. `cmd/driftcheck` feeds it a real
diff and exits non-zero on a blocking finding, which is what makes it a
required check rather than an opinion.

Two findings block: a decision record whose Decision section changed without
being superseded by a record arriving in the same change, and a status
document that moves a component towards complete while no test changed.
Three are raised for a human without blocking: a removed `not_evaluated`
stub, a new package with no test, and any edit to a normative document.

A reviewer that cannot run has not approved. A comparison that fails is an
error, never a pass — the same rule the tool applies to its own evidence.

Judgement stays advisory, with Copilot, as ADR-0013 left it. Merging still
needs the owner's approval; this check decides only whether the change is
allowed to reach that conversation.

## Consequences

The review is narrow. It catches the drifts that can be stated as rules and
misses everything else, and it will be wrong occasionally — a legitimate
supersession spelled differently, a status change whose tests landed in an
earlier pull request. The owner can override, because they own the repository
and the check is a guard rather than a gate.

The alternative was a review that needs a subscription to run, and that is
worse: it fails open the moment somebody stops paying, and nothing in a log
would say so.

## Enforcement

`internal/drift` carries a test per rule, including the supersession that must
be allowed and the one that must not. The rules were exercised against a real
sabotage of ADR-0004 before this was committed: the check reported NOT OK and
named the record. `.github/workflows/review.yml` runs it on every pull request
against the base branch.
