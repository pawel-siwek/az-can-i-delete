---
applyTo: "internal/verdict/**,internal/age/**,internal/assess/**"
---

# The verdict engine

This is the part of the tool that can be wrong quietly, so it is the part with
the least room for judgement.

`Decide()` is pure: no network, no clock. The observation cutoff arrives as an
input. A `time.Now()` call, an HTTP client or any other ambient dependency
reaching this code is a blocking finding, however convenient (ADR-0003).

The 66 acceptance cases in `docs/SPEC.md` appendix B are the contract. A diff
that changes an expected result is a specification change first: if the
appendix and the fixtures were not changed with it and argued for, the code is
wrong, not the table (ADR-0012).

`yes` is the dangerous answer. It stays impossible when any critical signal is
`unknown`, when the effective window is under 30 effective days, or when any
Required silence signal is not `present`. Read any change near those three
conditions as blocking until proven otherwise.

Tiers decide, never arithmetic: `BLOCKER -> HARD_DEPENDENCY -> LIVE_ACTIVITY
-> DESIGN_INTENT -> OBSERVED_IDLE -> INFO`. A score, a weight, a confidence
percentage or a count that stands in for one is a blocking finding (ADR-0002).

An empty Required catalogue, a Required list reduced relative to the trusted
catalogue and contradictory duplicate evidence IDs are internal errors with no
verdict — not inputs to be tolerated.
