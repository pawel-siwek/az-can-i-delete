# ADR-0003: Decide() is pure — no clock, no network

- Status: accepted
- Date: 2026-09-21
- Source: REQUIREMENTS.md section 8, docs/SPEC.md section 2

## Context

A verdict that depends on when it was computed cannot be re-checked. If
`Decide()` read the clock, replaying yesterday's evidence today would drift
the age chain and the effective window, and a disputed verdict could never
be reproduced.

## Decision

`Decide()` takes evidence and an observation cutoff as inputs and returns a
verdict. It performs no network calls and reads no clock. Live collection
sets the cutoff to today 00:00Z; fixture replay sets it to the recorded
cutoff. Windows are computed from that input, never from `time.Now()`.

## Consequences

Every caller has to decide what "now" means and say so, which is the
honest version of the question. Fixture replay, the acceptance suite and a
live run all exercise the same code path.

The cutoff is a reference point, not a filter. Evidence dated after it is
still evidence: a resource whose creation time falls after the cutoff was
created since then and is less than a day old, a verified age of zero days.
Discarding that timestamp made the age of every resource created on the day
of the check `unknown` (found by the end-to-end runs of 2026-09-24).

## Enforcement

`internal/verdict` imports neither `net/http` nor `time.Now`; the 66-case
suite passes a cutoff explicitly. `TestEffectiveWindows` covers the window
arithmetic, and `TestTheVerdictEngineReadsNoClockAndNoNetwork` in
`internal/conformance` reads the source for a clock or a network import.
