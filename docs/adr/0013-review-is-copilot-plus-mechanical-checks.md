# ADR-0013: Conformance is checked mechanically first, and by Copilot second

- Status: accepted
- Date: 2026-09-22
- Source: REQUIREMENTS.md section 7, docs/adr/README.md

## Context

The constraints that keep this tool honest are not the kind a compiler
catches. A clock read inside the verdict engine, an api-version copied into a
second constant, a permission error that starts reading as silence — each
compiles, passes the suite and reads fine in a hurried review.

Written records alone do not fix that: nobody re-reads thirteen documents
before merging a two-line change. An automated reviewer helps, but a reviewer
built on a model is a judgement call every time, needs a paid credential, and
cannot be relied on to notice the same thing twice.

## Decision

The review is split by what each half is actually good at.

The mechanical half is `internal/conformance`: the records' constraints
expressed as tests over the repository's own source. It runs in `go test
./...`, needs no credential, and goes red the same way a failing unit test
does. A constraint that can be checked this way is checked this way.

The judgement half is GitHub Copilot code review, briefed by
`.github/copilot-instructions.md` and the path-scoped files in
`.github/instructions/`. It reads a diff against `REQUIREMENTS.md`,
`docs/SPEC.md` and these records, and it comments. It is advisory: it does not
approve, does not merge, and cannot make a finding binding.

A third rule follows from the split: when a finding Copilot raises turns out
to be mechanically checkable, it moves into `internal/conformance` rather than
being fixed and forgotten.

## Consequences

The blocking part of conformance costs nothing and cannot be skipped; the
judgement part costs a Copilot seat and can be. Nothing red depends on a model
being available, in a good mood, or paid for.

The mechanical tests are literal and will occasionally be wrong — the storage
analyzer naming `listKeys` as an Activity Log observation is not the tool
acquiring a key. A false positive is argued out in a pull request and the test
is narrowed, which is the visible version of a rule being refined.

## Enforcement

`internal/conformance` carries one test per mechanically checkable record, and
`internal/adr` requires every accepted record to be cited in the reviewer's
brief, so a new decision cannot quietly leave the review's scope.
