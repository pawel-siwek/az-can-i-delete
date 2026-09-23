# Governance

## What decides

A change is judged against written documents, not against whoever is in the
room. In order of precedence:

1. [`REQUIREMENTS.md`](REQUIREMENTS.md) — normative.
2. [`docs/SPEC.md`](docs/SPEC.md) — normative where the requirements are
   silent.
3. The architecture decision records in [`docs/adr/`](docs/adr/README.md).

Where a change and a document disagree, the change is wrong until the document
is changed with it and the change is argued for in the same pull request. A
decision record is never edited to match new code: reversing a decision means a
new record that supersedes the old one.

## Roles

**Contributors** are anybody who opens an issue, a pull request or a review.

**Maintainers**, listed in [MAINTAINERS.md](MAINTAINERS.md), review and merge
pull requests, cut releases, triage security reports and look after the
project's infrastructure.

## Decisions

Day-to-day changes are decided by review: a pull request merges when it is
green — build, vet, tests, lint and the conformance checks in
`internal/conformance` and `internal/adr` — and a maintainer approves it.

A change that alters a normative document or adds or supersedes a decision
record needs the approval of a majority of maintainers. While the project has a
single maintainer, that maintainer decides, and the reasoning is written into
the record itself so that it can be challenged later.

Disagreements are settled in the pull request or issue where they arise. If
they cannot be settled there, the maintainers decide by majority, and the
outcome is recorded.

## Becoming a maintainer

A contributor with a record of sustained, good-quality contributions and
reviews may be nominated by any maintainer. The nomination is a pull request
adding them to `MAINTAINERS.md` and `.github/CODEOWNERS`; it merges when a
majority of existing maintainers approve it.

A maintainer may step down at any time, and one who has been inactive for six
months may be moved to emeritus status by a majority of the other maintainers.

## Changes to this document

Changes to this document follow the same rule as changes to a normative
document: a pull request approved by a majority of maintainers.

## Code of Conduct

Everybody involved is bound by the [Code of Conduct](CODE_OF_CONDUCT.md).
