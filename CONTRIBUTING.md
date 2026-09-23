# Contributing

Thank you for considering a contribution. This file is the short version of
how a change gets in.

## Before you write code

Read, in this order: [`REQUIREMENTS.md`](REQUIREMENTS.md),
[`docs/SPEC.md`](docs/SPEC.md) and the decision records in
[`docs/adr/`](docs/adr/README.md). They are normative, and a change that
disagrees with them is wrong until the document changes with it
([GOVERNANCE.md](GOVERNANCE.md)).

The constraints most likely to catch a first contribution:

- A failure is never an absence: an unreadable signal is `unknown(reason)`,
  never `absent` and never an empty result (ADR-0004).
- `Decide()` is pure — no clock, no network (ADR-0003).
- Verdicts are tiered, never scored (ADR-0002).
- Nothing in the `check` path writes (ADR-0005).
- No account keys, no SAS, no secret in any output (ADR-0006).
- Api-versions live in `internal/rules/rules.yaml`, never as literals
  (ADR-0008).

`internal/conformance` checks these mechanically, so breaking one fails
`go test`. [`.github/copilot-instructions.md`](.github/copilot-instructions.md)
is the review brief for everything that needs judgement.

For anything larger than a bug fix, open an issue first so the approach can be
agreed before the work is done.

## Checks

Every commit must pass:

```sh
go build ./... && go vet ./... && go test ./... && golangci-lint run ./...
```

No test reaches Azure. The fakes in `internal/collect/collecttest` stand in for
every client boundary; a test that needs a live subscription will not be
merged.

## Status documents

`README.md` and `IMPLEMENTATION-PLAN.md` may not claim that a component exists
before its tests do. A pull request that marks something complete while the
code still exits with `not implemented` will be sent back.

## Developer Certificate of Origin

Contributions are accepted under the [Apache License 2.0](LICENSE) and the
[Developer Certificate of Origin](https://developercertificate.org/). Sign off
every commit to certify that you wrote it or have the right to submit it:

```sh
git commit -s
```

which adds a line such as:

```
Signed-off-by: Jane Doe <jane@example.com>
```

The name and address must match the commit's author.

## Pull requests

- Work on a branch, and keep a pull request to one change.
- Fill in the pull request template.
- Commit messages say what the change does and why, in the imperative.
- A maintainer reviews every pull request; the automated reviewer described in
  [`docs/REVIEW-BOT.md`](docs/REVIEW-BOT.md) may request changes but never
  approves.

## Reporting bugs and security issues

Bugs go in [issues](https://github.com/pawel-siwek/az-can-i-delete/issues)
using the bug template. Security problems do not: follow
[SECURITY.md](SECURITY.md).

## Code of Conduct

Everybody taking part is bound by the [Code of Conduct](CODE_OF_CONDUCT.md).
