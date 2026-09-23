# Working in this repository

## Attribution

Commits and merges made by an agent are authored by the repository owner and
credit the agent as co-author — the owner is accountable for what lands, the
agent is not a second contributor with its own standing.

```sh
git config user.name "pawel-siwek"
git config user.email "29552463+pawel-siwek@users.noreply.github.com"
```

That is the owner's GitHub identity, so every commit links to their account.
No other spelling of the name and no other address: one identity across the
whole history is what makes `git log --author` and a blame worth reading.

Every commit message an agent writes ends with exactly this trailer, and
nothing else:

```
Co-Authored-By: Claude <noreply@anthropic.com>
```

Set the identity before the first commit of a session; a fresh container does
not carry it. Never put a model name or version anywhere — not in the trailer,
a commit message, a pull request, a code comment or any other file. "Claude"
is the co-author; which model wrote it is not attribution, it is noise that
ages badly.

## Branch and merge

Work happens on a branch, never directly on `main`. When the work is green,
open a pull request and merge it; an agent may merge its own work. Never
rewrite history on a branch somebody else may have checked out.

If the branch's pull request is already merged, start again from `main` under
the same branch name rather than stacking onto merged history.

## Before every commit

```sh
go build ./... && go vet ./... && go test ./... && golangci-lint run ./...
```

All four are clean at every commit. No test reaches Azure — the fakes in
`internal/collect/collecttest` stand in for all five client boundaries.

## What the code is not free to change

`REQUIREMENTS.md` is normative, then `docs/SPEC.md`, then the decision records
in `docs/adr/`. Where a change and a document disagree, the change is wrong
until the document is changed with it and argued for.

The constraints worth knowing before writing anything here:

- A failure is never an absence. An unreadable signal is `unknown(reason)`,
  never `absent`, never an empty result (ADR-0004). This is the bug this
  project exists to avoid.
- `Decide()` is pure: no clock, no network, the cutoff is an input (ADR-0003).
- Verdicts are tiered, never scored (ADR-0002).
- Assessment reads; nothing in the `check` path writes (ADR-0005).
- No account keys, no SAS, no secret in any output (ADR-0006).
- Azure free-form text reaches the report only under `untrusted`, sanitized
  (ADR-0007).
- Api-versions live in `internal/rules/rules.yaml`, never as literals
  (ADR-0008).

`internal/conformance` enforces those mechanically, so a violation fails
`go test` rather than waiting for review. `.github/copilot-instructions.md` is
the brief for everything that needs judgement.

## Status claims

`IMPLEMENTATION-PLAN.md` and `README.md` may not claim a component exists
before its tests do. A stub says what it does not evaluate, and why, in the
strings the specification gives it.
