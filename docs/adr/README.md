# Architecture decision records

These records hold the decisions that a change to this repository is not
free to reverse in passing. `REQUIREMENTS.md` says what the tool must do and
`docs/SPEC.md` says exactly how; an ADR says why a constraint exists, so a
reviewer reading a diff can tell a deliberate change from an accidental one.

Precedence is unchanged: `REQUIREMENTS.md`, then `docs/SPEC.md`, then these
records. Where an ADR and the specification disagree, the specification wins
and the ADR is stale — fix it in the same pull request.

## Changing a decision

A record is never edited to match new code. Reversing a decision means a new
ADR that supersedes the old one, and the old one's status becomes
`superseded by ADR-NNNN`. Correcting a typo or a stale file reference in
place is fine.

Every record carries `Status`, `Context`, `Decision`, `Consequences` and
`Enforcement`. `Enforcement` names the test or the code that makes the
decision real; a decision nothing checks is a wish, and the reviewer treats
it as one.

New records start from [0000-template.md](0000-template.md) and take the
next free number.

## Index

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-one-static-binary-with-no-model-in-the-engine.md) | One static binary, and no model inside the engine | accepted |
| [0002](0002-tiered-evidence-and-no-numeric-score.md) | Tiered evidence, never a numeric score | accepted |
| [0003](0003-decide-is-a-pure-function.md) | `Decide()` is pure — no clock, no network | accepted |
| [0004](0004-a-failure-is-never-an-absence.md) | A failure to observe is never evidence of absence | accepted |
| [0005](0005-assessment-is-read-only-and-cordon-is-separate.md) | Assessment is read-only; cordon is a separate, reversible act | accepted |
| [0006](0006-no-account-keys-no-sas-oauth-only.md) | No account keys, no SAS, no secret ever leaves a run | accepted |
| [0007](0007-azure-text-is-untrusted-input.md) | Azure free-form text is untrusted input | accepted |
| [0008](0008-api-versions-are-pinned-in-rules-yaml.md) | Every Azure api-version is pinned in `rules.yaml` | accepted |
| [0009](0009-collection-runs-inside-a-budget.md) | Collection runs inside a budget, and adapters never self-retry | accepted |
| [0010](0010-five-client-boundaries-and-no-live-azure-in-tests.md) | Five client boundaries, and no live Azure in tests | accepted |
| [0011](0011-the-installer-always-pins-a-version.md) | The installer always names a version, and verifies what it fetched | superseded by ADR-0014 |
| [0012](0012-the-66-case-table-is-the-contract.md) | The 66-case table is the contract, and fixtures cite their source | accepted |
| [0013](0013-review-is-copilot-plus-mechanical-checks.md) | Conformance is checked mechanically first, and by Copilot second | accepted |
| [0014](0014-nothing-arrives-unread.md) | Nothing this project tells you to run arrives unread | accepted |
| [0015](0015-a-change-is-reviewed-against-the-documents.md) | A change is reviewed against the documents, and that review blocks | accepted |
