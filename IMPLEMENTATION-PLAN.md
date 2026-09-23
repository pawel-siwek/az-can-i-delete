# Implementation plan and status

`docs/SPEC.md` section 6 names this file as the acceptance order and the
commit/push boundaries. It records what is actually built, what is deliberately
not built yet, and the order the rest is added in. It is a status document: no
entry may claim a component exists before its tests do.

**Normative order:** `REQUIREMENTS.md` → `docs/SPEC.md` → this file. Where a
component is described in both, the specification wins; this file only says how
far the implementation has got.

## Documents

`docs/SPEC.md` is the committed consolidated specification. The review history
it was consolidated from (`architect-3.md`, `research-3.md`,
`SPEC-RECONCILIATION.md`) is referenced by name throughout, including in
fixture provenance, but is not committed. Appendix B of `docs/SPEC.md` carries
the 66-case acceptance table verbatim, so the acceptance suite checks every
fixture's raw row against it.

`docs/adr/` records why each binding constraint exists, below the two normative
documents in precedence. Their mechanically checkable constraints are tests in
`internal/conformance`; the rest is the brief that GitHub Copilot code review
reads a diff against, in `.github/copilot-instructions.md` and the path-scoped
files in `.github/instructions/`.

## Status

| Component | State | Tests |
|---|---|---|
| `internal/armid` — ARM ID and portal URL parser | complete | parser table, rejection cases, child/extension identity |
| `internal/verdict` — `Decide()` v3, catalogue, validator | complete | the 66-case acceptance suite, contract, provenance, ordering |
| `internal/age` — seven-source age chain | complete | boundary table incl. delete resets and truncation |
| `internal/output` — schemaVersion 2 report, renderers, sanitization | complete | shape, policy boundary, Unicode corpus, redaction, exit codes, table view |
| `internal/collect` — five client boundaries, budgets, failure classification | complete | classification table, limiter, retry, gatherer |
| `internal/collect/collecttest` — fakes for all five boundaries | complete | used by every layer above it |
| `internal/signal` — shared catalogue, evidence constructors, bounded graph runner | complete | exercised by the generic and disk layers |
| `internal/rules` — embedded api-version pins and review date | complete | pins, operations, review date |
| `internal/generic` — SPEC 5.0 generic signals and their output policy | complete | catalogue completeness, graph blindness, tags, locks, Activity Log, output boundary |
| `internal/azure` — ARM, Resource Graph, metrics and Activity Log adapters | complete | local TLS test server: pinned versions, paging, classification, no self-retry |
| `internal/assess` — one target end to end | complete | window parsing, not-found, refusal, coverage, yes and no verdicts |
| `internal/disk` — the managed disk analyzer | complete | attachment, export, references, ownership age, blindness, I/O contradiction |
| `internal/network` — interface, public IP and security group analyzers | complete | owners, pools, associations incl. the scale set model, flow log sinks, platform ownership, detachment age, traffic contradiction |
| `internal/storage` — the storage account analyzer | complete except the name knowledge base | operation classification, write and read thresholds, Defender carve-out, queue polling, count growth, listings, references, control-plane silence |
| `internal/vm` — the virtual machine analyzer | complete | memberships, platform ownership, backup and replication, images, network references and pools, power state, start events, the three activity thresholds, deallocated silence |
| `internal/site` — App Service sites, slots and plans | complete | hosting class, domains and fronting, triggers, the request ceiling and probe shape, stopped state, metric and deployment silence, plan site count and autoscale |
| `internal/cli` — command tree, `check`, exit codes | `check` implemented; every other command exits 1 as not implemented | flags, targets, multi-target exit codes, rendering, verdict exits |
| `internal/azure` data-plane adapter and `--data-plane` | complete; **not exercised against a live tenant** | the prefix walk against a local blob endpoint: descent, the call budget, the delimiter, and a 403 classified as permission |
| `internal/kb` — the storage name knowledge base | complete | the 79 entries with the section 9.3 corrections, loader validation, ordered matcher, examples, precedence, tier sanity, tag value rules; end to end through the storage analyzer |
| Fixture replay (`--fixture`), `demo` | **not started** | — |
| `cordon` / `uncordon` / `status` | **not started** | — |
| Release pipeline — CI workflow, goreleaser, checksum-verifying installer | complete | workflows and goreleaser config validated; the installer was exercised against a local release, including a tampered archive |
| MCP server, the composite CI action for `terraform plan` and what-if | **not started** | — |
| `docs/adr/` — the binding decisions | complete | structure, index, enforcement sections and the reviewer's brief are checked in `internal/adr` |
| `tools/Saruman` (Saruman) — the judgement half of the review, on the owner's Azure AI model | written; **not yet exercised against a live endpoint** | built on every pull request so a compile error surfaces there; the api-version it reads is covered by the conformance scan, which was proved against a deliberate literal |
| `internal/drift` + `cmd/driftcheck` — the change compared against its base | complete | a test per rule: the edited Decision, the supersession that must be allowed and the one that must not, the claim without tests, the dropped stub, the untested package, the normative edit |
| `internal/conformance` — the records' constraints as tests | complete | clock and network purity, boundary imports, api-version literals, key acquisition, SDK retries, numeric scores, writes in the read path |
| Copilot code review configuration | complete; the repository ruleset that requests it automatically is a settings change, not a file | the brief cites every accepted record, checked in `internal/adr` |

`go test ./...`, `go vet ./...` and `golangci-lint run ./...` are clean at every
commit on this branch, and no test reaches Azure.

## Order of the remaining work

Each step is one commit boundary. A step is finished when its Required signals,
its tests and its honest `not_evaluated` strings all exist — not before.

1. **Fixture replay and `demo`.** Recorded responses behind the same five
   interfaces, golden JSON per scenario, `recorded` in every replayed header.
2. **MCP server.** `can_i_delete` and `cordon_status` only, read-only, tag
   values redacted by default, the verbatim tool descriptions.
3. **Cordon, uncordon, status.** Storage `publicNetworkAccess` and site `stop`
   only; the preflight order, the `azcid` tag grammar, rollback on mismatch and
   the refusal wording for every other type.
4. **The composite CI action** that extracts ids from `terraform show -json`
   and `az stack group what-if`, with `fail-on: no|tentative`. The build and
   release pipeline already exists.
5. **The day-1 empirical tests** against a real subscription, each with its
   documented rule flip.

## Deliberate gaps

- `generic.dns.records` is `not_evaluated`: the DNS reverse-reference query is
  named in the specification but its body is not part of it, and a missing
  query must not become an absence of records.
- `generic.roleassignments.direct` and `generic.policy.state` are the
  `not_evaluated` stubs of SPEC section 4.4, with its strings verbatim.
- `generic.pe.connections` is `not_evaluated` for a resource body that does not
  carry the collection, rather than reported as having none.
- `--query` (JMESPath), `--fixture` replay and `--data-plane` are rejected as
  not implemented rather than silently ignored.
- The disk I/O counters are read under the composite metric names of the
  Azure Monitor disk namespace; the names have not been verified against a live
  tenant, so an unsupported-metric answer surfaces as unknown rather than as an
  absence of activity.
- A knowledge base match reports the tier a name alone may claim, never the
  confirmed one: confirming a producer means finding it in configuration, which
  is the other storage signals' work. The six mechanism entries carry no name
  pattern and are unreachable until a confirming collector exists.
- The data-plane walk is a sample, not a survey: five containers, twelve calls
  and three seconds each. It can show that something was written; it cannot
  show that nothing was, and the signal's caveat says so. The `y=/m=/d=/h=`
  layout and the delimited-listing shape it assumes are read from the
  specification, not verified against a live account, so a producer that
  partitions differently is simply not found — never reported as silent.
- `storage.shares.usage`
  and `storage.metrics.writes-inventory-shaped` are not_evaluated stubs with
  the specification's strings, and a storage operation this version cannot
  classify (NFS, for example) makes the silence signal unknown(unsupported)
  rather than silent.
