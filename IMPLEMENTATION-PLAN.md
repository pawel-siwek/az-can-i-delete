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
| `internal/cli` — command tree, `check`, exit codes | `check` implemented; every other command exits 1 as not implemented | flags, targets, multi-target exit codes, rendering, verdict exits |
| Storage, NIC, public IP, NSG, VM, sites/plans analyzers | **not started** | — |
| `kb.yaml` storage knowledge base | **not started** | — |
| Fixture replay (`--fixture`), `demo` | **not started** | — |
| `cordon` / `uncordon` / `status` | **not started** | — |
| MCP server, CI action, goreleaser, installer | **not started** | — |

`go test ./...`, `go vet ./...` and `golangci-lint run ./...` are clean at every
commit on this branch, and no test reaches Azure.

## Order of the remaining work

Each step is one commit boundary. A step is finished when its Required signals,
its tests and its honest `not_evaluated` strings all exist — not before.

1. **Storage analyzer.** ARG reverse references, ARM lists, `kb.yaml` with the
   six regex corrections and the confirm ladder, metrics R1–R10 with the amended
   write and read classes and the Defender `scannerCouldRun` predicate.
2. **Data-plane collection.** The opt-in OAuth-only prefix walk behind
   `--data-plane`, bounded as SPEC section 3.2 requires, with the fifth client
   boundary implemented against the storage data plane.
3. **Fixture replay and `demo`.** Recorded responses behind the same five
   interfaces, golden JSON per scenario, `recorded` in every replayed header.
4. **NIC, public IP, NSG, VM, sites and plans analyzers**, in that order.
5. **MCP server.** `can_i_delete` and `cordon_status` only, read-only, tag
   values redacted by default, the verbatim tool descriptions.
6. **Cordon, uncordon, status.** Storage `publicNetworkAccess` and site `stop`
   only; the preflight order, the `azcid` tag grammar, rollback on mismatch and
   the refusal wording for every other type.
7. **CI action, goreleaser, installer**, then the day-1 empirical tests against
   a real subscription, each with its documented rule flip. The README exists
   and repeats the approved limitations; a test enforces that.

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
