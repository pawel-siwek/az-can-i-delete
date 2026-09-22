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
| `internal/output` — schemaVersion 2 report, renderers, sanitization | complete | shape, policy boundary, Unicode corpus, redaction, exit codes |
| `internal/collect` — five client boundaries, budgets, failure classification | complete | classification table, limiter, retry, gatherer |
| `internal/collect/collecttest` — fakes for all five boundaries | complete | used by the generic layer's tests |
| `internal/generic` — SPEC 5.0 generic signals and their output policy | complete | catalogue completeness, graph blindness, tags, locks, Activity Log, output boundary |
| `internal/cli` — command tree, flags, exit codes | scaffold only; every command except `version` exits 1 as not implemented | flag validation, exit codes, target validation |
| Azure SDK adapters for the five boundaries | **not started** | — |
| Storage, disk, NIC, public IP, NSG, VM, sites/plans analyzers | **not started** | — |
| `kb.yaml` storage knowledge base | **not started** | — |
| Fixture replay (`--fixture`), `demo` | **not started** | — |
| `cordon` / `uncordon` / `status` | **not started** | — |
| MCP server, CI action, goreleaser, installer | **not started** | — |

`go test ./...`, `go vet ./...` and `golangci-lint run ./...` are clean at every
commit on this branch, and no test reaches Azure.

## Order of the remaining work

Each step is one commit boundary. A step is finished when its Required signals,
its tests and its honest `not_evaluated` strings all exist — not before.

1. **SDK adapters.** Implement the five `internal/collect` interfaces against
   the pinned Azure SDK modules, with `DefaultAzureCredential` then
   `AzureCLICredential`, no account keys and no SAS. Every service error must
   surface as a `collect.Failure` so classification keeps working. Adapters are
   covered by transport-level tests only; no live tenant in CI.
2. **`check` wiring.** ARM GET (404 → exit 3), window resolution, the generic
   layer, `verdict.Evaluate` and `output.Build`, aggregation and exit codes for
   multiple targets. Until an analyzer exists, a supported type reports the
   generic layer's evidence and the analyzer's Required signals as missing.
3. **Storage analyzer.** ARG reverse references, ARM lists, `kb.yaml` with the
   six regex corrections and the confirm ladder, metrics R1–R10 with the amended
   write and read classes and the Defender `scannerCouldRun` predicate.
4. **Disk analyzer.** The cheapest live `yes`: disk state, `managedBy`,
   ownership age, backup/image/ASR references.
5. **Fixture replay and `demo`.** Recorded responses behind the same five
   interfaces, golden JSON per scenario, `recorded` in every replayed header.
6. **NIC, public IP, NSG, VM, sites and plans analyzers**, in that order.
7. **MCP server.** `can_i_delete` and `cordon_status` only, read-only, tag
   values redacted by default, the verbatim tool descriptions.
8. **Cordon, uncordon, status.** Storage `publicNetworkAccess` and site `stop`
   only; the preflight order, the `azcid` tag grammar, rollback on mismatch and
   the refusal wording for every other type.
9. **CI action, README, goreleaser, installer**, then the day-1 empirical tests
   against a real subscription, each with its documented rule flip.

## Deliberate gaps

- `generic.dns.records` is `not_evaluated`: the DNS reverse-reference query is
  named in the specification but its body is not part of it, and a missing
  query must not become an absence of records.
- `generic.roleassignments.direct` and `generic.policy.state` are the
  `not_evaluated` stubs of SPEC section 4.4, with its strings verbatim.
- `generic.pe.connections` is `not_evaluated` for a resource body that does not
  carry the collection, rather than reported as having none.
- `--query` (JMESPath) is rejected as not implemented, per the CLI contract.
