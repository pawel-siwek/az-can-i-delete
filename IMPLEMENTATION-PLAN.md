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
| `internal/cli` — command tree, `check`, exit codes | `check`, `cordon`, `uncordon`, `status`, `mcp`, `patterns list`, `demo` and `version` implemented; `history` exits 1 as not implemented | flags, targets, multi-target exit codes, rendering, verdict exits, status in JSON and table, the refusal exit for an uncordonable type, the MCP server's configuration, the pattern list, cordon's dry run, its plan without `--yes`, cordon → status → uncordon end to end over a fake writer, the refused type and the window bounds |
| `internal/azure` data-plane adapter and `--data-plane` | complete; **not exercised against a live tenant** | the prefix walk against a local blob endpoint: descent, the call budget, the delimiter, and a 403 classified as permission |
| `internal/kb` — the storage name knowledge base | complete | the 79 entries with the section 9.3 corrections, loader validation, ordered matcher, examples, precedence, tier sanity, tag value rules; end to end through the storage analyzer |
| Fixture replay (`--fixture`), `demo`, recording (`AZCID_RECORD`) | three scenarios recorded of the seven in SPEC 7.6; the recorder is wired into `check` but has not been run against a live subscription | every embedded scenario replayed end to end and held to its manifest; every string in every committed recording held to the report boundary's sanitizer; a miss proved to be an error rather than an empty answer; the recording command's refusals covered, its network half not |
| `internal/cordon` — `azcid` tag grammar, type gate, history, `status` | complete; **not exercised against a live tenant** | the ABNF cases (valid, wrong order, unknown key, bad prior, window bounds, slots, the 200-byte limit refusing three long slot names), the section 4.3 refusal strings, history append at 0600, newest-cordon lookup closed by an uncordon, a damaged line skipped; status: the own hour excluded, an unreadable or truncated counter as unknown rather than zero, a revert and its writer under `untrusted`, a damaged tag never interpreted, a tag of the wrong mode, every slot read, history only when asked; cordon: every pre-flight refusal in order with nothing written, what `--yes` and `--force` acknowledge, slots recorded in name order, the plan's tag; apply: state then tag then history, the undo when the tag is refused or removed, no undo of a concurrent foreign cordon (recorded with its owner), no undo on a timeout, the tag removed when the state is put back, a slot failure restarting only what this run stopped; uncordon: slots before production, the tag kept when the restore did not take or the tag is somebody else's, `--from-history` and `--prior` needing `--yes` |
| `internal/azure` cordon writer — PATCH, POST actions, the tags resource, `checkPolicyRestrictions`, long-running operations | complete; **not exercised against a live tenant** | against a local TLS server: an operation followed to Succeeded, one that never finishes reported as still running, a failed one as a failure, a poller off the management endpoint not followed, the tags body, Deny and Modify read from both halves of a policy answer, the principal read from the token |
| `check` on a cordoned resource | complete | the `cordon` field set from a valid tag, only `active` from a damaged one, and the verdict unchanged |
| Release pipeline — CI workflow, goreleaser, checksum-verifying installer | complete | workflows and goreleaser config validated; the installer was exercised against a local release, including a tampered archive |
| `internal/mcpserver` — the MCP server | complete; **not exercised with a live client or tenant** | an in-process client: exactly two tools, read-only annotations, the verbatim descriptions, no flag an agent could use to change a verdict, structured content equal to the JSON text, tag values redacted, failures as error results without a verdict, the 30-call budget, the cache keyed on everything that changes the answer, cordon_status on an untagged resource and on a refused type |
| `action.yml` — the composite CI action for `terraform plan` and what-if | complete; **not exercised in a live workflow** | the extractors against Terraform, stack and complete-mode ARM what-if samples (replacements, data-plane ids skipped, data sources ignored, detach, potential, unsupported, dedupe across sources, relative paths); the fail policy for every verdict and `fail-on`, not found as a pass, any error or missing result as a failure; the comment table; the declared inputs and outputs; the installer refusing an unpinned action and `latest` |
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

1. **The four scenarios SPEC 7.6 names that are not recorded yet**:
   `storage-no-pe`, `storage-tentative-defender`, `storage-untrusted-tag` and
   `site-tentative-linux-consumption`. The machinery is done — recorder,
   replay, `--fixture`, `demo` — so each is a scenario file and a re-record.
   `demo` lists what exists and refuses what does not; a missing recording is
   never answered with a different one.
2. **The day-1 empirical tests** against a real subscription, each with its
   documented rule flip.

## Deliberate gaps

- `generic.dns.records` is `not_evaluated`: the DNS reverse-reference query is
  named in the specification but its body is not part of it, and a missing
  query must not become an absence of records.
- `generic.roleassignments.direct` and `generic.policy.state` are the
  `not_evaluated` stubs of SPEC section 4.4, with its strings verbatim.
- `generic.pe.connections` is `not_evaluated` for a resource body that does not
  carry the collection, rather than reported as having none.
- `--query` (JMESPath) is rejected as not implemented rather than silently
  ignored.
- Four of SPEC 7.6's seven demo scenarios are not recorded yet. `demo` names
  the ones it has and refuses the rest; nothing substitutes for a missing
  recording.
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
