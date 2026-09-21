# az-can-i-delete — requirements (v0.1, hackathon)

**Normative documents, in precedence order:** this file → `docs/architect-3.md` (final sign-off: `Decide()` v3, signal catalogue, cordon, CLI/MCP/CI contracts, Go layout) → `docs/research-3.md` (REST/SDK/metrics/KQL reference, `kb.yaml`) → everything else in `docs/` is review history. Where a document conflicts with this file, this file wins. Where this file is silent, `architect-3.md` wins.

## 1. Product

A single static Go binary (`az-can-i-delete`) that, for ONE Azure resource ID, answers "is it in use / can I delete it?" with a deterministic verdict and tiered evidence. Also: reversible `cordon`/`uncordon`, an MCP server for coding agents, a GitHub Action for CI. No LLM inside; rules only; every run reproducible from the same inputs.

Two users, one engine: an engineer who inherited a resource and does not know every Azure feature; a coding agent whose cleanup workflow wants to delete something.

## 2. Scope (reconciled 2026-09-21)

**v0.1 analyzers (in this order of implementation):**
1. `Microsoft.Storage/storageAccounts`
2. `Microsoft.Compute/disks`
3. `Microsoft.Network/networkInterfaces`
4. `Microsoft.Network/publicIPAddresses`
5. `Microsoft.Network/networkSecurityGroups`
6. `Microsoft.Compute/virtualMachines`
7. `Microsoft.Web/sites` (web apps **and** function apps; slots) + `Microsoft.Web/serverfarms`

Disks are the eighth analyzer on top of the seven named in the pitch (cheapest live `yes` for the demo via `LastOwnershipUpdateTime`). Function apps share the analyzer with web apps but have their own hosting-class table, trigger bindings and execution counters (`architect-3.md` §5.7).

**Extended (research complete, not v0.1):** `Microsoft.Network/virtualNetworks`, `Microsoft.App/containerApps|jobs|managedEnvironments`. Any other type → exit 1 with `unsupported resource type`.

**Public IP** is not in `architect-3.md`; implement by analogy to NIC (§5.3): BLOCKER on `ipConfiguration.id` set (NIC, LB frontend, NAT gateway, VPN/ER gateway, Bastion, Application Gateway, Azure Firewall); HARD_DEP on DNS records → this IP (`dnsresources` KQL from research-3 §D), `Static` allocation + `dnsSettings.domainNameLabel` → DESIGN_INTENT; metrics `ByteCount`/`PacketCount`/`SynCount` (ns `Microsoft.Network/publicIPAddresses`) printed as INFO and as contradiction when non-zero on an unattached IP; OBSERVED_IDLE `pip.unassociated.ge-30d` via Activity Log + `resourcechanges` like `nic.detached.ge-30d`; Advisor recommendation for unassociated public IPs as corroboration.

## 3. Verdict model (binding)

- Display verdicts `yes | no | tentative`; `reasonClass ∈ {blocked, in-use, inconclusive, design-intent, no-evidence-of-use}`.
- Tiers: `BLOCKER → HARD_DEPENDENCY → LIVE_ACTIVITY → DESIGN_INTENT → OBSERVED_IDLE → INFO`. Every signal is emitted on every run as `present | absent | unknown(reason) | not_evaluated`.
- `Decide()` v3 exactly as `architect-3.md` §2, including the three fixes: age chain uses Succeeded-only events and resets after the last successful delete on the same id; `storage.lists.complete` (not `storage.kb.no-match`) in the Required set; LIVE evaluated over the requested window, OBSERVED_IDLE over the effective window.
- `yes` is impossible when: any critical signal is `unknown`; effective window `min(requested, ageLowerBound) < 30 d`; any Required silence signal is not `present`. Requested window default 30 d, max 93 d, min 7 d (7–29 can only yield `no`/`tentative`).
- No numeric score anywhere. Every verdict prints `unknowns[]`, `notEvaluated[]` (with `{id, reason, consequence, howToCheck}`), `coverage`, `limitations[]` (human-approved corrected v0.1 list in `docs/SPEC.md` §5.1, verbatim on every `yes`; limitations describe Decide v3 and never introduce additional verdict gates).
- The 66-case test table in `architect-3.md` §2.7 is the acceptance suite for `internal/verdict`; all must pass before any analyzer work.
- Before evaluation, reject an empty Required catalogue/list, a Required list improperly reduced relative to the trusted catalogue, or contradictory duplicate evidence IDs as an internal evaluation error with no verdict. Missing actual Azure observations remain unknown/tentative, not catalogue errors. Preserve the intended `generic.never` fallback and all original 66 inputs/expected results, including intentionally absent or unknown required evidence. Add three separate validator cases: empty Required list, omitted catalogue requirement, conflicting duplicate evidence ID (human-approved G6).

## 4. Storage specifics (binding)

- Reverse dependencies via ARG first (flow logs `storageId`, boot diagnostics, VM diagnostics extension, Backup instances, Function App Flex deployment storage, resource-instance rules), then ARM (private endpoint connections, object replication, Event Grid list-by-resource, immutability/legal hold).
- Metrics rules R1–R10 as amended in `architect-3.md` §1/§3.4: `TransactionType eq 'User'`; write floor ≥10 on ≥2 days or ≥1000/day; `SetBlobTier/SetBlobTags/SetBlobMetadata/SetBlobExpiry/DeleteBlob/AbortCopyBlob` excluded from the write class; Defender being enabled alone does not suppress OAuth-only reads: `scannerCouldRun = (malwareScanning.onUpload.isEnabled ∧ sum(WRITE′ ∪ PutBlob-class) > 0 in Requested) ∨ sensitiveDataDiscovery.isEnabled`, with tri-state unknown propagation, never unknown-as-false; when Defender is enabled and `scannerCouldRun` is true, OAuth-only reads emit DESIGN_INTENT rather than LIVE read evidence (reads-only otherwise-clear input yields `tentative`); when false, normal read thresholds apply, preserving case59 `no`; unknown scanner configuration yields `tentative` absent other decisive evidence; independent qualifying writes, dependencies or blockers can still yield `no` (human-approved G5, docs/SPEC-RECONCILIATION.md §2); queue `GetMessageWrite` = strong READ, `GetMessageRead` = polling (LIVE at ≥1000/day on ≥3 days, else DESIGN_INTENT); SMB verbs classified per §3.4.
- Name knowledge base = `kb.yaml` from `research-3.md` §G with the six regex fixes from `architect-3.md` §3.6. Name-only matches never exceed DESIGN_INTENT; a match becomes HARD_DEPENDENCY only when the producer is confirmed in configuration (flow log / diagnostic setting / VM / function app exists) — Functions-host entries stay DESIGN_INTENT under Reader.
- Data-plane freshness (`y=/m=/d=/h=` prefix walk, ≤12 calls / 3 s per container, ≤5 containers) is opt-in `--data-plane`, OAuth only, never account keys, and degrades to `unknown(permission|network)` — never to "empty".

## 5. Cordon (binding)

- v0.1 implements exactly: storage `publicNetworkAccess` Enabled→Disabled; site `stop` (+ every slot, ≤4). Everything else prints `not-yet-supported` (VM, function-app-specific, public IP) or `not-applicable` (disk, NIC, NSG) with the wording in `architect-3.md` §4.3.
- Pre-flight order §6.1; state tag `azcid` v1 per the ABNF in §6.4 (no resource ids in the tag; ≤200 chars); state change first (LRO polled to terminal), tag second, GET-verify both, roll back on mismatch (Azure Policy Modify); refuse when already isolated/stopped or a foreign `azcid` exists; `checkPolicyRestrictions` with the **uncordon** body, Deny or Modify on the flipped field = refusal.
- `status` prints honest caveats (private endpoints and trusted Microsoft services stay open; storage denials may not be visible in `Transactions`). `uncordon` supports `--from-history` (local history file) and `--prior`.
- The VM strategy shown on the pitch deck (temporary deny-all NSG swapped onto the NIC, original association recorded, never editing existing rules) is the v0.2 design; do not implement in v0.1 unless items 1–7 of §2 are done and tested.

## 6. CLI / MCP / CI (binding)

- Commands: `check`, `cordon`, `uncordon`, `status`, `patterns list`, `demo`, `mcp`, `version`. Flags mirror Azure CLI: `--ids` (one or more ARM ids or portal URLs), `--subscription`, `-o json|jsonc|table|tsv|yaml|none`, `--query` (JMESPath, may be stubbed in v0.1), `--window`, `--data-plane`, `--only-show-errors`, `--debug`, `--yes`, `--exit-on-verdict`.
- Exit codes: 0 ok, 1 error, 2 usage, 3 resource not found, 4 nothing evaluable; with `--exit-on-verdict`: no→10, tentative→11. For multiple targets, aggregate severity no > tentative > yes and then map to 10/11/0, never numeric maximum; without the flag, completed assessments return 0. Error precedence is usage (2), then runtime/auth/transport preventing a completed assessment (1), then nothing evaluable (4), then not found (3), then verdict aggregation. Retain all individual outcomes; errors never become evidence (human-approved G3).
- JSON `schemaVersion: "2"` field list from `architect-3.md` §7.4; Azure-sourced free-form strings (including names, callers, tag keys/values and app-setting keys) appear only under `untrusted` after Cc/Cf/Cs/Co/Cn stripping, NFC normalization and a 128-rune total cap including any truncation marker, with no ASCII exemption. Canonically parsed ARM IDs, validated GUIDs, parsed UTC timestamps and tool-known enum/version values may appear only at schema/allowlist-defined typed paths (`docs/SPEC-RECONCILIATION.md` G2); they remain data, never instructions. Free-form typed display fields use tool-owned placeholders/references; summaries do not copy Azure free-form values. No URLs or app-setting values; MCP redacts tag values by default (human-approved G2).
- Portal URL parsing per `research-3.md` §E (formats, `/overview` and `/tags` suffix rule, child-resource preservation, tenant hint validation).
- MCP (`github.com/modelcontextprotocol/go-sdk` v1.8.0, stdio): tools `can_i_delete` and `cordon_status` **only**; read-only; tag values redacted by default; tool descriptions verbatim from `architect-3.md` §8.3 ("evidence, not permission; surface `tentative` to a human; never shrink the window to obtain a yes"); `humanEscalation` + `requiredHumanQuestion` on every tentative.
- CI: composite GitHub Action; ids from `terraform show -json` (`resource_changes[].change.actions` containing `delete`, incl. replacements, `before.id`) and `az stack group what-if … --no-pretty-print` (`properties.changes.resourceChanges[]` with `changeType ∈ {delete, detach}`; `unsupported` → tentative); `fail-on: no|tentative` (default `no`); never incremental ARM what-if.

## 7. Engineering (binding)

- Go 1.25, module `github.com/pawel-siwek/az-can-i-delete`, layout and interfaces from `architect-3.md` §10; SDK modules pinned to the versions in §10.4; api-versions in `rules.yaml` (§10.3); `kb.yaml` embedded; cobra CLI; errgroup limit 6 with per-signal timeouts → `unknown(timeout)`; ARG token bucket 15/5 s; ARG visibility probe first — zero rows with a successful ARM GET → every ARG signal `unknown(permission)`.
- Auth: `azidentity.DefaultAzureCredential` (handles Cloud Shell `MSI_ENDPOINT`) → `AzureCLICredential`; no account keys, no SAS, no managed-identity assumptions.
- Tests: table-driven `Decide()` suite (66 cases), `kb.yaml` examples/counterexamples, fixture replay (`--fixture`), golden JSON per demo scenario, `go vet` + `golangci-lint`. Fakes for all five client interfaces; no live Azure in CI.
- Build: `CGO_ENABLED=0`, goreleaser (linux/amd64 first, then arm64, darwin, windows), SHA-256 checksums, installer into `~/.local/bin` (on PATH in Cloud Shell), no `curl | sh` without a pinned version.
- Day-1 empirical tests (`architect-3.md` §11) run against the presenter's own subscription before trusting the corresponding rule; each has a documented rule flip if the result differs.

## 8. Honesty rules

- Never present fixture/replay output as live. `demo` prints `recorded` in the header.
- Never claim an analyzer is implemented before its Required set, tests and `not_evaluated` strings exist.
- Every `yes` carries the §12 limitations; the README repeats them.
- `Decide()` is pure: no network, no clock reads — the observation cutoff is an input.

## 9. Implementation order (3 working days)

Day 1: parser (ARM id + portal URL), `Decide()` v3 + 66 tests, evidence schema/JSON/table output, generic signals, storage analyzer (ARG reverse refs, ARM lists + `kb.yaml`, metrics R1–R10), disk analyzer, `demo` with recorded fixtures.
Day 2: NIC, public IP, NSG, VM, App Service/Functions analyzers; age chain; MCP read-only; fixture replay; install script.
Day 3: cordon (storage pna + site stop), `status`/`uncordon`, CI action, README with limitations, goreleaser, day-1 empirical tests, video/demo dry run.
Cut first if late: `--query`, Public IP metrics, VM cordon, App Insights fallback, `--data-plane`.
