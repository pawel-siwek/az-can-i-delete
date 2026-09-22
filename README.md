# az-can-i-delete

A single Go binary that answers one question about one Azure resource: **is
anything still using it?** It collects evidence, applies fixed rules and prints
a verdict with every signal it rests on.

A verdict is evidence, not permission. `yes` means *no evidence of use was
found by the signals this tool could evaluate* — never *safe to delete*. The
limitations below are printed with every `yes`, and they are the point of the
tool, not a disclaimer.

## What works today

| Area | State |
|---|---|
| `check` for managed disks (`Microsoft.Compute/disks`) | full analyzer: attachment, owner, active export, backups, Kubernetes volumes, Site Recovery replicas, images, provenance, detachment age, Advisor, I/O counters |
| `check` for network interfaces, public IP addresses and network security groups | full analyzers: owners and associations (including a zero-instance scale set's network model), backend pools, NAT gateways, flow logs and their storage sinks, platform-owned groups, static addresses and domain labels, traffic counters, and the 30-day detachment age |
| `check` for storage accounts | full analyzer: immutability holds, private endpoints, resource-instance rules, replication and Event Grid, boot diagnostics, flow logs, backups, extensions and other references, the four child listings, leases, and the transaction, egress and object-count rules including the Defender scanner carve-out |
| `check` for virtual machines | full analyzer: scale set, availability set, reservation and host membership, platform ownership, backups and retained recovery points, Site Recovery, images, network references and backend pools, identity roles, power state, start events, and the processor, connection and traffic rules |
| `check` for App Service sites, slots and plans | full analyzers: custom domains, fronting, hybrid connections, virtual network integration, source control and deployments, function triggers, the request-ceiling and probe-shape rules, hosting class, stopped state, metric silence, and for plans the site count, autoscale and Advisor |
| Output | `table` (default at a terminal), `json`, `jsonc`, `yaml`, `tsv`, `none` |
| `cordon`, `uncordon`, `status`, `demo`, `mcp`, `patterns list`, `--fixture`, `--data-plane`, `--query` | not implemented; they exit 1 and say so |

`IMPLEMENTATION-PLAN.md` has the full status and the order the rest is built in.

## Build and run

```sh
CGO_ENABLED=0 go build -o ~/.local/bin/az-can-i-delete ./cmd/az-can-i-delete
az-can-i-delete check /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Compute/disks/<disk>
```

Targets may be ARM ids or Azure portal URLs, given positionally or with
`--ids` (space-delimited or repeated).

```sh
az-can-i-delete check --ids <id1> <id2> --window 60d -o json
az-can-i-delete check <id> --exit-on-verdict     # no → 10, tentative → 11, yes → 0
```

Useful flags: `--window` (7–93 days, default 30), `--subscription` (asserts the
target's subscription), `-o/--output`, `--redact-tags`, `--exit-on-verdict`.

## Authentication and permissions

Credentials come from `DefaultAzureCredential`, falling back to the Azure CLI
credential: `az login` is enough, and Cloud Shell works through its managed
identity endpoint. The tool never asks for, reads or accepts an account key or
a shared access signature.

**Reader at subscription scope** is what it expects. Reader on the resource
alone is not enough: without subscription-scope Reader the target is invisible
in Resource Graph, every graph-backed signal becomes `unknown(permission)`, and
the verdict cannot be `yes`. The report says so rather than reporting silence.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the assessment completed |
| 1 | a runtime, authentication or transport failure, or an unsupported resource type |
| 2 | invalid usage |
| 3 | the resource was not found |
| 4 | nothing was evaluable |
| 10 / 11 | with `--exit-on-verdict`: `no` / `tentative` |

For several targets the most severe outcome decides, and an error never becomes
evidence: targets that completed are still printed.

## How to read the output

* **verdict** — `yes`, `no` or `tentative`, with its reason class.
* **coverage** — how many signals were evaluated, how many are unknown, and how
  many of those are critical. A critical unknown is marked `!` and is what
  keeps a `yes` out of reach.
* **Evidence** — every signal, at its tier, with what was found. Tiers run
  `BLOCKER → HARD_DEPENDENCY → LIVE_ACTIVITY → DESIGN_INTENT → OBSERVED_IDLE →
  INFO`; the first tier with something present decides the verdict.
* **not_evaluated** — a check this version does not perform, with the
  consequence and the command to run yourself.

## Limitations, printed with every `yes`

1. `yes` means "no evidence of use was found by the signals this tool could evaluate", never "safe to delete". Consumers that reference a resource only through application settings, Key Vault secrets, source code, pipelines, Terraform state or on-premises configuration are not detectable.
2. Resources with unknown or inferred-only age, or an effective observation window shorter than 30 days, cannot be reported `yes`. A moved resource may qualify only when the age chain establishes a verified or bounded lower age bound of at least 30 days and every Required signal is present; evidence from an earlier deleted incarnation is discarded.
3. Only Azure public cloud is supported. v0.1 analyzes storage accounts, managed disks, network interfaces, public IP addresses, network security groups, virtual machines, App Service web apps and Function Apps, their slots, and App Service plans. VNet and Container Apps, jobs and environments are extended research, not v0.1 analyzers. Unsupported analyzer types return an error.
4. Linux Function Apps on Consumption, Premium and Dedicated plans have no execution metrics in Azure Monitor under the current rules. Missing execution evidence prevents `yes`; positive blockers, dependencies or supported live activity can still produce `no`. Flex Consumption and Windows counters are evaluated using their hosting-class rules. These platform claims remain subject to the documented empirical tests.
5. Defender for Storage scanner reads cannot be separated from other Entra-authenticated reads using these metrics alone. OAuth-only reads produce design intent rather than live-read evidence only when the configured scanner could have run under the rule's on-upload or sensitive-data-discovery conditions. Independent writes, dependencies or other positive evidence can still produce `no`.
6. App Service scanner and probe traffic may be indistinguishable from real users. The configured ceilings and probe-shape rules may produce `tentative`; network reachability is reported but is not an additional `yes` gate. `yes` still requires the complete tiered rules and all Required silence signals, including the metrics-silence or stopped-for-at-least-30-days alternative.
7. Storage data-plane freshness is opt-in (`--data-plane`), OAuth-only and bounded; a prefix sample does not prove the entire account is inactive. Without it, silence is inferred from metrics and object counts. Permission and network failures remain unknown. NFS operation classification remains unverified/unsupported under the documented rule.
8. SAS-authenticated use is observed (`Authentication = SAS` in metrics) but SAS holders cannot be enumerated; a token issued before the window may still be in someone's hands.
9. Reverse references are found through Azure Resource Graph in the target's subscription only; consumers in other subscriptions or tenants (private endpoints excepted) are not seen. The caller needs Reader at subscription scope.
10. Activity Log covers 90 days and Resource Graph changes 14 days; anything older is invisible to those sources. A `no` from live metrics is positive evidence under the configured rules; a `yes` only covers the effective window printed.
11. Cordon (scream test) is available for storage accounts (public network access) and App Service sites (stop) only. It does not block private endpoints, resource-instance rules or trusted Azure services, and denied requests may not appear in metrics. Infrastructure-as-code applies can revert it.
12. The MCP server cannot change Azure state; it exposes `can_i_delete` and `cordon_status` only.

Limitations 4 to 7, 11 and 12 describe parts of the specification that are not
implemented yet; they are printed because the rules they belong to are part of
the verdict model, and `IMPLEMENTATION-PLAN.md` says what exists today.

## Development

```sh
go test ./...        # no test reaches Azure
go vet ./...
golangci-lint run ./...
```

`REQUIREMENTS.md` and `docs/SPEC.md` are the normative documents, in that
order. The 66-case acceptance table of `docs/SPEC.md` appendix B is the test
suite for the verdict rules and must stay green before any analyzer work.
