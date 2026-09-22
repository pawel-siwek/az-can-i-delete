# ADR-0005: Assessment is read-only; cordon is a separate, reversible act

- Status: accepted
- Date: 2026-09-21
- Source: REQUIREMENTS.md sections 1 and 5, docs/SPEC.md section 1.2

## Context

A tool that both judges and mutates will eventually be trusted to do both in
one step. The verdict would become the authorization for the change it then
performs, with no human in between.

## Decision

`check` performs reads only. State changes live in `cordon`/`uncordon`,
which are separately invoked, separately confirmed, reversible, and never
delete anything. A verdict never becomes permission: `yes` means no evidence
of use was found within the evaluated scope and window, not that deleting is
safe or approved.

The MCP surface exposes `can_i_delete` and `cordon_status` only. No mutation
is reachable by an agent.

## Consequences

An agent that wants a resource gone still has to bring a human. The cordon
path carries its own pre-flight, verification and rollback because it is the
only place that writes.

## Enforcement

The `check` path uses read-only client methods; `internal/azure` adapters
for assessment expose no write operation. The MCP server registers exactly
two read-only tools.
