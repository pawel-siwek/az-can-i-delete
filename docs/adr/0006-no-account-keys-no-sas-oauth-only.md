# ADR-0006: No account keys, no SAS, no secret ever leaves a run

- Status: accepted
- Date: 2026-09-21
- Source: REQUIREMENTS.md sections 4 and 7, docs/SPEC.md section 1

## Context

The obvious way to read a storage container is to call `listKeys` and use
the key. It is also the way a read-only diagnostic tool turns into a
credential-harvesting tool, and the reason it would never be approved for a
production subscription.

## Decision

Authentication is `DefaultAzureCredential` (which covers Cloud Shell's
`MSI_ENDPOINT`) falling back to `AzureCLICredential`. The tool never calls
`listKeys`, never mints or accepts a SAS token, and never assumes a managed
identity it was not given. Optional data-plane reads are OAuth only and
degrade to `unknown(permission)` rather than acquiring a key.

No secret, token, connection string or app-setting value is collected,
printed, logged or placed in the report. App-setting *keys* may be
evidence; their values are never read.

## Consequences

Some questions cannot be answered with Reader alone, and the tool says so
instead of escalating itself. Data-plane freshness stays opt-in.

## Enforcement

No `listKeys` call exists in `internal/`. `TestRedactionAndSettingValueSmuggling` in `internal/output`
asserts that setting values cannot reach the report.
