# ADR-0007: Azure free-form text is untrusted input

- Status: accepted
- Date: 2026-09-21
- Source: REQUIREMENTS.md section 6, docs/SPEC.md section 5

## Context

Resource names, tag keys and values, caller identities and deployment names
are written by whoever created the resource. The report is read by humans in
a terminal and by agents over MCP. Free-form text placed into a summary line
is an instruction-injection channel aimed at the agent that asked the
question.

## Decision

Azure-sourced free-form strings appear only under the `untrusted` section of
the report, after control-character stripping (Cc/Cf/Cs/Co/Cn), NFC
normalization and a 128-rune cap including any truncation marker, with no
ASCII exemption. Summaries and display fields use tool-owned text and
references, never copied Azure values. Canonically parsed ARM IDs, validated
GUIDs, parsed UTC timestamps and tool-known enum values may appear at
schema-defined typed paths; they remain data, never instructions. No URLs.
MCP redacts tag values by default.

## Consequences

The output layer has a policy that rejects a report rather than printing
something unvetted, so new signals occasionally fail the boundary until
their wording is fixed. That failure is the mechanism working.

## Enforcement

`internal/output` policy plus `TestASCIIOnlyUnderUntrusted`,
`TestUnicodeCategoryCorpus`, `TestAllFormatLeakageCorpus`,
`TestMalformedInputNeverBecomesReport`, and
`TestEverySignalPolicyIsPublishable` in `internal/assess`, which asserts
every catalogued signal's wording can actually be published.
