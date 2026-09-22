---
applyTo: "internal/output/**,internal/cli/**,cmd/**"
---

# The output boundary

Everything Azure wrote is untrusted. Resource names, tag keys and values,
caller identities, deployment names and app-setting keys reach the report only
under `untrusted`, after Cc/Cf/Cs/Co/Cn stripping, NFC normalization and the
128-rune cap including any truncation marker — no ASCII exemption. A free-form
Azure string copied into a summary, a display field or a log line is a
blocking finding: the report is read by agents, and that is an injection
channel aimed at them (ADR-0007).

No secret, token, connection string, SAS or app-setting value is collected,
printed or logged, under any flag (ADR-0006).

Every `yes` carries the approved limitations from `docs/SPEC.md` section 5.1,
verbatim, and the README repeats them. A diff that edits either copy without
the other breaks a test, and should.

The report says what was not evaluated and why: `unknowns[]`,
`notEvaluated[]` with `{id, reason, consequence, howToCheck}`, and `coverage`.
Dropping an entry to tidy the output removes the reader's ability to see what
the verdict did not cover.

Exit codes are a contract: 0 ok, 1 error, 2 usage, 3 not found, 4 nothing
evaluable, and with `--exit-on-verdict` no→10, tentative→11, aggregated by
severity and never by numeric maximum.

A command that is not implemented says so and exits 1. Silently ignoring a
flag is worse than refusing it.
