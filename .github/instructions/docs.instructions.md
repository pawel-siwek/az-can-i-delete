---
applyTo: "docs/adr/**,IMPLEMENTATION-PLAN.md,README.md"
---

# Records and status documents

A decision record is never edited to match new code. Reversing a decision
means a new record that supersedes the old one, and the old one's status
becomes `superseded by ADR-NNNN`. Editing a record's Decision section so that
the diff stops contradicting it is the thing this whole arrangement exists to
prevent.

Every record carries Status, Context, Decision, Consequences and Enforcement,
and Enforcement names the test or the code that makes it real. A record whose
Enforcement names something that no longer exists is a finding.

`IMPLEMENTATION-PLAN.md` and `README.md` are status documents: no entry may
claim a component exists before its tests do. A diff that marks something
complete, or describes a command as working, while the code shows a stub or a
`not implemented` exit, is a blocking finding — this project's whole claim is
that it does not overstate what it knows.
