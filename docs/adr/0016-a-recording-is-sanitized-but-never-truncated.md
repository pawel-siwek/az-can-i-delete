# ADR-0016: A recording is sanitized but never truncated

- Status: accepted
- Date: 2026-09-23
- Source: docs/adr/0007, docs/SPEC.md section 7.5

## Context

ADR-0007 governs Azure free-form text reaching a report: control, format,
surrogate, private-use and unassigned runes removed, NFC normalization, and a
128-rune cap. SPEC 7.5 binds the fixture recorder to the same contract by
naming `untrusted()`.

A recording is not a report, and one of those three requirements does not
survive the move. A report is read by a person, where a long value is noise
and cutting it loses nothing that matters. A fixture is replayed through the
collectors, the analyzers and the verdict rules: a resource id cut at 128
runes is no longer a resource id, the ARM parser rejects it, and the replay
reports a failure Azure never produced. The cap would not weaken a recording,
it would falsify one.

The first attempt at this reasoned it out in a code comment and then edited
SPEC 7.5 so the document agreed with the code. That is the move this
repository exists to prevent, and it was caught by the reviewer rather than
by any test. What it hid was not only the truncation: the same commit shipped
a hand-written sanitizer that stripped C0 and C1 controls, surrogates and
invalid UTF-8, and let format characters through. A right-to-left override in
a committed fixture makes `invoice<U+202E>gpj.exe` read as `invoice.jpg` to
everybody reviewing it.

Two rules that are almost the same are worse than one rule and an exception.
The narrower one drifts, and the drift is invisible because both look
correct.

## Decision

The recorder applies ADR-0007's character contract by calling its
implementation, not by restating it. `output.Sanitized` is that
implementation; the recorder holds no rules of its own, and a test asserts
the two agree rune for rune.

It does not truncate. That is the only difference, it is bounded to this one
boundary, and it exists because a fixture is executed rather than read.

Fields under `tags`, `caller` and `claims` keep their shape and lose their
contents, as SPEC 7.5 already required. Response headers are kept for the
names a replay reads and dropped otherwise, because the rest identify one
call in one tenant on one day.

## Consequences

A recorded string can be arbitrarily long, so a fixture can carry more Azure
text than a report ever would. That text has still passed the same character
filter, so what it cannot carry is the part that acts on a reader rather than
informing one.

Tabs and newlines go, because ADR-0007 removes them and this record takes no
second exception. A recorded value that depended on an embedded newline would
be altered, and no fixture here has one; if that ever bites, it is a new
record, not a quiet widening of this one.

Sharing the implementation couples `internal/replay` to `internal/output`.
That is the point. The alternative was two copies of "which Unicode
categories are not text", and the copy nobody is reading is the one that
rots.

## Enforcement

`internal/replay` tests that a control character, a format character and a
per-call header do not survive a recording, and that a value longer than 128
runes does. `TestTheRecorderAndTheBoundaryAgreeOnWhatTextIs` compares the
recorder's output to `output.Sanitized` over a corpus, so a future
divergence fails rather than drifts.
