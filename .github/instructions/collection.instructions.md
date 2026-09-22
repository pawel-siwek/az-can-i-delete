---
applyTo: "internal/collect/**,internal/azure/**,internal/generic/**,internal/signal/**,internal/disk/**,internal/network/**,internal/storage/**,internal/vm/**,internal/site/**,internal/rules/**"
---

# Collection and the analyzers

A failure is never an absence. Every signal this layer cannot read is
`unknown(reason)` — `permission`, `timeout`, `network`, `throttled`,
`unsupported` — and the reason travels to the output. An error path that ends
in `absent`, an empty slice, a zero count or a `false` is a blocking finding,
and it is the single most likely bug in a diff here (ADR-0004).

Resource Graph is probed before it is trusted: zero rows alongside a
successful ARM GET means every ARG signal is `unknown(permission)`, never
"nothing references this".

Analyzers depend on the five interfaces in `internal/collect`, never on the
Azure SDK directly, so every one of them is testable with the fakes in
`collecttest` and no test needs a subscription (ADR-0010).

Api-versions come from `internal/rules`. A literal version at a call site, or
a second copy of a pin in a constant, is a blocking finding even when the two
agree today — they drift, and then a signal is collected under one version and
reported under another (ADR-0008).

Retries and rate limiting belong to `internal/collect` and nowhere else: the
concurrency limit of 6, the ARG bucket of 15 per 5 seconds, 20 seconds per
call, 60 per run, at most 3 retries honouring `Retry-After`. An SDK client
configured to retry on its own hides time from the budget and multiplies load
on the subscription being inspected (ADR-0009).

Assessment reads. A write, a delete, an LRO that mutates, or a `listKeys` call
does not belong in this path at all (ADR-0005, ADR-0006).
