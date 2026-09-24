# What the live runs found, and what changed because of them

Every test in this repository runs without Azure. That proves the code does
what the specification says. It cannot prove that the specification is right
about Azure. On 2026-09-24 the tool was run for the first time against a live
subscription, five times, with a script that:

- can build the binary from `main` instead of using a release;
- creates scratch resources (a storage account, an App Service plan and site,
  and an NSG);
- checks them and a few long-lived resources;
- runs the full cordon, status and uncordon cycle on the storage account and
  on the site;
- runs the day-1 probes that need no waiting (`docs/day1.md`).

The first run used the v0.4.0 release. The second failed to build from
source (a script fault, fixed) and so tested v0.4.0 again. The third, fourth
and fifth were built from `main`, each after the previous findings were
merged, and passed all 54 of their checks. Passing was not the finding. The
findings were in what the reports said, and each one below was invisible to
every test that existed at the time. Findings 1 and 2 came from a manual
`cordon` and `status` in Cloud Shell just before the first scripted run.

Each entry names what the run showed, what was wrong, what changed, and why
this change and not another. The specification text each one changed is in
SPEC section 11, "Outcomes recorded so far".

## 1. The cordon plan printed `tag: azcid=(URL omitted)`

- **Run:** the manual `cordon` (v0.4.0).
- **What was wrong:** the plan passed the whole tag through the filter for
  untrusted Azure text. The timestamp in the tag (`t=2026-09-24T08:19:16Z`)
  contains `T08:`, which the filter reads as a URL scheme, so it replaced the
  tag with `(URL omitted)`.
- **What changed (#31):** the plan prints the tag as a field of its own. The
  only parts of the tag someone else chose, the slot names, are shown by
  reference (`slot1`, …) and listed under `untrusted`.
- **Why:** the tag is this tool's own grammar, not Azure text. Running it
  through the filter protected nothing and hid what the tool was about to
  write. Slot names are still user-chosen, so they stay under `untrusted`
  (ADR-0007).

## 2. `status` reported `the request was rejected` for both cordon counters

- **Run:** the manual `status` right after that cordon.
- **What was wrong:** `status` asked Azure Monitor for hourly buckets over a
  window a few seconds long. Azure rejects a timespan shorter than its
  interval.
- **What changed (#31):** `status` asks only for whole hours, from the first
  hour after the cordon to the last hour that has ended. When no such hour
  exists yet, it sends no query and says when the first total can be read.
- **Why:** the hour the cordon was applied holds the tool's own writes and is
  excluded anyway (SPEC §6.5), so whole hours lose nothing. Saying "readable
  after 22:00Z" is true; a 400 reported as `unknown` was honest but useless.

## 3. Every storage metric signal was `unknown(transient)`

- **Run:** first run; confirmed by day-1 probe H1.
- **What was wrong:** the storage analyzer's main metrics call (M1) asked for
  `orderby=sum desc`. Azure refuses it: `Detected invalid Aggregation type:
  sum`.
- **What changed (#32):** M1 now uses `orderby=Total desc`, which Azure
  accepts with `top=200` and `top=1000`.
- **Why:** because of this, a storage account could never reach `yes` or a
  metric-based `no`. The unknowns were honest (ADR-0004), but the analyzer was
  blind. The runbook had predicted this exact outcome for H1.

## 4. Every Activity Log signal was `unknown(transient)`

- **Run:** first run.
- **What was wrong:** the history query went back 90 days from the cutoff,
  which is today at 00:00Z. Azure keeps the log for 90 days before *now* and
  refuses a query that starts earlier, and that window starts up to a day
  past the edge. The cordon pre-flight uses the same query shape over 30 days,
  and in the same run it succeeded. That isolated the cause.
- **What changed (#32):** the window is the 89 whole days before the cutoff.
  The write-history signal and age source 6 follow it.
- **Why not keep 90 and quietly start the query later?** That would claim
  coverage of a day Azure no longer holds, which is the failure-as-absence
  error ADR-0004 exists to prevent. 89 whole days is the longest complete log
  that ends at the cutoff.

## 5. Resources created minutes earlier were reported as ≥ 89 days old

- **Run:** third run, the first built from `main`.
- **What was wrong:** age source 6 reads "a complete log with zero events" as
  "at least as old as the log". The log ends at the cutoff, so a resource
  created this morning also has zero events in it.
- **What changed (#33):** source 6 is unavailable when anything dates the
  resource after the cutoff: its creation time, a Resource Changes create, an
  Activity Log event or a deployment.
- **Why:** the verdict was `tentative` before and after, because inferred age
  never allows `yes`. But the report printed a false age, and the storage
  silence signal claimed 30 quiet days for an account that was minutes old.

## 6. One slow call made nine site signals `unknown(timeout)`

- **Run:** third run, the first site ever checked live.
- **What was wrong:** nine configuration signals were read one after another
  under a single 20-second call budget. One slow sub-resource on a fresh F1
  site used it all up.
- **What changed (#33):** each sub-resource read is its own call with its own
  budget: configuration, hybrid connections, slots, source control,
  deployments and web tests.
- **Why:** the budget is meant per call (ADR-0009). Sharing it meant one slow
  call erased unrelated evidence. Since the change, only the slow call's own
  signal (`site.ci.active` on a fresh site) is `unknown`.

## 7. A resource created today had an `unknown` age despite `createdAt`

- **Run:** fourth run.
- **What was wrong:** the age chain set aside any timestamp later than the
  cutoff, so `systemData.createdAt` from this afternoon was discarded.
- **What changed (#34):** a creation time after the cutoff is a verified age
  of zero days. ADR-0003 now says the cutoff is a reference point, not a
  filter.
- **Why:** the resource provider says exactly when the resource was created.
  The verdict stays `tentative`, now for `window.too-short-for-yes`, which
  says why, instead of `age.unknown`, which suggested a read had failed.

## 8. Sites, plans and NSGs still had no age source

- **Run:** fifth run.
- **What was wrong:** a GET of a site, a plan or a network resource returns no
  `systemData`. With nothing in the Activity Log yet, such a resource had no
  age source at all.
- **What changed (this change):** when the GET has no creation time, source 1
  asks ARM's resource list with `$expand=createdTime`. That list answers for
  every resource type. The call's api-version is pinned in `rules.yaml` as
  `resources`.
- **Why:** it is ARM's own record of the creation, as reliable as `systemData`
  and available for every type. A failed call, a list that does not return
  the resource or its creation time, or a value that cannot be parsed, is not
  treated as "ARM has none": the resource was just read, so ARM has not
  answered. Like a failed change history, it
  marks the history incomplete, so source 6 cannot call a resource that may
  be minutes old at least 89 days old. The review bot caught the first two
  drafts of this: one dropped the error, the next still read a list without
  the resource as "none" (ADR-0004).

## 9. A resource created minutes earlier was reported as a permission problem

- **Run:** fifth run.
- **What was wrong:** a storage account checked minutes after it was created
  was not yet in Resource Graph. Eight graph-backed signals said the caller
  could not read them, with the advice to grant Reader. Its permissions were
  fine; the fourth run, with the same caller, had seen the same kind of
  account.
- **What changed (this change):** the reason names both causes: the caller
  lacks Reader at subscription scope, or Resource Graph has not indexed the
  resource yet. For a resource created since the cutoff, it names the
  indexing delay first.
- **Why keep the code `permission`?** SPEC §3.1 maps a readable resource with
  no graph row to `unknown(permission)`. The signals stay `unknown` (ADR-0004);
  what changed is that the advice is no longer wrong.

## What the runs confirmed without a change

- **H7:** a storage account, a plan and a site created by CLI write no
  `Created` marker in the Activity Log. The age chain already falls through
  to its next source.
- **H11:** the tool's own listing calls (`ListContainers`, `ListShares`,
  `ListQueues`, `QueryTables`) do appear in `Transactions`. They are in the
  ENUMERATE class, which is not activity, so they cannot make an idle account
  look used.
- **Verdicts on long-lived resources were right:**
  - a storage account with three private endpoints and seven references came
    out `no / in-use`;
  - a Terraform state account came out `tentative / design-intent`;
  - a Cloud Shell home account came out `no / in-use`;
  - a private-endpoint NIC and a NAT gateway's public IP came out
    `no / blocked`;
  - a plan with a site came out `no / blocked`.
- **Cordon and uncordon** worked end to end on a storage account and on a
  site. The state was restored and the tag was removed both times.
