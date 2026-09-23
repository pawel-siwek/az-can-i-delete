#!/usr/bin/env bash
# Extract the ARM ids a deployment plans to delete (SPEC appendix E section 9.2).
#
#   extract.sh <out-dir>
#
# Reads any of RESOURCE_IDS (newline-separated), TF_PLAN_JSON,
# STACK_WHATIF_JSON and ARM_WHATIF_JSON, and writes into <out-dir>:
#
#   changes.tsv      id<TAB>change, one row per distinct id, lower-cased
#   ids.txt          the ids to check, one per line
#   unsupported.txt  stack what-if rows the what-if could not evaluate
#   skipped          the count of Terraform deletions that are not ARM ids
#
# The jq filters are the specification's, with one change: `// ""` before each
# ascii_downcase, because a row without changeCertainty (an unsupported one,
# for instance) made the verbatim filter abort the whole extraction. Incremental ARM what-if is
# never read: it does not report deletions, so an empty answer from it would
# be an absence nobody observed.
set -euo pipefail

out="${1:?usage: extract.sh <out-dir>}"
# Inputs are paths relative to the workspace; they are resolved before this
# script moves into its own directory.
absolute() { case "$1" in ""|/*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }
TF_PLAN_JSON=$(absolute "${TF_PLAN_JSON:-}")
STACK_WHATIF_JSON=$(absolute "${STACK_WHATIF_JSON:-}")
ARM_WHATIF_JSON=$(absolute "${ARM_WHATIF_JSON:-}")
mkdir -p "$out"
cd "$out"
: > raw.tsv
: > unsupported.txt
: > potential.txt
: > detach.txt
SKIPPED=0

if [ -n "${RESOURCE_IDS:-}" ]; then
  printf '%s\n' "$RESOURCE_IDS" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^$/d' |
    while IFS= read -r id; do printf '%s\tdelete\n' "$id"; done >> raw.tsv
fi

if [ -n "${STACK_WHATIF_JSON:-}" ]; then
  # Deployment stacks what-if (api-version 2025-07-01); the CLI must run with --no-pretty-print or it returns nothing
  jq -r '.properties.changes.resourceChanges[]? | select(.id != null)
         | select((.changeType // "" | ascii_downcase) as $c | $c == "delete" or $c == "detach") | .id' "$STACK_WHATIF_JSON" > stack-ids.txt
  jq -r '.properties.changes.resourceChanges[]? | select(.id != null and (.changeType // "" | ascii_downcase) == "unsupported") | .id' "$STACK_WHATIF_JSON" > unsupported.txt
  jq -r '.properties.changes.resourceChanges[]? | select(.id != null and (.changeCertainty // "" | ascii_downcase) == "potential") | .id' "$STACK_WHATIF_JSON" > potential.txt
  jq -r '.properties.changes.resourceChanges[]? | select(.id != null and (.changeType // "" | ascii_downcase) == "detach") | .id' "$STACK_WHATIF_JSON" > detach.txt
  while IFS= read -r id; do
    change=delete
    if grep -qixF -- "$id" detach.txt; then change=detach; fi
    if grep -qixF -- "$id" potential.txt; then change="$change (potential)"; fi
    printf '%s\t%s\n' "$id" "$change" >> raw.tsv
  done < stack-ids.txt
fi

if [ -n "${ARM_WHATIF_JSON:-}" ]; then
  # ARM complete-mode what-if (flattened WhatIfOperationResult; Pascal-case changeType)
  jq -r '.changes[]? | select(.changeType == "Delete") | .resourceId' "$ARM_WHATIF_JSON" |
    while IFS= read -r id; do printf '%s\tdelete\n' "$id"; done >> raw.tsv
fi

if [ -n "${TF_PLAN_JSON:-}" ]; then
  # Terraform: deletes and replacements; managed resources only; non-ARM ids counted as skipped
  jq -r '.resource_changes[]? | select(.mode == "managed") | select(.change.actions | index("delete")) | .change.before.id // empty' "$TF_PLAN_JSON" > tf-all.txt
  grep -E '^/subscriptions/' tf-all.txt > tf-ids.txt || true; SKIPPED=$(grep -cvE '^/subscriptions/' tf-all.txt || true)
  while IFS= read -r id; do printf '%s\tdelete\n' "$id"; done < tf-ids.txt >> raw.tsv
fi

# Lower-case and dedupe. The first source to name an id decides its change.
awk -F '\t' '{ id = tolower($1) } !(id in seen) { seen[id] = 1; print id "\t" $2 }' raw.tsv > changes.tsv
# An id the what-if could not evaluate is reported as unsupported, not checked
# as if it were a plain deletion.
awk '{ print tolower($0) }' unsupported.txt | sort -u > unsupported.lower
awk -F '\t' 'FILENAME == ARGV[1] { skip[$0] = 1; next } !($1 in skip)' unsupported.lower changes.tsv > changes.keep
mv changes.keep changes.tsv
cut -f1 changes.tsv > ids.txt
mv unsupported.lower unsupported.txt
printf '%s\n' "${SKIPPED:-0}" > skipped
