#!/usr/bin/env bash
# Apply the fail policy and write the summary (SPEC appendix E section 9.3).
#
#   policy.sh <out-dir>
#
# Reads <out-dir>/changes.tsv, unsupported.txt, skipped and, when any id was
# checked, results.json. FAIL_ON is `no` or `tentative`; TOOL_EXIT is the
# check's exit code. Writes <out-dir>/verdict, summary.md and planned.tsv (the
# planned ids in table order), prints
# a warning per tentative resource, and exits 1 when the policy fails.
#
# An error never passes: a check that did not complete fails the job whatever
# FAIL_ON says, because a deletion nobody could assess is not a deletion that
# was assessed and found safe.
set -euo pipefail

out="${1:?usage: policy.sh <out-dir>}"
FAIL_ON="${FAIL_ON:-no}"
TOOL_EXIT="${TOOL_EXIT:-0}"
case "$FAIL_ON" in
  no|tentative) ;;
  *) echo "::error::fail-on must be no or tentative" >&2; exit 1 ;;
esac

results='[]'
if [ -s "$out/results.json" ]; then
  results=$(jq -c 'if type == "array" then . else [.] end' "$out/results.json")
fi
skipped=$(cat "$out/skipped" 2>/dev/null || echo 0)

jq -n \
  --rawfile changes "$out/changes.tsv" \
  --rawfile unsupported "$out/unsupported.txt" \
  --argjson results "$results" \
  --arg failOn "$FAIL_ON" \
  --arg skipped "$skipped" \
  --argjson toolExit "$TOOL_EXIT" '
  def esc: tostring | gsub("\\|"; "\\|") | gsub("[\r\n]+"; " ");
  # A row is named by what the tool parsed: the report'"'"'s canonical resourceId
  # and resourceType. An id straight from the plan is somebody'"'"'s text and is
  # never printed; a row without a report is named by its number, and the
  # plan'"'"'s ids are in the results artifact (ADR-0007).
  def cell: tostring | gsub("[`|\r\n]"; "");
  def rank: {"no": 3, "error": 4, "tentative": 2, "yes": 1}[.] // 0;

  ($changes | split("\n") | map(select(length > 0) | split("\t") | {id: .[0], change: .[1]})) as $rows
  | ($unsupported | split("\n") | map(select(length > 0))) as $uns
  | [ range(0; $rows | length) as $i
      | $rows[$i] as $row | ($results[$i] // null) as $r
      | if $r == null then
          $row + {verdict: "error", policy: "error", reason: "no result", evidence: "", unknowns: ""}
        elif ($r.error // null) != null then
          if $r.error.code == "not-found" then
            $row + {verdict: "not found", policy: "yes", reason: "not-found", evidence: "", unknowns: ""}
          else
            $row + {verdict: "error", policy: "error", reason: ($r.error.code | esc), evidence: "", unknowns: ""}
          end
        else
          $row + {resourceId: $r.resourceId, resourceType: $r.resourceType,
                  verdict: $r.verdict, policy: $r.verdict, reason: ($r.reasonClass // ""),
                  evidence: ([$r.evidence[]? | select(.status == "present")] | sort_by(.tier) | .[0:2] | map(.summary | esc) | join("; ")),
                  unknowns: ([$r.unknowns[]?] | length | tostring),
                  window: $r.window.requested, rulesDate: $r.rulesDate}
        end ]
    + [ $uns[] | {id: ., change: "unsupported", verdict: "tentative", policy: "tentative",
                  reason: "unsupported", evidence: "the what-if could not evaluate this change", unknowns: ""} ]
  | . as $all
  | (if ($all | length) == 0 then "none" else ($all | map(.policy) | max_by(rank)) end) as $worst
  | ([$all[] | select(.policy == "error")] | length > 0 or ([2, 1, 4] | index($toolExit)) != null) as $errored
  | ([$all[] | select(.policy == "no")] | length > 0) as $anyNo
  | ([$all[] | select(.policy == "tentative")] | length > 0) as $anyTentative
  | ([$all[] | select(.window != null)] | first // {}) as $first
  | {
      verdict: (if $worst == "error" then "error" else $worst end),
      fail: ($errored or $anyNo or ($failOn == "tentative" and $anyTentative)),
      planned: [$all[] | "\(.id)\t\(.change)"],
      warnings: [range(0; $all | length) as $i | select($all[$i].policy == "tentative")
                 | "az-can-i-delete: planned deletion #\($i + 1) is tentative: ask a human before this deletion"],
      summary: (
        if ($all | length) == 0 then
          "### az-can-i-delete — no planned deletions\n\nNothing in this plan deletes an Azure resource. Skipped non-ARM ids: \($skipped).\n"
        else
          "### az-can-i-delete — pre-flight for \($all | length) planned deletions\n"
          + "| resource | change | verdict | reason | top evidence | unknowns |\n|---|---|---|---|---|---|\n"
          + ([range(0; $all | length) as $i | $all[$i]
              | (if .resourceId then "`\(.resourceId | cell)`" else "#\($i + 1) (row \($i + 1) of planned.tsv)" end) as $name
              | "| \($name) | \(.change) | \(if .policy == "no" then "**no**" else .verdict end) | \(.reason) | \(.evidence) | \(.unknowns) |"]
             | join("\n"))
          + "\n"
          + (if $first.window then
               "Window \($first.window.start[0:10]) → \($first.window.end[0:10]) (\($first.window.days) d) · rules \($first.rulesDate) · "
             else "" end)
          + "fail-on: \($failOn) · skipped non-ARM ids: \($skipped) · planned ids in planned.tsv beside results.json\n"
          + "\nA verdict is evidence, not permission: `yes` means no evidence of use was found by the signals this tool could evaluate, never that deleting is safe.\n"
        end)
    }' > "$out/policy.json"

jq -r '.verdict' "$out/policy.json" > "$out/verdict"
jq -r '.summary' "$out/policy.json" > "$out/summary.md"
jq -r '.planned[]' "$out/policy.json" > "$out/planned.tsv"
jq -r '.warnings[] | "::warning::" + .' "$out/policy.json"
if [ "$(jq -r '.fail' "$out/policy.json")" = "true" ]; then
  exit 1
fi
