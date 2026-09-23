# ADR-0014: Nothing this project tells you to run arrives unread

- Status: accepted
- Date: 2026-09-23
- Supersedes: ADR-0011
- Source: REQUIREMENTS.md section 7

## Context

ADR-0011 said the installer names a version and verifies what it fetched, and
that held: `scripts/install.sh` refuses without an explicit tag and checks the
archive's SHA-256 before anything reaches a PATH.

It left two holes, and both were walked into.

The installer itself arrived unverified. The documented line piped it out of a
raw GitHub URL straight into a shell, so the thing doing the verifying was the
one thing nobody checked. That moves the trust; it does not establish it. A
pipe is also the one form where a truncated download still executes whatever
arrived, because the shell runs each line as it is read.

And the record only ever mentioned `install.sh`. `scripts/cloud-shell.sh`
builds from a clone and was documented as a pipe from a moving branch, which is
the same problem with a compile step in the middle: what runs tomorrow is not
what was reviewed today.

Both holes were live in this repository until somebody asked whether the
command in the README was legitimate. It was not.

## Decision

Nothing this project tells anybody to run is fetched and executed in one step.

The install scripts ship as release assets and are listed in the release's
`checksums.txt`, so the documented path is: fetch the script, verify it against
the checksums, read it, run it. The script then verifies the archive, as before.

Building from source names the tag or the commit. A clone of a moving branch,
run unread, is the same trust problem in a slower form.

Documentation may describe the anti-pattern — this record does — but no file in
this repository carries a runnable pipe-to-shell command. The single exception
is the CI workflow, which installs a pinned linter onto an ephemeral runner
that holds nothing and is not something a user is asked to run.

## Consequences

The install instructions are four commands instead of one, and somebody in a
hurry will find that annoying. That is the cost, and it buys the ability to
read what you are about to run and to know it is what the release published.

Releases now carry two more assets and two more checksum lines.

## Enforcement

`TestNothingTellsAnybodyToPipeAURLIntoAShell` in `internal/conformance` walks
every markdown, shell and YAML file in the repository and fails on a runnable
pipe-to-shell, with the CI workflow and the normative documents named as
exceptions rather than pattern-matched away.
`TestThePipeDetectorCatchesTheRealThing` holds that detector to the line that
prompted this record, so it cannot quietly stop firing.
`TestTheInstallScriptsAreReleasedAndChecksummed` requires both scripts to stay
in the release and in the checksums.
