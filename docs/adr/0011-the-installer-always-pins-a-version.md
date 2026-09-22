# ADR-0011: The installer always names a version, and verifies what it fetched

- Status: accepted
- Date: 2026-09-22
- Source: REQUIREMENTS.md section 7

## Context

The convenient install line is `curl … | sh`, resolving "latest" server
side. Whoever runs it cannot review what will execute, and the answer can
change between two runs of the same command.

## Decision

`scripts/install.sh` requires an explicit release tag; there is no "latest".
It downloads the archive and the release's `checksums.txt`, verifies the
SHA-256 before anything is placed on a PATH, and installs into
`~/.local/bin` — no sudo, nothing written outside `$HOME`. Releases are cut
by goreleaser with SHA-256 checksums for every archive.

## Consequences

The documented install line is one token longer and can be audited. A
tampered or truncated download fails loudly and installs nothing.

## Enforcement

`scripts/install.sh` rejects a missing or malformed version and aborts on a
checksum mismatch; `.goreleaser.yaml` emits `checksums.txt` with
`algorithm: sha256`.
