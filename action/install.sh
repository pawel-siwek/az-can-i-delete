#!/usr/bin/env bash
# Install the released binary the action runs, and verify it first.
#
# The version is never "latest" (ADR-0014): it is VERSION when given, and
# otherwise the release tag the workflow pinned this action to, so what runs is
# what the workflow author chose. A branch or a commit names no release, and is
# refused rather than resolved to whatever is newest.
set -euo pipefail

fail() { printf '::error::%s\n' "$*" >&2; exit 1; }

REPO="${REPO:-pawel-siwek/az-can-i-delete}"
VERSION="${VERSION:-}"
if [ -z "$VERSION" ]; then
  case "${ACTION_REF:-}" in
    v[0-9]*) VERSION="$ACTION_REF" ;;
    *) fail "the action is not pinned to a release tag; pin it (uses: ${REPO}@vX.Y.Z) or pass version" ;;
  esac
fi
case "$VERSION" in
  v[0-9]*) ;;
  *) fail "version must be a release tag such as v0.4.0" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) fail "no release binary for $(uname -m)" ;;
esac
ASSET="az-can-i-delete_linux_${ARCH}"

DIR="${RUNNER_TEMP:?}/az-can-i-delete"
mkdir -p "$DIR/bin"
gh release download "$VERSION" -R "$REPO" -p "$ASSET" -p checksums.txt -D "$DIR" --clobber
# Verified before it is made executable: a binary that does not match the
# release's checksum never runs.
(cd "$DIR" && grep -E "  ${ASSET}\$" checksums.txt | sha256sum -c -) || fail "checksum mismatch for ${ASSET} ${VERSION}"
install -m 0755 "$DIR/$ASSET" "$DIR/bin/az-can-i-delete"
echo "$DIR/bin" >> "${GITHUB_PATH:?}"
"$DIR/bin/az-can-i-delete" version
