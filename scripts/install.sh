#!/usr/bin/env bash
# Install a released az-can-i-delete binary into ~/.local/bin.
#
# The version is always explicit: piping a script from the internet into a
# shell is bad enough without letting it decide which code to run. The archive
# is verified against the release's SHA-256 checksums before anything is put on
# a PATH.
#
#   curl -fsSL .../scripts/install.sh | bash -s -- v0.1.0
#   ./scripts/install.sh v0.1.0
#   VERSION=v0.1.0 PREFIX=/opt/azcid ./scripts/install.sh
set -euo pipefail

REPO="${REPO:-pawel-siwek/az-can-i-delete}"
PREFIX="${PREFIX:-$HOME/.local}"
VERSION="${1:-${VERSION:-}}"
BINARY="az-can-i-delete"

say() { printf '==> %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat >&2 <<EOF
usage: install.sh <version>

  <version>   the release tag to install, for example v0.1.0. There is no
              "latest": an installer that picks the version for you cannot be
              reviewed before it runs.

environment:
  REPO        GitHub repository (default $REPO)
  PREFIX      install prefix (default \$HOME/.local)
  BASE_URL    where the release artifacts live (default the GitHub release)
EOF
  exit 2
}

[ -n "$VERSION" ] || usage
case "$VERSION" in
  v[0-9]*) ;;
  *) fail "version must look like v0.1.0, got '$VERSION'" ;;
esac

# platform reports the goreleaser os_arch pair for this machine.
platform() {
  local os arch
  case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=darwin ;;
    *) fail "unsupported operating system $(uname -s); build from source instead" ;;
  esac
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) fail "unsupported architecture $(uname -m); build from source instead" ;;
  esac
  printf '%s_%s\n' "$os" "$arch"
}

# sha256 of a file, using whichever tool this machine has.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "no sha256sum or shasum available, so the download cannot be verified"
  fi
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

number="${VERSION#v}"
archive="${BINARY}_${number}_$(platform).tar.gz"
base="${BASE_URL:-https://github.com/$REPO/releases/download/$VERSION}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

say "downloading $archive from $VERSION"
curl -fsSL "$base/$archive" -o "$work/$archive" ||
  fail "could not download $archive; check that $VERSION was released for this platform"
curl -fsSL "$base/checksums.txt" -o "$work/checksums.txt" ||
  fail "could not download the checksums for $VERSION"

expected="$(awk -v name="$archive" '$2 == name || $2 == "*" name {print $1}' "$work/checksums.txt")"
[ -n "$expected" ] || fail "$archive is not listed in the release checksums"
actual="$(sha256 "$work/$archive")"
if [ "$expected" != "$actual" ]; then
  fail "checksum mismatch for $archive (expected $expected, got $actual); nothing was installed"
fi
say "checksum verified"

tar -C "$work" -xzf "$work/$archive" "$BINARY"
mkdir -p "$PREFIX/bin"
install -m 0755 "$work/$BINARY" "$PREFIX/bin/$BINARY"

case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *)
    say "$PREFIX/bin is not on your PATH; add it with:"
    printf '\n    export PATH="%s/bin:$PATH"\n\n' "$PREFIX"
    ;;
esac

say "installed $("$PREFIX/bin/$BINARY" version) to $PREFIX/bin/$BINARY"
