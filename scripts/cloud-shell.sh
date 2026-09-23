#!/usr/bin/env bash
# Build az-can-i-delete in Azure Cloud Shell and put it on the PATH.
#
# Cloud Shell persists $HOME and nothing else, so everything this script
# installs lives under ~/.local. It installs a Go toolchain only if the one
# already there is too old to build this module. Nothing here needs sudo, and
# nothing is written outside $HOME.
#
# Run it from a clone you have checked out at the tag or commit you mean, so
# what you build is what you reviewed:
#
#   git clone --branch <tag> <repo url> ~/src/az-can-i-delete
#   less ~/src/az-can-i-delete/scripts/cloud-shell.sh
#   ~/src/az-can-i-delete/scripts/cloud-shell.sh
#
# Deliberately not documented as `curl … | bash`: a command you cannot read
# before it runs is one you are trusting rather than checking.
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/pawel-siwek/az-can-i-delete.git}"
REPO_REF="${REPO_REF:-main}"
GO_VERSION="${GO_VERSION:-1.25.0}"
PREFIX="${PREFIX:-$HOME/.local}"
SRC_DIR="${SRC_DIR:-$HOME/src/az-can-i-delete}"

say() { printf '==> %s\n' "$*"; }

# BOOTSTRAP_GO is the oldest Go that can build this module at all: from 1.21
# the go command downloads the exact toolchain a module asks for, so an older
# Cloud Shell image needs nothing but this one.
BOOTSTRAP_GO="1.21.0"

# required_go reports the toolchain the module pins, so this script does not
# drift from go.mod.
required_go() {
  if [ -f "$SRC_DIR/go.mod" ]; then
    awk '/^go /{print $2; exit}' "$SRC_DIR/go.mod"
  else
    printf '%s\n' "$GO_VERSION"
  fi
}

# version_at_least compares two dotted versions without needing sort -V.
version_at_least() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$2" ]
}

install_go() {
  local version="$1"
  local target="$PREFIX/go-$version"
  if [ -x "$target/bin/go" ]; then
    say "using the Go toolchain already installed at $target"
  else
    say "installing Go $version into $target (nothing outside \$HOME is touched)"
    mkdir -p "$PREFIX"
    local archive="/tmp/go$version.linux-amd64.tar.gz"
    curl -fsSL "https://go.dev/dl/go$version.linux-amd64.tar.gz" -o "$archive"
    rm -rf "$target"
    mkdir -p "$target"
    tar -C "$target" --strip-components=1 -xzf "$archive"
    rm -f "$archive"
  fi
  export PATH="$target/bin:$PATH"
}

say "checking out the source"
if [ -d "$SRC_DIR/.git" ]; then
  git -C "$SRC_DIR" fetch --depth 1 origin "$REPO_REF"
  git -C "$SRC_DIR" checkout -q FETCH_HEAD
else
  mkdir -p "$(dirname "$SRC_DIR")"
  git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$SRC_DIR"
fi

want="$(required_go)"
have="$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')"
if [ -n "$have" ] && version_at_least "$have" "$BOOTSTRAP_GO"; then
  say "using the Go $have that is already here (it fetches the pinned $want toolchain if it needs to)"
else
  install_go "$want"
fi

say "building"
mkdir -p "$PREFIX/bin"
( cd "$SRC_DIR" && CGO_ENABLED=0 go build -o "$PREFIX/bin/az-can-i-delete" ./cmd/az-can-i-delete )

case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *)
    say "adding $PREFIX/bin to your PATH in ~/.bashrc"
    printf '\nexport PATH="%s/bin:$PATH"\n' "$PREFIX" >> "$HOME/.bashrc"
    export PATH="$PREFIX/bin:$PATH"
    ;;
esac

say "installed: $("$PREFIX/bin/az-can-i-delete" version)"
cat <<'EOF'

Try it on something. Cloud Shell is already signed in, so there is nothing to
configure; the tool uses the same identity az does.

  # an unattached managed disk
  az graph query -q "resources | where type =~ 'microsoft.compute/disks' and isnull(managedBy) | project id" -o tsv --query "data[0].id" \
    | xargs -r az-can-i-delete check

  # an App Service plan with no sites on it
  az graph query -q "resources | where type =~ 'microsoft.web/serverfarms' and properties.numberOfSites == 0 | project id" -o tsv --query "data[0].id" \
    | xargs -r az-can-i-delete check

If `az graph` asks for an extension, run `az extension add --name resource-graph`
once. A verdict is evidence, not permission.
EOF
