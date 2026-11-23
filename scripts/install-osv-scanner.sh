#!/usr/bin/env bash
# Install the pinned OSV-Scanner for scripts/osv-deps-facts.py (NEXUS, user ohio_).
#
# The version is estate/osv-scanner.version (one source). The binary is built
# with `go install` from the Go module proxy: every module, and the Go
# toolchain the module requires, is verified against sum.golang.org, so no
# unverified release asset is downloaded. The build runs under `env -i` with
# an explicit allow-list (PATH, HOME, GOENV=off, GOBIN, GOFLAGS, GOPROXY,
# GOSUMDB, GOTOOLCHAIN), so no inherited GOINSECURE, GONOSUMDB, GOPRIVATE,
# GONOPROXY or go.env file can weaken the checksum verification.
#
# Installs to <prefix>/<version>/osv-scanner and repoints <prefix>/current
# atomically, so a failed build never replaces a working binary.
#
#   scripts/install-osv-scanner.sh [--prefix DIR]   (default ~/.local/lib/osv-scanner)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
prefix="${HOME}/.local/lib/osv-scanner"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) prefix="$2"; shift 2 ;;
    *) echo "install-osv-scanner: unknown arg: $1" >&2; exit 2 ;;
  esac
done

version="$(tr -d '[:space:]' < "$here/../estate/osv-scanner.version")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "install-osv-scanner: bad pin '$version'" >&2; exit 2; }

dest="$prefix/$version"
if [[ -x "$dest/osv-scanner" ]] && "$dest/osv-scanner" --version 2>/dev/null | grep -qx "osv-scanner version: $version"; then
  echo "install-osv-scanner: $version already installed at $dest"
else
  mkdir -p -- "$prefix"
  stage="$(mktemp -d "$prefix/.stage.XXXXXX")"
  trap 'rm -rf -- "$stage"' EXIT
  go_bin="$(command -v go)" || { echo "install-osv-scanner: go not on PATH" >&2; exit 2; }
  env -i PATH="$(dirname "$go_bin"):/usr/bin:/bin" HOME="$HOME" GOENV=off \
    GOBIN="$stage" GOFLAGS=-mod=mod GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
    GOTOOLCHAIN=auto \
    "$go_bin" install "github.com/google/osv-scanner/v2/cmd/osv-scanner@v$version"
  "$stage/osv-scanner" --version | grep -qx "osv-scanner version: $version" \
    || { echo "install-osv-scanner: built binary does not report $version" >&2; exit 1; }
  mkdir -p "$dest"
  install -m 0755 "$stage/osv-scanner" "$dest/osv-scanner.new"
  mv -f "$dest/osv-scanner.new" "$dest/osv-scanner"
  echo "install-osv-scanner: installed $version at $dest"
fi

ln -sfn "$version" "$prefix/current.new"
mv -Tf "$prefix/current.new" "$prefix/current"
echo "install-osv-scanner: $prefix/current -> $version"
