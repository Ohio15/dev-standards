#!/usr/bin/env bash
# Install the size guard into a target repo.
#
# Usage:
#   ./install.sh /path/to/target-repo
#
# Copies the pre-commit hook, the CI workflow, and an empty allowlist
# template into the target repo. Configures core.hooksPath locally.
# Does not commit — review and commit yourself.

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 /path/to/target-repo" >&2
  exit 2
fi

target="$1"
if [ ! -d "$target/.git" ]; then
  echo "ERROR: $target is not a git repo" >&2
  exit 1
fi

here="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$target/.githooks" "$target/.github/workflows"
cp "$here/hooks/pre-commit" "$target/.githooks/pre-commit"
chmod +x "$target/.githooks/pre-commit"
cp "$here/workflows/size-guard.yml" "$target/.github/workflows/size-guard.yml"

if [ ! -f "$target/.large-files-allowlist" ]; then
  cp "$here/templates/.large-files-allowlist" "$target/.large-files-allowlist"
fi

git -C "$target" config core.hooksPath .githooks

echo "Installed into $target"
echo "  .githooks/pre-commit"
echo "  .github/workflows/size-guard.yml"
echo "  .large-files-allowlist (if not present)"
echo "  git config core.hooksPath .githooks (local)"
echo
echo "Review the files, then: git add -A && git commit -m 'ci: install size guard'"
