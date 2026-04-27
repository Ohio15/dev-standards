#!/usr/bin/env bash
# Install the dev-standards guards into a target repo.
#
# Usage:
#   ./install.sh /path/to/target-repo
#
# Wires the chained pre-commit dispatcher plus the size-guard and secret-scan
# sub-hooks into .githooks/, drops the CI workflow, and seeds default
# allowlist + gitleaks config files. Does not commit — review and commit
# yourself.

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

# Chained dispatcher + sub-hooks. Each sub-hook is independently executable so
# the dispatcher can compose them.
cp "$here/hooks/pre-commit" "$target/.githooks/pre-commit"
cp "$here/hooks/pre-commit-size-guard.sh" "$target/.githooks/pre-commit-size-guard.sh"
cp "$here/hooks/pre-commit-secret-scan.sh" "$target/.githooks/pre-commit-secret-scan.sh"
chmod +x \
  "$target/.githooks/pre-commit" \
  "$target/.githooks/pre-commit-size-guard.sh" \
  "$target/.githooks/pre-commit-secret-scan.sh"

# CI workflows.
#   size-guard.yml      — always-on tracked-file size guard
#   security-audit.yml  — Layer A: always-on dep-vuln gate (npm/go/python)
#   dep-auto-apply.yml  — Layer B: weekly auto-apply cron (per-repo opt-in
#                         via .github/auto-apply-enabled — NOT created here)
cp "$here/workflows/size-guard.yml" "$target/.github/workflows/size-guard.yml"
cp "$here/templates/.github/workflows/security-audit.yml" "$target/.github/workflows/security-audit.yml"
cp "$here/templates/.github/workflows/dep-auto-apply.yml" "$target/.github/workflows/dep-auto-apply.yml"

# Templates: copy only if absent so we don't clobber repo-specific tuning.
if [ ! -f "$target/.large-files-allowlist" ]; then
  cp "$here/templates/.large-files-allowlist" "$target/.large-files-allowlist"
fi
if [ ! -f "$target/.gitleaks.toml" ]; then
  cp "$here/templates/.gitleaks.toml" "$target/.gitleaks.toml"
fi

git -C "$target" config core.hooksPath .githooks

echo "Installed into $target"
echo "  .githooks/pre-commit                  (chained dispatcher)"
echo "  .githooks/pre-commit-size-guard.sh    (>10 MB file guard)"
echo "  .githooks/pre-commit-secret-scan.sh   (gitleaks)"
echo "  .github/workflows/size-guard.yml"
echo "  .github/workflows/security-audit.yml  (Layer A — always on)"
echo "  .github/workflows/dep-auto-apply.yml  (Layer B — opt-in)"
echo "  .large-files-allowlist                (if not present)"
echo "  .gitleaks.toml                        (if not present)"
echo "  git config core.hooksPath .githooks   (local)"
echo
echo "Layer B (weekly auto-apply) is OPT-IN per repo. To enable, create an"
echo "empty enrollment file (NOT done by this installer):"
echo "  touch $target/.github/auto-apply-enabled"
echo "  git -C $target add .github/auto-apply-enabled"
echo "Kill switch: rm that file and push."
echo
echo "Gitleaks must be installed on each developer's machine. Install instructions:"
echo "  macOS:    brew install gitleaks"
echo "  Windows:  choco install gitleaks"
echo "  Any:      go install github.com/zricethezav/gitleaks/v8@latest"
echo
echo "Review the files, then:"
echo "  git add -A && git commit -m 'ci: install dev-standards guards'"
