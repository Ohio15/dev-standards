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
# A linked worktree has a .git FILE, not a directory; ask git instead of stat.
if ! git -C "$target" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: $target is not a git working tree" >&2
  exit 1
fi

here="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$target/.githooks" "$target/.github/workflows"

# Chained dispatcher + sub-hooks. Each sub-hook is independently executable so
# the dispatcher can compose them.
cp "$here/hooks/pre-commit" "$target/.githooks/pre-commit"
cp "$here/hooks/pre-commit-size-guard.sh" "$target/.githooks/pre-commit-size-guard.sh"
cp "$here/hooks/pre-commit-secret-scan.sh" "$target/.githooks/pre-commit-secret-scan.sh"
cp "$here/hooks/pre-commit-healthcheck-lint.sh" "$target/.githooks/pre-commit-healthcheck-lint.sh"
cp "$here/hooks/pre-commit-tests.sh" "$target/.githooks/pre-commit-tests.sh"
# commit-msg: conventional subject + attribution scrub (issue #5, 2026-10-04).
# Always overwritten — the per-repo copies diverged for five months before
# this file existed; the hook is a contract, not repo-specific tuning.
cp "$here/hooks/commit-msg" "$target/.githooks/commit-msg"
chmod +x \
  "$target/.githooks/commit-msg" \
  "$target/.githooks/pre-commit" \
  "$target/.githooks/pre-commit-size-guard.sh" \
  "$target/.githooks/pre-commit-secret-scan.sh" \
  "$target/.githooks/pre-commit-healthcheck-lint.sh" \
  "$target/.githooks/pre-commit-tests.sh"
# chmod alone is lost on every fresh clone and is invisible on Windows
# (core.filemode=false): git decides whether to RUN a hook from the mode in
# the index. Record 100755 there, so a POSIX clone does not silently skip the
# whole chain (audit-openos-2026-09-16: 31 of 32 repos carried 100644).
git -C "$target" add --chmod=+x   ".githooks/commit-msg"   ".githooks/pre-commit"   ".githooks/pre-commit-size-guard.sh"   ".githooks/pre-commit-secret-scan.sh"   ".githooks/pre-commit-healthcheck-lint.sh"   ".githooks/pre-commit-tests.sh"

# CI workflows.
#   size-guard.yml      — always-on tracked-file size guard
#   security-audit.yml  — Layer A: always-on dep-vuln gate (npm/go/python)
#   dep-auto-apply.yml  — Layer B: weekly auto-apply cron (per-repo opt-in
#                         via .github/auto-apply-enabled — NOT created here)
cp "$here/workflows/size-guard.yml" "$target/.github/workflows/size-guard.yml"
cp "$here/templates/.github/workflows/security-audit.yml" "$target/.github/workflows/security-audit.yml"
cp "$here/templates/.github/workflows/dep-auto-apply.yml" "$target/.github/workflows/dep-auto-apply.yml"

# Security register (security/REVIEW-MODEL.md): the per-session gate reads
# <repo>/SECURITY-CHECKS.md and falls back to the canonical copy, reporting
# the fallback as a finding — so every repo gets its own copy. Always
# overwritten: the register is a contract, not repo-specific tuning; local
# additions go through the audit's "Proposed additions" path.
cp "$here/security/SECURITY-CHECKS.md" "$target/SECURITY-CHECKS.md"

# Templates: copy only if absent so we don't clobber repo-specific tuning.
if [ ! -f "$target/.large-files-allowlist" ]; then
  cp "$here/templates/.large-files-allowlist" "$target/.large-files-allowlist"
fi
if [ ! -f "$target/.gitleaks.toml" ]; then
  cp "$here/templates/.gitleaks.toml" "$target/.gitleaks.toml"
fi

# Dependabot keeps the SHA pins in the workflows above current (SC-25). Seed a
# github-actions config only when the repo has none at all: an existing config
# (either extension) is the repo's own and is never overwritten. One that does
# not cover github-actions is reported, not edited.
dependabot_existing=""
for f in "$target/.github/dependabot.yml" "$target/.github/dependabot.yaml"; do
  if [ -e "$f" ]; then dependabot_existing="$f"; break; fi
done
if [ -z "$dependabot_existing" ]; then
  cp "$here/templates/.github/dependabot.yml" "$target/.github/dependabot.yml"
  dependabot_note="seeded (github-actions, weekly, grouped)"
elif grep -Eq '^[[:space:]]*-?[[:space:]]*package-ecosystem:[[:space:]]*["'"'"']?github-actions["'"'"']?[[:space:]]*(#.*)?$' "$dependabot_existing"; then
  dependabot_note="kept existing ${dependabot_existing#"$target/"} (covers github-actions)"
else
  dependabot_note="kept existing ${dependabot_existing#"$target/"} - WARNING: it has no github-actions entry, so the SHA-pinned actions will go stale"
  echo "WARNING: $dependabot_existing has no 'package-ecosystem: github-actions' entry; add one so the SHA-pinned actions stay current." >&2
fi

git -C "$target" config core.hooksPath .githooks

echo "Installed into $target"
echo "  .githooks/commit-msg                  (conventional subject; attribution scrubbed)"
echo "  .githooks/pre-commit                  (chained dispatcher)"
echo "  .githooks/pre-commit-size-guard.sh    (>10 MB file guard)"
echo "  .githooks/pre-commit-secret-scan.sh   (gitleaks)"
echo "  .githooks/pre-commit-healthcheck-lint.sh  (release-config.yml shape)"
echo "  .github/workflows/size-guard.yml"
echo "  .github/workflows/security-audit.yml  (Layer A — always on)"
echo "  .github/workflows/dep-auto-apply.yml  (Layer B — opt-in)"
echo "      before enrolling: create environment auto-apply-publish (Settings -> Environments),"
echo "      deployment branches = the default branch only, and put DEP_AUTO_APPLY_NTFY_TOKEN /"
echo "      SHARED_BRAIN_TOKEN there as environment secrets (README, Layer B)."
echo "  SECURITY-CHECKS.md                    (security register — always refreshed)"
echo "  .large-files-allowlist                (if not present)"
echo "  .gitleaks.toml                        (if not present)"
echo "  .github/dependabot.yml                ($dependabot_note)"
echo "  git config core.hooksPath .githooks   (local)"
echo "  hooks staged with mode 100755          (git add --chmod=+x)"
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
