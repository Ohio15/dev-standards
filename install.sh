#!/usr/bin/env bash
# Install the dev-standards guards into a target repo.
#
# Usage:
#   ./install.sh [--private|--public] [--no-gh] /path/to/target-repo
#
# Wires the chained pre-commit dispatcher plus the size-guard and secret-scan
# sub-hooks into .githooks/, drops the CI workflows, and seeds default
# allowlist + gitleaks config files. Does not commit — review and commit
# yourself.
#
# Runner (register SC-37, STANDARDS.md section 4): the pull_request-reachable
# templates carry the canonical allow-list predicate, which lets a private
# repo's jobs (same-repo PRs included) run on vars.CI_RUNNER (nexus-ci). A
# public repo must carry the hosted literal instead, so the repo's visibility
# decides what is written. It comes from GitHub (`gh api repos/<origin>`)
# unless --private/--public says so; an explicit flag that GitHub contradicts
# is refused, and an unknown visibility installs nothing.
#
# nexus-ci onboarding (private repos whose owner the ci-registrar serves):
# with gh available the installer sets the repo variable CI_RUNNER=nexus-ci
# when it is unset, and reads the tracked registrar config (Ohio15/infra
# ci-vm/registrar/config.json) to report whether the repo is mapped there.
# The registrar mapping and its apply on NEXUS are a reviewed infra change, so
# the installer prints those steps and never performs them. --no-gh skips
# every GitHub call (a visibility flag is then required) and prints the
# commands instead.

set -euo pipefail

usage() {
  echo "Usage: $0 [--private|--public] [--no-gh] /path/to/target-repo" >&2
  exit 2
}

visibility=""
use_gh=1
target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --private|--public)
      [ -z "$visibility" ] || usage
      visibility="${1#--}"
      ;;
    --no-gh) use_gh=0 ;;
    -*) usage ;;
    *)
      [ -z "$target" ] || usage
      target="$1"
      ;;
  esac
  shift
done
[ -n "$target" ] || usage

# A linked worktree has a .git FILE, not a directory; ask git instead of stat.
if ! git -C "$target" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: $target is not a git working tree" >&2
  exit 1
fi

here="$(cd "$(dirname "$0")" && pwd)"

# The tracked ci-registrar config: which repos nexus-ci serves. Ohio15/infra
# ci-vm/README.md ("apply-config") is the procedure that deploys it.
REGISTRAR_REPO="Ohio15/infra"
REGISTRAR_CONFIG="ci-vm/registrar/config.json"
# The canonical SC-37 predicate, exactly as the templates carry it. A public
# repo's copy gets the hosted literal in its place.
CANON_RUNS_ON="runs-on: \${{ (github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || github.event_name == 'release' || github.event_name == 'merge_group' || github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository) && vars.CI_RUNNER || 'ubuntu-latest' }}"
HOSTED_RUNS_ON="runs-on: ubuntu-latest"

# owner/repo of origin when it is a github.com remote, else empty.
slug=""
origin_url="$(git -C "$target" remote get-url origin 2>/dev/null || true)"
case "$origin_url" in
  https://github.com/*|git@github.com:*|ssh://git@github.com/*)
    slug="${origin_url#*github.com[:/]}"
    slug="${slug%/}"
    slug="${slug%.git}"
    [[ "$slug" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || slug=""
    ;;
esac

gh_ok=0
gh_private=""
repo_name=""
repo_owner=""
if [ "$use_gh" -eq 1 ] && [ -n "$slug" ] && command -v gh >/dev/null 2>&1; then
  if meta="$(gh api "repos/$slug" --jq '[.private, .name, .owner.login] | @tsv' 2>/dev/null)"; then
    IFS=$'\t' read -r gh_private repo_name repo_owner <<<"$meta" || true
    if { [ "$gh_private" = "true" ] || [ "$gh_private" = "false" ]; } \
       && [[ "$repo_name" =~ ^[A-Za-z0-9_.-]+$ ]] && [[ "$repo_owner" =~ ^[A-Za-z0-9_.-]+$ ]]; then
      gh_ok=1
    fi
  fi
fi

if [ "$gh_ok" -eq 1 ]; then
  if [ "$gh_private" = "true" ]; then gh_visibility="private"; else gh_visibility="public"; fi
  if [ -n "$visibility" ] && [ "$visibility" != "$gh_visibility" ]; then
    echo "ERROR: --$visibility given, but GitHub reports $slug as $gh_visibility; nothing installed" >&2
    exit 1
  fi
  visibility="$gh_visibility"
elif [ -z "$visibility" ]; then
  echo "ERROR: cannot determine whether $target is a private or a public repository" >&2
  echo "  (needs a github.com origin and an authenticated gh, or --private / --public)." >&2
  echo "  The runner predicate depends on it (SC-37); nothing installed." >&2
  exit 1
fi

# Copy a pull_request-reachable template. Private: verbatim. Public: every
# canonical runs-on becomes the hosted literal, and a runs-on expression left
# over afterwards is refused rather than installed.
install_pr_workflow() {
  local src="$1" dst="$2" content
  if [ "$visibility" = "private" ]; then
    cp "$src" "$dst"
    return
  fi
  content="$(cat "$src"; printf x)"
  content="${content%x}"
  content="${content//"$CANON_RUNS_ON"/"$HOSTED_RUNS_ON"}"
  # shellcheck disable=SC2016  # the pattern matches the literal text `${{`; no expansion wanted
  case "$content" in
    *'runs-on: ${{'*)
      echo "ERROR: $src has a runs-on expression that is not the canonical predicate; refusing to install it into a public repository" >&2
      exit 1
      ;;
  esac
  printf '%s' "$content" >"$dst"
}

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
#   size-guard.yml and security-audit.yml are pull_request-reachable: their
#   runs-on follows the repo's visibility (install_pr_workflow above).
#   dep-auto-apply.yml runs on schedule/workflow_dispatch only and carries its
#   own private-only literal toggle, so it is copied as is.
install_pr_workflow "$here/workflows/size-guard.yml" "$target/.github/workflows/size-guard.yml"
install_pr_workflow "$here/templates/.github/workflows/security-audit.yml" "$target/.github/workflows/security-audit.yml"
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

# nexus-ci onboarding. Every line goes into runner_report, printed at the end.
# A step that could not be done or checked says so; it is never reported done.
runner_report=()
onboarding_incomplete=0
report() { runner_report+=("$1"); }

if [ "$visibility" = "public" ]; then
  report "Public repository: PR-reachable jobs run on the hosted literal (ubuntu-latest)."
  report "  The nexus-ci registrar refuses public repositories; CI_RUNNER must stay unset (SC-37, SC-46)."
  if [ "$gh_ok" -eq 1 ] && public_var="$(gh api "repos/$slug/actions/variables/CI_RUNNER" --jq .value 2>/dev/null)"; then
    report "  WARNING: CI_RUNNER is set to '$public_var' on public $slug. Remove it:"
    report "    gh variable delete CI_RUNNER --repo $slug"
    onboarding_incomplete=1
  fi
elif [ "$gh_ok" -ne 1 ]; then
  report "Private repository (from --private; GitHub not consulted): nexus-ci onboarding NOT checked."
  report "  1. gh variable set CI_RUNNER --body nexus-ci --repo ${slug:-<owner>/<repo>}"
  report "  2. map the repo in $REGISTRAR_REPO $REGISTRAR_CONFIG (\"<repo>\": [\"nexus-ci\"]); PR, gate, merge;"
  report "     apply it on NEXUS (ci-vm/README.md, apply-config)."
  report "  3. the ci-registrar GitHub App installation must include the repo."
  report "  Until then its PR jobs ask for ubuntu-latest."
  onboarding_incomplete=1
else
  reg_owner="" reg_mapped="" reg_installation=""
  if reg="$(gh api -H "Accept: application/vnd.github.raw+json" "repos/$REGISTRAR_REPO/contents/$REGISTRAR_CONFIG" \
            --jq "[.owner, (.repos | has(\"$repo_name\")), .installation_id] | @tsv" 2>/dev/null)"; then
    IFS=$'\t' read -r reg_owner reg_mapped reg_installation <<<"$reg" || true
  fi

  if [ -z "$reg_owner" ] || [ "$reg_owner" = "null" ]; then
    report "Private repository: could not read $REGISTRAR_REPO $REGISTRAR_CONFIG, so nexus-ci onboarding is NOT checked"
    report "  and CI_RUNNER was left as it is. Check the registrar mapping, then:"
    report "    gh variable set CI_RUNNER --body nexus-ci --repo $slug"
    onboarding_incomplete=1
  elif [ "$reg_owner" != "$repo_owner" ]; then
    report "Private repository owned by $repo_owner: the nexus-ci registrar serves $reg_owner only."
    report "  CI_RUNNER not set; this repo's PR jobs run on ubuntu-latest."
  else
    var_err="$(mktemp)"
    if current="$(gh api "repos/$slug/actions/variables/CI_RUNNER" --jq .value 2>"$var_err")"; then
      var_state="set"
    elif grep -q "HTTP 404" "$var_err"; then
      var_state="unset"
    else
      var_state="unknown"
    fi
    rm -f "$var_err"
    case "$var_state" in
      set)
        if [ "$current" = "nexus-ci" ]; then
          report "CI_RUNNER=nexus-ci already set on $slug."
        else
          report "WARNING: CI_RUNNER on $slug is '$current', not nexus-ci; left unchanged."
          onboarding_incomplete=1
        fi
        ;;
      unset)
        if gh variable set CI_RUNNER --body nexus-ci --repo "$slug" >/dev/null 2>&1 \
           && [ "$(gh api "repos/$slug/actions/variables/CI_RUNNER" --jq .value 2>/dev/null)" = "nexus-ci" ]; then
          report "CI_RUNNER=nexus-ci set on $slug (read back from GitHub)."
        else
          report "ERROR: could not set CI_RUNNER on $slug. Run:"
          report "    gh variable set CI_RUNNER --body nexus-ci --repo $slug"
          onboarding_incomplete=1
        fi
        ;;
      *)
        report "ERROR: could not read CI_RUNNER on $slug (not a 404); left unchanged. Check it, then:"
        report "    gh variable set CI_RUNNER --body nexus-ci --repo $slug"
        onboarding_incomplete=1
        ;;
    esac
    if [ "$reg_mapped" = "true" ]; then
      report "$repo_name is mapped in the tracked registrar config ($REGISTRAR_REPO $REGISTRAR_CONFIG)."
      report "  Whether NEXUS has applied it is not checked from here; the apply-config.py dry run answers that."
    else
      report "$repo_name is NOT in the tracked registrar config, so nexus-ci serves no job for it yet:"
      report "  1. add \"$repo_name\": [\"nexus-ci\"] to \"repos\" in $REGISTRAR_REPO $REGISTRAR_CONFIG; PR, gate, merge."
      report "  2. on NEXUS, from a checkout of merged main (ci-vm/README.md, apply-config):"
      report "       sudo python3 -I /opt/ci-registrar/apply-config.py ~ohio_/infra/ci-vm/registrar/config.json"
      report "       sudo python3 -I /opt/ci-registrar/apply-config.py ~ohio_/infra/ci-vm/registrar/config.json --apply --restart"
      report "       systemctl is-active ci-registrar"
      onboarding_incomplete=1
    fi
    report "The registrar's GitHub App installation ($reg_installation) must include $repo_name, or its"
    report "  visibility check fails (HTTP 404) and it serves nothing for the repo:"
    report "  https://github.com/settings/installations/$reg_installation"
  fi
fi

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
echo
if [ "$onboarding_incomplete" -eq 1 ]; then
  echo "CI runner ($visibility repository): nexus-ci onboarding INCOMPLETE"
else
  echo "CI runner ($visibility repository):"
fi
for line in "${runner_report[@]}"; do
  echo "  $line"
done
