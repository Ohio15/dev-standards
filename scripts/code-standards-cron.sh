#!/usr/bin/env bash
# Cron entry point for the code-standards facts export (STANDARDS.md §2).
#
# Every 6 hours: mirror every estate repo (estate/code-standards-roster.txt),
# run the hygiene scanner and the npm audit over the mirror, and export the
# result as a Prometheus textfile that Steward consumes as its
# code-standards-* positions.
#
#   1. fast-forward this dev-standards checkout (as hygiene-scan-cron.sh
#      does), then re-exec the updated copy of this script once
#   2. scripts/estate-mirror.sh          -> <mirror>/<repo>, <work>/mirror-status.txt
#   3. scripts/repo-hygiene-scan.py      -> <work>/hygiene/hygiene-scan-<date>.json
#      (--no-layout; no --brain-store, --check-drift: nothing is posted to
#      shared-brain or ntfy and no release drift scan runs)
#   4. scripts/npm-audit-weekly.sh       -> <work>/npm/npm-audit-<date>.json
#      (`npm audit` only: no install, no lifecycle script; no --brain-store)
#   5. scripts/code-standards-facts.py   -> <output> (atomic replace)
#   6. scripts/osv-deps-facts.py         -> <deps-output> + <work>/osv/osv-report.json
#      (OSV-Scanner over the same mirror, every ecosystem, offline database;
#      a separate textfile because Steward refuses code_standards.prom whole
#      on any series outside its allow-list. Degradable: a failure here never
#      blocks step 5; the old code_deps.prom keeps its old last_run.)
#
# Fail-closed: if the mirror cannot be set up, the security roster or the
# canonical register was not refreshed this run, the scanner crashes, or the
# export is refused, NOTHING is written; the previous textfile keeps its old
# code_standards_last_run_timestamp_seconds and Steward sees the staleness.
# A failed npm audit only costs the deps series (read as not scanned).
#
# One-time setup on NEXUS (user ohio_):
#   sudo install -d -o ohio_ -g ohio_ -m 0755 /var/lib/estate-code
#   scripts/install-osv-scanner.sh            (pinned in estate/osv-scanner.version)
# crontab (NEXUS, user ohio_):
#   0 */6 * * * /home/ohio_/dev-standards/scripts/code-standards-cron.sh > /var/lib/estate-code/code-standards-cron.log 2>&1
#
# Options (defaults in brackets):
#   --mirror <dir>   mirror root               [/var/lib/estate-code/repos]
#   --work <dir>     work dir (reports, lock)  [/var/lib/estate-code/work]
#   --output <file>  textfile                  [/var/lib/node_exporter/textfile_collector/code_standards.prom]
#   --roster <file>  roster                    [<checkout>/estate/code-standards-roster.txt]
#   --deps-output <file> OSV textfile         [<output dir>/code_deps.prom]
#   --osv-scanner <bin>  pinned scanner       [~/.local/lib/osv-scanner/current/osv-scanner]
#   --no-pull        skip step 1 (local runs)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
checkout="$(cd "$here/.." && pwd)"

mirror="/var/lib/estate-code/repos"
work="/var/lib/estate-code/work"
output="/var/lib/node_exporter/textfile_collector/code_standards.prom"
roster="$checkout/estate/code-standards-roster.txt"
deps_output=""
osv_bin="${HOME}/.local/lib/osv-scanner/current/osv-scanner"
pull="true"
orig_args=("$@")

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mirror) mirror="$2"; shift 2 ;;
    --work) work="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --roster) roster="$2"; shift 2 ;;
    --deps-output) deps_output="$2"; shift 2 ;;
    --osv-scanner) osv_bin="$2"; shift 2 ;;
    --no-pull) pull="false"; shift ;;
    *) echo "code-standards-cron: unknown arg: $1" >&2; exit 2 ;;
  esac
done

log() { echo "code-standards-cron: $*"; }

[[ -n "$deps_output" ]] || deps_output="$(dirname "$output")/code_deps.prom"

mkdir -p -- "$mirror" "$work" "$work/hygiene" "$work/npm" "$work/osv" \
  || { log "ERROR cannot create $mirror / $work (see the one-time setup in this header)"; exit 2; }

# One run at a time: a 6-hourly cron plus a manual run must not interleave
# clones or reports.
exec 9>"$work/.lock"
if ! flock -n 9; then
  log "another run holds $work/.lock; exiting"
  exit 0
fi

# 1. Fast-forward, then re-exec the updated script exactly once. A failed pull
#    is logged and the run continues on the stale checkout (as the weekly scan
#    does); the pull result is the first line of every log.
if [[ "$pull" == "true" && -z "${CODE_STANDARDS_PULLED:-}" ]]; then
  before="$(git -C "$checkout" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  if git -C "$checkout" pull -q --ff-only origin main 2>"$work/pull-error.txt"; then
    after="$(git -C "$checkout" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    log "dev-standards $before -> $after"
  else
    log "WARNING dev-standards pull failed at $before; running the stale checkout"
    sed 's/^/  /' "$work/pull-error.txt"
  fi
  exec 9>&-
  CODE_STANDARDS_PULLED=1 exec "$here/code-standards-cron.sh" "${orig_args[@]}"
fi

status_file="$work/mirror-status.txt"

# 2. Mirror. Exit 1 = some repos failed (recorded in the status file).
mirror_rc=0
"$here/estate-mirror.sh" --roster "$roster" --dir "$mirror" --status "$status_file" || mirror_rc=$?
if (( mirror_rc != 0 && mirror_rc != 1 )); then
  log "ERROR estate-mirror.sh exit $mirror_rc; nothing exported"
  exit 1
fi

# The two scanner inputs must be from THIS run: a stale roster or register
# would read repos it never examined against them as clean.
security_roster="$mirror/cortex-hooks/config/security-repos.json"
canonical_register="$mirror/dev-standards/security/SECURITY-CHECKS.md"
for dep in cortex-hooks dev-standards; do
  if ! grep -q "^$dep ok " "$status_file"; then
    log "ERROR $dep was not refreshed this run; the security checks have no current input; nothing exported"
    exit 1
  fi
done
for f in "$security_roster" "$canonical_register"; do
  [[ -f "$f" ]] || { log "ERROR missing $f; nothing exported"; exit 1; }
done

# 3. Hygiene scan over the mirror only. Global and system git config are
#    switched off so `git check-ignore` judges tracked files against the
#    repo's own .gitignore, not this account's excludes.
rm -f -- "$work"/hygiene/hygiene-scan-*.json
scan_rc=0
env GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null XDG_CONFIG_HOME="$work/no-xdg" \
  GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=20" \
  timeout --kill-after=60 3600 python3 -I "$here/repo-hygiene-scan.py" \
    --root "$mirror" \
    --output-dir "$work/hygiene" \
    --no-layout \
    --security-roster "$security_roster" \
    --canonical-register "$canonical_register" \
    > "$work/hygiene/hygiene-scan.md" || scan_rc=$?
# 0/1/2 = completed with no / MEDIUM / HIGH findings; anything else is a failure.
if (( scan_rc > 2 )); then
  log "ERROR repo-hygiene-scan.py exit $scan_rc; nothing exported"
  exit 1
fi
shopt -s nullglob
reports=("$work"/hygiene/hygiene-scan-*.json)
shopt -u nullglob
if (( ${#reports[@]} != 1 )); then
  log "ERROR expected one hygiene report, found ${#reports[@]}; nothing exported"
  exit 1
fi

# 4. npm audit (degradable, bounded). npm-audit-weekly.sh owns the npm and
#    pnpm configuration: it never runs either inside a mirrored repo
#    (package.json and the lockfile are staged into an operator tree with no
#    .npmrc and, for pnpm, a script-written pnpm-workspace.yaml) and pins
#    userconfig/globalconfig to empty files, the registry, strict-ssl, proxies
#    and scripts itself (audit 2026-11-10.2 M3). The pins below are redundant
#    belt-and-braces for any npm call made before the script's own.
rm -f -- "$work"/npm/npm-audit-*.json
npm_args=()
npm_rc=0
env npm_config_registry="https://registry.npmjs.org/" npm_config_ignore_scripts=true \
  npm_config_update_notifier=false npm_config_fund=false \
  timeout --kill-after=60 3600 "$here/npm-audit-weekly.sh" --root "$mirror" --output-dir "$work/npm" \
  > "$work/npm/npm-audit.md" 2> "$work/npm/npm-audit.err" || npm_rc=$?
shopt -s nullglob
npm_reports=("$work"/npm/npm-audit-*.json)
shopt -u nullglob
# 0 = under thresholds, 3 = thresholds exceeded, 4 = some repo not examined
# (status "error", null counts); all three wrote a report. code-standards-facts.py
# exports only status "ok" entries with integer counts as scanned, so an error
# entry reads as deps_scanned 0, never as clean, and the rest of the report is kept.
if (( (npm_rc == 0 || npm_rc == 3 || npm_rc == 4) && ${#npm_reports[@]} == 1 )); then
  npm_args=(--npm-audit "${npm_reports[0]}")
else
  log "WARNING npm-audit-weekly.sh exit $npm_rc, ${#npm_reports[@]} report(s); deps exported as not scanned"
fi

# 5. Export.
python3 -I "$here/code-standards-facts.py" \
  --roster "$roster" \
  --mirror-status "$status_file" \
  --hygiene-report "${reports[0]}" \
  "${npm_args[@]}" \
  --output "$output"

# 6. OSV dependency facts (degradable, bounded; runs after step 5 so a slow
#    or failing scanner can never delay or suppress the code-standards export).
osv_rc=0
timeout --kill-after=60 5400 python3 -I "$here/osv-deps-facts.py"   --roster "$roster"   --mirror "$mirror"   --mirror-status "$status_file"   --osv-scanner "$osv_bin"   --db-dir "$work/osv/db"   --report "$work/osv/osv-report.json"   --output "$deps_output"   2> "$work/osv/osv-deps.err" || osv_rc=$?
if (( osv_rc != 0 )); then
  log "WARNING osv-deps-facts.py exit $osv_rc (see $work/osv/osv-deps.err); $deps_output not refreshed"
fi
tail -n 1 "$work/osv/osv-deps.err" 2>/dev/null | sed 's/^/  /' || true
log "done (mirror rc $mirror_rc, scan rc $scan_rc, npm rc $npm_rc, osv rc $osv_rc)"
