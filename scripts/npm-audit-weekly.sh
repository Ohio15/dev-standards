#!/usr/bin/env bash
# Weekly npm-audit roll-up across all Node.js repos under one or more roots.
#
# A repo is in scope when it has a root package.json or a lockfile anywhere in
# its tree (node_modules and .git pruned). It is audited as every package
# directory it holds: the root (when it has a package.json) plus every
# directory holding a lockfile of its own, i.e. each standalone install such
# as deploy/<svc>/pnpm-lock.yaml installed --ignore-workspace (item 0323e3cc:
# until 1.2.2 only the root lockfile was read, so a repo whose nested package
# carried 26 prod highs reported prod-clean). A workspace member has no
# lockfile of its own, so it is covered once, through the root. The repo entry
# is "ok" only when EVERY directory was examined, with counts summed over
# them; one unexamined directory makes the whole repo "error" with null counts
# ("<dir>:<reason>" in its reason). Per-directory results are in "units" and
# the audited lockfiles in "lockfiles". For each package directory:
#   * picks the auditor from the committed lockfile: npm-shrinkwrap.json or
#     package-lock.json -> npm; pnpm-lock.yaml -> pnpm (npm wins when both)
#   * runs `npm audit --json` + `npm audit --omit=dev --json`, or
#     `pnpm audit --json` + `pnpm audit --prod --json`
#   * captures totals by severity (both tools emit .metadata.vulnerabilities)
#   * best-effort cross-references against CISA KEV
#
# A repo with no lockfile is reason "no-lockfile" (its dependencies are not
# pinned, so there is nothing to audit: a repo defect). A yarn or bun lockfile
# is "unsupported-lockfile:<tool>" (an exporter gap). Both are unexamined.
#
# Writes per-repo + roll-up to <output-dir>/npm-audit-<YYYY-MM-DD>.json.
#
# Unknown is never clean (SC-07). Every repo entry carries status "ok" or
# "error". "ok" means BOTH audits returned a numeric .metadata.vulnerabilities
# summary and no .error; only then are counts emitted. On any failure (npm or
# jq missing, no lockfile, audit error such as ENOLOCK/network/registry,
# timeout, empty or unparseable output) the entry is status "error" with a
# "reason" and every count is null, never 0. The roll-up has the same status,
# repos_ok/repos_error, and its totals cover examined repos only.
#
# Exit codes: 0 examined and under thresholds; 3 thresholds exceeded;
# 4 some repo (or the run) was not examined (a report is still written).
#
# npm configuration is the operator's, never the scanned repo's (audit
# 2026-11-10.2 M3, SC-07/SC-12). npm reads <project>/.npmrc from the directory
# it runs in, and its env override cannot neutralise every key that file sets
# (an empty npm_config_* value is ignored, so a repo `cafile=`, `noproxy=` or
# `@scope:registry=` survives any env pin; probed against npm 11.7). So npm
# never runs in the repo: package.json, the lockfile and each workspace
# manifest the lockfile names are copied (regular files only, no symlink on
# the path, nothing outside the repo) into an operator-owned scratch tree with
# no .npmrc, and npm runs there with userconfig/globalconfig pinned to empty
# files this script creates, the public registry, strict-ssl on, proxies off
# and scripts off. A tree that cannot be staged is status "error", never ok.
#
# pnpm gets the same isolation, adapted to what pnpm actually reads (probed
# against pnpm 12.21.0 under corepack 0.34.6 on NEXUS, 2026-11-22):
#   * pnpm-workspace.yaml is config, not only a package list: its `registry:`
#     redirects the audit (probed: a dead registry there hangs the audit) and
#     it can carry auditConfig, overrides and configDependencies. The repo's
#     copy is never staged. The script writes its own `packages: []`, which
#     also ends pnpm's search for a workspace root above the scratch dir. The
#     audit reads the dependency graph from the lockfile's importers (workspace
#     packages included), so workspace manifests are not staged either:
#     probed, staging them plus the repo's yaml gives identical counts on all
#     three estate pnpm repos.
#   * package.json is rebuilt by jq from its name, version and dependency
#     fields only, dropping "pnpm" (overrides, auditConfig ignores),
#     "packageManager" and "devEngines" (corepack and pnpm fetch and run the
#     version a repo names). COREPACK_ENABLE_PROJECT_SPEC=0 keeps corepack on
#     the operator's pnpm whatever a parent dir's package.json names.
#   * pnpm 12 ignores npm_config_* for settings and reads pnpm_config_*, but
#     still takes registry from npm_config_userconfig and settings from
#     $XDG_CONFIG_HOME/pnpm/config.yaml (all probed). Both prefixes are pinned
#     (older pnpm reads npm_config_*), the userconfig is the empty file and
#     XDG_CONFIG_HOME an empty dir. .npmrc and .pnpmfile.cjs are never staged.
#   * repo audit ignores (pnpm auditConfig) are dropped on purpose: this is the
#     operator's estate count, and accepted risk lives in the operator's
#     .github/npm-audit-exceptions.json, never in the scanned repo.
#
# Designed to run from cron weekly. Idempotent.

set -uo pipefail

# ------------------------------- defaults --------------------------------
ROOTS=()
OUTPUT_DIR=""
BRAIN_STORE="false"
DRY_RUN="false"
THRESH_CRIT="${THRESH_CRIT:-1}"      # exit non-zero if critical >= this
THRESH_HIGH="${THRESH_HIGH:-3}"      # exit non-zero if high >= this
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ------------------------------- args ------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) ROOTS+=("$2"); shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --brain-store) BRAIN_STORE="true"; shift ;;
    --dry-run) DRY_RUN="true"; shift ;;
    -h|--help)
      cat <<USAGE
npm-audit-weekly.sh — weekly npm/pnpm audit roll-up

Usage: $0 [--root <path>]... [--output-dir <dir>] [--brain-store] [--dry-run]

Options:
  --root <path>      Root directory to scan (repeatable).
                     Defaults: D:/Projects on Windows, ~/ elsewhere.
  --output-dir <dir> Where to write the report (default: ~/scans/).
  --brain-store      Post the summary to shared-brain.
  --dry-run          Print summary; skip file write and brain post.
  --help             This message.

Environment:
  THRESH_CRIT=$THRESH_CRIT  exit non-zero when critical-count >= this
  THRESH_HIGH=$THRESH_HIGH  exit non-zero when high-count >= this
  MAX_PACKAGE_DIRS=${MAX_PACKAGE_DIRS:-50}  a repo with more package dirs is unexamined
USAGE
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

# Default roots
if [[ ${#ROOTS[@]} -eq 0 ]]; then
  case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*) ROOTS=("/d/Projects") ;;
    *) ROOTS=("$HOME") ;;
  esac
fi

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$HOME/scans"
fi
mkdir -p "$OUTPUT_DIR"

SCAN_DATE="$(date -u +%Y-%m-%d)"
REPORT_FILE="$OUTPUT_DIR/npm-audit-$SCAN_DATE.json"
TMP_DIR="$(mktemp -d -t npm-audit.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ------------------------------- KEV fetch -------------------------------
KEV_FILE="$TMP_DIR/kev.json"
if command -v curl >/dev/null 2>&1; then
  curl -sS --max-time 30 "$KEV_URL" -o "$KEV_FILE" 2>/dev/null \
    || echo "{}" > "$KEV_FILE"
else
  echo "{}" > "$KEV_FILE"
fi

# Extract KEV CVE list (best-effort; skip silently if jq missing)
KEV_CVES=""
if command -v jq >/dev/null 2>&1; then
  KEV_CVES="$(jq -r '.vulnerabilities[]?.cveID // empty' < "$KEV_FILE" 2>/dev/null | sort -u || true)"
fi

# ------------------------------- discover repos --------------------------
LOCK_FIND_EXPR=( -name npm-shrinkwrap.json -o -name package-lock.json -o -name pnpm-lock.yaml
                 -o -name yarn.lock -o -name bun.lock -o -name bun.lockb )

# Every lockfile below <repo> as a NUL-separated list of repo-relative paths,
# written to file $2. node_modules (installed trees) and .git are pruned; find
# does not follow a symlinked directory, so nothing outside the repo is
# reached, and a symlinked lockfile is listed so staging refuses it rather than
# reading it as absent. Returns find's exit status: a walk that failed is not
# a walk that found nothing.
list_lockfiles() {
  local repo="$1" out="$2"
  find "$repo" \( -name .git -o -name node_modules \) -prune \
    -o \( -type f -o -type l \) \( "${LOCK_FIND_EXPR[@]}" \) -printf '%P\0' > "$out" 2>/dev/null
}

REPOS=()
for root in "${ROOTS[@]}"; do
  if [[ ! -d "$root" ]]; then continue; fi
  # Top-level only — same scoping as the hygiene scanner. A repo is in scope
  # when it has a root package.json OR a lockfile anywhere in the tree: a
  # standalone package in a subdirectory (frontend/, deploy/<svc>/) carries its
  # own lockfile and is never covered by the root's (item 0323e3cc). A repo
  # whose walk fails is kept so it reports as unexamined, never dropped.
  for d in "$root"/*/; do
    [[ -d "$d" && -d "$d/.git" ]] || continue
    d="${d%/}"
    if [[ -f "$d/package.json" ]]; then REPOS+=("$d"); continue; fi
    if ! list_lockfiles "$d" "$TMP_DIR/discover.lst" || [[ -s "$TMP_DIR/discover.lst" ]]; then REPOS+=("$d"); fi
  done
done

# ------------------------------- helpers ---------------------------------
# Escape a string for embedding in hand-built JSON. Used instead of jq so the
# report stays valid JSON even when jq itself is the missing dependency.
json_str() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="$(printf '%s' "$s" | tr -d '\000-\037')"
  printf '"%s"' "$s"
}

# Validate one `npm audit --json` / `pnpm audit --json` result. Prints "" when it carries a usable
# severity summary, else a short reason token. A result is usable only if it is
# a JSON object with no .error and .metadata.vulnerabilities holding all five
# numeric severities. "Nothing found" and "the audit never ran" are different
# facts: only the first may become zeros (SC-07, SC-04).
audit_file_problem() {
  local file="$1" rc="$2"
  if [[ "$rc" == "124" ]]; then echo "audit-timeout"; return; fi
  if [[ ! -s "$file" ]]; then
    # pnpm reports its failures (ERR_PNPM_BROKEN_LOCKFILE, ...) on stderr only.
    local code=""
    [[ -f "$file.err" ]] && code="$(grep -o 'ERR_PNPM_[A-Z0-9_]*' "$file.err" 2>/dev/null | head -1 | cut -c1-80)"
    if [[ -n "$code" ]]; then echo "audit-error:$code"; else echo "audit-no-output(rc=$rc)"; fi
    return
  fi
  if ! jq -e 'type == "object"' < "$file" >/dev/null 2>&1; then
    echo "audit-output-unparseable(rc=$rc)"; return
  fi
  if jq -e '.error' < "$file" >/dev/null 2>&1; then
    local err
    err="$(jq -r '.error | (.code // .summary // "unknown") | tostring' < "$file" 2>/dev/null | tr -cd 'A-Za-z0-9_ .:-' | cut -c1-80)"
    echo "audit-error:${err:-unknown}"; return
  fi
  if ! jq -e '(.metadata.vulnerabilities // null) as $v
              | ($v | type) == "object"
              and ([ "info","low","moderate","high","critical" ]
                   | all(. as $k | ($v[$k] | type) == "number"))' < "$file" >/dev/null 2>&1; then
    echo "audit-summary-missing"; return
  fi
}

# True when <repo>/<rel> is a regular file and no component of <rel>
# (the leaf included) is a symlink: a committed `package-lock.json -> ~/x`
# must not be read (audit 2026-11-10.2 M3/M4, proposed SC-58).
repo_regular_file() {
  local repo="$1" rel="$2" cur part
  case "/$rel/" in
    *"/../"*|*"/./"*|"//"*) return 1 ;;
  esac
  cur="$repo"
  local IFS=/
  for part in $rel; do
    [[ -n "$part" ]] || return 1
    cur="$cur/$part"
    [[ -L "$cur" ]] && return 1
  done
  [[ -f "$cur" ]]
}

# The lockfile a repo commits, as "<tool>:<file>", or "" for none.
# npm-shrinkwrap.json wins over package-lock.json as npm itself prefers it,
# and npm over pnpm so a repo carrying both keeps its npm result. Presence
# counts a symlink too, so a symlinked lockfile is refused at staging rather
# than read as absent.
lockfile_kind() {
  local repo="$1" f
  for f in npm-shrinkwrap.json package-lock.json; do
    if [[ -e "$repo/$f" || -L "$repo/$f" ]]; then echo "npm:$f"; return; fi
  done
  if [[ -e "$repo/pnpm-lock.yaml" || -L "$repo/pnpm-lock.yaml" ]]; then echo "pnpm:pnpm-lock.yaml"; return; fi
  if [[ -e "$repo/yarn.lock" || -L "$repo/yarn.lock" ]]; then echo "yarn:yarn.lock"; return; fi
  for f in bun.lock bun.lockb; do
    if [[ -e "$repo/$f" || -L "$repo/$f" ]]; then echo "bun:$f"; return; fi
  done
  echo ""
}

# Copy what `npm audit` reads (package.json, the lockfile, every workspace
# manifest the lockfile lists) from repo $1 into the empty dir $2. Echoes ""
# when staged, else a reason token. Never copies .npmrc or anything else.
stage_audit_tree() {
  local repo="$1" dest="$2" f lock="" key
  for f in package.json package-lock.json npm-shrinkwrap.json; do
    if [[ -e "$repo/$f" || -L "$repo/$f" ]]; then
      if ! repo_regular_file "$repo" "$f"; then echo "stage-refused:$f-not-a-regular-file"; return; fi
      if ! cp -- "$repo/$f" "$dest/$f"; then echo "stage-copy-failed:$f"; return; fi
    fi
  done
  # npm prefers npm-shrinkwrap.json over package-lock.json.
  if [[ -f "$dest/npm-shrinkwrap.json" ]]; then lock="$dest/npm-shrinkwrap.json"; else lock="$dest/package-lock.json"; fi
  local keys
  if ! keys="$(jq -r '(.packages // {}) | keys[] | select(. != "" and (test("(^|/)node_modules/") | not))' < "$lock" 2>/dev/null)"; then
    echo "stage-lockfile-unparseable"; return
  fi
  while IFS= read -r key; do
    [[ -n "$key" ]] || continue
    key="${key%$'\r'}"
    if [[ ! "$key" =~ ^[A-Za-z0-9_@][A-Za-z0-9._@/-]*$ ]] || [[ "/$key/" == *"/../"* ]]; then
      echo "stage-refused:workspace-path-outside-repo"; return
    fi
    if [[ -e "$repo/$key/package.json" || -L "$repo/$key/package.json" || -L "$repo/$key" ]]; then
      if ! repo_regular_file "$repo" "$key/package.json"; then
        echo "stage-refused:workspace-manifest-not-a-regular-file"; return
      fi
      if ! mkdir -p -- "$dest/$key" || ! cp -- "$repo/$key/package.json" "$dest/$key/package.json"; then
        echo "stage-copy-failed:workspace-manifest"; return
      fi
    fi
  done <<<"$keys"
}

# Stage what `pnpm audit` reads from repo $1 into the empty dir $2: the
# lockfile verbatim, a package.json rebuilt from its dependency fields only,
# and a pnpm-workspace.yaml this script writes (header). Echoes "" when staged,
# else a reason token. Never copies the repo's pnpm-workspace.yaml, .npmrc,
# .pnpmfile.cjs, workspace manifests or anything else.
stage_pnpm_tree() {
  local repo="$1" dest="$2" f
  for f in package.json pnpm-lock.yaml; do
    if ! repo_regular_file "$repo" "$f"; then echo "stage-refused:$f-not-a-regular-file"; return; fi
  done
  if ! cp -- "$repo/pnpm-lock.yaml" "$dest/pnpm-lock.yaml"; then echo "stage-copy-failed:pnpm-lock.yaml"; return; fi
  if ! jq -e 'type == "object"' < "$repo/package.json" >/dev/null 2>&1 \
     || ! jq '{name, version, dependencies, devDependencies, optionalDependencies, peerDependencies}
              | with_entries(select(.value != null))' < "$repo/package.json" > "$dest/package.json" 2>/dev/null; then
    echo "stage-manifest-unparseable"; return
  fi
  if ! printf 'packages: []\n' > "$dest/pnpm-workspace.yaml"; then echo "stage-copy-failed:pnpm-workspace.yaml"; return; fi
}

# Run one audit by tool $1 ("npm" or "pnpm") of the staged tree $2 into $3
# (stderr into $3.err) with a timeout; echoes the exit code. The environment
# is the whole package-manager configuration (header).
run_audit() {
  local tool="$1" tree="$2" out="$3"; shift 3
  local rc=0
  local -a pm_env=(
    npm_config_userconfig="$NPM_USERCONFIG"
    npm_config_globalconfig="$NPM_GLOBALCONFIG"
    npm_config_registry="https://registry.npmjs.org/"
    npm_config_strict_ssl=true
    npm_config_proxy=false
    npm_config_https_proxy=false
    npm_config_ignore_scripts=true
    npm_config_update_notifier=false
    npm_config_fund=false
  )
  if [[ "$tool" == "pnpm" ]]; then
    pm_env+=(
      pnpm_config_registry="https://registry.npmjs.org/"
      pnpm_config_strict_ssl=true
      pnpm_config_proxy=false
      pnpm_config_https_proxy=false
      pnpm_config_ignore_scripts=true
      pnpm_config_update_notifier=false
      npm_config_manage_package_manager_versions=false
      pnpm_config_manage_package_manager_versions=false
      XDG_CONFIG_HOME="$PNPM_XDG_CONFIG"
      COREPACK_ENABLE_PROJECT_SPEC=0
      COREPACK_ENABLE_AUTO_PIN=0
      COREPACK_ENABLE_DOWNLOAD_PROMPT=0
      COREPACK_DEFAULT_TO_LATEST=0
    )
  fi
  if [[ -n "$TIMEOUT_BIN" ]]; then
    ( cd "$tree" && env "${pm_env[@]}" "$TIMEOUT_BIN" "$AUDIT_TIMEOUT" "$tool" audit "$@" --json > "$out" 2>"$out.err" ) || rc=$?
  else
    ( cd "$tree" && env "${pm_env[@]}" "$tool" audit "$@" --json > "$out" 2>"$out.err" ) || rc=$?
  fi
  echo "$rc"
}

# ------------------------------- per-repo audit --------------------------
RAW_DIR="$TMP_DIR/raw"
STAGE_DIR="$TMP_DIR/stage"
mkdir -p "$RAW_DIR" "$STAGE_DIR"
# Empty, operator-owned npm user/global config (header): created here, in the
# mktemp dir, so nothing a scanned repo or the account's ~/.npmrc holds applies.
NPM_USERCONFIG="$TMP_DIR/npmrc-user"
NPM_GLOBALCONFIG="$TMP_DIR/npmrc-global"
: > "$NPM_USERCONFIG"
: > "$NPM_GLOBALCONFIG"
PNPM_XDG_CONFIG="$TMP_DIR/xdg-config"
mkdir -p "$PNPM_XDG_CONFIG"

AUDIT_TIMEOUT="${AUDIT_TIMEOUT:-180}"
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN="$(command -v timeout)"; fi

HAVE_JQ="false"; command -v jq >/dev/null 2>&1 && HAVE_JQ="true"
HAVE_NPM="false"; command -v npm >/dev/null 2>&1 && HAVE_NPM="true"
HAVE_PNPM="false"; command -v pnpm >/dev/null 2>&1 && HAVE_PNPM="true"
KEV_CHECKED="false"; [[ -n "$KEV_CVES" ]] && KEV_CHECKED="true"

declare -A SEV_TOTALS
SEV_TOTALS[critical]=0
SEV_TOTALS[high]=0
SEV_TOTALS[moderate]=0
SEV_TOTALS[low]=0
SEV_TOTALS[info]=0

REPOS_OK=0
REPOS_ERROR=0
ERROR_LINES=()
PER_REPO_JSON="["
first="true"

# True when <repo>/<rel> is a directory and no component of <rel> is a
# symlink: a package directory is entered only through real directories.
repo_real_dir() {
  local repo="$1" rel="$2" cur part
  case "/$rel/" in
    *"/../"*|*"/./"*|"//"*) return 1 ;;
  esac
  cur="$repo"
  local IFS=/
  for part in $rel; do
    [[ -n "$part" ]] || return 1
    cur="$cur/$part"
    [[ -L "$cur" ]] && return 1
  done
  [[ -d "$cur" ]]
}

# Audit one package directory <repo>/<rel> ("." is the root) as unit $4 of
# repo number $3. Sets U_REASON ("" when examined), U_LOCK (the lockfile name,
# "" for none), U_CRIT U_HIGH U_MOD U_LOW U_INFO U_PCRIT U_PHIGH and U_CVES.
# Counts are set only when U_REASON is "".
audit_unit() {
  local repo="$1" rel="$2" ridx="$3" uidx="$4"
  local dir lock tool tree problem prod_flag full_rc prod_rc
  local full_json="$RAW_DIR/$ridx.$uidx.full.json" prod_json="$RAW_DIR/$ridx.$uidx.prod.json"
  U_REASON=""; U_LOCK=""; U_CVES=""
  U_CRIT=""; U_HIGH=""; U_MOD=""; U_LOW=""; U_INFO=""; U_PCRIT=""; U_PHIGH=""
  if [[ "$rel" == "." ]]; then
    dir="$repo"
  elif repo_real_dir "$repo" "$rel"; then
    dir="$repo/$rel"
  else
    U_REASON="stage-refused:package-dir-not-a-real-directory"; return
  fi
  lock="$(lockfile_kind "$dir")"
  tool="${lock%%:*}"
  U_LOCK="${lock#*:}"

  if [[ -z "$lock" ]]; then
    # Nothing pins the dependency tree, so no auditor can examine it.
    U_REASON="no-lockfile"
  elif [[ "$tool" != "npm" && "$tool" != "pnpm" ]]; then
    U_REASON="unsupported-lockfile:$tool"
  elif [[ "$tool" == "npm" && "$HAVE_NPM" != "true" ]]; then
    U_REASON="npm-missing"
  elif [[ "$tool" == "pnpm" && "$HAVE_PNPM" != "true" ]]; then
    U_REASON="pnpm-missing"
  elif [[ "$HAVE_JQ" != "true" ]]; then
    U_REASON="jq-missing"
  else
    tree="$STAGE_DIR/$ridx.$uidx"
    if ! mkdir -- "$tree"; then
      U_REASON="stage-dir-failed"
    elif [[ "$tool" == "pnpm" ]]; then
      U_REASON="$(stage_pnpm_tree "$dir" "$tree")"
    else
      U_REASON="$(stage_audit_tree "$dir" "$tree")"
    fi
  fi
  [[ -n "$U_REASON" ]] && return

  # Both audits exit non-zero on findings, so the exit code alone says nothing;
  # the JSON body decides (audit_file_problem). Only 124 (timeout) is read from rc.
  if [[ "$tool" == "pnpm" ]]; then prod_flag="--prod"; else prod_flag="--omit=dev"; fi
  full_rc="$(run_audit "$tool" "$tree" "$full_json")"
  prod_rc="$(run_audit "$tool" "$tree" "$prod_json" "$prod_flag")"
  problem="$(audit_file_problem "$full_json" "$full_rc")"
  if [[ -n "$problem" ]]; then U_REASON="full:$problem"; return; fi
  problem="$(audit_file_problem "$prod_json" "$prod_rc")"
  if [[ -n "$problem" ]]; then U_REASON="prod:$problem"; return; fi

  U_CRIT=$(jq -r '.metadata.vulnerabilities.critical' < "$full_json")
  U_HIGH=$(jq -r '.metadata.vulnerabilities.high' < "$full_json")
  U_MOD=$(jq -r '.metadata.vulnerabilities.moderate' < "$full_json")
  U_LOW=$(jq -r '.metadata.vulnerabilities.low' < "$full_json")
  U_INFO=$(jq -r '.metadata.vulnerabilities.info' < "$full_json")
  U_PCRIT=$(jq -r '.metadata.vulnerabilities.critical' < "$prod_json")
  U_PHIGH=$(jq -r '.metadata.vulnerabilities.high' < "$prod_json")
  # CVE IDs from advisory entries, intersected with KEV by the caller.
  # npm: .vulnerabilities[].via[].url; pnpm: .advisories[].cves[] and .url.
  U_CVES=$(jq -r '
    ( [ .vulnerabilities[]?.via[]? | select(type=="object") | .url // empty ]
      + [ .advisories[]? | ((.cves // [])[]?), (.url // empty) ] )
    | map(strings | capture("CVE-[0-9]{4}-[0-9]+"; "g")?.[]?)
    | unique[]?
  ' < "$full_json" 2>/dev/null | sort -u || true)
}

# A repo is audited as every package directory it holds: the root when it has
# a package.json, and every directory holding a lockfile (item 0323e3cc). A
# directory with a lockfile of its own is a standalone install (a workspace
# member has none: the root lockfile resolves it), so the root audit never
# covers it. The repo is "ok" only when EVERY directory was examined; its
# counts are the sums over them. One unexamined directory makes the whole repo
# "error" with null counts, so a repo is never reported prod-clean on the
# strength of its root lockfile alone (SC-07). MAX_PACKAGE_DIRS bounds the
# audits per repo; a repo over it is unexamined, never truncated.
MAX_PACKAGE_DIRS="${MAX_PACKAGE_DIRS:-50}"
if [[ ! "$MAX_PACKAGE_DIRS" =~ ^[1-9][0-9]*$ ]]; then
  echo "MAX_PACKAGE_DIRS must be a positive integer, got '$MAX_PACKAGE_DIRS'" >&2
  exit 2
fi

repo_idx=0
for repo in "${REPOS[@]}"; do
  name="$(basename "$repo")"
  echo "auditing $name..." >&2
  repo_idx=$(( repo_idx + 1 ))

  walk_reason=""
  units=()
  [[ -e "$repo/package.json" || -L "$repo/package.json" ]] && units+=(".")
  locks_file="$TMP_DIR/locks.$repo_idx"
  if ! list_lockfiles "$repo" "$locks_file"; then
    walk_reason="lockfile-walk-failed"
  else
    while IFS= read -r -d '' rel; do
      # A path is repo content: a control character (a newline above all)
      # would split the list or forge report lines, so the repo is refused.
      if [[ "$rel" == *[[:cntrl:]]* ]]; then walk_reason="unsafe-lockfile-path"; break; fi
      if [[ "$rel" == */* ]]; then units+=("${rel%/*}"); else units+=("."); fi
    done < "$locks_file"
  fi
  if [[ -z "$walk_reason" && ${#units[@]} -gt 0 ]]; then
    mapfile -t units < <(printf '%s\n' "${units[@]}" | LC_ALL=C sort -u)
  fi
  if [[ -z "$walk_reason" ]] && (( ${#units[@]} > MAX_PACKAGE_DIRS )); then
    walk_reason="too-many-package-dirs:${#units[@]}>${MAX_PACKAGE_DIRS}"
  fi
  if [[ -z "$walk_reason" && ${#units[@]} -eq 0 ]]; then
    walk_reason="no-lockfile"
  fi

  reasons=()
  root_lock=""
  lockfiles_json="["
  units_json="["
  r_crit=0; r_high=0; r_mod=0; r_low=0; r_info=0; r_pcrit=0; r_phigh=0
  r_cves=""
  if [[ -n "$walk_reason" ]]; then
    reasons+=("$walk_reason")
  else
    unit_idx=0
    for rel in "${units[@]}"; do
      unit_idx=$(( unit_idx + 1 ))
      audit_unit "$repo" "$rel" "$repo_idx" "$unit_idx"
      if [[ "$rel" == "." ]]; then
        root_lock="$U_LOCK"; path_prefix=""; lock_path="$U_LOCK"
      else
        path_prefix="$rel:"; lock_path="${U_LOCK:+$rel/$U_LOCK}"
      fi
      if [[ -n "$lock_path" ]]; then
        [[ "$lockfiles_json" == "[" ]] || lockfiles_json+=","
        lockfiles_json+="$(json_str "$lock_path")"
      fi
      lock_json="null"; [[ -n "$U_LOCK" ]] && lock_json="$(json_str "$U_LOCK")"
      [[ "$units_json" == "[" ]] || units_json+=","
      if [[ -n "$U_REASON" ]]; then
        reasons+=("$path_prefix$U_REASON")
        units_json+=$(printf '{"path":%s,"lockfile":%s,"status":"error","reason":%s,"critical":null,"high":null,"moderate":null,"low":null,"info":null,"prod_critical":null,"prod_high":null}' \
          "$(json_str "$rel")" "$lock_json" "$(json_str "$U_REASON")")
      else
        units_json+=$(printf '{"path":%s,"lockfile":%s,"status":"ok","reason":null,"critical":%s,"high":%s,"moderate":%s,"low":%s,"info":%s,"prod_critical":%s,"prod_high":%s}' \
          "$(json_str "$rel")" "$lock_json" "$U_CRIT" "$U_HIGH" "$U_MOD" "$U_LOW" "$U_INFO" "$U_PCRIT" "$U_PHIGH")
        r_crit=$(( r_crit + U_CRIT )); r_high=$(( r_high + U_HIGH )); r_mod=$(( r_mod + U_MOD ))
        r_low=$(( r_low + U_LOW )); r_info=$(( r_info + U_INFO ))
        r_pcrit=$(( r_pcrit + U_PCRIT )); r_phigh=$(( r_phigh + U_PHIGH ))
        if [[ -n "$U_CVES" ]]; then r_cves+="$U_CVES"$'\n'; fi
      fi
    done
  fi
  lockfiles_json+="]"
  units_json+="]"
  root_lock_json="null"; [[ -n "$root_lock" ]] && root_lock_json="$(json_str "$root_lock")"

  if (( ${#reasons[@]} > 0 )); then
    # Unexamined, wholly or in part: no counts at all (null), never zeros.
    reason="$(printf '%s; ' "${reasons[@]}")"; reason="${reason%; }"
    REPOS_ERROR=$(( REPOS_ERROR + 1 ))
    ERROR_LINES+=("$name: $reason")
    echo "  UNEXAMINED $name: $reason" >&2
    entry=$(printf '{"repo":%s,"path":%s,"status":"error","reason":%s,"lockfile":%s,"lockfiles":%s,"units":%s,"critical":null,"high":null,"moderate":null,"low":null,"info":null,"prod_critical":null,"prod_high":null,"kev_cves":null,"kev_checked":false}' \
      "$(json_str "$name")" "$(json_str "$repo")" "$(json_str "$reason")" "$root_lock_json" "$lockfiles_json" "$units_json")
  else
    REPOS_OK=$(( REPOS_OK + 1 ))
    # KEV cross-reference over every directory's CVEs (best effort, reported
    # via kev_checked so a failed KEV fetch is not read as "no KEV hits").
    cves="$(printf '%s' "$r_cves" | sed '/^$/d' | sort -u)"
    kev_hits=""
    if [[ -n "$KEV_CVES" && -n "$cves" ]]; then
      kev_hits=$(comm -12 <(echo "$cves") <(echo "$KEV_CVES") | tr '\n' ',' | sed 's/,$//')
    fi

    SEV_TOTALS[critical]=$(( SEV_TOTALS[critical] + r_crit ))
    SEV_TOTALS[high]=$(( SEV_TOTALS[high] + r_high ))
    SEV_TOTALS[moderate]=$(( SEV_TOTALS[moderate] + r_mod ))
    SEV_TOTALS[low]=$(( SEV_TOTALS[low] + r_low ))
    SEV_TOTALS[info]=$(( SEV_TOTALS[info] + r_info ))

    entry=$(printf '{"repo":%s,"path":%s,"status":"ok","reason":null,"lockfile":%s,"lockfiles":%s,"units":%s,"critical":%s,"high":%s,"moderate":%s,"low":%s,"info":%s,"prod_critical":%s,"prod_high":%s,"kev_cves":%s,"kev_checked":%s}' \
      "$(json_str "$name")" "$(json_str "$repo")" "$root_lock_json" "$lockfiles_json" "$units_json" \
      "$r_crit" "$r_high" "$r_mod" "$r_low" "$r_info" "$r_pcrit" "$r_phigh" \
      "$(json_str "$kev_hits")" "$KEV_CHECKED")
  fi

  if [[ "$first" == "true" ]]; then first="false"; else PER_REPO_JSON+=","; fi
  PER_REPO_JSON+="$entry"
done

PER_REPO_JSON+="]"

# Roll-up status: "ok" only when at least one repo was found and every repo was
# examined. Zero repos found means the roots were wrong or empty - unexamined.
if [[ ${#REPOS[@]} -eq 0 ]]; then
  ROLLUP_STATUS="error"; ROLLUP_REASON="no-repos-discovered"
elif (( REPOS_ERROR > 0 )); then
  ROLLUP_STATUS="error"; ROLLUP_REASON="${REPOS_ERROR}-of-${#REPOS[@]}-repos-unexamined"
else
  ROLLUP_STATUS="ok"; ROLLUP_REASON=""
fi

# ------------------------------- write report ----------------------------
ROOTS_JSON="["
rfirst="true"
for r in "${ROOTS[@]}"; do
  if [[ "$rfirst" == "true" ]]; then rfirst="false"; else ROOTS_JSON+=","; fi
  ROOTS_JSON+="$(json_str "$r")"
done
ROOTS_JSON+="]"

# totals are over examined repos only; when repos_error > 0 they are a floor,
# not the estate total.
SUMMARY=$(printf '{"scan_date":"%s","status":"%s","reason":%s,"roots":%s,"repo_count":%s,"repos_ok":%s,"repos_error":%s,"totals":{"critical":%s,"high":%s,"moderate":%s,"low":%s,"info":%s},"thresholds":{"critical":%s,"high":%s},"repos":%s}' \
  "$SCAN_DATE" "$ROLLUP_STATUS" "$(json_str "$ROLLUP_REASON")" "$ROOTS_JSON" \
  "${#REPOS[@]}" "$REPOS_OK" "$REPOS_ERROR" \
  "${SEV_TOTALS[critical]}" "${SEV_TOTALS[high]}" "${SEV_TOTALS[moderate]}" "${SEV_TOTALS[low]}" "${SEV_TOTALS[info]}" \
  "$THRESH_CRIT" "$THRESH_HIGH" \
  "$PER_REPO_JSON")

PRETTY="$SUMMARY"
if [[ "$HAVE_JQ" == "true" ]]; then
  PRETTY=$(echo "$SUMMARY" | jq . 2>/dev/null || echo "$SUMMARY")
fi

# Human summary
{
  echo "# npm audit weekly — $SCAN_DATE"
  echo ""
  echo "Roots: ${ROOTS[*]}"
  echo "Status: $ROLLUP_STATUS${ROLLUP_REASON:+ ($ROLLUP_REASON)}"
  echo "Repos found: ${#REPOS[@]}  examined: $REPOS_OK  UNEXAMINED: $REPOS_ERROR"
  echo ""
  echo "Totals (examined repos only):"
  echo "  critical=${SEV_TOTALS[critical]}"
  echo "  high=${SEV_TOTALS[high]}"
  echo "  moderate=${SEV_TOTALS[moderate]}"
  echo "  low=${SEV_TOTALS[low]}"
  echo "  info=${SEV_TOTALS[info]}"
  echo ""
  echo "Thresholds: critical>=$THRESH_CRIT  high>=$THRESH_HIGH"
  if (( ${#ERROR_LINES[@]} > 0 )); then
    echo ""
    echo "Unexamined repos (NOT clean):"
    printf '  %s\n' "${ERROR_LINES[@]}"
  fi
} | tee "$TMP_DIR/summary.md"

if [[ "$DRY_RUN" == "true" ]]; then
  echo "[dry-run — not writing $REPORT_FILE]" >&2
else
  echo "$PRETTY" > "$REPORT_FILE"
  echo "[wrote $REPORT_FILE]" >&2
fi

# ------------------------------- brain store -----------------------------
if [[ "$BRAIN_STORE" == "true" && "$DRY_RUN" != "true" ]]; then
  KEY_FILE="$HOME/.config/shared-brain/api-key"
  if [[ -f "$KEY_FILE" ]]; then
    api_key=$(cat "$KEY_FILE")
    summary_text=$(cat "$TMP_DIR/summary.md")
    body=$(jq -n \
      --arg c "$summary_text" \
      --arg t "npm-audit-$SCAN_DATE" \
      '{type:"observation",tags:[$t,"automation","npm-audit"],content:$c,importance:0.65,domain:"security",project:"dev-standards"}' \
      2>/dev/null || echo '{}')
    if [[ "$body" != "{}" ]]; then
      resp=$(curl -sS -X POST \
        -H "Authorization: Bearer $api_key" \
        -H "Content-Type: application/json" \
        -d "$body" \
        https://shared-brain.us/api/memory/ingest 2>&1)
      if [[ "$resp" == \{* ]]; then
        echo "[brain-store ok]" >&2
      else
        echo "[brain-store failed: ${resp:0:120}]" >&2
      fi
    fi
  else
    echo "[brain-store skipped — no api-key at $KEY_FILE]" >&2
  fi
fi

# ------------------------------- exit code -------------------------------
# 3 = thresholds exceeded, 4 = some repo (or the whole run) could not be
# examined. Both are non-zero so cron alerts; 0 means examined and under threshold.
if (( SEV_TOTALS[critical] >= THRESH_CRIT )) || (( SEV_TOTALS[high] >= THRESH_HIGH )); then
  echo "ALERT: thresholds exceeded" >&2
  exit 3
fi

if [[ "$ROLLUP_STATUS" != "ok" ]]; then
  echo "ALERT: audit incomplete ($ROLLUP_REASON); unexamined is not clean" >&2
  exit 4
fi

exit 0
