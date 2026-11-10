#!/usr/bin/env bash
# Weekly npm-audit roll-up across all Node.js repos under one or more roots.
#
# For each repo containing package.json:
#   * runs `npm audit --json`
#   * runs `npm audit --omit=dev --json`
#   * captures totals by severity
#   * best-effort cross-references against CISA KEV
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
npm-audit-weekly.sh — weekly npm audit roll-up

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
REPOS=()
for root in "${ROOTS[@]}"; do
  if [[ ! -d "$root" ]]; then continue; fi
  # Top-level only — same scoping as the hygiene scanner
  for d in "$root"/*/; do
    [[ -d "$d" ]] || continue
    if [[ -f "$d/package.json" && -d "$d/.git" ]]; then
      REPOS+=("${d%/}")
    fi
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

# Validate one `npm audit --json` result. Prints "" when it carries a usable
# severity summary, else a short reason token. A result is usable only if it is
# a JSON object with no .error and .metadata.vulnerabilities holding all five
# numeric severities. "Nothing found" and "the audit never ran" are different
# facts: only the first may become zeros (SC-07, SC-04).
audit_file_problem() {
  local file="$1" rc="$2"
  if [[ "$rc" == "124" ]]; then echo "audit-timeout"; return; fi
  if [[ ! -s "$file" ]]; then echo "audit-no-output(rc=$rc)"; return; fi
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

# Run one audit into $2 with a timeout; echoes the exit code.
run_audit() {
  local repo="$1" out="$2"; shift 2
  local rc=0
  if [[ -n "$TIMEOUT_BIN" ]]; then
    ( cd "$repo" && "$TIMEOUT_BIN" "$AUDIT_TIMEOUT" npm audit "$@" --json > "$out" 2>/dev/null ) || rc=$?
  else
    ( cd "$repo" && npm audit "$@" --json > "$out" 2>/dev/null ) || rc=$?
  fi
  echo "$rc"
}

# ------------------------------- per-repo audit --------------------------
RAW_DIR="$TMP_DIR/raw"
mkdir -p "$RAW_DIR"

AUDIT_TIMEOUT="${AUDIT_TIMEOUT:-180}"
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN="$(command -v timeout)"; fi

HAVE_JQ="false"; command -v jq >/dev/null 2>&1 && HAVE_JQ="true"
HAVE_NPM="false"; command -v npm >/dev/null 2>&1 && HAVE_NPM="true"
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

for repo in "${REPOS[@]}"; do
  name="$(basename "$repo")"
  echo "auditing $name..." >&2

  reason=""
  full_json="$RAW_DIR/$name.full.json"
  prod_json="$RAW_DIR/$name.prod.json"

  if [[ "$HAVE_NPM" != "true" ]]; then
    reason="npm-missing"
  elif [[ "$HAVE_JQ" != "true" ]]; then
    reason="jq-missing"
  elif [[ ! -f "$repo/package-lock.json" && ! -f "$repo/npm-shrinkwrap.json" ]]; then
    # npm audit reads the lockfile only; without one it errors ENOLOCK, and a
    # repo that locks with yarn/pnpm cannot be examined by this script.
    reason="missing-lockfile"
  else
    # npm audit exits non-zero on findings, so the exit code alone says nothing;
    # the JSON body decides (audit_file_problem). Only 124 (timeout) is read from rc.
    full_rc="$(run_audit "$repo" "$full_json")"
    prod_rc="$(run_audit "$repo" "$prod_json" --omit=dev)"
    problem="$(audit_file_problem "$full_json" "$full_rc")"
    [[ -n "$problem" ]] && reason="full:$problem"
    if [[ -z "$reason" ]]; then
      problem="$(audit_file_problem "$prod_json" "$prod_rc")"
      [[ -n "$problem" ]] && reason="prod:$problem"
    fi
  fi

  if [[ -n "$reason" ]]; then
    # Unexamined: no counts at all (null), never zeros.
    REPOS_ERROR=$(( REPOS_ERROR + 1 ))
    ERROR_LINES+=("$name: $reason")
    echo "  UNEXAMINED $name: $reason" >&2
    entry=$(printf '{"repo":%s,"path":%s,"status":"error","reason":%s,"critical":null,"high":null,"moderate":null,"low":null,"info":null,"prod_critical":null,"prod_high":null,"kev_cves":null,"kev_checked":false}' \
      "$(json_str "$name")" "$(json_str "$repo")" "$(json_str "$reason")")
  else
    REPOS_OK=$(( REPOS_OK + 1 ))
    crit=$(jq -r '.metadata.vulnerabilities.critical' < "$full_json")
    high=$(jq -r '.metadata.vulnerabilities.high' < "$full_json")
    mod=$(jq -r '.metadata.vulnerabilities.moderate' < "$full_json")
    low=$(jq -r '.metadata.vulnerabilities.low' < "$full_json")
    info=$(jq -r '.metadata.vulnerabilities.info' < "$full_json")
    pcrit=$(jq -r '.metadata.vulnerabilities.critical' < "$prod_json")
    phigh=$(jq -r '.metadata.vulnerabilities.high' < "$prod_json")

    # Collect CVE IDs from advisory entries; intersect with KEV (best effort,
    # reported via kev_checked so a failed KEV fetch is not read as "no KEV hits").
    cves=$(jq -r '
      [ .vulnerabilities[]?.via[]? | select(type=="object") | .url // empty ]
      | map(capture("CVE-[0-9]{4}-[0-9]+"; "g")?.[]?)
      | unique[]?
    ' < "$full_json" 2>/dev/null | sort -u || true)
    kev_hits=""
    if [[ -n "$KEV_CVES" && -n "$cves" ]]; then
      kev_hits=$(comm -12 <(echo "$cves") <(echo "$KEV_CVES") | tr '\n' ',' | sed 's/,$//')
    fi

    SEV_TOTALS[critical]=$(( SEV_TOTALS[critical] + crit ))
    SEV_TOTALS[high]=$(( SEV_TOTALS[high] + high ))
    SEV_TOTALS[moderate]=$(( SEV_TOTALS[moderate] + mod ))
    SEV_TOTALS[low]=$(( SEV_TOTALS[low] + low ))
    SEV_TOTALS[info]=$(( SEV_TOTALS[info] + info ))

    entry=$(printf '{"repo":%s,"path":%s,"status":"ok","reason":null,"critical":%s,"high":%s,"moderate":%s,"low":%s,"info":%s,"prod_critical":%s,"prod_high":%s,"kev_cves":%s,"kev_checked":%s}' \
      "$(json_str "$name")" "$(json_str "$repo")" "$crit" "$high" "$mod" "$low" "$info" "$pcrit" "$phigh" \
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
