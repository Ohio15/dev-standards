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
# Exits non-zero if any repo crosses configured thresholds (cron will alert).
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

# ------------------------------- per-repo audit --------------------------
RAW_DIR="$TMP_DIR/raw"
mkdir -p "$RAW_DIR"

declare -A SEV_TOTALS
SEV_TOTALS[critical]=0
SEV_TOTALS[high]=0
SEV_TOTALS[moderate]=0
SEV_TOTALS[low]=0
SEV_TOTALS[info]=0

PER_REPO_JSON="["
first="true"

for repo in "${REPOS[@]}"; do
  name="$(basename "$repo")"
  echo "auditing $name..." >&2

  # Run audit (allow non-zero rc — npm audit returns non-zero on findings)
  full_json="$RAW_DIR/$name.full.json"
  prod_json="$RAW_DIR/$name.prod.json"
  ( cd "$repo" && npm audit --json > "$full_json" 2>/dev/null ) || true
  ( cd "$repo" && npm audit --omit=dev --json > "$prod_json" 2>/dev/null ) || true

  # Extract totals (npm v7+ format: .metadata.vulnerabilities.{severity})
  if command -v jq >/dev/null 2>&1; then
    crit=$(jq -r '.metadata.vulnerabilities.critical // 0' < "$full_json" 2>/dev/null || echo 0)
    high=$(jq -r '.metadata.vulnerabilities.high // 0' < "$full_json" 2>/dev/null || echo 0)
    mod=$(jq -r '.metadata.vulnerabilities.moderate // 0' < "$full_json" 2>/dev/null || echo 0)
    low=$(jq -r '.metadata.vulnerabilities.low // 0' < "$full_json" 2>/dev/null || echo 0)
    info=$(jq -r '.metadata.vulnerabilities.info // 0' < "$full_json" 2>/dev/null || echo 0)
    pcrit=$(jq -r '.metadata.vulnerabilities.critical // 0' < "$prod_json" 2>/dev/null || echo 0)
    phigh=$(jq -r '.metadata.vulnerabilities.high // 0' < "$prod_json" 2>/dev/null || echo 0)

    # Collect CVE IDs from advisory entries; intersect with KEV
    cves=$(jq -r '
      [ .vulnerabilities[]?.via[]? | select(type=="object") | .url // empty ]
      | map(capture("CVE-[0-9]{4}-[0-9]+"; "g")?.[]?)
      | unique[]?
    ' < "$full_json" 2>/dev/null | sort -u || true)
    kev_hits=""
    if [[ -n "$KEV_CVES" && -n "$cves" ]]; then
      kev_hits=$(comm -12 <(echo "$cves") <(echo "$KEV_CVES") | tr '\n' ',' | sed 's/,$//')
    fi
  else
    crit=0; high=0; mod=0; low=0; info=0; pcrit=0; phigh=0; kev_hits=""
  fi

  SEV_TOTALS[critical]=$(( SEV_TOTALS[critical] + crit ))
  SEV_TOTALS[high]=$(( SEV_TOTALS[high] + high ))
  SEV_TOTALS[moderate]=$(( SEV_TOTALS[moderate] + mod ))
  SEV_TOTALS[low]=$(( SEV_TOTALS[low] + low ))
  SEV_TOTALS[info]=$(( SEV_TOTALS[info] + info ))

  if [[ "$first" == "true" ]]; then first="false"; else PER_REPO_JSON+=","; fi
  PER_REPO_JSON+=$(printf '{"repo":"%s","path":"%s","critical":%s,"high":%s,"moderate":%s,"low":%s,"info":%s,"prod_critical":%s,"prod_high":%s,"kev_cves":"%s"}' \
    "$name" "$repo" "$crit" "$high" "$mod" "$low" "$info" "$pcrit" "$phigh" "${kev_hits//\"/\\\"}")
done

PER_REPO_JSON+="]"

# ------------------------------- write report ----------------------------
SUMMARY=$(printf '{"scan_date":"%s","roots":%s,"repo_count":%s,"totals":{"critical":%s,"high":%s,"moderate":%s,"low":%s,"info":%s},"thresholds":{"critical":%s,"high":%s},"repos":%s}' \
  "$SCAN_DATE" \
  "$(printf '%s\n' "${ROOTS[@]}" | jq -R . 2>/dev/null | jq -s . 2>/dev/null || echo "[]")" \
  "${#REPOS[@]}" \
  "${SEV_TOTALS[critical]}" "${SEV_TOTALS[high]}" "${SEV_TOTALS[moderate]}" "${SEV_TOTALS[low]}" "${SEV_TOTALS[info]}" \
  "$THRESH_CRIT" "$THRESH_HIGH" \
  "$PER_REPO_JSON")

if command -v jq >/dev/null 2>&1; then
  PRETTY=$(echo "$SUMMARY" | jq . 2>/dev/null || echo "$SUMMARY")
else
  PRETTY="$SUMMARY"
fi

# Human summary
{
  echo "# npm audit weekly — $SCAN_DATE"
  echo ""
  echo "Roots: ${ROOTS[*]}"
  echo "Repos audited: ${#REPOS[@]}"
  echo ""
  echo "Totals:"
  echo "  critical=${SEV_TOTALS[critical]}"
  echo "  high=${SEV_TOTALS[high]}"
  echo "  moderate=${SEV_TOTALS[moderate]}"
  echo "  low=${SEV_TOTALS[low]}"
  echo "  info=${SEV_TOTALS[info]}"
  echo ""
  echo "Thresholds: critical>=$THRESH_CRIT  high>=$THRESH_HIGH"
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
      '{action:"ingest",type:"observation",tags:[$t,"automation","npm-audit"],content:$c,importance:0.65,source:"npm-audit-weekly.sh"}' \
      2>/dev/null || echo '{}')
    if [[ "$body" != "{}" ]]; then
      curl -sS -X POST \
        -H "Authorization: Bearer $api_key" \
        -H "Content-Type: application/json" \
        -d "$body" \
        https://shared-brain.us/api/memory >/dev/null 2>&1 \
        && echo "[brain-store ok]" >&2 \
        || echo "[brain-store failed]" >&2
    fi
  else
    echo "[brain-store skipped — no api-key at $KEY_FILE]" >&2
  fi
fi

# ------------------------------- exit code -------------------------------
if (( SEV_TOTALS[critical] >= THRESH_CRIT )) || (( SEV_TOTALS[high] >= THRESH_HIGH )); then
  echo "ALERT: thresholds exceeded" >&2
  exit 3
fi

exit 0
