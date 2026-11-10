#!/usr/bin/env bash
# Shallow, read-only mirror of every estate repo, for the code-standards scan.
#
# Usage: estate-mirror.sh --roster <file> --dir <mirror-root> --status <status-file>
#
# For each repo named in the roster (one GitHub repo name per line, `#`
# comments allowed; owner Ohio15):
#   first time  git clone --depth 1 --no-tags --single-branch
#               git@github.com:Ohio15/<Name>.git <dir>/<lowercase name>
#               (cloned into <dir>/.tmp-<name> and renamed into place, so a
#               half-finished clone is never scanned: discovery skips dot dirs)
#   refresh     git fetch --depth 1 --no-tags origin HEAD
#               git checkout -q --force --detach FETCH_HEAD
#               git clean -ffdq
# `git reset --hard` is never used. Each repo gets 300 s in total; a failure
# or timeout for one repo is recorded and the rest still run.
#
# The mirror is DATA. Nothing inside a mirrored repo is ever executed: every
# git call runs with core.hooksPath=/dev/null and fsmonitor off, prompts are
# disabled (GIT_TERMINAL_PROMPT=0, ssh BatchMode), LFS smudge is skipped, and
# no build, install, hook or script from a mirrored tree is run.
#
# Status file (written atomically, one line per roster repo):
#   <lowercase name> ok <head sha>      refreshed this run
#   <lowercase name> fail -             not refreshed this run (any cause)
# code-standards-facts.py reads it: only `ok` repos are exported as scanned.
#
# Exit: 0 every repo ok; 1 one or more repos failed (status still written);
#       2 usage or setup error (no status written).
set -euo pipefail

OWNER="Ohio15"
PER_REPO_SECONDS=300
roster=""
dir=""
status=""

usage() {
  echo "usage: $0 --roster <file> --dir <mirror-root> --status <status-file>" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --roster) [[ $# -ge 2 ]] || usage; roster="$2"; shift 2 ;;
    --dir) [[ $# -ge 2 ]] || usage; dir="$2"; shift 2 ;;
    --status) [[ $# -ge 2 ]] || usage; status="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "estate-mirror: unknown arg: $1" >&2; usage ;;
  esac
done
[[ -n "$roster" && -n "$dir" && -n "$status" ]] || usage
[[ -f "$roster" ]] || { echo "estate-mirror: roster not found: $roster" >&2; exit 2; }
mkdir -p -- "$dir" "$(dirname -- "$status")"

export GIT_TERMINAL_PROMPT=0
export GCM_INTERACTIVE=never
export GIT_LFS_SKIP_SMUDGE=1
export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o BatchMode=yes -o ConnectTimeout=30}"

# Remaining seconds of the current repo's budget (set by mirror_one).
deadline=0
remaining() {
  local left=$(( deadline - SECONDS ))
  if (( left <= 0 )); then
    return 1
  fi
  echo "$left"
}

# git with the mirror's safety config, bounded by the repo's remaining budget.
sgit() {
  local left
  left="$(remaining)" || { echo "estate-mirror: time budget exhausted" >&2; return 124; }
  timeout --kill-after=10 "$left" git \
    -c core.hooksPath=/dev/null \
    -c core.fsmonitor=false \
    -c protocol.file.allow=never \
    -c advice.detachedHead=false \
    "$@"
}

# Mirror one repo; prints the head sha on success. Every step is checked
# explicitly: `set -e` does not apply inside a function called from `if`.
mirror_one() {
  local name="$1" lc="$2"
  local target="$dir/$lc" tmp="$dir/.tmp-$lc" url="git@github.com:$OWNER/$name.git"
  deadline=$(( SECONDS + PER_REPO_SECONDS ))

  # An existing directory that is not a usable checkout is re-cloned; a
  # usable one is refreshed in place.
  # (`.git` is checked first so a parent repo can never satisfy rev-parse.)
  if [[ -e "$target" ]] && { [[ ! -d "$target/.git" ]] || ! sgit -C "$target" rev-parse --git-dir >/dev/null 2>&1; }; then
    echo "estate-mirror: $lc: existing mirror unusable, re-cloning" >&2
    rm -rf -- "$target" || return 1
  fi

  if [[ ! -e "$target" ]]; then
    rm -rf -- "$tmp" || return 1
    if ! sgit clone -q --depth 1 --no-tags --single-branch -- "$url" "$tmp" >&2; then
      rm -rf -- "$tmp" || true
      return 1
    fi
    mv -- "$tmp" "$target" || { rm -rf -- "$tmp" || true; return 1; }
  else
    sgit -C "$target" fetch -q --depth 1 --no-tags origin HEAD >&2 || return 1
    sgit -C "$target" checkout -q --force --detach FETCH_HEAD >&2 || return 1
    sgit -C "$target" clean -ffdq >&2 || return 1
  fi

  local sha
  sha="$(sgit -C "$target" rev-parse --verify HEAD)" || return 1
  [[ "$sha" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || return 1
  echo "$sha"
}

status_tmp="$(mktemp "$status.XXXXXX")"
trap 'rm -f -- "$status_tmp"' EXIT

# Pass 1: validate the whole roster before touching the network, so a bad
# line never leaves a half-run behind. Only leading/trailing blanks are
# trimmed: an interior space makes the entry invalid, as in the exporter.
names=()
declare -A seen=()
while IFS= read -r raw || [[ -n "$raw" ]]; do
  line="${raw%%#*}"
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -n "$line" ]] || continue
  if [[ ! "$line" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
    echo "estate-mirror: invalid roster entry: $line" >&2
    exit 2
  fi
  lc="${line,,}"
  if [[ -n "${seen[$lc]:-}" ]]; then
    echo "estate-mirror: duplicate roster entry: $line" >&2
    exit 2
  fi
  seen[$lc]=1
  names+=("$line")
done < "$roster"
total="${#names[@]}"
(( total > 0 )) || { echo "estate-mirror: roster lists no repos" >&2; exit 2; }

# Pass 2: mirror. stdin is /dev/null so neither git nor ssh can read input.
failed=0
for name in "${names[@]}"; do
  lc="${name,,}"
  if sha="$(mirror_one "$name" "$lc" </dev/null)"; then
    printf '%s ok %s\n' "$lc" "$sha" >> "$status_tmp"
    echo "estate-mirror: $lc ok ${sha:0:12}" >&2
  else
    printf '%s fail -\n' "$lc" >> "$status_tmp"
    echo "estate-mirror: $lc FAILED" >&2
    failed=$(( failed + 1 ))
  fi
done

chmod 0644 -- "$status_tmp"
mv -f -- "$status_tmp" "$status"
trap - EXIT
echo "estate-mirror: $(( total - failed ))/$total repos refreshed; status in $status" >&2
(( failed == 0 )) || exit 1
exit 0
