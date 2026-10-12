#!/usr/bin/env bash
# Lint every tracked shell script: `bash -n` and shellcheck.
#
# Run by .github/workflows/shell-lint.yml; runnable locally from anywhere in
# the repo (needs shellcheck on PATH): scripts/lint-shell.sh
#
# The file list is DERIVED from the tree, never kept by hand: every tracked
# *.sh, plus every tracked file whose BASENAME has no extension and whose first
# line is a bash/sh shebang (hooks/pre-commit, hooks/commit-msg and their
# .githooks/ copies). The extension test is on the basename, not the path, so a
# dotted directory such as .githooks/ does not hide its extensionless hooks.
# Dotted names other than *.sh (e.g. *.bash, *.sh.j2) are not probed - add them
# here if one ever appears.
#
# hooks/ and .githooks/ ARE linted here: consumer repos receive them verbatim
# from install.sh and skip them in their own lint (an inline exception written
# into a consumer copy would be clobbered by the next sync), so this repo is
# the only place their exceptions can live. Each exception is an inline
# `# shellcheck disable=` directive with its reason; there are no global
# exclusions.
#
# Exit 0 when every file passes both checks, 1 otherwise.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

command -v shellcheck >/dev/null || { echo "lint-shell: shellcheck not on PATH" >&2; exit 1; }

files=()
while IFS= read -r -d '' f; do
  [ -f "$f" ] || continue
  base="${f##*/}"
  case "$base" in
    *.sh) files+=("$f") ;;
    *.*) ;;
    *)
      first="$(head -n 1 -- "$f" 2>/dev/null | tr -d '\r')" || first=""
      if [[ "$first" =~ ^\#!.*(/|[[:space:]])(ba)?sh([[:space:]]|$) ]]; then
        files+=("$f")
      fi
      ;;
  esac
done < <(git -c core.quotepath=off ls-files -z)

[ "${#files[@]}" -gt 0 ] || { echo "lint-shell: no shell script found - the enumeration is broken" >&2; exit 1; }

fail=0
for f in "${files[@]}"; do
  bash -n -- "$f" || { echo "lint-shell: bash -n failed: $f" >&2; fail=1; }
done
echo "lint-shell: bash -n over ${#files[@]} file(s)"
printf '  %s\n' "${files[@]}"

shellcheck --version | sed -n '2p'
shellcheck -f gcc -- "${files[@]}" || fail=1
echo "lint-shell: shellcheck over ${#files[@]} file(s)"

if [ "$fail" -ne 0 ]; then echo "lint-shell: FAILED" >&2; exit 1; fi
echo "lint-shell: OK"
