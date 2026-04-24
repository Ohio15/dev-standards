#!/usr/bin/env bash
# Reject staged files larger than MAX_BYTES unless listed in .large-files-allowlist.
#
# Install per-repo:
#   mkdir -p .githooks && cp path/to/this/pre-commit .githooks/pre-commit
#   chmod +x .githooks/pre-commit
#   git config core.hooksPath .githooks
#
# Policy source: https://github.com/Ohio15/dev-standards

set -euo pipefail

MAX_BYTES=$((10 * 1024 * 1024))
ALLOWLIST=".large-files-allowlist"

mapfile -t staged < <(git diff --cached --name-only --diff-filter=ACMR)
[ ${#staged[@]} -eq 0 ] && exit 0

violations=()
for f in "${staged[@]}"; do
  [ -z "$f" ] && continue
  allow=0
  if [ -f "$ALLOWLIST" ]; then
    while IFS= read -r pat; do
      [[ "$pat" =~ ^[[:space:]]*# ]] && continue
      [[ -z "$pat" ]] && continue
      if [[ "$f" == $pat || "$f" == ${pat%/}/* ]]; then allow=1; break; fi
    done <"$ALLOWLIST"
  fi
  [ "$allow" -eq 1 ] && continue
  sz=$(git cat-file -s ":$f" 2>/dev/null || echo 0)
  if [ "$sz" -gt "$MAX_BYTES" ]; then
    hr=$(awk -v b="$sz" 'BEGIN{s="BKMGT";v=b;i=1;while(v>=1024&&i<length(s)){v/=1024;i++}printf "%.1f%s",v,substr(s,i,1)}')
    violations+=("  $f ($hr)")
  fi
done

if [ ${#violations[@]} -gt 0 ]; then
  {
    echo "ERROR: staged files exceed 10 MB. Binaries don't belong in git."
    echo
    printf '%s\n' "${violations[@]}"
    echo
    echo "Options:"
    echo "  Release artifact?   Ship via GitHub Releases (gh release upload)."
    echo "  Build output?       Add to .gitignore."
    echo "  Vendored dep?       Add to .gitignore, restore via package manifest."
    echo "  Source asset?       Add to .large-files-allowlist with a # reason: comment."
    echo
    echo "Bypass (use only with written justification): git commit --no-verify"
  } >&2
  exit 1
fi

exit 0
