#!/usr/bin/env bash
# Cron entry point for the weekly repo hygiene scan.
#
# The scan runs from a plain checkout of dev-standards on NEXUS. Nothing else
# advances that checkout, and on 2026-09-11 it was found 46 commits behind —
# the Sunday scan had been running May-era code with none of the newer
# findings. This wrapper fast-forwards the checkout first, then runs the
# scanner from whatever is now on disk. A failed pull is logged and the scan
# still runs (a stale scan beats no scan); the pull result is the first line
# of every log so the lag is visible.
#
# crontab (NEXUS, user ohio_):
#   0 5 * * 0 /home/ohio_/dev-standards/scripts/hygiene-scan-cron.sh --root /home/ohio_ --brain-store > /home/ohio_/scans/hygiene-$(date -u +\%Y-\%m-\%d).log 2>&1
#
# All arguments are passed through to repo-hygiene-scan.py.

set -u

here="$(cd "$(dirname "$0")" && pwd)"
checkout="$(cd "$here/.." && pwd)"

before="$(git -C "$checkout" rev-parse --short HEAD 2>/dev/null || echo unknown)"
if git -C "$checkout" pull -q --ff-only origin main 2>"$checkout/.pull-error"; then
  after="$(git -C "$checkout" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "hygiene-scan-cron: dev-standards $before -> $after"
  rm -f "$checkout/.pull-error"
else
  echo "hygiene-scan-cron: WARNING dev-standards pull failed at $before; scanning with the stale checkout"
  sed 's/^/  /' "$checkout/.pull-error"
fi

exec python3 "$here/repo-hygiene-scan.py" "$@"
