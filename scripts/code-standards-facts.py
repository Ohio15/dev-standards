#!/usr/bin/env python3
"""
Code-standards facts export: hygiene-scan JSON (+ npm-audit JSON) -> a
Prometheus textfile that Steward consumes as its code-standards-* positions.

Inputs (all produced by scripts/code-standards-cron.sh in the same run):
    --roster         estate/code-standards-roster.txt (GitHub repo names)
    --mirror-status  estate-mirror.sh status file: `<repo> ok|fail <sha|->`
    --hygiene-report repo-hygiene-scan.py --output-dir JSON
    --npm-audit      npm-audit-weekly.sh JSON (optional)
    --output         textfile path, e.g.
                     /var/lib/node_exporter/textfile_collector/code_standards.prom

Output contract (Steward parses exactly this; do not change it unilaterally):
    code_standards_repo_scanned{repo}            0|1, every roster repo
    code_standards_violation{repo,check}         1, violations only, scanned repos only
    code_standards_deps_scanned{repo}            0|1, scanned repos with a root package.json
    code_standards_deps_prod_vulns{repo,severity} >0 counts, deps_scanned repos only
    code_standards_last_run_timestamp_seconds    unix seconds, last line
  All gauges; integral values; no timestamps; ASCII; LF; each series once;
  label order repo first; repo label ^[a-z0-9][a-z0-9._-]{0,63}$. A file over
  64 KiB or 1024 lines is refused (non-zero exit, nothing written).

"Unknown is never clean": a repo is scanned=1 only when its mirror refresh
succeeded THIS run and the hygiene report contains it; a dependency audit
counts only when its npm-audit entry says status "ok". npm-audit-weekly.sh
does not yet emit a per-repo status (an errored `npm audit` reads as all
zeros there), so until it does every deps_scanned is 0 by design.

The write is atomic: temp file in the target directory, fsync, chmod 0644,
os.replace. node_exporter's textfile collector reads only *.prom, so the
temp name never surfaces as a partial file.

Exit codes: 0 written; 1 invalid input (nothing written); 3 output budget
exceeded (nothing written).

Stdlib only. Python 3.8+.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

# Hygiene finding code -> exported check id. An allow-list: every other code
# is local-checkout state or advisory (hooks-path-*, stale-working-tree,
# hook-missing, idle-repo, noise-files, layout-*, submodule-*, cache-restore,
# *-unexamined) and means nothing on a fresh mirror clone, so it is dropped.
CHECK_MAP: dict[str, str] = {
    "independence-runbook-missing": "s13-release-runbook",
    "independence-no-release-workflow": "s13-release-workflow",
    "independence-ai-vendor-runtime": "s13-ai-vendor-runtime",
    "tracked-binary-or-oversized": "s2-tracked-binary",
    "tracked-but-gitignored": "s2-tracked-ignored",
    "hook-drift": "s2-hook-drift",
    "version-divergence": "s3-version-sync",
    "tests-undeclared": "s2-tests-declared",
    "stub-marker": "no-stubs",
    "security-register-missing": "sec-register-missing",
    "security-register-stale": "sec-register-stale",
}
REPO_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_BYTES = 64 * 1024
MAX_LINES = 1024
EXIT_INVALID_INPUT = 1
EXIT_BUDGET = 3

METRICS: tuple[tuple[str, str], ...] = (
    ("code_standards_repo_scanned",
     "1 when the repo's mirror refreshed this run and the hygiene scan covered it, else 0."),
    ("code_standards_violation",
     "1 per code-standards check the repo violates (violations only; scanned repos only)."),
    ("code_standards_deps_scanned",
     "1 when npm audit succeeded for a scanned repo with a root package.json, else 0."),
    ("code_standards_deps_prod_vulns",
     "Production-dependency vulnerabilities by severity (counts above 0 only)."),
    ("code_standards_last_run_timestamp_seconds",
     "Unix time at which this export was computed."),
)


class InputError(Exception):
    """An input this run cannot trust; nothing is written."""


def read_roster(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"roster {path} unreadable: {exc}") from exc
    repos: list[str] = []
    seen: set[str] = set()
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        label = line.lower()
        if not REPO_LABEL_RE.match(label):
            raise InputError(f"roster {path}:{n}: {line!r} is not a valid repo label")
        if label in seen:
            raise InputError(f"roster {path}:{n}: {line!r} listed twice")
        seen.add(label)
        repos.append(label)
    if not repos:
        raise InputError(f"roster {path} lists no repos")
    return repos


def read_mirror_status(path: Path) -> dict[str, bool]:
    """{repo: refreshed_ok}. A malformed line fails the run: the status file
    is the only proof a mirror is current."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"mirror status {path} unreadable: {exc}") from exc
    status: dict[str, bool] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        parts = raw.split()
        if len(parts) != 3 or parts[1] not in ("ok", "fail"):
            raise InputError(f"mirror status {path}:{n}: malformed line {raw!r}")
        name, state, sha = parts
        if state == "ok" and not re.fullmatch(r"[0-9a-f]{40}([0-9a-f]{24})?", sha):
            raise InputError(f"mirror status {path}:{n}: ok without a commit sha")
        status[name.lower()] = state == "ok"
    return status


def read_hygiene_report(path: Path) -> dict[str, dict[str, Any]]:
    """{repo name: report entry}. Synthetic entries ("<root> [layout]" etc.)
    carry a bracket and never match a roster label."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InputError(f"hygiene report {path} unreadable: {exc}") from exc
    repos = data.get("repos") if isinstance(data, dict) else None
    if not isinstance(repos, list):
        raise InputError(f"hygiene report {path} has no repos[] list")
    out: dict[str, dict[str, Any]] = {}
    for entry in repos:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise InputError(f"hygiene report {path}: entry without a name: {entry!r}")
        findings = entry.get("findings")
        if not isinstance(findings, list):
            raise InputError(f"hygiene report {path}: {entry['name']} has no findings[] list")
        out[entry["name"]] = entry
    return out


def read_npm_audit(path: Path | None) -> dict[str, dict[str, int]]:
    """{repo: {"critical": n, "high": n}} for entries that report success.

    Degrades rather than fails: an unreadable npm report must not suppress the
    code-standards facts, and every repo it would have covered reads as
    deps_scanned 0 (not scanned), never as clean."""
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"code-standards-facts: npm-audit report {path} unusable ({exc}); deps read as not scanned",
              file=sys.stderr)
        return {}
    repos = data.get("repos") if isinstance(data, dict) else None
    if not isinstance(repos, list):
        print(f"code-standards-facts: npm-audit report {path} has no repos[]; deps read as not scanned",
              file=sys.stderr)
        return {}
    out: dict[str, dict[str, int]] = {}
    unmarked = 0
    for entry in repos:
        if not isinstance(entry, dict) or not isinstance(entry.get("repo"), str):
            continue
        if entry.get("status") != "ok":
            unmarked += 1
            continue
        crit, high = entry.get("prod_critical"), entry.get("prod_high")
        if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in (crit, high)):
            continue
        out[entry["repo"].lower()] = {"critical": crit, "high": high}
    if unmarked:
        print(f"code-standards-facts: {unmarked} npm-audit entr{'y' if unmarked == 1 else 'ies'} without "
              f'status "ok" read as not scanned', file=sys.stderr)
    return out


def has_root_package_json(entry: dict[str, Any]) -> bool:
    path = entry.get("path")
    return isinstance(path, str) and bool(path) and (Path(path) / "package.json").is_file()


def build_series(
    roster: list[str],
    mirror_ok: dict[str, bool],
    hygiene: dict[str, dict[str, Any]],
    npm: dict[str, dict[str, int]],
) -> dict[str, list[tuple[str, int]]]:
    """{metric: [(label block, value)]} in output order (timestamp excluded)."""
    series: dict[str, list[tuple[str, int]]] = {name: [] for name, _ in METRICS}
    for repo in sorted(roster):
        entry = hygiene.get(repo)
        scanned = bool(mirror_ok.get(repo)) and entry is not None
        series["code_standards_repo_scanned"].append((f'{{repo="{repo}"}}', 1 if scanned else 0))
        if not scanned:
            continue
        assert entry is not None
        checks = sorted({CHECK_MAP[f["code"]] for f in entry["findings"]
                         if isinstance(f, dict) and f.get("code") in CHECK_MAP})
        for check in checks:
            series["code_standards_violation"].append((f'{{repo="{repo}",check="{check}"}}', 1))
        if has_root_package_json(entry):
            audit = npm.get(repo)
            series["code_standards_deps_scanned"].append((f'{{repo="{repo}"}}', 1 if audit else 0))
            if audit:
                for severity in ("critical", "high"):
                    if audit[severity] > 0:
                        series["code_standards_deps_prod_vulns"].append(
                            (f'{{repo="{repo}",severity="{severity}"}}', audit[severity]))
    return series


def render(series: dict[str, list[tuple[str, int]]], now: int) -> str:
    lines: list[str] = []
    for name, help_text in METRICS:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        if name == "code_standards_last_run_timestamp_seconds":
            lines.append(f"{name} {now}")
            continue
        for labels, value in series[name]:
            lines.append(f"{name}{labels} {int(value)}")
    text = "\n".join(lines) + "\n"
    text.encode("ascii")  # every label is regex-checked; this is the backstop
    return text


def write_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".code_standards.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    if hasattr(os, "O_DIRECTORY"):
        dfd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Export code-standards facts as a Prometheus textfile")
    ap.add_argument("--roster", required=True, type=Path)
    ap.add_argument("--mirror-status", required=True, type=Path)
    ap.add_argument("--hygiene-report", required=True, type=Path)
    ap.add_argument("--npm-audit", type=Path, default=None)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args(argv)

    try:
        roster = read_roster(args.roster)
        mirror_ok = read_mirror_status(args.mirror_status)
        hygiene = read_hygiene_report(args.hygiene_report)
    except InputError as exc:
        print(f"code-standards-facts: {exc}; nothing written", file=sys.stderr)
        return EXIT_INVALID_INPUT
    npm = read_npm_audit(args.npm_audit)

    series = build_series(roster, mirror_ok, hygiene, npm)
    text = render(series, int(time.time()))
    size, count = len(text.encode("ascii")), text.count("\n")
    if size > MAX_BYTES or count > MAX_LINES:
        print(f"code-standards-facts: output {size} bytes / {count} lines exceeds the "
              f"{MAX_BYTES}-byte / {MAX_LINES}-line budget; nothing written", file=sys.stderr)
        return EXIT_BUDGET
    write_atomic(args.output, text)
    scanned = sum(v for _, v in series["code_standards_repo_scanned"])
    print(f"code-standards-facts: wrote {args.output} ({count} lines, {size} bytes; "
          f"{scanned}/{len(roster)} repos scanned, {len(series['code_standards_violation'])} violations)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
