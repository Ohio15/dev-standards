#!/usr/bin/env python3
"""
Repo hygiene scanner — flags drift, misconfig, and noise across git repos.

Scans one or more configured root directories, walks each immediate
subdirectory that contains a .git folder, and produces a structured
report. Designed to run from cron weekly; idempotent and side-effect-free
on the scanned repos.

Findings (severity-tagged):
    HIGH    tracked binary extensions or any tracked file >5 MB
    HIGH    tracked files matching the repo's own .gitignore
    MEDIUM  working-tree drift older than --age-threshold days
    MEDIUM  core.hooksPath misconfigured (legacy or non-.githooks while
            .githooks/ exists)
    LOW     last commit older than 30 days (idle warning)
    LOW     noise files (.DS_Store, *.swp, Thumbs.db) tracked or
            untracked

Output:
    JSON      <output-dir>/hygiene-scan-<YYYY-MM-DD>.json
    Markdown  human-readable summary to stdout

Optional --brain-store posts the JSON summary to shared-brain via curl
using the API key at ~/.config/shared-brain/api-key.

Stdlib only. Python 3.8+.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

LEGACY_HOOKSPATH = "D:/Projects/git-hooks"
NOISE_NAMES = {".DS_Store", "Thumbs.db"}
NOISE_SUFFIXES = {".swp"}
BINARY_SUFFIXES = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc",
    ".class", ".jar", ".a",
}
MAX_TRACKED_BYTES = 5 * 1024 * 1024  # 5 MB
IDLE_DAYS = 30
SEVERITIES = ("HIGH", "MEDIUM", "LOW")


def run(cmd: list[str], cwd: Path | None = None, check: bool = False) -> tuple[int, str, str]:
    """Run a subprocess. Returns (rc, stdout, stderr)."""
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=check,
    )
    return proc.returncode, proc.stdout, proc.stderr


def is_git_repo(path: Path) -> bool:
    return (path / ".git").is_dir() or (path / ".git").is_file()


def discover_repos(roots: list[Path]) -> list[Path]:
    """Find immediate-subdirectory git repos under each root.

    Does not recurse — keeps the scan bounded and predictable. If a root
    is itself a git repo, it's included.
    """
    found: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        candidates = [root] if is_git_repo(root) else []
        try:
            for child in sorted(root.iterdir()):
                if child.is_dir() and is_git_repo(child):
                    candidates.append(child)
        except PermissionError:
            continue
        for c in candidates:
            rc = c.resolve()
            if rc not in seen:
                seen.add(rc)
                found.append(c)
    return found


def gitconfig(repo: Path, key: str) -> str | None:
    rc, out, _ = run(["git", "config", "--get", key], cwd=repo)
    if rc == 0:
        return out.strip()
    return None


def tracked_files(repo: Path) -> list[str]:
    rc, out, _ = run(["git", "ls-files"], cwd=repo)
    if rc != 0:
        return []
    return [line for line in out.splitlines() if line]


def check_ignored(repo: Path, paths: list[str]) -> list[str]:
    """Return tracked files that are matched by the repo's .gitignore.

    Uses `git check-ignore --no-index` against tracked paths — counter-
    intuitive but correct: ls-files returns tracked entries, and
    check-ignore tells us which would be ignored if untracked. Tracked
    files that match .gitignore signal stale ignore rules or accidental
    add -f.
    """
    if not paths:
        return []
    # Batch via stdin to avoid command-line length limits.
    proc = subprocess.run(
        ["git", "check-ignore", "--no-index", "--stdin"],
        cwd=str(repo),
        input="\n".join(paths),
        capture_output=True,
        text=True,
    )
    # rc 0 = some matched; rc 1 = none matched; rc >1 = error
    if proc.returncode > 1:
        return []
    # Strip CR/whitespace from each entry — git check-ignore on Windows
    # echoes a trailing \r when fed CRLF stdin.
    return [line.strip().strip('"') for line in proc.stdout.splitlines() if line.strip()]


def file_size(repo: Path, rel: str) -> int | None:
    p = repo / rel
    try:
        return p.stat().st_size
    except (OSError, FileNotFoundError):
        return None


def working_tree_drift(repo: Path) -> list[str]:
    rc, out, _ = run(["git", "status", "--porcelain"], cwd=repo)
    if rc != 0:
        return []
    return [line for line in out.splitlines() if line]


def last_commit_age_days(repo: Path) -> int | None:
    rc, out, _ = run(
        ["git", "log", "-1", "--format=%ct"], cwd=repo
    )
    if rc != 0 or not out.strip():
        return None
    try:
        ts = int(out.strip())
    except ValueError:
        return None
    age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromtimestamp(ts, dt.timezone.utc)
    return age.days


def noise_files(repo: Path, tracked: list[str]) -> list[str]:
    hits: set[str] = set()
    # Tracked noise
    for f in tracked:
        name = os.path.basename(f)
        if name in NOISE_NAMES:
            hits.add(f)
        for s in NOISE_SUFFIXES:
            if f.endswith(s):
                hits.add(f)
    # Untracked noise (from status output)
    rc, out, _ = run(["git", "status", "--porcelain"], cwd=repo)
    if rc == 0:
        for line in out.splitlines():
            if not line.startswith("??"):
                continue
            path = line[3:].strip()
            name = os.path.basename(path.rstrip("/"))
            if name in NOISE_NAMES or any(path.endswith(s) for s in NOISE_SUFFIXES):
                hits.add(path)
    return sorted(hits)


def scan_repo(repo: Path, age_threshold: int) -> dict[str, Any]:
    name = repo.name
    findings: list[dict[str, Any]] = []

    tracked = tracked_files(repo)

    # HIGH: binaries / oversized
    big: list[dict[str, Any]] = []
    for f in tracked:
        suf = os.path.splitext(f)[1].lower()
        if suf in BINARY_SUFFIXES:
            big.append({"path": f, "reason": f"binary extension {suf}"})
            continue
        size = file_size(repo, f)
        if size is not None and size > MAX_TRACKED_BYTES:
            big.append({"path": f, "reason": f"size {size} bytes (>5 MB)"})
    if big:
        findings.append({
            "severity": "HIGH",
            "code": "tracked-binary-or-oversized",
            "count": len(big),
            "items": big[:20],
        })

    # HIGH: tracked files matching .gitignore
    ignored_tracked = check_ignored(repo, tracked)
    if ignored_tracked:
        findings.append({
            "severity": "HIGH",
            "code": "tracked-but-gitignored",
            "count": len(ignored_tracked),
            "items": ignored_tracked[:20],
        })

    # MEDIUM: working-tree drift
    drift = working_tree_drift(repo)
    if drift:
        # Approximate "older than threshold" by checking the oldest mtime
        # of any modified/untracked file.
        oldest_age = 0
        now = dt.datetime.now().timestamp()
        for line in drift:
            path = line[3:].strip()
            full = repo / path
            try:
                mtime = full.stat().st_mtime
                age = (now - mtime) / 86400
                if age > oldest_age:
                    oldest_age = age
            except (OSError, FileNotFoundError):
                continue
        if oldest_age >= age_threshold:
            findings.append({
                "severity": "MEDIUM",
                "code": "stale-working-tree",
                "count": len(drift),
                "oldest_age_days": round(oldest_age, 1),
                "items": [d.strip() for d in drift[:20]],
            })

    # MEDIUM: hooksPath misconfig
    hp = gitconfig(repo, "core.hooksPath")
    githooks_dir = repo / ".githooks"
    if hp == LEGACY_HOOKSPATH:
        findings.append({
            "severity": "MEDIUM",
            "code": "hooks-path-legacy",
            "value": hp,
            "note": "still pointing at retired D:/Projects/git-hooks",
        })
    elif githooks_dir.is_dir() and hp not in (".githooks", str(githooks_dir)):
        findings.append({
            "severity": "MEDIUM",
            "code": "hooks-path-misconfigured",
            "value": hp,
            "note": ".githooks/ exists but core.hooksPath does not point at it",
        })

    # LOW: idle
    age = last_commit_age_days(repo)
    if age is not None and age > IDLE_DAYS:
        findings.append({
            "severity": "LOW",
            "code": "idle-repo",
            "last_commit_age_days": age,
        })

    # LOW: noise
    noise = noise_files(repo, tracked)
    if noise:
        findings.append({
            "severity": "LOW",
            "code": "noise-files",
            "count": len(noise),
            "items": noise[:20],
        })

    return {
        "name": name,
        "path": str(repo),
        "tracked_count": len(tracked),
        "findings": findings,
    }


def severity_filter(report: dict[str, Any], min_sev: str | None) -> dict[str, Any]:
    if not min_sev:
        return report
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    keep_at = rank[min_sev]
    for repo in report["repos"]:
        repo["findings"] = [f for f in repo["findings"] if rank[f["severity"]] <= keep_at]
    return report


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# Repo hygiene scan — {report['scan_date']}")
    lines.append("")
    lines.append(f"Roots scanned: {', '.join(report['roots'])}")
    lines.append(f"Repos scanned: {report['repo_count']}")
    lines.append(f"Total findings: {report['total_findings']}")
    by_sev = report["totals_by_severity"]
    lines.append(
        f"  HIGH={by_sev.get('HIGH', 0)}  "
        f"MEDIUM={by_sev.get('MEDIUM', 0)}  "
        f"LOW={by_sev.get('LOW', 0)}"
    )
    lines.append("")
    for repo in report["repos"]:
        if not repo["findings"]:
            continue
        lines.append(f"## {repo['name']}  ({repo['path']})")
        for f in repo["findings"]:
            head = f"- **{f['severity']}** `{f['code']}`"
            extras: list[str] = []
            if "count" in f:
                extras.append(f"count={f['count']}")
            if "value" in f:
                extras.append(f"value={f['value']!r}")
            if "last_commit_age_days" in f:
                extras.append(f"age={f['last_commit_age_days']}d")
            if "oldest_age_days" in f:
                extras.append(f"oldest={f['oldest_age_days']}d")
            if extras:
                head += " (" + ", ".join(extras) + ")"
            lines.append(head)
            if "note" in f:
                lines.append(f"    note: {f['note']}")
            for item in f.get("items", [])[:5]:
                if isinstance(item, dict):
                    lines.append(f"    - {item.get('path', item)}: {item.get('reason', '')}")
                else:
                    lines.append(f"    - {item}")
            if f.get("count", 0) > 5:
                lines.append(f"    ... +{f['count'] - 5} more")
        lines.append("")
    return "\n".join(lines)


def post_to_brain(summary: str, scan_date: str) -> tuple[bool, str]:
    """Post the scan summary to shared-brain. Returns (ok, message)."""
    key_path = Path.home() / ".config" / "shared-brain" / "api-key"
    if not key_path.is_file():
        return False, f"api-key file not found at {key_path}"
    api_key = key_path.read_text().strip()
    payload = {
        "action": "ingest",
        "type": "observation",
        "tags": [f"hygiene-scan-{scan_date}", "automation", "dev-standards"],
        "content": summary[:8000],
        "importance": 0.6,
        "source": "repo-hygiene-scan.py",
    }
    body = json.dumps(payload)
    cmd = [
        "curl", "-sS", "-X", "POST",
        "-H", f"Authorization: Bearer {api_key}",
        "-H", "Content-Type: application/json",
        "-d", body,
        "https://shared-brain.us/api/memory",
    ]
    rc, out, err = run(cmd)
    if rc != 0:
        return False, f"curl rc={rc}: {err.strip()}"
    return True, out.strip()[:200]


def main() -> int:
    ap = argparse.ArgumentParser(description="Repo hygiene scanner")
    ap.add_argument(
        "--root", action="append", default=[],
        help="Root directory to scan (repeatable). Defaults: D:/Projects on Windows, ~/ elsewhere.",
    )
    ap.add_argument(
        "--age-threshold", type=int, default=7,
        help="Days before working-tree drift is flagged (default 7)",
    )
    ap.add_argument(
        "--output-dir", default=None,
        help="Directory to write JSON report (default: ~/scans/)",
    )
    ap.add_argument(
        "--severity", choices=SEVERITIES, default=None,
        help="Filter findings to this severity or higher",
    )
    ap.add_argument(
        "--brain-store", action="store_true",
        help="Post the markdown summary to shared-brain",
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="Print to stdout but don't write JSON or post to brain",
    )
    args = ap.parse_args()

    # Default roots
    roots = [Path(r) for r in args.root]
    if not roots:
        if sys.platform.startswith("win"):
            roots = [Path("D:/Projects")]
        else:
            roots = [Path.home()]

    repos = discover_repos(roots)
    scan_date = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")

    repo_reports = [scan_repo(r, args.age_threshold) for r in repos]
    total_findings = sum(len(r["findings"]) for r in repo_reports)
    totals_by_severity: dict[str, int] = {s: 0 for s in SEVERITIES}
    for r in repo_reports:
        for f in r["findings"]:
            totals_by_severity[f["severity"]] = totals_by_severity.get(f["severity"], 0) + 1

    report = {
        "scan_date": scan_date,
        "roots": [str(r) for r in roots],
        "age_threshold_days": args.age_threshold,
        "repo_count": len(repos),
        "total_findings": total_findings,
        "totals_by_severity": totals_by_severity,
        "repos": repo_reports,
    }
    report = severity_filter(report, args.severity)

    md = render_markdown(report)
    print(md)

    if args.dry_run:
        return 0

    out_dir = Path(args.output_dir) if args.output_dir else Path.home() / "scans"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"hygiene-scan-{scan_date}.json"
    out_file.write_text(json.dumps(report, indent=2, sort_keys=True))
    print(f"\n[wrote {out_file}]", file=sys.stderr)

    if args.brain_store:
        ok, msg = post_to_brain(md, scan_date)
        marker = "[brain-store ok]" if ok else "[brain-store failed]"
        print(f"\n{marker} {msg}", file=sys.stderr)

    # Exit code reflects severity: HIGH findings = 2, MEDIUM = 1, else 0
    if totals_by_severity.get("HIGH", 0) > 0:
        return 2
    if totals_by_severity.get("MEDIUM", 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
