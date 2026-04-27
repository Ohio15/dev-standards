#!/usr/bin/env python3
"""
replay-missing-ingestions.py

Backfills brain memory entries that were silently lost during the
/api/memory/ingest 500-bug window (post-commit hook sent source="git" while
the PG CHECK constraint required "git_history"). The hook silently exit-0'd
on 500, so commits never ingested. The D4 verify cron flagged the gap on
2026-04-27 -- this script reconciles the missing inventory.

This is an idempotent reusable artifact. Re-running is safe: each commit is
recall-checked first and skipped if already present in the brain.

Inputs (defaults can be overridden via flags):
  --verify-log    C:\\Users\\ohio_\\.config\\shared-brain\\verify.log
  --commit-log    C:\\Users\\ohio_\\.config\\shared-brain\\post-commit.log
  --projects-root D:\\Projects
  --api-key-file  C:\\Users\\ohio_\\.config\\shared-brain\\api-key
  --endpoint      https://shared-brain.us
  --dry-run       (don't POST, just print what would happen)

Output:
  Per-commit log line: <sha> <project> -> ingested|skipped|failed <reason>
  Final summary: counts by status, by project.

Exit codes:
  0  all commits resolved (ingested or skipped) cleanly
  1  one or more commits failed
  2  setup error (missing files, unreachable endpoint, etc.)

The bearer token is NEVER echoed to stdout/stderr or any log line.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error
from collections import defaultdict
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------------------------------
# Constants / defaults
# ---------------------------------------------------------------------------

DEFAULT_VERIFY_LOG = r"C:\Users\ohio_\.config\shared-brain\verify.log"
DEFAULT_COMMIT_LOG = r"C:\Users\ohio_\.config\shared-brain\post-commit.log"
DEFAULT_PROJECTS_ROOT = r"D:\Projects"
DEFAULT_API_KEY_FILE = r"C:\Users\ohio_\.config\shared-brain\api-key"
DEFAULT_ENDPOINT = "https://shared-brain.us"

VERIFY_MISS_RE = re.compile(r"^\S+\s+MISS\s+(?P<project>\S+)\s+(?P<sha>[0-9a-f]{7,40})\b")
COMMITLOG_500_RE = re.compile(
    r"^\S+\s+(?P<project>\S+)\s+(?P<sha>[0-9a-f]{7,40})\s+HTTP_500\b"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(msg: str) -> None:
    print(msg, flush=True)


def warn(msg: str) -> None:
    print(f"WARN: {msg}", file=sys.stderr, flush=True)


def err(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr, flush=True)


def read_api_key(path: str) -> str:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"api key file not found: {path}")
    raw = p.read_text(encoding="utf-8").strip()
    if not raw:
        raise ValueError("api key file is empty")
    return raw


def parse_verify_log(path: Path) -> set[tuple[str, str]]:
    """Extract (project, sha) tuples from D4 verify log MISS lines."""
    out: set[tuple[str, str]] = set()
    if not path.exists():
        warn(f"verify log not found: {path} (skipping)")
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = VERIFY_MISS_RE.match(line)
        if m:
            out.add((m.group("project"), m.group("sha").lower()))
    return out


def parse_commit_log(path: Path) -> set[tuple[str, str]]:
    """Extract (project, sha) tuples from post-commit HTTP_500 lines."""
    out: set[tuple[str, str]] = set()
    if not path.exists():
        warn(f"post-commit log not found: {path} (skipping)")
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = COMMITLOG_500_RE.match(line)
        if m:
            project = m.group("project")
            # Some entries (e.g., 'hooktest.WkQ6wC') are throwaway test repos --
            # they will fail repo lookup later; we surface them rather than
            # silently dropping, so that triage is honest.
            out.add((project, m.group("sha").lower()))
    return out


def find_repo(projects_root: Path, project_name: str) -> Path | None:
    """Case-insensitive match of project_name under projects_root.

    Returns the matched repo path (with .git verified) or None.
    """
    if not projects_root.exists():
        return None
    target = project_name.lower()
    for entry in projects_root.iterdir():
        if not entry.is_dir():
            continue
        if entry.name.lower() == target and (entry / ".git").exists():
            return entry
    return None


def git(repo: Path, *args: str) -> tuple[int, str, str]:
    """Run git -C <repo> <args>; return (rc, stdout, stderr)."""
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, proc.stdout, proc.stderr


def commit_resolves(repo: Path, sha: str) -> str | None:
    """Verify the sha resolves to a commit in this repo. Return full sha or None."""
    rc, out, _ = git(repo, "rev-parse", "--verify", f"{sha}^{{commit}}")
    if rc != 0:
        return None
    return out.strip()


def commit_subject(repo: Path, sha: str) -> str:
    rc, out, _ = git(repo, "log", "-1", "--pretty=format:%s", sha)
    if rc != 0:
        return ""
    return out.strip()


def commit_files(repo: Path, sha: str, limit: int = 20) -> str:
    rc, out, _ = git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", sha)
    if rc != 0:
        return ""
    files = [f for f in out.splitlines() if f.strip()][:limit]
    return ", ".join(files)


def commit_branch(repo: Path, sha: str) -> str:
    """Return 'main' if reachable from main; else first branch containing it."""
    # Try main first.
    rc, _, _ = git(repo, "merge-base", "--is-ancestor", sha, "main")
    if rc == 0:
        return "main"
    # Try master (some repos still use it).
    rc, _, _ = git(repo, "merge-base", "--is-ancestor", sha, "master")
    if rc == 0:
        return "master"
    # Fall back to first containing branch.
    rc, out, _ = git(repo, "branch", "--contains", sha)
    if rc == 0:
        for line in out.splitlines():
            cleaned = line.strip().lstrip("*").strip()
            if cleaned:
                return cleaned
    return "main"  # last-ditch default


def build_payload(project: str, sha: str, branch: str, subject: str, files: str) -> dict:
    return {
        "content": f"Commit {sha} on {project} ({branch}): {subject}. Files: {files}",
        "source": "git_history",
        "type": "episodic",
        "project": project,
        "tags": ["commit", branch],
        "priority_hint": "normal",
    }


def http_post_json(url: str, token: str, body: dict, timeout: float = 30.0) -> tuple[int, dict | str]:
    """POST JSON, return (status, parsed-body-or-raw-text). Token never logged."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "replay-missing-ingestions/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
        try:
            return e.code, json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return e.code, raw or str(e)
    except urllib.error.URLError as e:
        return 0, f"URLError: {e.reason}"
    except Exception as e:  # noqa: BLE001
        return 0, f"Exception: {e}"


def already_ingested(endpoint: str, token: str, sha: str, project: str) -> bool:
    """Pre-flight recall check for an existing commit memory.

    Note on idempotency strategy
    ----------------------------
    The brain's /api/memory/recall is a *semantic* search over embeddings
    (all-MiniLM-L6-v2). Short git SHAs like 5486f07 are high-entropy literals
    that the embedding model does NOT preserve well -- a SHA-only query does
    not reliably surface a memory whose content contains that SHA, even when
    the memory exists. Empirically verified 2026-04-27.

    So this pre-check is a best-effort early-out for the case where someone
    has manually documented the commit (different content, but mentioning
    the SHA enough to surface). The PRIMARY idempotency guarantee comes from
    the server's content_hash + semantic-similarity dedup at ingest time:
    re-POSTing identical content returns {"deduplicated": true, ...} with
    the existing memory's id, and we treat that as "skipped already-present"
    in the caller. See ingest_with_dedup_handling() below.
    """
    status, body = http_post_json(
        f"{endpoint}/api/memory/recall",
        token,
        {"query": f"Commit {sha}", "max_results": 5},
    )
    if status != 200 or not isinstance(body, dict):
        return False

    project_lc = project.lower()
    candidates: Iterable[dict] = body.get("primary", []) or []
    for entry in candidates:
        content = (entry.get("content") or "")
        source = entry.get("source") or ""
        ent_project = (entry.get("project") or "").lower()
        if sha not in content:
            continue
        if source == "git_history":
            return True
        if source == "git" and (ent_project == project_lc or content.startswith("Commit ")):
            return True
        if ent_project == project_lc and content.startswith(f"Commit {sha}"):
            return True
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verify-log", default=DEFAULT_VERIFY_LOG)
    parser.add_argument("--commit-log", default=DEFAULT_COMMIT_LOG)
    parser.add_argument("--projects-root", default=DEFAULT_PROJECTS_ROOT)
    parser.add_argument("--api-key-file", default=DEFAULT_API_KEY_FILE)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    # ---- Setup -----------------------------------------------------------
    try:
        token = read_api_key(args.api_key_file)
    except Exception as e:  # noqa: BLE001
        err(f"failed to read api key: {e}")
        return 2

    projects_root = Path(args.projects_root)
    if not projects_root.exists():
        err(f"projects root not found: {projects_root}")
        return 2

    # ---- Build deduped inventory -----------------------------------------
    verify_pairs = parse_verify_log(Path(args.verify_log))
    commit_pairs = parse_commit_log(Path(args.commit_log))
    inventory = sorted(verify_pairs | commit_pairs)

    log(f"=== Replay missing ingestions ===")
    log(f"verify-log entries:  {len(verify_pairs)}")
    log(f"commit-log entries:  {len(commit_pairs)}")
    log(f"deduped inventory:   {len(inventory)}")
    log(f"endpoint:            {args.endpoint}")
    log(f"dry-run:             {args.dry_run}")
    log("")

    # ---- Process ---------------------------------------------------------
    by_status: dict[str, int] = defaultdict(int)
    by_project_status: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    failure_modes: dict[str, int] = defaultdict(int)
    ingested_shas: list[tuple[str, str]] = []

    for project, short_sha in inventory:
        repo = find_repo(projects_root, project)
        if repo is None:
            log(f"{short_sha} {project} -> failed repo-not-found")
            by_status["failed"] += 1
            by_project_status[project]["failed"] += 1
            failure_modes["repo-not-found"] += 1
            continue

        full_sha = commit_resolves(repo, short_sha)
        if full_sha is None:
            log(f"{short_sha} {project} -> failed sha-not-resolved")
            by_status["failed"] += 1
            by_project_status[project]["failed"] += 1
            failure_modes["sha-not-resolved"] += 1
            continue

        # Idempotency: recall pre-check.
        try:
            present = already_ingested(args.endpoint, token, short_sha, project)
        except Exception as e:  # noqa: BLE001
            warn(f"recall raised for {short_sha}: {e}")
            present = False

        if present:
            log(f"{short_sha} {project} -> skipped already-present")
            by_status["skipped"] += 1
            by_project_status[project]["skipped"] += 1
            continue

        subject = commit_subject(repo, full_sha)
        files = commit_files(repo, full_sha)
        branch = commit_branch(repo, full_sha)
        payload = build_payload(project, short_sha, branch, subject, files)

        if args.dry_run:
            log(f"{short_sha} {project} -> dry-run would-ingest ({len(payload['content'])} bytes)")
            by_status["dry-run"] += 1
            by_project_status[project]["dry-run"] += 1
            continue

        status, body = http_post_json(
            f"{args.endpoint}/api/memory/ingest", token, payload
        )
        if 200 <= status < 300:
            # Server-side semantic dedup: identical/near-identical content
            # returns 200 with {"deduplicated": true, ...}. Treat as skipped.
            is_dedup = isinstance(body, dict) and bool(body.get("deduplicated"))
            if is_dedup:
                existing_id = body.get("existing_id", "?")
                similarity = body.get("similarity", "?")
                log(
                    f"{short_sha} {project} -> skipped already-present "
                    f"(server-dedup id={existing_id} sim={similarity})"
                )
                by_status["skipped"] += 1
                by_project_status[project]["skipped"] += 1
                continue
            log(f"{short_sha} {project} -> ingested status={status}")
            by_status["ingested"] += 1
            by_project_status[project]["ingested"] += 1
            ingested_shas.append((project, short_sha))
        else:
            # Sanitize body so we don't dump anything sensitive; the bearer is
            # never in body but err on the side of brevity.
            reason = ""
            if isinstance(body, dict):
                reason = body.get("error") or body.get("message") or json.dumps(body)[:200]
            else:
                reason = str(body)[:200]
            log(f"{short_sha} {project} -> failed status={status} reason={reason}")
            by_status["failed"] += 1
            by_project_status[project]["failed"] += 1
            failure_modes[f"http-{status}"] += 1

    # ---- Summary ---------------------------------------------------------
    log("")
    log("=== Summary ===")
    for status in ("ingested", "skipped", "dry-run", "failed"):
        if by_status.get(status):
            log(f"  {status:10s} {by_status[status]}")
    log("")
    log("Per project:")
    for project in sorted(by_project_status):
        counts = by_project_status[project]
        parts = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        log(f"  {project}: {parts}")
    if failure_modes:
        log("")
        log("Failure modes:")
        for mode, n in sorted(failure_modes.items()):
            log(f"  {mode}: {n}")
    if ingested_shas:
        log("")
        log("Ingested shas (project, sha):")
        for project, sha in ingested_shas:
            log(f"  {project} {sha}")

    return 0 if by_status.get("failed", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
