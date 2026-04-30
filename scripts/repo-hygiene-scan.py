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

# Drift detection constants
NEXUS_HOST = "ohio_@100.98.48.63"
NTFY_URL = "http://192.168.1.20:2586/nexus-alerts"
DRIFT_LAG_THRESHOLD = 2  # N>=2 releases behind => HIGH severity
GH_OWNER = "Ohio15"
SEMVER_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")


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
        "type": "observation",
        "tags": [f"hygiene-scan-{scan_date}", "automation", "dev-standards"],
        "content": summary[:8000],
        "importance": 0.6,
        "domain": "implementation",
        "project": "dev-standards",
    }
    body = json.dumps(payload)
    cmd = [
        "curl", "-sS", "-X", "POST",
        "-H", f"Authorization: Bearer {api_key}",
        "-H", "Content-Type: application/json",
        "-d", body,
        "https://shared-brain.us/api/memory/ingest",
    ]
    rc, out, err = run(cmd)
    if rc != 0:
        return False, f"curl rc={rc}: {err.strip()}"
    # The endpoint returns JSON on success; HTML on 404. Reject HTML.
    out_stripped = out.strip()
    if out_stripped.startswith("<"):
        return False, f"non-JSON response: {out_stripped[:120]}"
    return True, out_stripped[:200]


# ---------------------------------------------------------------------------
# Drift detection (Phase 1C)
# ---------------------------------------------------------------------------
#
# Records, per enrolled repo (those with release-config.yml), the latest
# released tag, the latest GHCR image tag (for docker/mcp surfaces), and
# the tag currently running on NEXUS. Writes versions.yml. Emits HIGH
# findings + ntfy when a running tag is N>=2 releases behind latest.
#
# All gh / ssh / curl calls degrade gracefully: a missing capability emits
# a LOW finding rather than aborting the scan.


def _yaml_strip_comment(line: str) -> str:
    """Strip a trailing `#` comment that's not inside a quoted string."""
    out: list[str] = []
    in_single = False
    in_double = False
    for ch in line:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            break
        out.append(ch)
    return "".join(out).rstrip()


def _yaml_scalar(value: str) -> Any:
    """Coerce a YAML scalar string to bool/int/float/str. Strips quotes."""
    v = value.strip()
    if not v:
        return ""
    if v.startswith(("'", '"')) and len(v) >= 2 and v[0] == v[-1]:
        return v[1:-1]
    low = v.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~"):
        return None
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


def parse_yaml(text: str) -> Any:
    """Minimal indentation-aware YAML parser for the subset we use.

    Supports nested mappings, sequences of scalars, and sequences of
    inline mappings (block-style). Does not support multi-line strings,
    anchors, flow style, or tagged values. That's exactly the subset
    used in release-config.yml and the compose files we read.

    Returns a Python dict / list / scalar.
    """
    # Pre-process: strip comments and trailing whitespace; keep blank lines
    # to preserve structure semantics where needed (we mostly skip them).
    raw_lines = text.splitlines()
    lines: list[tuple[int, str]] = []  # (indent, content)
    for ln in raw_lines:
        stripped = _yaml_strip_comment(ln)
        if not stripped.strip():
            continue
        # tab -> 2 spaces normalisation; YAML technically forbids tabs but we
        # handle them defensively.
        expanded = stripped.expandtabs(2)
        indent = len(expanded) - len(expanded.lstrip(" "))
        lines.append((indent, expanded.lstrip(" ")))
    if not lines:
        return {}

    pos = [0]

    def peek() -> tuple[int, str] | None:
        if pos[0] >= len(lines):
            return None
        return lines[pos[0]]

    def consume() -> tuple[int, str]:
        item = lines[pos[0]]
        pos[0] += 1
        return item

    def parse_block(min_indent: int) -> Any:
        # Decide list vs mapping by looking at first line
        first = peek()
        if first is None or first[0] < min_indent:
            return {}
        if first[1].startswith("- "):
            return parse_seq(first[0])
        return parse_map(first[0])

    def parse_map(indent: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while True:
            cur = peek()
            if cur is None or cur[0] < indent:
                return result
            if cur[0] > indent:
                # shouldn't happen at the top of a mapping; skip defensively
                consume()
                continue
            ind, content = consume()
            if content.startswith("- "):
                # We were called expecting a map; rewind and let caller see seq
                pos[0] -= 1
                return result
            if ":" not in content:
                # malformed; skip
                continue
            key, _, rest = content.partition(":")
            key = key.strip()
            rest = rest.strip()
            if rest == "":
                # nested block
                nxt = peek()
                if nxt is None or nxt[0] <= ind:
                    result[key] = None
                else:
                    result[key] = parse_block(nxt[0])
            elif rest.startswith("[") and rest.endswith("]"):
                # inline flow sequence of scalars
                inner = rest[1:-1].strip()
                if not inner:
                    result[key] = []
                else:
                    parts = [_yaml_scalar(p) for p in _split_flow(inner)]
                    result[key] = parts
            elif rest.startswith("{") and rest.endswith("}"):
                inner = rest[1:-1].strip()
                obj: dict[str, Any] = {}
                if inner:
                    for pair in _split_flow(inner):
                        if ":" in pair:
                            k, _, v = pair.partition(":")
                            obj[k.strip()] = _yaml_scalar(v.strip())
                result[key] = obj
            elif rest in ("|", ">", "|-", ">-", "|+", ">+"):
                # block scalar; capture all subsequent more-indented lines
                buf: list[str] = []
                while True:
                    nxt = peek()
                    if nxt is None or nxt[0] <= ind:
                        break
                    consume()
                    buf.append(nxt[1])
                result[key] = "\n".join(buf)
            else:
                result[key] = _yaml_scalar(rest)
        # unreachable

    def parse_seq(indent: int) -> list[Any]:
        result: list[Any] = []
        while True:
            cur = peek()
            if cur is None or cur[0] < indent:
                return result
            if cur[0] > indent:
                consume()
                continue
            ind, content = cur
            if not content.startswith("- "):
                return result
            consume()
            tail = content[2:].strip()
            if not tail:
                # block element underneath
                nxt = peek()
                if nxt is None or nxt[0] <= ind:
                    result.append(None)
                else:
                    result.append(parse_block(nxt[0]))
            elif ":" in tail and not (tail.startswith("[") or tail.startswith("{")):
                # inline mapping starting on the dash line; treat the dash
                # line as the first key:value, then continue with more indented
                # keys at (ind + 2).
                key, _, rest = tail.partition(":")
                obj: dict[str, Any] = {}
                rest = rest.strip()
                if rest == "":
                    nxt = peek()
                    if nxt is None or nxt[0] <= ind:
                        obj[key.strip()] = None
                    else:
                        obj[key.strip()] = parse_block(nxt[0])
                else:
                    obj[key.strip()] = _yaml_scalar(rest)
                # Pull additional keys at ind+2 (the column after `- `)
                child_indent = ind + 2
                while True:
                    nxt = peek()
                    if nxt is None or nxt[0] != child_indent:
                        break
                    if nxt[1].startswith("- "):
                        break
                    sub_ind, sub_content = consume()
                    if ":" not in sub_content:
                        continue
                    sk, _, sv = sub_content.partition(":")
                    sk = sk.strip()
                    sv = sv.strip()
                    if sv == "":
                        nxt2 = peek()
                        if nxt2 is None or nxt2[0] <= sub_ind:
                            obj[sk] = None
                        else:
                            obj[sk] = parse_block(nxt2[0])
                    elif sv.startswith("[") and sv.endswith("]"):
                        inner = sv[1:-1].strip()
                        obj[sk] = (
                            [_yaml_scalar(p) for p in _split_flow(inner)] if inner else []
                        )
                    else:
                        obj[sk] = _yaml_scalar(sv)
                result.append(obj)
            else:
                result.append(_yaml_scalar(tail))

    return parse_block(lines[0][0])


def _split_flow(inner: str) -> list[str]:
    """Split a flow-style inline list/map body on commas, respecting quotes."""
    out: list[str] = []
    buf: list[str] = []
    depth_sq = 0
    depth_cu = 0
    in_s = False
    in_d = False
    for ch in inner:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif not in_s and not in_d:
            if ch == "[":
                depth_sq += 1
            elif ch == "]":
                depth_sq -= 1
            elif ch == "{":
                depth_cu += 1
            elif ch == "}":
                depth_cu -= 1
            elif ch == "," and depth_sq == 0 and depth_cu == 0:
                out.append("".join(buf).strip())
                buf = []
                continue
        buf.append(ch)
    if buf:
        tail = "".join(buf).strip()
        if tail:
            out.append(tail)
    return out


def emit_yaml(value: Any, indent: int = 0) -> str:
    """Emit a Python value as block-style YAML. Stable key order.

    Dicts and lists only. Strings that need quoting (contain : or start with
    special chars) get double-quoted. None -> null.
    """
    sp = "  " * indent
    if isinstance(value, dict):
        if not value:
            return "{}\n"
        out: list[str] = []
        for k, v in value.items():
            if isinstance(v, (dict, list)) and v:
                out.append(f"{sp}{k}:")
                out.append(emit_yaml(v, indent + 1))
            elif isinstance(v, dict) and not v:
                out.append(f"{sp}{k}: {{}}")
            elif isinstance(v, list) and not v:
                out.append(f"{sp}{k}: []")
            else:
                out.append(f"{sp}{k}: {_emit_scalar(v)}")
        return "\n".join(out) + ("\n" if indent == 0 else "")
    if isinstance(value, list):
        if not value:
            return "[]\n"
        out = []
        for item in value:
            if isinstance(item, dict) and item:
                # Render first key on the dash line, rest indented
                items = list(item.items())
                first_k, first_v = items[0]
                if isinstance(first_v, (dict, list)) and first_v:
                    out.append(f"{sp}- {first_k}:")
                    out.append(emit_yaml(first_v, indent + 2))
                else:
                    out.append(f"{sp}- {first_k}: {_emit_scalar(first_v)}")
                for k, v in items[1:]:
                    if isinstance(v, (dict, list)) and v:
                        out.append(f"{sp}  {k}:")
                        out.append(emit_yaml(v, indent + 2))
                    else:
                        out.append(f"{sp}  {k}: {_emit_scalar(v)}")
            else:
                out.append(f"{sp}- {_emit_scalar(item)}")
        return "\n".join(out)
    return f"{sp}{_emit_scalar(value)}\n"


def _emit_scalar(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    needs_quote = (
        s == ""
        or s.lower() in ("null", "true", "false", "yes", "no", "on", "off", "~")
        or any(c in s for c in (":", "#", "&", "*", "!", "|", ">", "%", "@", "`"))
        or s.startswith(("-", "?", "[", "{", '"', "'", " "))
        or s.endswith(" ")
    )
    if needs_quote:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def discover_enrolled_repos(roots: list[Path]) -> list[tuple[Path, dict[str, Any]]]:
    """Find repos with release-config.yml and parse the config."""
    enrolled: list[tuple[Path, dict[str, Any]]] = []
    seen: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        candidates: list[Path] = []
        if is_git_repo(root) and (root / "release-config.yml").is_file():
            candidates.append(root)
        try:
            for child in sorted(root.iterdir()):
                if child.is_dir() and (child / "release-config.yml").is_file():
                    candidates.append(child)
        except PermissionError:
            continue
        for c in candidates:
            rc = c.resolve()
            if rc in seen:
                continue
            seen.add(rc)
            try:
                cfg = parse_yaml((c / "release-config.yml").read_text(encoding="utf-8"))
                if isinstance(cfg, dict):
                    enrolled.append((c, cfg))
            except (OSError, UnicodeDecodeError):
                continue
    return enrolled


def parse_compose_services(repo: Path, compose_file: str) -> dict[str, dict[str, str]]:
    """Read compose and return {service_name: {container_name, image_name}}.

    image_name is the registry/repo portion (before the `:tag`), useful for
    matching against running container images.
    """
    cf = repo / compose_file
    if not cf.is_file():
        return {}
    try:
        data = parse_yaml(cf.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return {}
    services = data.get("services", {}) if isinstance(data, dict) else {}
    out: dict[str, dict[str, str]] = {}
    if not isinstance(services, dict):
        return out
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        cn = svc.get("container_name") or svc_name
        img = svc.get("image", "")
        # strip the :${TAG} part to get just the image name
        img_name = img
        if isinstance(img, str) and ":" in img:
            img_name = img.split(":", 1)[0]
        out[svc_name] = {"container_name": str(cn), "image_name": str(img_name)}
    return out


def gh_latest_release(repo_name: str) -> tuple[str | None, str | None, str | None]:
    """Return (tag, published_at, error). Errors degrade gracefully."""
    cmd = [
        "gh", "release", "list", "-L", "1",
        "--json", "tagName,publishedAt",
        "--repo", f"{GH_OWNER}/{repo_name}",
    ]
    rc, out, err = run(cmd)
    if rc != 0:
        return None, None, f"gh rc={rc}: {err.strip()[:200]}"
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        return None, None, f"json parse: {e}"
    if not data:
        return None, None, "no releases"
    rec = data[0]
    return rec.get("tagName"), rec.get("publishedAt"), None


def gh_ghcr_latest_tag(package: str) -> tuple[str | None, str | None]:
    """Query GHCR for the newest semver image tag of `<owner>/<package>`.

    Returns (tag, error). Falls back gracefully if the auth token lacks
    `read:packages` scope or the package is not found.
    """
    # gh api requires the leading slash to be omitted on Git Bash / MSYS,
    # which path-mangles a leading `/` into a Windows path. Use the relative
    # form everywhere — gh accepts both.
    endpoint = f"users/{GH_OWNER}/packages/container/{package}/versions?per_page=50"
    rc, out, err = run(["gh", "api", endpoint])
    if rc != 0:
        return None, f"gh api rc={rc}: {err.strip()[:200]}"
    try:
        versions = json.loads(out)
    except json.JSONDecodeError as e:
        return None, f"json parse: {e}"
    if not isinstance(versions, list):
        return None, f"unexpected response shape: {type(versions).__name__}"
    best: tuple[int, int, int] | None = None
    best_tag: str | None = None
    for v in versions:
        meta = v.get("metadata", {}).get("container", {}) if isinstance(v, dict) else {}
        for tag in meta.get("tags", []) or []:
            m = SEMVER_TAG_RE.match(tag)
            if not m:
                continue
            cur = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            if best is None or cur > best:
                best = cur
                best_tag = tag
    if best_tag is None:
        return None, "no semver tags on package"
    return best_tag, None


def ssh_nexus(remote_cmd: str, timeout: int = 10) -> tuple[int, str, str]:
    """Run a command on NEXUS via SSH. Returns (rc, stdout, stderr)."""
    return run([
        "ssh",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        NEXUS_HOST,
        remote_cmd,
    ])


def nexus_running_tag(container_name: str, image_name: str) -> tuple[str | None, str | None]:
    """Return (running_semver_tag, error).

    Walks: container -> Config.Image -> if non-semver, look up via image
    sha and pick the best semver RepoTag matching `image_name`.
    """
    # First grab Config.Image and the image sha in one round-trip.
    fmt = "{{.Image}}|{{.Config.Image}}"
    rc, out, err = ssh_nexus(
        f"docker inspect --format '{fmt}' {shlex.quote(container_name)}"
    )
    if rc != 0:
        return None, f"docker inspect rc={rc}: {err.strip()[:200]}"
    line = out.strip().splitlines()[0] if out.strip() else ""
    if "|" not in line:
        return None, f"unexpected inspect output: {line[:120]}"
    img_sha, _, config_image = line.partition("|")
    # Fast path: Config.Image already has a semver tag
    if ":" in config_image:
        candidate = config_image.rsplit(":", 1)[1]
        if SEMVER_TAG_RE.match(candidate):
            return candidate, None
    # Fall back: enumerate all RepoTags on the image sha, find a semver
    # tag whose name portion matches image_name.
    rc2, out2, err2 = ssh_nexus(
        f"docker image inspect --format '{{{{join .RepoTags \",\"}}}}' {shlex.quote(img_sha)}"
    )
    if rc2 != 0:
        return None, f"docker image inspect rc={rc2}: {err2.strip()[:200]}"
    repo_tags = [t.strip() for t in out2.strip().split(",") if t.strip()]
    best: tuple[int, int, int] | None = None
    best_tag: str | None = None
    for rt in repo_tags:
        if ":" not in rt:
            continue
        name, _, tag = rt.rpartition(":")
        if image_name and name != image_name:
            continue
        m = SEMVER_TAG_RE.match(tag)
        if not m:
            continue
        cur = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if best is None or cur > best:
            best = cur
            best_tag = tag
    if best_tag is not None:
        return best_tag, None
    # No semver match — return whatever Config.Image had as a "raw" running tag
    if ":" in config_image:
        return config_image.rsplit(":", 1)[1], "no semver tag in RepoTags"
    return config_image or None, "no tag information"


def semver_lag(running: str | None, latest: str | None) -> int | None:
    """Return how many patch+minor+major version increments running is
    behind latest, summed crudely.

    Concretely:
        major delta * 1000 + minor delta * 10 + patch delta
    so any major delta dominates. Used only for the threshold check.
    Returns None if either side is not a parseable semver.
    """
    if not running or not latest:
        return None
    rm = SEMVER_TAG_RE.match(running)
    lm = SEMVER_TAG_RE.match(latest)
    if not rm or not lm:
        return None
    rv = (int(rm.group(1)), int(rm.group(2)), int(rm.group(3)))
    lv = (int(lm.group(1)), int(lm.group(2)), int(lm.group(3)))
    if rv >= lv:
        return 0
    # Count distinct release "steps". For threshold purposes treat each
    # patch step as 1 and each minor or major bump as also at least 2
    # (since they imply intermediate patch releases were skipped).
    if lv[0] != rv[0]:
        return max(2, (lv[0] - rv[0]) * 2)
    if lv[1] != rv[1]:
        return max(2, lv[1] - rv[1])
    return lv[2] - rv[2]


def ntfy_post(title: str, message: str, priority: str = "high") -> tuple[bool, str]:
    """POST to ntfy. Tries a 2s connect; skips silently if unreachable.

    Uses curl (stdlib http.client would also work, but curl is already
    used for shared-brain and avoids surprise behaviour with proxies).
    """
    cmd = [
        "curl", "-sS", "-m", "5",
        "-X", "POST",
        "-H", f"Title: {title}",
        "-H", f"Priority: {priority}",
        "-H", "Tags: warning,version-drift",
        "--data-binary", message,
        NTFY_URL,
    ]
    rc, out, err = run(cmd)
    if rc != 0:
        return False, f"curl rc={rc}: {err.strip()[:200]}"
    return True, out.strip()[:200]


def ntfy_reachable() -> bool:
    """Quick probe: is the LAN ntfy endpoint reachable?"""
    rc, _, _ = run(["curl", "-sS", "-m", "2", "-o", os.devnull, "-w", "%{http_code}", NTFY_URL.rstrip("/").rsplit("/", 1)[0] + "/"])
    return rc == 0


def scan_repo_drift(repo: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    """Inspect a single enrolled repo for version drift.

    Returns a dict with `findings` (list of severity-tagged dicts) plus a
    `version` block ready for inclusion in versions.yml.
    """
    name = repo.name
    project = cfg.get("project") or name
    surface = cfg.get("surface") or "unknown"
    findings: list[dict[str, Any]] = []
    version_block: dict[str, Any] = {
        "surface": surface,
    }

    # 1) Latest release
    latest_tag, published_at, err = gh_latest_release(name)
    if err:
        findings.append({
            "severity": "LOW",
            "code": "drift-gh-release-unavailable",
            "note": f"could not query latest release for {name}: {err}",
        })
    if latest_tag:
        version_block["latest_release"] = latest_tag
    if published_at:
        version_block["latest_release_at"] = published_at

    # Electron / lib surfaces stop here — no running tag to track on NEXUS.
    if surface not in ("docker", "mcp"):
        return {"name": name, "project": project, "findings": findings,
                "version_block": version_block}

    # 2) Resolve images + running tags via compose + NEXUS
    docker_cfg = cfg.get("docker") if surface == "docker" else cfg.get("mcp")
    if not isinstance(docker_cfg, dict):
        findings.append({
            "severity": "LOW",
            "code": "drift-config-incomplete",
            "note": f"surface={surface} but no `{surface}:` block in release-config.yml",
        })
        return {"name": name, "project": project, "findings": findings,
                "version_block": version_block}

    deploy = docker_cfg.get("deploy", {}) if isinstance(docker_cfg.get("deploy"), dict) else {}
    compose_file = deploy.get("compose_file", "docker-compose.yml")
    services_to_check = deploy.get("services", []) or []
    if not isinstance(services_to_check, list):
        services_to_check = []

    compose_services = parse_compose_services(repo, compose_file)
    if not compose_services:
        findings.append({
            "severity": "LOW",
            "code": "drift-compose-missing",
            "note": f"could not read services from {compose_file}",
        })

    # Latest GHCR image tag — query per declared image, then map by service.
    images_cfg = docker_cfg.get("images") if surface == "docker" else None
    declared_images: list[str] = []
    if isinstance(images_cfg, list):
        for item in images_cfg:
            if isinstance(item, dict) and item.get("name"):
                declared_images.append(str(item["name"]))
    elif surface == "mcp" and isinstance(docker_cfg.get("image"), str):
        declared_images.append(str(docker_cfg["image"]))

    ghcr_latest_by_image: dict[str, str | None] = {}
    ghcr_unauth = False
    for img in declared_images:
        # img is `ghcr.io/ohio15/<package>` — package is the last path segment
        package = img.rsplit("/", 1)[-1]
        tag, qerr = gh_ghcr_latest_tag(package)
        ghcr_latest_by_image[img] = tag
        if qerr and "rc=" in qerr and ("403" in qerr or "401" in qerr or "scope" in qerr.lower()):
            ghcr_unauth = True
        elif qerr:
            findings.append({
                "severity": "LOW",
                "code": "drift-ghcr-query-failed",
                "note": f"{package}: {qerr}",
            })
    if ghcr_unauth:
        findings.append({
            "severity": "LOW",
            "code": "drift-ghcr-unauthorised",
            "note": "gh token lacks read:packages scope; falling back to release tag for image tag",
        })

    services_block: dict[str, dict[str, Any]] = {}
    for svc_name in services_to_check:
        svc_meta = compose_services.get(svc_name)
        if not svc_meta:
            findings.append({
                "severity": "LOW",
                "code": "drift-service-not-in-compose",
                "note": f"service '{svc_name}' declared in release-config but absent from {compose_file}",
            })
            continue
        container_name = svc_meta["container_name"]
        image_name = svc_meta["image_name"]
        # Latest image tag for this service: prefer GHCR query result for the
        # matching image; otherwise fall back to latest_release.
        image_latest = ghcr_latest_by_image.get(image_name)
        if not image_latest:
            image_latest = latest_tag  # contract: image is tagged with release tag
        running_tag, run_err = nexus_running_tag(container_name, image_name)
        if run_err and not running_tag:
            findings.append({
                "severity": "LOW",
                "code": "drift-nexus-inspect-failed",
                "note": f"container '{container_name}': {run_err}",
            })
        services_block[svc_name] = {
            "container_name": container_name,
            "image": image_name,
            "running": running_tag,
            "latest": image_latest,
        }
        # Drift evaluation
        lag = semver_lag(running_tag, image_latest)
        if lag is not None and lag >= DRIFT_LAG_THRESHOLD:
            findings.append({
                "severity": "HIGH",
                "code": "version-drift",
                "service": svc_name,
                "container": container_name,
                "running": running_tag,
                "latest": image_latest,
                "lag": lag,
                "note": f"{svc_name} on NEXUS is {lag} releases behind latest",
            })

    version_block["services"] = services_block
    # Roll up convenience fields when a single image is in play
    if len(services_block) == 1:
        only = next(iter(services_block.values()))
        if only.get("running"):
            version_block["running_tag_on_nexus"] = only["running"]
        if only.get("latest"):
            version_block["latest_image_tag"] = only["latest"]

    return {"name": name, "project": project, "findings": findings,
            "version_block": version_block}


def render_drift_markdown(drift: dict[str, Any]) -> str:
    if not drift.get("repos"):
        return ""
    lines: list[str] = []
    lines.append("")
    lines.append(f"# Drift detection — {drift['scanned_at']}")
    lines.append("")
    lines.append(f"Enrolled repos: {drift['enrolled_count']}")
    lines.append(f"Drift findings: {drift['drift_findings']}")
    if drift.get("ntfy_sent"):
        lines.append(f"ntfy: {drift['ntfy_sent']}")
    lines.append("")
    for r in drift["repos"]:
        vb = r.get("version_block", {})
        lines.append(f"## {r['name']} ({vb.get('surface', '?')})")
        if "latest_release" in vb:
            lines.append(f"  latest_release: {vb['latest_release']}")
        for svc, sb in (vb.get("services") or {}).items():
            running = sb.get("running") or "?"
            latest = sb.get("latest") or "?"
            marker = "  " if running == latest else "  ! "
            lines.append(f"{marker}{svc}: running={running} latest={latest}")
        for f in r["findings"]:
            lines.append(f"  - **{f['severity']}** {f['code']}: {f.get('note','')}")
        lines.append("")
    return "\n".join(lines)


def run_drift_scan(roots: list[Path]) -> dict[str, Any]:
    """Top-level drift entry point. Discovers enrolled repos, queries each."""
    scanned_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    enrolled = discover_enrolled_repos(roots)
    repo_results: list[dict[str, Any]] = []
    versions_payload: dict[str, dict[str, Any]] = {}
    drift_count = 0
    for repo, cfg in enrolled:
        result = scan_repo_drift(repo, cfg)
        repo_results.append(result)
        project_key = result["project"]
        versions_payload[project_key] = result["version_block"]
        for f in result["findings"]:
            if f["severity"] == "HIGH" and f.get("code") == "version-drift":
                drift_count += 1
    return {
        "scanned_at": scanned_at,
        "enrolled_count": len(enrolled),
        "drift_findings": drift_count,
        "repos": repo_results,
        "versions_payload": versions_payload,
    }


def write_versions_yml(out_path: Path, drift: dict[str, Any]) -> None:
    body = {"last_scanned": drift["scanned_at"], "repos": drift["versions_payload"]}
    text = (
        "# Auto-generated by scripts/repo-hygiene-scan.py --check-drift\n"
        "# Records latest released vs latest GHCR vs running-on-NEXUS per enrolled repo.\n"
        + emit_yaml(body)
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")


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
    ap.add_argument(
        "--check-drift", action="store_true",
        help="Additionally run drift detection: query GitHub releases, GHCR "
             "image tags, and NEXUS running tags for enrolled repos. Writes "
             "release/versions.yml in dev-standards.",
    )
    ap.add_argument(
        "--versions-yml", default=None,
        help="Path to write versions.yml (default: dev-standards/release/versions.yml "
             "co-located with this script)",
    )
    ap.add_argument(
        "--no-ntfy", action="store_true",
        help="Skip the ntfy alert even when drift is detected",
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

    # Drift detection (Phase 1C) — additive: produces its own findings list
    # that gets merged into the corresponding repo report by name, and a
    # separate versions.yml artifact.
    drift_result: dict[str, Any] | None = None
    if args.check_drift:
        drift_result = run_drift_scan(roots)
        # Merge drift findings into the matching repo entry, or append a
        # synthetic entry if the repo wasn't in the hygiene-scan set.
        by_path: dict[str, dict[str, Any]] = {r["path"]: r for r in repo_reports}
        by_name: dict[str, dict[str, Any]] = {r["name"]: r for r in repo_reports}
        for dr in drift_result["repos"]:
            host_repo = by_name.get(dr["name"])
            if host_repo is None:
                # Enrolled repo wasn't reachable as a git repo (rare). Add a
                # minimal entry so its findings still surface.
                host_repo = {
                    "name": dr["name"],
                    "path": "",
                    "tracked_count": 0,
                    "findings": [],
                }
                repo_reports.append(host_repo)
                by_path[host_repo["path"]] = host_repo
                by_name[host_repo["name"]] = host_repo
            host_repo["findings"].extend(dr["findings"])

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
    if drift_result is not None:
        report["drift"] = {
            "scanned_at": drift_result["scanned_at"],
            "enrolled_count": drift_result["enrolled_count"],
            "drift_findings": drift_result["drift_findings"],
            "versions": drift_result["versions_payload"],
        }
    report = severity_filter(report, args.severity)

    md = render_markdown(report)
    if drift_result is not None:
        md += render_drift_markdown(drift_result)
    print(md)

    # ntfy alert + versions.yml write happen regardless of --dry-run for
    # drift, since the user explicitly opted in via --check-drift. The
    # --dry-run flag still suppresses JSON write + brain-store.
    if drift_result is not None and drift_result["drift_findings"] > 0 and not args.no_ntfy:
        if ntfy_reachable():
            title = f"Version drift on NEXUS — {drift_result['drift_findings']} service(s) lagging"
            body_lines: list[str] = []
            for dr in drift_result["repos"]:
                for f in dr["findings"]:
                    if f.get("code") == "version-drift":
                        body_lines.append(
                            f"{dr['name']}/{f['service']}: running={f['running']} latest={f['latest']} (lag={f['lag']})"
                        )
            ok, msg = ntfy_post(title, "\n".join(body_lines))
            print(f"\n[ntfy {'ok' if ok else 'failed'}] {msg}", file=sys.stderr)
        else:
            print("\n[ntfy skipped] LAN endpoint not reachable", file=sys.stderr)

    if drift_result is not None:
        if args.versions_yml:
            versions_path = Path(args.versions_yml)
        else:
            # Co-located with this script: dev-standards/release/versions.yml
            versions_path = Path(__file__).resolve().parent.parent / "release" / "versions.yml"
        if not args.dry_run:
            write_versions_yml(versions_path, drift_result)
            print(f"\n[wrote {versions_path}]", file=sys.stderr)
        else:
            print(f"\n[--dry-run: would write {versions_path}]", file=sys.stderr)

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
