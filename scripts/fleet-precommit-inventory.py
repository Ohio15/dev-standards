#!/usr/bin/env python3
"""Inventory which repos under a projects root are actually gated by the
dev-standards pre-commit-tests hook.

WHY THIS EXISTS. hooks/pre-commit-tests.sh runs ONLY the command a repo declares
in `.pre-commit-tests`; with no file it skips (loudly, exit 0). A repo can
therefore have the hook installed and still be ungated. This script makes that
state visible per repo. It is read-only: it never writes to, or runs anything
in, a repo (git is invoked only for `config --get core.hooksPath`).

Status per repo:
  gated    hook installed AND .pre-commit-tests declares a usable TEST_CMD
  inert    hook installed but no usable .pre-commit-tests (hook skips or errors)
  no-hook  .githooks/pre-commit-tests.sh absent

Layout walked: <root>/<repo> and <root>/<namespace>/<repo> (one level of
namespace). A directory with a `.git` entry is a repo; any other directory is
treated as a namespace and its direct children are checked. `.archive`,
`.staging-licenses` and `data` at the root are skipped.

`.pre-commit-tests` is parsed exactly as hooks/pre-commit-tests.sh parses it
(KEY=value, '#'/blank lines skipped, key whitespace stripped, value verbatim,
TEST_TIMEOUT whitespace stripped, default 300, last assignment wins). If the
hook's parser changes, change `parse_config` with it.

Run:  python -I scripts/fleet-precommit-inventory.py [--root D:/Projects] [--json]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SKIP_ROOT_ENTRIES = {".archive", ".staging-licenses", "data"}
HOOK_REL = Path(".githooks") / "pre-commit-tests.sh"
DISPATCHER_REL = Path(".githooks") / "pre-commit"
CONFIG_NAME = ".pre-commit-tests"
DEFAULT_TIMEOUT = "300"
CANONICAL_HOOK = Path(__file__).resolve().parent.parent / "hooks" / "pre-commit-tests.sh"
# The keys the hook's `case "$key" in` arms accept; anything else it ignores as
# unknown. parse_config rejects every key not listed here, and
# scripts/tests/test_fleet_precommit_inventory.py derives the hook's set from
# its source and requires equality, so a new hook key cannot drift silently.
HOOK_CONFIG_KEYS = frozenset({"TEST_CMD", "TEST_TIMEOUT", "TEST_PATHS", "TEST_CLEANUP_CMD"})


def _read_text(path: Path) -> str:
    return path.read_bytes().decode("utf-8", errors="replace")


def parse_config(path: Path) -> dict:
    """Mirror of the parsing loop in hooks/pre-commit-tests.sh."""
    test_cmd = ""
    timeout = DEFAULT_TIMEOUT
    paths = ""
    cleanup_cmd = ""
    unknown: list[str] = []
    # bash `read -r` splits on \n only; a trailing \r stays on the line.
    raw = _read_text(path)
    lines = raw.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for line in lines:
        if line == "" or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            value = line  # ${line#*=} with no '=' leaves the whole line
        key = re.sub(r"\s+", "", key)
        if key not in HOOK_CONFIG_KEYS:
            unknown.append(key)
        elif key == "TEST_CMD":
            test_cmd = value
        elif key == "TEST_TIMEOUT":
            timeout = re.sub(r"\s+", "", value)
        elif key == "TEST_PATHS":
            paths = re.sub(r"\s+", "", value)
        elif key == "TEST_CLEANUP_CMD":
            cleanup_cmd = value
        else:  # a HOOK_CONFIG_KEYS entry with no branch is a bug here, not in the config
            raise AssertionError(f"parse_config has no branch for hook key {key}")
    problems = []
    if not test_cmd:
        problems.append("no TEST_CMD")
    if not timeout.isdigit():
        problems.append(f"bad TEST_TIMEOUT {timeout!r}")
    return {
        "test_cmd": test_cmd,
        "test_timeout": timeout,
        "test_paths": paths,
        "test_cleanup_cmd": cleanup_cmd,
        "unknown_keys": unknown,
        "valid": not problems,
        "problems": problems,
        # Not a validity failure here, but the hook keeps the \r in TEST_CMD, so
        # `bash -c` receives a command ending in a carriage return.
        "warnings": ["CRLF line endings"] if "\r" in raw else [],
    }


def detect_test_command(repo: Path) -> str:
    """Best guess from the tree. Informational only; the hook never guesses."""
    has_pytest_cfg = (repo / "pytest.ini").is_file()
    if not has_pytest_cfg and (repo / "pyproject.toml").is_file():
        has_pytest_cfg = "[tool.pytest" in _read_text(repo / "pyproject.toml")
    if not has_pytest_cfg and (repo / "setup.cfg").is_file():
        has_pytest_cfg = "[tool:pytest]" in _read_text(repo / "setup.cfg")
    has_venv = (repo / ".venv").is_dir() or (repo / "venv").is_dir()
    if has_pytest_cfg or ((repo / "tests").is_dir() and has_venv):
        return "python -m pytest"
    pkg = repo / "package.json"
    if pkg.is_file():
        try:
            scripts = json.loads(_read_text(pkg)).get("scripts") or {}
            cmd = scripts.get("test") if isinstance(scripts, dict) else None
        except (ValueError, AttributeError):
            cmd = None
        if isinstance(cmd, str) and cmd.strip() and "no test specified" not in cmd:
            return "npm test"
    if (repo / "go.mod").is_file():
        return "go test ./..."
    if (repo / "Cargo.toml").is_file():
        return "cargo test"
    return "unknown"


def hooks_path(repo: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "config", "--get", "core.hooksPath"],
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return "?"
    return out.stdout.strip() if out.returncode == 0 else ""


def discover(root: Path) -> list[Path]:
    repos: list[Path] = []
    for entry in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if entry.name in SKIP_ROOT_ENTRIES or not entry.is_dir():
            continue
        if (entry / ".git").exists():
            repos.append(entry)
            continue
        try:
            children = sorted(entry.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            continue
        for child in children:
            if child.is_dir() and (child / ".git").exists():
                repos.append(child)
    return repos


def inspect(repo: Path, root: Path, canonical: bytes | None) -> dict:
    hook = repo / HOOK_REL
    has_hook = hook.is_file()
    identical = None
    if has_hook and canonical is not None:
        identical = hook.read_bytes() == canonical
    cfg_path = repo / CONFIG_NAME
    cfg = parse_config(cfg_path) if cfg_path.is_file() else None
    if not has_hook:
        status = "no-hook"
    elif cfg is not None and cfg["valid"]:
        status = "gated"
    else:
        status = "inert"
    return {
        "path": repo.relative_to(root).as_posix(),
        "status": status,
        "has_hook": has_hook,
        "hook_identical_to_canonical": identical,
        "has_dispatcher": (repo / DISPATCHER_REL).is_file(),
        "hooks_path": hooks_path(repo),
        "has_config": cfg is not None,
        "test_cmd": cfg["test_cmd"] if cfg else None,
        "test_timeout": cfg["test_timeout"] if cfg else None,
        "config_problems": cfg["problems"] if cfg else [],
        "config_warnings": cfg["warnings"] if cfg else [],
        "detected_test_cmd": detect_test_command(repo),
    }


def _cell(value) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value).replace("|", "\\|").replace("\r", "").replace("\n", " ")


def render_markdown(rows: list[dict]) -> str:
    counts = {s: sum(r["status"] == s for r in rows) for s in ("gated", "inert", "no-hook")}
    head = (
        f"{len(rows)} repos: {counts['gated']} gated, {counts['inert']} inert, "
        f"{counts['no-hook']} no hook\n\n"
    )
    cols = ["repo", "status", "hook", "identical", "core.hooksPath", ".pre-commit-tests",
            "TEST_CMD", "TIMEOUT", "detected"]
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for r in rows:
        cfg = _cell(r["has_config"])
        notes = r["config_problems"] + r["config_warnings"]
        if notes:
            cfg += " (" + "; ".join(notes) + ")"
        lines.append("| " + " | ".join([
            _cell(r["path"]), r["status"], _cell(r["has_hook"]),
            _cell(r["hook_identical_to_canonical"]), _cell(r["hooks_path"]), _cell(cfg),
            _cell(r["test_cmd"]), _cell(r["test_timeout"]), _cell(r["detected_test_cmd"]),
        ]) + " |")
    return head + "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default="D:/Projects", help="projects root (default D:/Projects)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)
    root = Path(args.root)
    if not root.is_dir():
        print(f"error: root {root} is not a directory", file=sys.stderr)
        return 2
    canonical = CANONICAL_HOOK.read_bytes() if CANONICAL_HOOK.is_file() else None
    if canonical is None:
        print(f"warning: canonical hook {CANONICAL_HOOK} missing; identity unknown", file=sys.stderr)
    rows = [inspect(r, root, canonical) for r in discover(root)]
    if args.json:
        json.dump({"root": root.as_posix(), "repos": rows}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_markdown(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
