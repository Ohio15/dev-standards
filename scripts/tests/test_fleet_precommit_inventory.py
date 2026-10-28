"""fleet-precommit-inventory.py classifies repos by whether the commit gate is live.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "fleet-precommit-inventory.py"
CANONICAL = SCRIPT.parent.parent / "hooks" / "pre-commit-tests.sh"

spec = importlib.util.spec_from_file_location("fleet_inventory", SCRIPT)
inv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inv)


def make_repo(path: Path, *, hook: bytes | None = None, config: str | None = None,
              files: dict[str, str] | None = None) -> Path:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    if hook is not None:
        (path / ".githooks").mkdir()
        (path / ".githooks" / "pre-commit-tests.sh").write_bytes(hook)
    if config is not None:
        (path / ".pre-commit-tests").write_bytes(config.encode("utf-8"))
    for name, body in (files or {}).items():
        (path / name).write_text(body, encoding="utf-8")
    return path


@pytest.fixture()
def fleet(tmp_path: Path) -> Path:
    canon = CANONICAL.read_bytes()
    root = tmp_path / "Projects"
    root.mkdir()
    make_repo(root / "gated", hook=canon,
              config="# c\nTEST_CMD=python -m pytest -q\nTEST_TIMEOUT = 60\n",
              files={"pytest.ini": "[pytest]\n"})
    make_repo(root / "inert", hook=canon + b"# drift\n",
              files={"package.json": json.dumps({"scripts": {"test": "vitest"}})})
    make_repo(root / "nohook", files={"go.mod": "module x\n"})
    make_repo(root / "ns" / "inner", hook=canon, config="TEST_CMD=cargo test\n",
              files={"Cargo.toml": "[package]\n"})
    # Skipped root entries: repos inside them must not be reported.
    for skipped in (".archive", ".staging-licenses", "data"):
        make_repo(root / skipped / "hidden", hook=canon, config="TEST_CMD=true\n")
    (root / "stray.txt").write_text("x")
    return root


def by_path(rows):
    return {r["path"]: r for r in rows}


def run(root: Path) -> list[dict]:
    canonical = CANONICAL.read_bytes()
    return [inv.inspect(r, root, canonical) for r in inv.discover(root)]


def test_discovery_covers_namespaces_and_skips_reserved_entries(fleet):
    assert sorted(by_path(run(fleet))) == ["gated", "inert", "nohook", "ns/inner"]


def test_gated_repo(fleet):
    r = by_path(run(fleet))["gated"]
    assert r["status"] == "gated"
    assert r["hook_identical_to_canonical"] is True
    assert (r["test_cmd"], r["test_timeout"]) == ("python -m pytest -q", "60")
    assert r["detected_test_cmd"] == "python -m pytest"


def test_hook_present_but_inert(fleet):
    r = by_path(run(fleet))["inert"]
    assert r["status"] == "inert"
    assert r["has_hook"] and not r["has_config"]
    assert r["hook_identical_to_canonical"] is False
    assert r["detected_test_cmd"] == "npm test"


def test_no_hook_repo(fleet):
    r = by_path(run(fleet))["nohook"]
    assert r["status"] == "no-hook"
    assert r["hook_identical_to_canonical"] is None
    assert r["detected_test_cmd"] == "go test ./..."


def test_namespace_grouped_repo(fleet):
    r = by_path(run(fleet))["ns/inner"]
    assert r["status"] == "gated"
    assert r["test_timeout"] == "300"  # the hook's default
    assert r["detected_test_cmd"] == "cargo test"


def test_config_without_test_cmd_is_inert(tmp_path):
    root = tmp_path / "P"
    root.mkdir()
    make_repo(root / "r", hook=CANONICAL.read_bytes(), config="TEST_TIMEOUT=10\nBOGUS=1\n")
    r = run(root)[0]
    assert r["status"] == "inert" and r["config_problems"] == ["no TEST_CMD"]


def test_parse_matches_hook_semantics(tmp_path):
    f = tmp_path / ".pre-commit-tests"
    f.write_bytes(b"TEST_CMD=a\nTEST_CMD=echo  x=y\nTEST_TIMEOUT=abc\n")
    cfg = inv.parse_config(f)
    assert cfg["test_cmd"] == "echo  x=y"  # last wins, value verbatim, split on first '='
    assert cfg["problems"] == ["bad TEST_TIMEOUT 'abc'"]


def test_indented_comment_is_not_a_comment_to_the_hook(tmp_path):
    f = tmp_path / ".pre-commit-tests"
    f.write_bytes(b"  # note\nTEST_CMD=a\n")
    assert inv.parse_config(f)["unknown_keys"] == ["#note"]


def test_cli_markdown_and_json(fleet):
    base = ["python", "-I", str(SCRIPT), "--root", str(fleet)]
    md = subprocess.run(base, capture_output=True, text=True, check=True).stdout
    assert md.startswith("4 repos: 2 gated, 1 inert, 1 no hook")
    assert "| ns/inner | gated |" in md
    data = json.loads(subprocess.run(base + ["--json"], capture_output=True, text=True, check=True).stdout)
    assert [r["path"] for r in data["repos"]] == ["gated", "inert", "nohook", "ns/inner"]

def test_crlf_config_is_flagged_and_keeps_the_carriage_return(tmp_path):
    f = tmp_path / ".pre-commit-tests"
    f.write_bytes(b"TEST_CMD=pytest -q\r\nTEST_TIMEOUT=60\r\n")
    cfg = inv.parse_config(f)
    assert cfg["test_cmd"] == "pytest -q\r"  # as the hook would read it
    assert cfg["test_timeout"] == "60" and cfg["valid"]
    assert cfg["warnings"] == ["CRLF line endings"]


# --- key set derived from the hook, never restated ---------------------------
# parse_config claims to mirror the hook's parser. The accepted key set is the
# part that drifted (TEST_CLEANUP_CMD, PR #63): derive it from the hook's own
# `case "$key" in` arms and require the inventory to accept exactly that set.

def hook_config_keys() -> set[str]:
    src = CANONICAL.read_text(encoding="utf-8")
    start = src.index('case "$key" in')
    block = src[start:src.index("esac", start)]
    keys = set(re.findall(r"^\s*([A-Z][A-Z0-9_]*)\)", block, re.MULTILINE))
    # Not vacuous: the parse found the real arms and the catch-all is still there.
    assert {"TEST_CMD", "TEST_TIMEOUT", "TEST_PATHS"} <= keys, block
    assert re.search(r"^\s*\*\)", block, re.MULTILINE), block
    return keys


def test_inventory_key_set_equals_the_hooks_case_arms():
    assert set(inv.HOOK_CONFIG_KEYS) == hook_config_keys()


def test_inventory_parser_accepts_every_hook_key_and_rejects_others(tmp_path):
    keys = sorted(hook_config_keys())
    f = tmp_path / ".pre-commit-tests"
    f.write_bytes("".join(f"{k}=1\n" for k in keys).encode() + b"TEST_BOGUS=1\n")
    cfg = inv.parse_config(f)
    assert cfg["unknown_keys"] == ["TEST_BOGUS"]


def test_cleanup_cmd_is_parsed_verbatim(tmp_path):
    f = tmp_path / ".pre-commit-tests"
    f.write_bytes(b"TEST_CMD=pytest -q\nTEST_CLEANUP_CMD=python  tests/m.py --restore\n")
    cfg = inv.parse_config(f)
    assert cfg["test_cleanup_cmd"] == "python  tests/m.py --restore"
    assert cfg["unknown_keys"] == [] and cfg["valid"]
