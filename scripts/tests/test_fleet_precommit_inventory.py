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


# --- CRLF / BOM: parsed as the hook parses them --------------------------------
# Since 75ce527 (#56, shared-brain a0649d94) the hook drops one trailing CR per
# line and a UTF-8 BOM from the first line, so a Windows-saved config gates
# exactly like an LF one. The inventory used to keep the CR and warn about it
# (shared-brain 73bd6fdd); it must report what the hook will actually run.

LF_CONFIG = b"# c\nTEST_CMD=pytest -q\nTEST_TIMEOUT=60\nTEST_PATHS=src/**\n"
BOM = b"\xef\xbb\xbf"


@pytest.mark.parametrize("variant", ["crlf", "bom-lf", "bom-crlf"])
def test_windows_saved_config_parses_like_lf(tmp_path, variant):
    body = LF_CONFIG.replace(b"\n", b"\r\n") if variant.endswith("crlf") else LF_CONFIG
    if variant.startswith("bom"):
        body = BOM + body
    lf, other = tmp_path / "lf", tmp_path / variant
    lf.write_bytes(LF_CONFIG)
    other.write_bytes(body)
    expected = inv.parse_config(lf)
    assert expected["test_cmd"] == "pytest -q" and expected["valid"]
    assert inv.parse_config(other) == expected
    assert "warnings" not in expected  # the hook emits no CRLF warning, so neither do we


def test_bom_is_only_dropped_at_the_start_of_the_file(tmp_path):
    f = tmp_path / ".pre-commit-tests"
    f.write_bytes(b"TEST_CMD=a\n" + BOM + b"TEST_TIMEOUT=5\n")
    cfg = inv.parse_config(f)
    assert cfg["unknown_keys"] == ["﻿TEST_TIMEOUT"] and cfg["test_timeout"] == "300"


def test_only_one_trailing_carriage_return_is_dropped(tmp_path):
    f = tmp_path / ".pre-commit-tests"
    f.write_bytes(b"TEST_CMD=a\r\r\nTEST_CLEANUP_CMD=b\rc\n")
    cfg = inv.parse_config(f)
    assert (cfg["test_cmd"], cfg["test_cleanup_cmd"]) == ("a\r", "b\rc")


# --- parser parity with the REAL hook ----------------------------------------
# parse_config claims to mirror the hook's parser. Rather than restate the
# hook's rules here, run the hook's own parsing code (sliced verbatim from
# hooks/pre-commit-tests.sh, from the defaults through the TEST_TIMEOUT check)
# under Git's bash over the same configs, and require identical results. Any
# future change to either parser that the other does not share fails here.

PARITY_CONFIGS = {
    "lf-all-keys": b"# c\nTEST_CMD=python -m pytest -q\nTEST_TIMEOUT = 60\n"
                   b"TEST_PATHS= src/** | tests/** \nTEST_CLEANUP_CMD=python  t.py --restore\n",
    "crlf-all-keys": b"# c\r\nTEST_CMD=python -m pytest -q\r\nTEST_TIMEOUT = 60\r\n"
                     b"TEST_PATHS= src/** | tests/** \r\nTEST_CLEANUP_CMD=python  t.py --restore\r\n",
    "bom-lf": BOM + b"TEST_CMD=pytest -q\nTEST_TIMEOUT=60\n",
    "bom-crlf": BOM + b"TEST_CMD=pytest -q\r\nTEST_TIMEOUT=60\r\n",
    "bom-then-blank-and-comment": BOM + b"\r\n# x\r\nTEST_CMD=a\r\n",
    "bom-only": BOM,
    "bom-mid-file": b"TEST_CMD=a\n" + BOM + b"TEST_TIMEOUT=5\n",
    "crlf-no-final-newline": b"TEST_CMD=a b\r",
    "double-cr": b"TEST_CMD=a\r\r\n",
    "mid-line-cr": b"TEST_CMD=a\rb\n",
    "cr-only-lines": b"\r\n\r\nTEST_CMD=x\r\n",
    "crlf-trailing-spaces": b"TEST_CMD=pytest -q  \r\nTEST_TIMEOUT= 60 \r\n",
    "comments-noequals-last-wins": b"  # note\nTEST_CMD=a\nTEST_CMD=echo  x=y\nNOEQUALS\nTEST_TIMEOUT=abc\n",
    "non-ascii-whitespace-in-key": "TEST_CMD =x\nTEST\x1cTIMEOUT=5\n\x0bTEST_PATHS\t= a | b\n".encode(),
    "non-ascii-digit-timeout": "TEST_CMD=x\nTEST_TIMEOUT=²\n".encode(),
    "no-test-cmd": b"TEST_TIMEOUT=10\r\nBOGUS=1\r\n",
    "empty": b"",
}


def hook_parse_block() -> str:
    """The hook's parser, verbatim: defaults, read loop, and the validity checks."""
    lines = CANONICAL.read_text(encoding="utf-8").split("\n")
    start = lines.index('test_cmd=""')
    loop_end = lines.index('done < "$config"', start)
    timeout_case = lines.index('case "$test_timeout" in', loop_end)
    end = lines.index("esac", timeout_case)
    block = "\n".join(lines[start:end + 1])
    # Not vacuous: the slice holds the read loop, the CR/BOM normalisation and
    # both validity exits.
    for needle in ("while IFS= read -r line", "$'\\r'", "$'\\xef\\xbb\\xbf'",
                   'if [ -z "$test_cmd" ]', "exit 1"):
        assert needle in block, needle
    return block


def run_hook_parser(config: Path, block: str | None = None) -> dict:
    from test_pre_commit_tests_env import BASH, clean_env

    if block is None:
        block = hook_parse_block()
    # The EXIT trap reports the parsed variables NUL-separated whether the
    # block falls through (valid) or hits one of its `exit 1`s (invalid).
    script = (
        "set -euo pipefail\n"
        'config="$1"\n'
        "trap 'printf \"%s\\0\" \"$test_cmd\" \"$test_timeout\" \"$test_paths\" "
        "\"$test_cleanup_cmd\"' EXIT\n"
        + block + "\n"
    )
    proc = subprocess.run([BASH, "-c", script, "hook-parse", config.as_posix()],
                          env=clean_env(), capture_output=True, timeout=60, check=False)
    assert proc.returncode in (0, 1), proc.stderr
    fields = proc.stdout.decode("utf-8", errors="replace").split("\0")
    assert len(fields) == 5 and fields[4] == "", proc.stdout
    stderr = proc.stderr.decode("utf-8", errors="replace")
    return {
        "test_cmd": fields[0],
        "test_timeout": fields[1],
        "test_paths": fields[2],
        "test_cleanup_cmd": fields[3],
        "unknown_keys": re.findall(
            r"^pre-commit-tests: ignoring unknown key '(.*)' in \.pre-commit-tests$",
            stderr, re.MULTILINE),
        "valid": proc.returncode == 0,
    }


@pytest.mark.parametrize("name", sorted(PARITY_CONFIGS))
def test_parse_config_matches_the_hooks_own_parser(tmp_path, name):
    config = tmp_path / ".pre-commit-tests"
    config.write_bytes(PARITY_CONFIGS[name])
    hook = run_hook_parser(config)
    ours = inv.parse_config(config)
    assert {k: ours[k] for k in hook} == hook


@pytest.mark.parametrize("name", ["lf-all-keys", "crlf-all-keys", "bom-crlf", "double-cr"])
def test_parse_config_matches_the_full_hook_end_to_end(tmp_path, name):
    """The whole hook, in a throwaway repo, as git would run it: the command and
    timeout it announces (and the cleanup command it runs) are exactly what
    parse_config reports. Guards the slice above against no longer being the
    code the hook actually executes."""
    from test_pre_commit_tests_env import BASH, clean_env

    body = PARITY_CONFIGS[name]
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], env=clean_env(), check=True)
    # TEST_CMD/TEST_CLEANUP_CMD run for real: neutralise them to `true` while
    # keeping the bytes around each value (CRs, spacing) under test.
    body = re.sub(rb"(TEST_(?:CLEANUP_)?CMD=)[^\r\n]*?(\r*)(?=\n|$)", rb"\1true \2", body)
    body = re.sub(rb"TEST_PATHS=[^\r\n]*", b"TEST_PATHS=*", body)
    (repo / ".pre-commit-tests").write_bytes(body)
    (repo / "a.txt").write_text("x")
    subprocess.run(["git", "add", "a.txt"], cwd=repo, env=clean_env(), check=True)
    proc = subprocess.run([BASH, CANONICAL.as_posix()], cwd=repo, env=clean_env(),
                          capture_output=True, timeout=120, check=False)
    stderr = proc.stderr.decode("utf-8", errors="replace")
    # [^\n], not '.': a CR the hook kept must be captured, not end the match.
    ran = re.search(r"^pre-commit-tests: running `([^\n]*)` \(timeout ([0-9]+)s\)$",
                    stderr, re.MULTILINE)
    assert ran, stderr
    cfg = inv.parse_config(repo / ".pre-commit-tests")
    assert (ran.group(1), ran.group(2)) == (cfg["test_cmd"], cfg["test_timeout"])
    cleanup = re.search(r"^pre-commit-tests: running cleanup `([^\n]*)`$",
                        stderr, re.MULTILINE)
    assert (cleanup.group(1) if cleanup else "") == cfg["test_cleanup_cmd"]


def test_parity_harness_detects_a_divergent_parser(tmp_path):
    """Not vacuous: with the hook's CR strip removed (the pre-#56 hook), the
    harness reports a different TEST_CMD than parse_config for a CRLF config."""
    strip = "  line=\"${line%$'\\r'}\""
    block = hook_parse_block()
    assert block.count(strip + "\n") == 1, "CR-strip line moved; update this test"
    config = tmp_path / ".pre-commit-tests"
    config.write_bytes(PARITY_CONFIGS["crlf-all-keys"])
    mutated = run_hook_parser(config, block=block.replace(strip + "\n", ""))
    assert mutated["test_cmd"] == "python -m pytest -q\r"
    assert mutated["test_cmd"] != inv.parse_config(config)["test_cmd"]


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
