"""repo-hygiene-scan.py never follows a symlink out of a scanned repo and never
trusts st_size (audit 2026-11-10.2 M4, proposed SC-58).

A scanned repo is third-party content. A committed `VERSION -> <secret>` used
to put the secret's first line into the report (and the shared-brain post) as
a "version"; `src/a.py -> /dev/zero` passed the size cap (st_size 0) and was
read without bound. Every repo-relative read now goes through one helper,
read_repo_file: lstat on every component, S_ISREG, bounded read(cap + 1).

Run:  python -m pytest scripts/tests/test_hygiene_symlinks.py -q
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "repo-hygiene-scan.py"
spec = importlib.util.spec_from_file_location("hygiene_symlinks", SCRIPT)
hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(hygiene)

SECRET = "ghp_TOPSECRETTOKENVALUE0123456789"


def _can_symlink(tmp: Path) -> bool:
    try:
        (tmp / ".probe-target").write_text("x", encoding="utf-8")
        os.symlink(tmp / ".probe-target", tmp / ".probe-link")
        return True
    except (OSError, NotImplementedError):
        return False


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    if not _can_symlink(tmp_path):
        pytest.skip("this account cannot create symlinks")
    r = tmp_path / "repo"
    r.mkdir()
    return r


@pytest.fixture
def secret(tmp_path: Path) -> Path:
    s = tmp_path / "outside" / ".git-credentials"
    s.parent.mkdir()
    s.write_text(SECRET + "\n", encoding="utf-8")
    return s


def write(repo: Path, rel: str, body: str) -> str:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8", newline="\n")
    return rel


# ── the helper itself ──

def test_regular_file_is_read(repo: Path) -> None:
    write(repo, "a/b.txt", "hello")
    assert hygiene.read_repo_file(repo, "a/b.txt") == (b"hello", None)


def test_symlinked_leaf_is_refused(repo: Path, secret: Path) -> None:
    os.symlink(secret, repo / "VERSION")
    data, reason = hygiene.read_repo_file(repo, "VERSION")
    assert data is None and "symlink" in reason


def test_symlinked_parent_directory_is_refused(repo: Path, secret: Path) -> None:
    os.symlink(secret.parent, repo / "src", target_is_directory=True)
    data, reason = hygiene.read_repo_file(repo, "src/.git-credentials")
    assert data is None and "symlink" in reason


@pytest.mark.parametrize("rel", ["../outside/.git-credentials", "a/../../outside/.git-credentials"])
def test_path_escaping_the_repo_is_refused(repo: Path, secret: Path, rel: str) -> None:
    data, reason = hygiene.read_repo_file(repo, rel)
    assert data is None and "escapes" in reason


def test_absolute_path_is_refused(repo: Path, secret: Path) -> None:
    data, reason = hygiene.read_repo_file(repo, str(secret))
    assert data is None and "escapes" in reason


def test_directory_is_not_a_regular_file(repo: Path) -> None:
    (repo / "d").mkdir()
    data, reason = hygiene.read_repo_file(repo, "d")
    assert data is None and "regular file" in reason


def test_cap_is_enforced_on_bytes_read_not_st_size(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(repo, "big.py", "x" * 100)
    real_fstat = os.fstat

    class Lying:
        def __init__(self, st: os.stat_result) -> None:
            self._st = st

        def __getattr__(self, name: str):
            return 0 if name == "st_size" else getattr(self._st, name)

    # st_size 0 (what /dev/zero and a FIFO report) must not let 100 bytes past a 64-byte cap.
    monkeypatch.setattr(hygiene.os, "fstat", lambda fd: Lying(real_fstat(fd)))
    monkeypatch.setattr(hygiene.os, "lstat", lambda p, _l=os.lstat: Lying(_l(p)))
    data, reason = hygiene.read_repo_file(repo, "big.py", cap=64)
    assert data is None and "exceeds 64-byte cap" in reason
    assert hygiene.read_repo_file(repo, "big.py", cap=100) == (b"x" * 100, None)


@pytest.mark.skipif(sys.platform == "win32" or not Path("/dev/zero").exists(), reason="needs /dev/zero")
def test_symlink_to_dev_zero_is_not_read(repo: Path) -> None:
    os.symlink("/dev/zero", repo / "a.py")
    data, reason = hygiene.read_repo_file(repo, "a.py")
    assert data is None and "symlink" in reason


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_fifo_is_refused_without_blocking(repo: Path) -> None:
    os.mkfifo(repo / "pipe.py")
    data, reason = hygiene.read_repo_file(repo, "pipe.py")
    assert data is None and "regular file" in reason


# ── the scan passes: no content from a symlink target reaches a finding ──

def test_version_symlink_leaks_nothing_into_the_report(repo: Path, secret: Path) -> None:
    write(repo, "package.json", '{"version": "1.0.0"}')
    os.symlink(secret, repo / "VERSION")
    findings = hygiene.scan_version_divergence(repo, ["package.json", "VERSION"])
    assert SECRET not in repr(findings)
    [unexamined] = [f for f in findings if f["code"] == "version-unexamined"]
    assert unexamined["items"] == [{"path": "VERSION", "reason": "symlink: not followed"}]
    assert not [f for f in findings if f["code"] == "version-divergence"]


def test_symlinked_runtime_source_is_unexamined_not_read(repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "outside" / "vendor.ts"
    target.parent.mkdir(exist_ok=True)
    target.write_text("fetch('https://api.openai.com')\n", encoding="utf-8")
    (repo / "src").mkdir()
    os.symlink(target, repo / "src" / "a.ts")
    findings = hygiene.scan_stub_markers(repo, ["src/a.ts"])
    [f] = findings
    assert f["code"] == "stub-marker-unexamined"
    assert f["items"] == [{"path": "src/a.ts", "kind": "runtime-source", "reason": "symlink: not followed"}]


def test_cache_restore_walk_reports_symlinked_workflows_and_dirs(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside-wf"
    outside.mkdir()
    (outside / "evil.yml").write_text("jobs: {}\n", encoding="utf-8")
    wf = repo / ".github" / "workflows"
    wf.mkdir(parents=True)
    (repo / ".github" / "auto-apply-enabled").write_text("", encoding="utf-8")
    (wf / "ok.yml").write_text("name: ok\non: push\njobs: {}\n", encoding="utf-8")
    os.symlink(outside / "evil.yml", wf / "linked.yml")
    os.symlink(outside, wf / "sub", target_is_directory=True)
    [finding] = hygiene.scan_cache_restore(repo)
    got = {(i["path"], i["form"]) for i in finding["items"]}
    assert got == {(".github/workflows/linked.yml", "symlink: not followed"),
                   (".github/workflows/sub", "symlink: not followed")}, got


def test_symlinked_workflows_dir_is_reported_not_passed(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside-wf2"
    outside.mkdir()
    (outside / "x.yml").write_text("jobs: {}\n", encoding="utf-8")
    (repo / ".github").mkdir()
    (repo / ".github" / "auto-apply-enabled").write_text("", encoding="utf-8")
    os.symlink(outside, repo / ".github" / "workflows", target_is_directory=True)
    [finding] = hygiene.scan_cache_restore(repo)
    assert [(i["path"], i["form"]) for i in finding["items"]] == [(".github/workflows", "symlink: not followed")]


def test_symlinked_installed_hook_is_drift_not_a_match(repo: Path, tmp_path: Path) -> None:
    canon = tmp_path / "canon"
    canon.mkdir()
    (canon / "pre-commit").write_bytes(b"#!/bin/sh\nexit 0\n")
    (repo / ".githooks").mkdir()
    os.symlink(canon / "pre-commit", repo / ".githooks" / "pre-commit")  # identical content via the link
    [f] = hygiene.scan_hook_drift(repo, canon)
    assert f["code"] == "hook-drift"
    assert "symlink" in f["items"][0]["installed"]


def test_symlinked_release_config_reads_as_strictest_mode(repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "rc.yml"
    target.write_text("independence: harness\n", encoding="utf-8")
    os.symlink(target, repo / "release-config.yml")
    assert hygiene.read_independence_mode(repo) == ("full", None)


def test_compose_file_outside_the_repo_is_not_read(repo: Path, tmp_path: Path) -> None:
    (tmp_path / "compose.yml").write_text("services:\n  x:\n    image: a/b:1\n", encoding="utf-8")
    assert hygiene.parse_compose_services(repo, "../compose.yml") == {}


def test_tracked_symlink_size_is_its_own_not_the_targets(repo: Path, tmp_path: Path) -> None:
    big = tmp_path / "big.bin"
    big.write_bytes(b"\0" * (64 * 1024))
    os.symlink(big, repo / "link")
    size = hygiene.file_size(repo, "link")
    assert size is not None and size < 64 * 1024


# ── class check: no repo-relative read bypasses the helper ──

def test_every_repo_read_goes_through_read_repo_file() -> None:
    """The only read_text/read_bytes calls left are on operator inputs (the
    canonical hooks, the allow-list, the roster and register, the key file); a
    new direct read of a scanned repo must be routed through read_repo_file."""
    src = SCRIPT.read_text(encoding="utf-8")
    operator_receivers = {"canon", "allowlist_path", "path", "key_path"}
    receivers = re.findall(r"(\w+)\.read_(?:text|bytes)\(", src)
    assert receivers, "the pattern no longer sees the operator reads"
    assert set(receivers) <= operator_receivers, sorted(set(receivers) - operator_receivers)
    # `path.read_text(` is allowed only inside the two operator-file loaders.
    for m in re.finditer(r"(?<![\w.])path\.read_text\(", src):
        fn = re.findall(r"^def (\w+)", src[: m.start()], re.M)[-1]
        assert fn in {"load_security_roster", "load_canonical_register"}, fn
    assert "rglob(" not in src, "a recursive glob follows symlinked files; use walk_repo_files"
    assert src.count("os.open(") == 1, "read_repo_file is the only opener"
