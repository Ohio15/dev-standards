"""cortex-core ADR 0012: `submodule-pointer-lag` finding in repo-hygiene-scan.py.

Every test builds its own throwaway child + bare "origin" + superproject under
pytest's tmp_path. Nothing here touches a real repo or a network remote: the
child's "remote" is a bare clone on disk, which `git ls-remote` reads exactly
like a hosted one.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "repo-hygiene-scan.py"
spec = importlib.util.spec_from_file_location("hygiene", SCRIPT)
hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(hygiene)

GIT_ENV = dict(
    os.environ,
    GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t",
    GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
)


def git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "protocol.file.allow=always", *args],
        cwd=str(cwd), capture_output=True, text=True, env=GIT_ENV, check=True,
    )
    return proc.stdout.strip()


def commit(repo: Path, subject: str, **files: str) -> str:
    for rel, body in files.items():
        (repo / rel).write_text(body, encoding="utf-8")
        git(repo, "add", rel)
    git(repo, "commit", "-q", "--allow-empty", "-m", subject)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def world(tmp_path: Path):
    """child (working clone of origin), origin (bare), parent (superproject
    recording child at its first commit). Returns a dict of paths + shas."""
    origin = tmp_path / "child.git"
    git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
    child = tmp_path / "child"
    git(tmp_path, "clone", "-q", str(origin), str(child))
    git(child, "checkout", "-q", "-b", "main")
    base = commit(child, "chore: initial", **{"package.json": '{"name":"child","version":"1.0.0"}\n'})
    git(child, "push", "-q", "-u", "origin", "main")

    parent = tmp_path / "parent"
    git(tmp_path, "init", "-q", "-b", "main", str(parent))
    git(parent, "submodule", "add", "-q", "-b", "main", str(origin), "child")
    git(parent, "commit", "-q", "-m", "chore: add child submodule")
    return {"origin": origin, "child": child, "parent": parent, "base": base}


def advance(world: dict, subject: str, **files: str) -> str:
    """Commit in the working clone and push so origin/main moves; the parent's
    embedded checkout (parent/child) is then fetched so it can measure the lag
    the way a real superproject checkout that has run `git fetch` can."""
    sha = commit(world["child"], subject, **files)
    git(world["child"], "push", "-q", "origin", "main")
    git(world["parent"] / "child", "fetch", "-q", "origin")
    return sha


def findings(world: dict) -> list[dict]:
    return hygiene.scan_submodule_pointer_lag(world["parent"])


def test_parse_gitmodules_reads_path_url_and_branch(world):
    mods = hygiene.parse_gitmodules(world["parent"])
    assert [m["path"] for m in mods] == ["child"]
    assert mods[0]["branch"] == "main"
    assert Path(mods[0]["url"]).resolve() == world["origin"].resolve()


def test_in_sync_pointer_yields_no_finding(world):
    assert findings(world) == []


def test_non_bump_lag_is_low(world):
    advance(world, "fix: something small", **{"README.md": "x\n"})
    advance(world, "docs: more", **{"README.md": "y\n"})
    out = findings(world)
    assert len(out) == 1
    f = out[0]
    assert f["code"] == "submodule-pointer-lag"
    assert f["severity"] == "LOW"
    assert f["lag"] == 2
    assert f["crosses_version_bump"] is False
    assert f["pointer"] == world["base"]
    assert f["remote_head"] == git(world["child"], "rev-parse", "HEAD")
    assert "submodule update --remote" in f["note"]


def test_lag_across_subject_bump_is_medium(world):
    advance(world, "fix: prep", **{"README.md": "x\n"})
    advance(world, "chore: bump to 1.1.0")
    out = findings(world)
    assert out[0]["severity"] == "MEDIUM"
    assert out[0]["lag"] == 2
    assert out[0]["crosses_version_bump"] is True


def test_lag_across_version_field_change_is_medium(world):
    # Subject deliberately free of "bump" / semver so only the diff can tell.
    advance(world, "release prep", **{"package.json": '{"name":"child","version":"1.0.1"}\n'})
    out = findings(world)
    assert out[0]["severity"] == "MEDIUM"
    assert out[0]["crosses_version_bump"] is True


def test_package_json_change_without_version_change_is_low(world):
    advance(world, "chore: deps", **{"package.json": '{"name":"child","version":"1.0.0","private":true}\n'})
    out = findings(world)
    assert out[0]["severity"] == "LOW"
    assert out[0]["crosses_version_bump"] is False


def test_pointer_ahead_of_remote_is_low_not_ancestor(world):
    # Parent records a commit that exists only locally in the embedded checkout.
    inner = world["parent"] / "child"
    local = commit(inner, "wip: unpushed", **{"local.txt": "z\n"})
    git(world["parent"], "add", "child")
    git(world["parent"], "commit", "-q", "-m", "chore: point at unpushed commit")
    out = findings(world)
    assert len(out) == 1
    assert out[0]["severity"] == "LOW"
    assert out[0]["pointer"] == local
    assert out[0]["lag"] == 0
    assert "not an ancestor" in out[0]["note"]


def test_unreachable_remote_is_unverified_low(world, tmp_path):
    git(world["parent"], "config", "-f", ".gitmodules", "submodule.child.url", str(tmp_path / "missing.git"))
    out = findings(world)
    assert len(out) == 1
    assert out[0]["code"] == "submodule-pointer-unverified"
    assert out[0]["severity"] == "LOW"


def test_repo_without_gitmodules_is_skipped(tmp_path):
    plain = tmp_path / "plain"
    git(tmp_path, "init", "-q", "-b", "main", str(plain))
    commit(plain, "chore: init", **{"a.txt": "a\n"})
    assert hygiene.scan_submodule_pointer_lag(plain) == []


def test_scan_repo_surfaces_the_finding_and_markdown_renders_it(world):
    advance(world, "chore: bump to 2.0.0")
    report = hygiene.scan_repo(world["parent"], age_threshold=7)
    codes = [f["code"] for f in report["findings"]]
    assert "submodule-pointer-lag" in codes
    md = hygiene.render_markdown({
        "scan_date": "2026-09-09", "roots": [str(world["parent"])], "repo_count": 1,
        "total_findings": len(report["findings"]),
        "totals_by_severity": {"HIGH": 0, "MEDIUM": 1, "LOW": 0},
        "repos": [report],
    })
    assert "`submodule-pointer-lag`" in md
    assert "submodule=child" in md and "lag=1" in md
