"""discover_repos: top-level repos plus one namespace level (STANDARDS.md §2).

Throwaway directory trees under pytest's tmp_path; a "repo" is any directory
with a `.git` entry, which is all `is_git_repo` looks at. The linked-worktree
test at the end builds a real repo with `git worktree add`; no network.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "repo-hygiene-scan.py"
spec = importlib.util.spec_from_file_location("hygiene", SCRIPT)
hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(hygiene)


def repo(path: Path) -> Path:
    (path / ".git").mkdir(parents=True)
    return path


def names(root: Path, found: list[Path]) -> set[str]:
    return {p.relative_to(root).as_posix() for p in found}


def test_top_level_and_namespace_repos_are_found(tmp_path: Path) -> None:
    repo(tmp_path / "APM")
    repo(tmp_path / "aibrowser" / "AIWebBrowser")
    repo(tmp_path / "brain" / "Shared-Brain")
    repo(tmp_path / "brain" / "brain-mcp-proxy")
    assert names(tmp_path, hygiene.discover_repos([tmp_path])) == {
        "APM", "aibrowser/AIWebBrowser", "brain/Shared-Brain", "brain/brain-mcp-proxy",
    }


def test_recursion_stops_after_one_namespace_level(tmp_path: Path) -> None:
    repo(tmp_path / "ns" / "deeper" / "repo")
    assert hygiene.discover_repos([tmp_path]) == []


def test_repo_children_are_not_descended(tmp_path: Path) -> None:
    # A repo that contains another .git (vendored checkout, worktree dir) is
    # one repo; its insides are its own business.
    repo(tmp_path / "cortex")
    repo(tmp_path / "cortex" / "cortex-hooks")
    assert names(tmp_path, hygiene.discover_repos([tmp_path])) == {"cortex"}


def test_hidden_and_allowed_root_dirs_are_not_namespaces(tmp_path: Path) -> None:
    repo(tmp_path / ".archive" / "old-repo")
    repo(tmp_path / ".staging-licenses" / "x")
    for allowed in hygiene.LAYOUT_ALLOWED_ROOT_DIRS:
        repo(tmp_path / allowed / "inner")
    assert hygiene.discover_repos([tmp_path]) == []


def test_empty_namespace_dir_is_harmless(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "loose-file.txt").write_text("x")
    repo(tmp_path / "APM")
    assert names(tmp_path, hygiene.discover_repos([tmp_path])) == {"APM"}


def test_root_that_is_itself_a_repo_is_included(tmp_path: Path) -> None:
    root = repo(tmp_path / "home")
    repo(root / "child")
    assert names(root, hygiene.discover_repos([root])) == {".", "child"}


# --- linked worktrees are scanned in place (work item b66ef6b3) ----------
# A linked worktree's `.git` is a FILE pointing into the main checkout's
# gitdir. Discovery and every per-repo check must read the worktree's own
# files, never the gitdir owner's, so a finding is attributed to the
# checkout that has it, exactly once.

GIT_ENV = dict(
    os.environ,
    GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t",
    GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
)
CACHING_WF = ("name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
              "      - uses: actions/cache@0123456789abcdef0123456789abcdef01234567\n")
CLEAN_WF = "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"


def git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, env=GIT_ENV, check=True)


def write_wf(checkout: Path, text: str) -> None:
    (checkout / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (checkout / ".github" / "auto-apply-enabled").write_text("", encoding="utf-8")
    (checkout / ".github" / "workflows" / "ci.yml").write_text(text, encoding="utf-8")


def cache_hits(reports: list[dict]) -> list[tuple[str, str, int]]:
    return sorted((Path(r["path"]).name, i["path"], i["line"]) for r in reports for f in r["findings"]
                  if f["code"] == "auto-apply-cache-restore" for i in f["items"])


def test_linked_worktrees_are_scanned_at_their_own_path(tmp_path: Path) -> None:
    main = tmp_path / "projects" / "ns" / "app"
    main.mkdir(parents=True)
    git(main, "init", "-q", "-b", "main")
    write_wf(main, CLEAN_WF)
    git(main, "add", "-A")
    git(main, "commit", "-q", "-m", "init")
    wt_root = tmp_path / "worktrees" / "app"
    git(main, "worktree", "add", "-q", "-b", "dirty", str(wt_root / "dirty"))
    git(main, "worktree", "add", "-q", "-b", "clean", str(wt_root / "clean"))
    write_wf(wt_root / "dirty", CACHING_WF)  # only this worktree restores a cache

    found = hygiene.discover_repos([wt_root])
    assert names(wt_root, found) == {"clean", "dirty"}
    assert all((p / ".git").is_file() for p in found), "the worktrees, not their main checkout"

    reports = [hygiene.scan_repo(p, 7) for p in found]
    assert cache_hits(reports) == [("dirty", ".github/workflows/ci.yml", 7)]

    # The main checkout, scanned on its own, is clean: the hit is not echoed there.
    assert cache_hits([hygiene.scan_repo(p, 7) for p in hygiene.discover_repos([main.parent])]) == []
