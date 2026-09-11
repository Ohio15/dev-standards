"""discover_repos: top-level repos plus one namespace level (STANDARDS.md §2).

Throwaway directory trees under pytest's tmp_path; a "repo" is any directory
with a `.git` entry, which is all `is_git_repo` looks at. No git, no network.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
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
