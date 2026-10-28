"""hooks/pre-commit-tests.sh: TEST_CLEANUP_CMD and the tracked-tree check.

On 2026-10-27 a timeout kill landed inside a mutation test in truck-mcp and
left a safety guard deleted from src/. The commit aborted on the timeout, but
nothing said the tree was now wrong, and the next `git add -A` would have
committed it (truck-mcp PR #12; shared-brain discovery a7a155d8). The hook now
(a) runs an optional TEST_CLEANUP_CMD after the suite on EVERY outcome,
including a timeout kill, and (b) fails the commit, naming the files, when a
tracked file's content changed during the hook. Edits already in the work tree
before the hook ran do not trip (b).

Drives the REAL hook under Git's own bash in throwaway repos under pytest's
tmp_path, with the same helpers as test_pre_commit_tests_env.py.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from test_pre_commit_tests_env import PY, clean_env, run_hook

IDENT = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, env={**clean_env(), **IDENT}, check=True)


def py(code: str) -> str:
    """A TEST_CMD / TEST_CLEANUP_CMD running one line of Python (single quotes only)."""
    assert '"' not in code
    return f'"{PY}" -c "{code}"'


def make_repo(tmp_path: Path, test_cmd: str, cleanup: str | None = None,
              timeout: int = 60) -> Path:
    """A repo with two committed tracked files and the given config."""
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], env=clean_env(), check=True)
    git(repo, "config", "core.autocrlf", "false")
    (repo / "a.txt").write_text("original\n", encoding="utf-8", newline="\n")
    (repo / "b.txt").write_text("other\n", encoding="utf-8", newline="\n")
    cfg = f"TEST_CMD={test_cmd}\nTEST_TIMEOUT={timeout}\n"
    if cleanup is not None:
        cfg += f"TEST_CLEANUP_CMD={cleanup}\n"
    (repo / ".pre-commit-tests").write_text(cfg, encoding="utf-8", newline="\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    return repo


def marker_cleanup(tmp_path: Path) -> tuple[str, Path]:
    """A cleanup command that records that it ran, outside the repo."""
    marker = tmp_path / "cleanup-ran"
    return py(f"open(r'{marker.as_posix()}','w').write('x')"), marker


MUTATE_A = "open('a.txt','w').write('mutated')"


def changed_block(stderr: str) -> str:
    """The list of paths the tree check named, and nothing else."""
    assert "CHANGED TRACKED FILES" in stderr, stderr
    return stderr.split("CHANGED TRACKED FILES", 1)[1].split("A suite may not", 1)[0]


# --- TEST_CLEANUP_CMD runs on every outcome ----------------------------------

def test_cleanup_runs_after_a_passing_suite(tmp_path: Path) -> None:
    cleanup, marker = marker_cleanup(tmp_path)
    repo = make_repo(tmp_path, py("import sys; sys.exit(0)"), cleanup)
    proc = run_hook(repo, {})
    assert "pre-commit-tests: running cleanup" in proc.stderr, proc.stderr
    assert marker.is_file(), proc.stderr
    assert proc.returncode == 0, proc.stderr


def test_cleanup_runs_after_a_failing_suite_and_keeps_its_exit_code(tmp_path: Path) -> None:
    cleanup, marker = marker_cleanup(tmp_path)
    repo = make_repo(tmp_path, py("import sys; sys.exit(5)"), cleanup)
    proc = run_hook(repo, {})
    assert marker.is_file(), proc.stderr
    assert proc.returncode == 5, proc.stderr


def test_cleanup_runs_after_a_timeout_kill(tmp_path: Path) -> None:
    cleanup, marker = marker_cleanup(tmp_path)
    repo = make_repo(tmp_path, py("import time; time.sleep(8)"), cleanup, timeout=2)
    proc = run_hook(repo, {})
    assert "exceeded 2s and was killed" in proc.stderr, proc.stderr
    assert marker.is_file(), proc.stderr
    assert proc.returncode == 1, proc.stderr


def test_cleanup_repairs_what_a_killed_suite_left_mutated(tmp_path: Path) -> None:
    """The truck-mcp case: mutate, get killed, cleanup puts the source back."""
    repo = make_repo(
        tmp_path,
        py(f"import time; {MUTATE_A}; time.sleep(8)"),
        "git checkout -- a.txt",
        timeout=2,
    )
    proc = run_hook(repo, {})
    assert "exceeded 2s and was killed" in proc.stderr, proc.stderr
    assert "CHANGED TRACKED FILES" not in proc.stderr, proc.stderr
    assert (repo / "a.txt").read_text() == "original\n"
    assert proc.returncode == 1, proc.stderr


def test_failing_cleanup_refuses_an_otherwise_green_commit(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, py("import sys; sys.exit(0)"), py("import sys; sys.exit(3)"))
    proc = run_hook(repo, {})
    assert "cleanup command failed (exit 3)" in proc.stderr, proc.stderr
    assert proc.returncode == 1, proc.stderr


def test_no_cleanup_key_runs_no_cleanup(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, py("import sys; sys.exit(0)"))
    proc = run_hook(repo, {})
    assert "pre-commit-tests: running `" in proc.stderr, proc.stderr
    assert "running cleanup" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr


# --- the suite may not change the tree it judges -----------------------------

def test_tracked_file_modified_by_a_passing_suite_fails_and_is_named(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, py(MUTATE_A))
    proc = run_hook(repo, {})
    named = changed_block(proc.stderr)
    assert "    a.txt" in named, proc.stderr
    assert "b.txt" not in named, proc.stderr
    assert "suite passed, but the tree check above failed" in proc.stderr
    assert proc.returncode == 1, proc.stderr


def test_tracked_file_modified_by_a_failing_suite_is_named_and_exit_kept(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, py(f"import sys; {MUTATE_A}; sys.exit(5)"))
    proc = run_hook(repo, {})
    assert "    a.txt" in changed_block(proc.stderr), proc.stderr
    assert proc.returncode == 5, proc.stderr


def test_tracked_file_deleted_by_the_suite_fails(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, py("import os; os.remove('a.txt')"))
    proc = run_hook(repo, {})
    assert "    a.txt" in changed_block(proc.stderr), proc.stderr
    assert proc.returncode == 1, proc.stderr


def test_path_with_spaces_and_glob_characters_is_named_whole(tmp_path: Path) -> None:
    """Named intact in the list AND in the --stat summary (literal pathspec)."""
    odd = "my [ab] file.txt"
    repo = make_repo(tmp_path, py(f"open('{odd}','w').write('mutated')"))
    (repo / odd).write_text("original\n", encoding="utf-8", newline="\n")
    # A file the glob `[ab]` would match if the pathspec were not literal.
    (repo / "my a file.txt").write_text("decoy\n", encoding="utf-8", newline="\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "odd names")
    proc = run_hook(repo, {})
    named = changed_block(proc.stderr)
    assert f"    {odd}\n" in named, proc.stderr
    assert "1 file changed" in proc.stderr, proc.stderr
    assert "my a file.txt" not in proc.stderr, proc.stderr
    assert proc.returncode == 1, proc.stderr


def test_pre_existing_modification_does_not_trip(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, py("import sys; sys.exit(0)"))
    (repo / "b.txt").write_text("edited before the commit\n", encoding="utf-8", newline="\n")
    proc = run_hook(repo, {})
    assert "pre-commit-tests: running" in proc.stderr, proc.stderr
    assert "CHANGED TRACKED FILES" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr


def test_suite_changing_an_already_modified_file_still_trips(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, py(MUTATE_A))
    (repo / "a.txt").write_text("edited before the commit\n", encoding="utf-8", newline="\n")
    (repo / "b.txt").write_text("also edited before\n", encoding="utf-8", newline="\n")
    proc = run_hook(repo, {})
    named = changed_block(proc.stderr)
    assert "    a.txt" in named, proc.stderr
    assert "b.txt" not in named, proc.stderr
    assert proc.returncode == 1, proc.stderr


def test_rewrite_with_identical_bytes_does_not_trip(tmp_path: Path) -> None:
    """A mutation that was correctly restored is not a change."""
    repo = make_repo(
        tmp_path,
        py("p='a.txt'; o=open(p,'rb').read(); open(p,'wb').write(b'x'); open(p,'wb').write(o)"),
    )
    proc = run_hook(repo, {})
    assert "pre-commit-tests: running" in proc.stderr, proc.stderr
    assert "CHANGED TRACKED FILES" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr
