"""hooks/commit-msg: conventional subject + attribution-trailer policy (issue #5).

Runs the real hook script under bash against a message file in pytest's tmp
dir, exactly as git would. No repo, no network. Paths are passed POSIX-style
so Git Bash on Windows does not eat the backslashes.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parent.parent.parent / "hooks" / "commit-msg"


def bash_exe() -> str:
    """The bash git itself would run the hook with.

    On Windows a bare "bash" resolves through CreateProcess to the WSL stub in
    System32 before PATH is consulted, so ask for Git's own usr/bin/bash next
    to git.exe. Elsewhere PATH lookup is fine.
    """
    git = shutil.which("git")
    if os.name == "nt" and git:
        candidate = Path(git).resolve().parent.parent / "usr" / "bin" / "bash.exe"
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("bash")
    assert found, "bash not found"
    return found


BASH = bash_exe()

TRAILERS = (
    "\n\nCo-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>\n"
    "Claude-Session: https://claude.ai/code/session_01JGWYBRJjg45TeEczYMVXW5\n"
)


def run_hook(tmp_path: Path, message: str) -> subprocess.CompletedProcess[str]:
    msg_file = tmp_path / "COMMIT_EDITMSG"
    msg_file.write_text(message, encoding="utf-8")
    return subprocess.run(
        [BASH, HOOK.as_posix(), msg_file.as_posix()], capture_output=True, text=True, check=False
    )


@pytest.mark.parametrize(
    "message",
    [
        "feat: add player stats dashboard" + TRAILERS,
        "fix: resolve auth token expiry" + TRAILERS,
        "chore: merge main (v2.23.0) into fix/bridge-hardening → v2.23.1" + TRAILERS,
        "chore: plain human commit, no trailers\n",
        "docs: note it\n\nCo-Authored-By: A Human <human@example.com>\n",
    ],
)
def test_attribution_trailers_are_accepted(tmp_path: Path, message: str) -> None:
    proc = run_hook(tmp_path, message)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.parametrize(
    "line",
    [
        "🤖 Generated with [Claude Code](https://claude.com/claude-code)",
        "generated with some tool",
        "Auditor: reviewer-bot",
    ],
)
def test_pr_boilerplate_is_rejected(tmp_path: Path, line: str) -> None:
    proc = run_hook(tmp_path, f"feat: something\n\n{line}\n")
    assert proc.returncode == 1
    assert "boilerplate" in proc.stdout


def test_auditor_only_rejected_at_line_start(tmp_path: Path) -> None:
    # "Auditor:" in prose mid-line is not the boilerplate marker.
    proc = run_hook(tmp_path, "docs: explain the Auditor: field semantics\n")
    assert proc.returncode == 0, proc.stdout


@pytest.mark.parametrize(
    "subject",
    [
        "feat: x",
        "chore(deps): bump fast-uri to 3.0.6",
        "chore(deps-dev): bump vitest",
        "feat!: drop the v1 manifest format",
        "fix(api)!: reject empty ids",
        "ci: install dev-standards guards",
        "build: pin the WebView2 runtime",
        "security: register SC-16..SC-21",
        "perf: cache the manifest",
        "test: cover the hook",
        "refactor: split dispatcher",
    ],
)
def test_valid_subjects_are_accepted(tmp_path: Path, subject: str) -> None:
    proc = run_hook(tmp_path, subject + "\n")
    assert proc.returncode == 0, proc.stdout


@pytest.mark.parametrize(
    "subject",
    [
        "Add player stats",  # no type
        "feature: add x",  # unknown type
        "feat:missing space",
        "feat: ",  # empty summary
        "FEAT: uppercase type",
        "chore(): empty scope",
        "",
    ],
)
def test_invalid_subjects_are_rejected(tmp_path: Path, subject: str) -> None:
    proc = run_hook(tmp_path, subject + "\n")
    assert proc.returncode == 1
    assert "COMMIT REJECTED" in proc.stdout


@pytest.mark.parametrize(
    "subject",
    [
        "Merge pull request #4 from Ohio15/feat/register-sc16-sc21",
        "Merge branch 'main' into fix/x",
        'Revert "feat: add x"',
    ],
)
def test_git_authored_subjects_are_exempt(tmp_path: Path, subject: str) -> None:
    proc = run_hook(tmp_path, subject + "\n")
    assert proc.returncode == 0, proc.stdout


@pytest.mark.parametrize(
    "subject",
    ["feat: Added a thing", "fix(auth): Fixed the token", "chore!: Removed the flag"],
)
def test_past_tense_is_rejected_even_with_scope(tmp_path: Path, subject: str) -> None:
    proc = run_hook(tmp_path, subject + "\n")
    assert proc.returncode == 1
    assert "imperative" in proc.stdout


def test_long_subject_warns_but_passes(tmp_path: Path) -> None:
    proc = run_hook(tmp_path, "feat: " + "x" * 80 + "\n")
    assert proc.returncode == 0
    assert "COMMIT WARNING" in proc.stdout


def test_comment_template_lines_are_ignored(tmp_path: Path) -> None:
    # git's editor template puts '#' lines after the message; a commented
    # 'Generated with' hint must not trip the check and a commented first line
    # must not be taken as the subject.
    msg = "# Please enter the commit message\nfeat: real subject\n# Generated with nothing\n"
    proc = run_hook(tmp_path, msg)
    assert proc.returncode == 0, proc.stdout


def test_missing_file_argument_fails_closed(tmp_path: Path) -> None:
    proc = subprocess.run([BASH, HOOK.as_posix()], capture_output=True, text=True, check=False)
    assert proc.returncode == 1
