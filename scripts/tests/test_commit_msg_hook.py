"""hooks/commit-msg: conventional subject + attribution scrub (issue #5; scrub 2026-10-04).

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
    msg_file.write_text(message, encoding="utf-8", newline="")
    return subprocess.run(
        [BASH, HOOK.as_posix(), msg_file.as_posix()], capture_output=True, text=True, check=False
    )


def scrubbed(tmp_path: Path) -> str:
    return (tmp_path / "COMMIT_EDITMSG").read_bytes().decode("utf-8")


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("feat: add player stats dashboard" + TRAILERS, "feat: add player stats dashboard\n"),
        (
            "fix: resolve auth token expiry\n\nBody line.\n" + TRAILERS,
            "fix: resolve auth token expiry\n\nBody line.\n",
        ),
        ("docs: note it\n\nCo-Authored-By: A Human <human@example.com>\n", "docs: note it\n"),
        ("docs: note it\n\nco-authored-by: lower <l@example.com>\n", "docs: note it\n"),
        ("docs: note it\n\nCo-authored by: Spaced <s@example.com>\n", "docs: note it\n"),
        (
            "feat: x\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)\n"
            "\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n",
            "feat: x\n",
        ),
        # A trailer in the middle of the body still goes; surrounding text stays.
        (
            "feat: x\n\nfirst\nCo-Authored-By: C <c@example.com>\nsecond\n",
            "feat: x\n\nfirst\nsecond\n",
        ),
    ],
)
def test_attribution_is_scrubbed(tmp_path: Path, message: str, expected: str) -> None:
    proc = run_hook(tmp_path, message)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert scrubbed(tmp_path) == expected
    assert "removed" in proc.stdout


def test_crlf_message_keeps_its_line_endings(tmp_path: Path) -> None:
    msg = "feat: x\r\n\r\nBody.\r\n\r\nCo-Authored-By: C <c@example.com>\r\n"
    msg_file = tmp_path / "COMMIT_EDITMSG"
    msg_file.write_bytes(msg.encode("utf-8"))
    proc = subprocess.run(
        [BASH, HOOK.as_posix(), msg_file.as_posix()], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert msg_file.read_bytes() == b"feat: x\r\n\r\nBody.\r\n"


@pytest.mark.parametrize(
    "subject",
    ["Merge branch 'main' into fix/x", 'Revert "feat: add x"'],
)
def test_git_authored_messages_are_scrubbed_too(tmp_path: Path, subject: str) -> None:
    proc = run_hook(tmp_path, subject + TRAILERS)
    assert proc.returncode == 0, proc.stdout
    assert scrubbed(tmp_path) == subject + "\n"


@pytest.mark.parametrize(
    "message",
    [
        "chore: plain human commit, no trailers\n",
        "docs: explain how co-authored-by: trailers work\n",  # prose, not a trailer
        "docs: thanks\n\nSee the Co-Authored-By: docs for details.\n",
        "feat: x\n\nBody.\n\n\n",  # untouched: nothing scrubbed means no rewrite
        "# Co-Authored-By: template comment <c@example.com>\nfeat: x\n",
        # Wrapped prose that happens to start with a trailer key (the 1e7b31c
        # false positive): no <email> / URL value, so it is not a trailer.
        "docs: x\n\nThe hook now deletes every Co-Authored-By: trailer, every\n"
        "Claude-Session: trailer and the Generated-with line from the\nfile.\n",
        "docs: x\n\nCo-Authored-By: is a standard git trailer.\n",
    ],
)
def test_non_attribution_messages_are_untouched(tmp_path: Path, message: str) -> None:
    proc = run_hook(tmp_path, message)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert scrubbed(tmp_path) == message
    assert "removed" not in proc.stdout


def test_trailer_only_message_is_rejected_not_committed_empty(tmp_path: Path) -> None:
    proc = run_hook(tmp_path, "Co-Authored-By: C <c@example.com>\n")
    assert proc.returncode == 1
    assert "COMMIT REJECTED" in proc.stdout


def test_scrub_leaves_no_temp_file(tmp_path: Path) -> None:
    run_hook(tmp_path, "feat: x" + TRAILERS)
    assert [p.name for p in tmp_path.iterdir()] == ["COMMIT_EDITMSG"]


def test_awk_warning_on_stderr_does_not_skip_the_scrub(tmp_path: Path) -> None:
    # audit-openos-2026-10-05: the count was read from awk's stderr, so any awk
    # warning made it non-numeric and the commit went through unscrubbed in
    # silence. An awk that warns must still scrub (and must never pass silently).
    real_awk = shutil.which("awk", path=str(Path(BASH).parent)) or shutil.which("awk")
    assert real_awk, "awk not found"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    wrapper = bindir / "awk"
    wrapper.write_text(
        f'#!/bin/sh\necho "awk: warning: simulated" >&2\nexec "{Path(real_awk).as_posix()}" "$@"\n',
        encoding="utf-8",
        newline="\n",
    )
    wrapper.chmod(0o755)
    msg_dir = tmp_path / "msg"
    msg_dir.mkdir()
    msg_file = msg_dir / "COMMIT_EDITMSG"
    msg_file.write_text("feat: x" + TRAILERS, encoding="utf-8", newline="")
    env = dict(os.environ, PATH=f"{bindir.as_posix()}{os.pathsep}{os.environ.get('PATH', '')}")
    proc = subprocess.run(
        [BASH, "-c", f'PATH="{bindir.as_posix()}:$PATH" exec "{HOOK.as_posix()}" "{msg_file.as_posix()}"'],
        capture_output=True, text=True, check=False, env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert msg_file.read_bytes().decode("utf-8") == "feat: x\n"
    assert "removed 2 attribution line(s)" in proc.stdout


@pytest.mark.parametrize(
    "line",
    [
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
