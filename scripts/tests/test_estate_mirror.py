"""estate-mirror.sh: roster validation happens before any network access.

The clone/refresh path needs GitHub and is proven on NEXUS; these tests cover
what must hold offline: a bad, duplicate or empty roster exits 2, writes no
status file and creates no mirror entry.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "estate-mirror.sh"


def bash_exe() -> str:
    git = shutil.which("git")
    if os.name == "nt" and git:
        candidate = Path(git).resolve().parent.parent / "usr" / "bin" / "bash.exe"
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("bash")
    assert found, "bash not found"
    return found


BASH = bash_exe()


def run(tmp_path: Path, roster_text: str | None, *extra: str) -> tuple[subprocess.CompletedProcess, Path, Path]:
    roster = tmp_path / "roster.txt"
    if roster_text is not None:
        roster.write_text(roster_text, encoding="utf-8", newline="\n")
    mirror, status = tmp_path / "repos", tmp_path / "status.txt"
    args = [BASH, SCRIPT.as_posix(), "--roster", roster.as_posix(), "--dir", mirror.as_posix(),
            "--status", status.as_posix(), *extra]
    return subprocess.run(args, capture_output=True, text=True, timeout=60), mirror, status


@pytest.mark.parametrize("roster", [
    "good-repo\nBad Name\n",           # interior space is invalid, not squashed
    "good-repo\n../escape\n",
    "good-repo\n-flag\n",
    "Good-Repo\ngood-repo\n",          # duplicate after lowercasing
    "# comments only\n\n",
])
def test_invalid_roster_exits_2_before_any_clone(tmp_path: Path, roster: str) -> None:
    proc, mirror, status = run(tmp_path, roster)
    assert proc.returncode == 2, proc.stderr
    assert not status.exists()
    assert not mirror.exists() or not any(mirror.iterdir())


def test_missing_roster_and_missing_args_exit_2(tmp_path: Path) -> None:
    proc, _, status = run(tmp_path, None)
    assert proc.returncode == 2 and not status.exists()
    proc = subprocess.run([BASH, SCRIPT.as_posix(), "--roster"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2


def test_script_never_uses_reset_hard_and_disables_hooks() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "reset --hard" not in code
    assert "core.hooksPath=/dev/null" in code
    assert "GIT_TERMINAL_PROMPT=0" in code
