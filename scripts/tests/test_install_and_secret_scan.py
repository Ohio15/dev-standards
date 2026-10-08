"""install.sh Dependabot seeding (SC-25) and the secret-scan hook's gitleaks
lookup (SC-12), from the 2026-10-05 security gate on the templates.

- SC-25: installed repos got SHA-pinned actions and no Dependabot config, so
  the pins went stale. install.sh now seeds .github/dependabot.yml when the
  target has none, and never touches an existing one.
- SC-12: with gitleaks off PATH the hook ran `${GOPATH:-$HOME/go}/bin/gitleaks`,
  a binary an inherited environment chooses. It now fails closed.

Everything runs against throwaway repos and directories under tmp_path.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
INSTALL = ROOT / "install.sh"
SECRET_SCAN = ROOT / "hooks" / "pre-commit-secret-scan.sh"


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


def bash_path(p: Path) -> str:
    posix = p.resolve().as_posix()
    m = re.match(r"^([A-Za-z]):/(.*)$", posix)
    return f"/{m.group(1).lower()}/{m.group(2)}" if m else posix


def target_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "target"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    return repo


def install(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([BASH, INSTALL.as_posix(), repo.as_posix()], capture_output=True, text=True)


# ─── SC-25: dependabot seeding ───────────────────────────────────────────────

def test_dependabot_is_seeded_when_absent(tmp_path):
    repo = target_repo(tmp_path)
    proc = install(repo)
    assert proc.returncode == 0, proc.stderr
    seeded = (repo / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert seeded == (ROOT / "templates" / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert "package-ecosystem: github-actions" in seeded
    assert "interval: weekly" in seeded and "groups:" in seeded
    assert "dependabot.yml                (seeded" in proc.stdout


@pytest.mark.parametrize("name", ["dependabot.yml", "dependabot.yaml"])
def test_existing_dependabot_config_is_never_overwritten(tmp_path, name):
    repo = target_repo(tmp_path)
    (repo / ".github").mkdir()
    mine = "version: 2\nupdates:\n  - package-ecosystem: \"github-actions\"\n    directory: /\n    schedule: {interval: daily}\n"
    (repo / ".github" / name).write_text(mine, encoding="utf-8", newline="\n")
    proc = install(repo)
    assert proc.returncode == 0, proc.stderr
    assert (repo / ".github" / name).read_text(encoding="utf-8") == mine
    others = {"dependabot.yml", "dependabot.yaml"} - {name}
    assert not any((repo / ".github" / o).exists() for o in others), "a second config must not be added"
    assert "covers github-actions" in proc.stdout
    assert "WARNING" not in proc.stderr


def test_existing_config_without_actions_is_reported_not_edited(tmp_path):
    repo = target_repo(tmp_path)
    (repo / ".github").mkdir()
    mine = "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule: {interval: weekly}\n"
    (repo / ".github" / "dependabot.yml").write_text(mine, encoding="utf-8", newline="\n")
    proc = install(repo)
    assert proc.returncode == 0, proc.stderr
    assert (repo / ".github" / "dependabot.yml").read_text(encoding="utf-8") == mine
    assert "no 'package-ecosystem: github-actions' entry" in proc.stderr


# ─── SC-12: gitleaks is resolved from PATH only ──────────────────────────────

def test_secret_scan_fails_closed_instead_of_running_a_gopath_binary(tmp_path):
    # A hostile GOPATH carrying a "gitleaks" that would pass every commit.
    evil = tmp_path / "evil"
    (evil / "bin").mkdir(parents=True)
    marker = tmp_path / "PWNED"
    for name in ("gitleaks", "gitleaks.exe"):
        fake = evil / "bin" / name
        fake.write_text(f"#!/usr/bin/env bash\ntouch '{marker.as_posix()}'\nexit 0\n", encoding="utf-8", newline="\n")
        fake.chmod(0o755)
    repo = target_repo(tmp_path)
    (repo / "a.txt").write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "a.txt"], check=True)
    git_dir = Path(shutil.which("git")).resolve().parent
    env = {**os.environ, "GOPATH": evil.as_posix(), "HOME": tmp_path.as_posix(),
           "PATH": f"{bash_path(git_dir)}:/usr/bin:/bin"}
    proc = subprocess.run([BASH, SECRET_SCAN.as_posix()], cwd=repo, env=env, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "gitleaks not found on PATH" in proc.stderr
    assert not marker.exists(), "the hook executed a binary chosen by GOPATH"


def test_no_hook_resolves_an_executable_from_env_locations():
    for hook in sorted((ROOT / "hooks").iterdir()):
        text = hook.read_text(encoding="utf-8")
        assert not re.search(r"\$\{?(GOPATH|HOME)\b[^\n]*/bin/", text), f"{hook.name} locates an executable via env"


def test_installed_hook_copies_match_canonical():
    for name in ("pre-commit-secret-scan.sh", "commit-msg", "pre-commit"):
        assert (ROOT / ".githooks" / name).read_bytes() == (ROOT / "hooks" / name).read_bytes(), name
