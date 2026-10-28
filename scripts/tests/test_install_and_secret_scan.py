"""install.sh Dependabot seeding (SC-25) and the secret-scan hook's gitleaks
lookup (SC-12), from the 2026-10-05 security gate on the templates.

- SC-25: installed repos got SHA-pinned actions and no Dependabot config, so
  the pins went stale. install.sh now seeds .github/dependabot.yml when the
  target has none, and never touches an existing one.
- SC-12: with gitleaks off PATH the hook ran `${GOPATH:-$HOME/go}/bin/gitleaks`,
  a binary an inherited environment chooses. It now fails closed.

Runner predicate (SC-37, amended 2026-10-27): install.sh writes the canonical
allow-list predicate into a private repo's pull_request-reachable workflows and
the hosted literal into a public repo's, and refuses to install when it cannot
tell which the target is. The tests pass --no-gh with an explicit visibility,
so no test talks to GitHub.

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


def install(repo: Path, *flags: str) -> subprocess.CompletedProcess[str]:
    """Run install.sh offline. Without flags the target is treated as a private
    repo (the case every pre-SC-37 test covered); pass flags to override."""
    if not flags:
        flags = ("--private", "--no-gh")
    return subprocess.run([BASH, INSTALL.as_posix(), *flags, repo.as_posix()], capture_output=True, text=True)


REGISTER = ROOT / "security" / "SECURITY-CHECKS.md"


def canonical_predicate() -> str:
    """The SC-37 canonical Linux predicate, read from the register so the test
    and the installer cannot drift from it independently."""
    sc37 = REGISTER.read_text(encoding="utf-8").split("### SC-37", 1)[1]
    m = re.search(r"`(\(github\.event_name == 'push'.*?\|\| 'ubuntu-latest')`", sc37, re.S)
    assert m, "SC-37 canonical predicate not found in the register"
    return m.group(1)


PR_TEMPLATES = {
    "size-guard.yml": ROOT / "workflows" / "size-guard.yml",
    "security-audit.yml": ROOT / "templates" / ".github" / "workflows" / "security-audit.yml",
}


def runs_on_lines(text: str) -> list[str]:
    return [l.strip() for l in text.splitlines() if l.strip().startswith("runs-on:")]


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


# ─── SC-37: runner predicate follows the target's visibility ─────────────────

def test_private_repo_gets_the_canonical_predicate_verbatim(tmp_path):
    repo = target_repo(tmp_path)
    proc = install(repo, "--private", "--no-gh")
    assert proc.returncode == 0, proc.stderr
    canon = "runs-on: ${{ " + canonical_predicate() + " }}"
    for name, template in PR_TEMPLATES.items():
        installed = (repo / ".github" / "workflows" / name).read_bytes()
        assert installed == template.read_bytes(), f"{name} is not the template byte for byte"
        lines = runs_on_lines(installed.decode("utf-8"))
        assert lines and all(l == canon for l in lines), (name, lines)
    assert "CI runner (private repository): nexus-ci onboarding INCOMPLETE" in proc.stdout
    assert "gh variable set CI_RUNNER --body nexus-ci" in proc.stdout
    assert "ci-vm/registrar/config.json" in proc.stdout


def test_public_repo_gets_the_hosted_literal_and_no_runs_on_expression(tmp_path):
    repo = target_repo(tmp_path)
    proc = install(repo, "--public", "--no-gh")
    assert proc.returncode == 0, proc.stderr
    for name, template in PR_TEMPLATES.items():
        installed = (repo / ".github" / "workflows" / name).read_text(encoding="utf-8")
        lines = runs_on_lines(installed)
        assert lines and all(l == "runs-on: ubuntu-latest" for l in lines), (name, lines)
        assert "runs-on: ${{" not in installed
        # Only the runs-on lines differ from the template.
        expected = template.read_text(encoding="utf-8").replace(
            "runs-on: ${{ " + canonical_predicate() + " }}", "runs-on: ubuntu-latest")
        assert installed == expected, name
    assert "CI runner (public repository):" in proc.stdout
    assert "CI_RUNNER must stay unset" in proc.stdout
    assert "gh variable set CI_RUNNER" not in proc.stdout


def test_dep_auto_apply_is_copied_as_is_whatever_the_visibility(tmp_path):
    for flag in ("--private", "--public"):
        repo = tmp_path / flag.strip("-")
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        proc = install(repo, flag, "--no-gh")
        assert proc.returncode == 0, proc.stderr
        assert (repo / ".github" / "workflows" / "dep-auto-apply.yml").read_bytes() ==             (ROOT / "templates" / ".github" / "workflows" / "dep-auto-apply.yml").read_bytes()


def test_unknown_visibility_installs_nothing(tmp_path):
    repo = target_repo(tmp_path)  # no origin, and --no-gh: visibility cannot be learned
    proc = install(repo, "--no-gh")
    assert proc.returncode == 1
    assert "cannot determine whether" in proc.stderr and "nothing installed" in proc.stderr
    assert not (repo / ".github").exists() and not (repo / ".githooks").exists()
    assert subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath"],
                          capture_output=True, text=True).returncode != 0


def test_both_visibility_flags_is_a_usage_error(tmp_path):
    repo = target_repo(tmp_path)
    proc = install(repo, "--private", "--public", "--no-gh")
    assert proc.returncode == 2
    assert "Usage:" in proc.stderr
    assert not (repo / ".github").exists()


def test_installer_substitutes_only_the_register_predicate():
    """install.sh's CANON_RUNS_ON must be the register's SC-37 text, so a public
    copy loses exactly the canonical predicate and nothing else."""
    text = INSTALL.read_text(encoding="utf-8")
    m = re.search(r'^CANON_RUNS_ON="runs-on: \\\$\{\{ (.*?) \}\}"$', text, re.M)
    assert m, "CANON_RUNS_ON not found in install.sh"
    assert m.group(1).replace('\\"', '"') == canonical_predicate()
    for template in PR_TEMPLATES.values():
        for line in runs_on_lines(template.read_text(encoding="utf-8")):
            assert line == "runs-on: ${{ " + canonical_predicate() + " }}", (template.name, line)
