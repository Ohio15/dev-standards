"""release-gates.yml npm-audit: audit every tracked manifest, never pass having examined nothing.

Discovered 2026-10-17 (brain cb5d82c9): the job ran `npm audit` at the repo
root and skipped when there was no root package.json. ToolVault (backend/,
frontend/) and APM (frontend/) both declare `gates.npm_audit: high`, so their
release gate reported a pass while auditing nothing, with 2 critical / 3 high
advisories live in ToolVault's backend.

These tests run the SHIPPED script: the `run:` block of the npm-audit job is
extracted from .github/workflows/release-gates.yml and executed under bash in
throwaway git repos, with `npm` replaced by a recorder on PATH. The recorder
mirrors only what the gate relies on (exit status per directory), so the real
npm audit semantics are exercised by the release run itself, not here.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release-gates.yml"
WORKFLOW = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
JOB = WORKFLOW["jobs"]["npm-audit"]


def bash_exe() -> str:
    """Git's own bash on Windows (a bare "bash" is the WSL stub), else PATH."""
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


def audit_script() -> str:
    steps = [s for s in JOB["steps"] if s.get("id") == "audit"]
    assert len(steps) == 1
    return steps[0]["run"]


@pytest.fixture
def tools(tmp_path: Path) -> tuple[str, Path]:
    """PATH with python3 bound to this interpreter and a recording `npm`.

    The fake npm appends "<repo-relative cwd> <args>" to a log and exits
    non-zero when the directory holds a FAIL marker file."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = Path(sys.executable).as_posix()
    (bindir / "python3").write_text(f'#!/usr/bin/env bash\nexec "{exe}" "$@"\n',
                                    encoding="utf-8", newline="\n")
    log = tmp_path / "npm.log"
    (bindir / "npm").write_text(
        "#!/usr/bin/env bash\n"
        # The repo-relative cwd, from git itself: Git-bash may spell the
        # temp dir as /tmp, so a $PWD prefix comparison is not reliable.
        'rel=$(git rev-parse --show-prefix); rel=${rel%/}\n'
        f'printf "%s %s\\n" "${{rel:-.}}" "$*" >> "{bash_path(tmp_path)}/npm.log"\n'
        "[ -f FAIL ] && exit 1\n"
        "exit 0\n",
        encoding="utf-8", newline="\n")
    for f in bindir.iterdir():
        f.chmod(0o755)
    git_dir = Path(shutil.which("git")).resolve().parent
    return f"{bash_path(bindir)}:{bash_path(git_dir)}:/usr/bin:/bin", log


def git_repo(root: Path, files: dict[str, str]) -> Path:
    repo = root / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    if files:
        subprocess.run(["git", "-C", str(repo), "add", "-f", "--", *files], check=True)
    return repo


def run_gate(tmp_path: Path, tools, files: dict[str, str], *, severity: str = "high",
             declared: str = "true"):
    path, log = tools
    repo = git_repo(tmp_path, files)
    summary = tmp_path / "summary.md"
    env = {**os.environ, "PATH": path, "SEVERITY": severity, "DECLARED": declared,
           "GITHUB_STEP_SUMMARY": str(summary)}
    proc = subprocess.run([BASH, "-c", audit_script()], cwd=repo, env=env,
                          capture_output=True, text=True)
    audited = []
    if log.exists():
        for line in log.read_text(encoding="utf-8").splitlines():
            rel, args = line.split(" ", 1)
            audited.append((rel, args))
    text = summary.read_text(encoding="utf-8") if summary.exists() else ""
    return proc, audited, text


PKG = '{"name": "x", "version": "1.0.0"}'
LOCK = '{"lockfileVersion": 3, "packages": {"": {}}}'


def test_subdirectory_trees_without_a_root_manifest_are_all_audited(tmp_path, tools):
    # The ToolVault shape: the original gate skipped this and passed.
    proc, audited, _ = run_gate(tmp_path, tools, {
        "backend/package.json": PKG, "backend/package-lock.json": LOCK,
        "frontend/package.json": PKG, "frontend/package-lock.json": LOCK,
    })
    assert proc.returncode == 0, proc.stderr
    assert audited == [("backend", "audit --package-lock-only --audit-level=high"),
                       ("frontend", "audit --package-lock-only --audit-level=high")]


def test_a_failing_subtree_fails_the_gate_and_the_rest_still_runs(tmp_path, tools):
    proc, audited, summary = run_gate(tmp_path, tools, {
        "backend/package.json": PKG, "backend/package-lock.json": LOCK, "backend/FAIL": "",
        "frontend/package.json": PKG, "frontend/package-lock.json": LOCK,
    }, severity="critical")
    assert proc.returncode == 1
    assert [d for d, _ in audited] == ["backend", "frontend"]
    assert "npm_audit (backend): **FAIL** at critical" in summary
    assert "npm_audit (frontend): pass at critical" in summary


def test_declared_gate_with_no_manifest_fails_closed(tmp_path, tools):
    proc, audited, summary = run_gate(tmp_path, tools, {"main.go": "package main\n"})
    assert proc.returncode == 1
    assert audited == []
    assert "declared" in proc.stdout and "nothing would be audited" in proc.stdout
    assert "**FAIL**" in summary


def test_undeclared_default_with_no_manifest_reports_not_examined(tmp_path, tools):
    proc, audited, summary = run_gate(tmp_path, tools, {"main.go": "package main\n"},
                                      declared="false")
    assert proc.returncode == 0, proc.stderr
    assert audited == []
    assert "NOT EXAMINED" in summary


def test_manifest_without_a_covering_lockfile_fails(tmp_path, tools):
    proc, audited, summary = run_gate(tmp_path, tools, {
        "package.json": PKG, "package-lock.json": LOCK,
        "tools/package.json": PKG,  # not a workspace member of the root lock
    })
    assert proc.returncode == 1
    assert audited == [(".", "audit --package-lock-only --audit-level=high")]
    assert "tools/package.json has no package-lock.json" in proc.stdout
    assert "npm_audit (tools): **NOT EXAMINED**" in summary


def test_workspace_members_are_covered_by_the_root_lockfile(tmp_path, tools):
    lock = json.dumps({"lockfileVersion": 3,
                       "packages": {"": {"workspaces": ["packages/*"]},
                                    "packages/a": {"version": "1.0.0"}}})
    proc, audited, _ = run_gate(tmp_path, tools, {
        "package.json": PKG, "package-lock.json": lock, "packages/a/package.json": PKG,
    })
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert audited == [(".", "audit --package-lock-only --audit-level=high")]


def test_node_modules_manifests_are_ignored(tmp_path, tools):
    proc, audited, _ = run_gate(tmp_path, tools, {
        "package.json": PKG, "package-lock.json": LOCK,
        "node_modules/dep/package.json": PKG,
    })
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert audited == [(".", "audit --package-lock-only --audit-level=high")]


def test_an_invalid_severity_is_an_error_not_a_default(tmp_path, tools):
    proc, audited, _ = run_gate(tmp_path, tools, {
        "package.json": PKG, "package-lock.json": LOCK}, severity="hihg")
    assert proc.returncode == 1
    assert audited == []


def test_declared_flag_is_read_from_release_config():
    parse = next(s for s in WORKFLOW["jobs"]["read-config"]["steps"] if s.get("id") == "parse")
    assert "npm_audit_declared=$(yq '.gates.npm_audit != null' release-config.yml)" in parse["run"]
    assert WORKFLOW["jobs"]["read-config"]["outputs"]["npm_audit_declared"]


def test_no_expression_is_pasted_into_the_audit_script():
    # Inputs reach the script through env, never `${{ }}` substitution.
    assert "${{" not in audit_script()
