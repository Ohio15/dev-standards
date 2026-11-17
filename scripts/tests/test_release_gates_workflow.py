"""release-gates.yml: an enabled dependency gate must see every manifest and never pass unexamined.

audit-keystone-2026-11-16 (MEDIUM, brain ac517cd7, work item 6a5ac8ad): the
npm-audit gate ran `[ ! -f package.json ] && exit 0` at the repo root only.
Keystone's only manifest is frontend/package.json, so `npm_audit: high`
examined nothing while the release runbook claimed the gate. The same
skip-means-pass shape lived in cargo_audit for a Cargo.toml without a
Cargo.lock.

These tests run the SHIPPED scripts: the `run:` blocks are extracted from
.github/workflows/release-gates.yml and executed under bash against throwaway
git repos. `npm` and `cargo-audit` are shims that record how they were called
and exit as told, so nothing touches the network or any repo outside tmp_path.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import atexit
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
GATES = ROOT / ".github" / "workflows" / "release-gates.yml"
AUDIT_TEMPLATE = ROOT / "templates" / ".github" / "workflows" / "security-audit.yml"

SHARED_BEGIN = "# >>> shared manifest detection"
SHARED_END = "# <<< shared manifest detection\n"


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
WORKFLOW = yaml.safe_load(GATES.read_text(encoding="utf-8"))
JOBS = WORKFLOW["jobs"]


def bash_argv(script: str) -> list[str]:
    """Run a step body from a file, as Actions does (`bash {0}`); git-bash
    truncates a long `bash -c` argument."""
    fd, path = tempfile.mkstemp(suffix=".sh", prefix="step-")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(script)
    atexit.register(lambda: os.path.exists(path) and os.remove(path))
    return [BASH, "--noprofile", "--norc", path]


def step(job: str, name: str) -> dict:
    found = [s for s in JOBS[job]["steps"] if s.get("name") == name]
    assert len(found) == 1, f"expected one step {name!r} in {job}"
    return found[0]


def bash_path(p: Path) -> str:
    posix = p.resolve().as_posix()
    m = re.match(r"^([A-Za-z]):/(.*)$", posix)
    return f"/{m.group(1).lower()}/{m.group(2)}" if m else posix


def shared_detection(body: str) -> str:
    assert body.count(SHARED_BEGIN) == 1 and body.count(SHARED_END) == 1, "one marked shared block expected"
    start = body.index(SHARED_BEGIN)
    return body[start:body.index(SHARED_END, start) + len(SHARED_END)]


CLEAN_REPORT = json.dumps({"auditReportVersion": 2, "vulnerabilities": {}, "metadata": {}})
HIGH_REPORT = json.dumps({"auditReportVersion": 2, "vulnerabilities": {"left-pad": {
    "name": "left-pad", "severity": "high", "via": [{
        "source": 1, "name": "left-pad", "title": "t", "severity": "high",
        "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}]}}, "metadata": {}})


@pytest.fixture
def env(tmp_path: Path) -> dict:
    """PATH with python3 bound to this interpreter, git reachable, and
    recording shims for npm and cargo-audit."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls.log"
    log.write_text("", encoding="utf-8")
    exe = Path(sys.executable).as_posix()
    shims = {
        "python3": f'#!/usr/bin/env bash\nexec "{exe}" "$@"\n',
        # Records "npm /<dir-within-repo> <args>", prints the audit report in
        # $SHIM_REPORT (a clean v2 report when unset) and exits $SHIM_EXIT. The
        # directory comes from git, so it is the same on every path form.
        # `npm ci` (the lockfile sync check) is logged as "npm-ci /<dir>" and
        # exits $SHIM_CI_EXIT, so audit expectations stay about the audit.
        "npm": ('#!/usr/bin/env bash\nrel=$(git rev-parse --show-prefix)\n'
                'if [ "$1" = ci ]; then printf "npm-ci /%s %s\\n" "${rel%/}" "$*" >> "$CALL_LOG"; exit "${SHIM_CI_EXIT:-0}"; fi\n'
                'printf "npm /%s %s\\n" "${rel%/}" "$*" >> "$CALL_LOG"\n'
                'if [ -n "${SHIM_REPORT:-}" ]; then cat "$SHIM_REPORT"; else echo \'@CLEAN@\'; fi\n'
                'exit "${SHIM_EXIT:-0}"\n').replace("@CLEAN@", CLEAN_REPORT),
        "cargo-audit": '#!/usr/bin/env bash\nprintf "cargo-audit %s\\n" "$*" >> "$CALL_LOG"\nexit "${SHIM_EXIT:-0}"\n',
    }
    for name, body in shims.items():
        p = bindir / name
        p.write_text(body, encoding="utf-8", newline="\n")
        p.chmod(0o755)
    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()
    summary = tmp_path / "summary.md"
    summary.write_text("", encoding="utf-8")
    git_dir = Path(shutil.which("git")).resolve().parent
    return {
        **os.environ,
        "PATH": f"{bash_path(bindir)}:{bash_path(git_dir)}:/usr/bin:/bin",
        "RUNNER_TEMP": bash_path(runner_temp),
        "GITHUB_STEP_SUMMARY": bash_path(summary),
        "CALL_LOG": bash_path(log),
        "NPM_AUDIT_LEVEL": "high",
        "_log": str(log),
        "_summary": str(summary),
    }


def git_repo(root: Path, files: dict[str, str]) -> Path:
    repo = root / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for rel, body in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8", newline="\n")
    if files:
        subprocess.run(["git", "-C", str(repo), "add", "-f", "--", *files], check=True)
    return repo


def run(script: str, repo: Path, env: dict, **extra) -> subprocess.CompletedProcess:
    e = {**env, **extra}
    return subprocess.run(bash_argv(script), cwd=repo, env=e, capture_output=True, text=True)


def gate(tmp_path: Path, env: dict, files: dict[str, str], **extra):
    """Run detect, then (if it passed) the audit step, as the job does."""
    repo = git_repo(tmp_path, files)
    detect = run(step("npm-audit", "Detect npm manifests")["run"], repo, env, **extra)
    audit = None
    if detect.returncode == 0:
        audit = run(step("npm-audit", "Run npm audit on every manifest")["run"], repo, env, **extra)
    log = Path(env["_log"]).read_text(encoding="utf-8").splitlines()
    calls = [c for c in log if not c.startswith("npm-ci ")]
    checks = [c for c in log if c.startswith("npm-ci ")]
    # No directory is audited without its lockfile sync check.
    assert {c.split()[1] for c in calls} <= {c.split()[1] for c in checks}, log
    summary = Path(env["_summary"]).read_text(encoding="utf-8")
    return detect, audit, calls, summary


LOCK = json.dumps({"lockfileVersion": 3, "packages": {"": {}}})
DEPS = json.dumps({"dependencies": {"left-pad": "^1.3.0"}})


# --- shape -------------------------------------------------------------------

def test_detection_is_the_shared_block():
    detect = step("npm-audit", "Detect npm manifests")["run"]
    audit = yaml.safe_load(AUDIT_TEMPLATE.read_text(encoding="utf-8"))
    [audit_detect] = [s["run"] for s in audit["jobs"]["detect"]["steps"] if s.get("id") == "detect"]
    assert shared_detection(detect) == shared_detection(audit_detect), \
        "release-gates.yml npm detection differs from the shared block in security-audit.yml"
    # All three copies, not two (gate pass 1 note): dep-auto-apply.yml too.
    apply_wf = yaml.safe_load((ROOT / "templates" / ".github" / "workflows" / "dep-auto-apply.yml").read_text(encoding="utf-8"))
    apply_runs = [s["run"] for job in apply_wf["jobs"].values() for s in job.get("steps", [])
                  if SHARED_BEGIN in s.get("run", "")]
    assert len(apply_runs) == 1
    assert shared_detection(detect) == shared_detection(apply_runs[0]), \
        "release-gates.yml npm detection differs from the shared block in dep-auto-apply.yml"
    rest = detect[detect.index(SHARED_END) + len(SHARED_END):]
    for name in ("dirs_of", "npm_dirs", "npm_covered"):
        assert not re.search(rf"(?m)^\s*{name}(=|\(\))", rest), f"{name} is reassigned after the shared block"


def test_no_root_only_manifest_check_remains():
    for s in JOBS["npm-audit"]["steps"]:
        body = s.get("run", "")
        assert "[ ! -f package.json ]" not in body
        assert "skipping" not in body
    assert "hashFiles" not in json.dumps(JOBS["npm-audit"])


def test_no_expression_is_pasted_into_a_run_body():
    for job in ("npm-audit", "cargo_audit"):
        for s in JOBS[job]["steps"]:
            assert "${{" not in s.get("run", ""), f"{job}/{s.get('name')} pastes an expression into run:"


def test_off_is_the_only_way_to_disable():
    assert JOBS["npm-audit"]["if"] == "needs.read-config.outputs.npm_audit_severity != 'off'"


# --- detection ---------------------------------------------------------------

def test_nested_manifest_is_audited(tmp_path, env):
    # The Keystone shape the root-only check skipped.
    detect, audit, calls, summary = gate(tmp_path, env, {
        "frontend/package.json": DEPS, "frontend/package-lock.json": LOCK, "README.md": "x",
    })
    assert detect.returncode == 0, detect.stdout + detect.stderr
    assert audit.returncode == 0, audit.stdout + audit.stderr
    assert calls == ["npm /frontend audit --json --audit-level=high --package-lock-only"]
    assert "`frontend`: clean at high" in summary


def test_every_manifest_is_audited(tmp_path, env):
    detect, audit, calls, _ = gate(tmp_path, env, {
        "package.json": DEPS, "package-lock.json": LOCK,
        "web/package.json": DEPS, "web/package-lock.json": LOCK,
        "web/node_modules/x/package.json": DEPS,
    })
    assert audit.returncode == 0, audit.stdout + audit.stderr
    assert calls == ["npm / audit --json --audit-level=high --package-lock-only", "npm /web audit --json --audit-level=high --package-lock-only"]


def test_enabled_gate_with_no_manifest_fails(tmp_path, env):
    detect, audit, calls, _ = gate(tmp_path, env, {"README.md": "x", "go.mod": "module x\n"})
    assert detect.returncode == 1
    assert "nothing was audited" in detect.stdout
    assert "gates.npm_audit: off" in detect.stdout
    assert audit is None and calls == []


def test_untracked_manifest_does_not_count(tmp_path, env):
    repo = git_repo(tmp_path, {"README.md": "x"})
    (repo / "package.json").write_text(DEPS, encoding="utf-8")
    proc = run(step("npm-audit", "Detect npm manifests")["run"], repo, env)
    assert proc.returncode == 1
    assert "nothing was audited" in proc.stdout


@pytest.mark.parametrize("level", ["", "medium", "high; rm -rf /", "none"])
def test_an_unknown_level_is_an_error(tmp_path, env, level):
    detect, _, calls, _ = gate(tmp_path, env, {"package.json": DEPS, "package-lock.json": LOCK},
                               NPM_AUDIT_LEVEL=level)
    assert detect.returncode == 1
    assert "is not one of off" in detect.stdout
    assert calls == []


@pytest.mark.parametrize("level", ["info", "low", "moderate", "high", "critical"])
def test_each_npm_level_is_passed_through(tmp_path, env, level):
    _, audit, calls, _ = gate(tmp_path, env, {"package.json": DEPS, "package-lock.json": LOCK},
                              NPM_AUDIT_LEVEL=level)
    assert audit.returncode == 0
    assert calls == [f"npm / audit --json --audit-level={level} --package-lock-only"]


# --- examination -------------------------------------------------------------

def test_an_advisory_fails_the_gate(tmp_path, env):
    report = tmp_path / "report.json"
    report.write_text(HIGH_REPORT, encoding="utf-8")
    _, audit, _, summary = gate(tmp_path, env, {"app/package.json": DEPS, "app/package-lock.json": LOCK},
                                SHIM_EXIT="1", SHIM_REPORT=bash_path(report))
    assert audit.returncode == 1
    assert "`app`: **FAILED**" in summary


def test_one_failing_directory_fails_the_gate_but_all_run(tmp_path, env):
    files = {"a/package.json": DEPS, "a/package-lock.json": LOCK,
             "b/package.json": DEPS, "b/package-lock.json": LOCK}
    repo = git_repo(tmp_path, files)
    assert run(step("npm-audit", "Detect npm manifests")["run"], repo, env).returncode == 0
    # Fail only in a/; b/ must still be audited and reported.
    npm = tmp_path / "bin" / "npm"
    npm.write_text('#!/usr/bin/env bash\nrel=$(git rev-parse --show-prefix)\n'
                   '[ "$1" = ci ] && exit 0\n'
                   'printf "npm /%s\\n" "${rel%/}" >> "$CALL_LOG"\n'
                   'case "$rel" in a/) exit 1 ;; esac\necho \'@CLEAN@\'\nexit 0\n'.replace("@CLEAN@", CLEAN_REPORT), encoding="utf-8", newline="\n")
    audit = run(step("npm-audit", "Run npm audit on every manifest")["run"], repo, env)
    assert audit.returncode == 1
    assert Path(env["_log"]).read_text(encoding="utf-8").splitlines() == ["npm /a", "npm /b"]
    summary = Path(env["_summary"]).read_text(encoding="utf-8")
    assert "`a`: **FAILED**" in summary and "`b`: clean at high" in summary
    assert "wrote no JSON report" in audit.stdout, "a/ printed nothing: not examined, never clean"


def test_a_lockfile_out_of_sync_is_not_examined(tmp_path, env):
    # Gate pass 1 (SC-07): a member's dependency missing from the root
    # lockfile must not read as "audited through the root".
    root_manifest = json.dumps({"workspaces": ["packages/*"]})
    lock = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "packages/a": {}}})
    _, audit, calls, summary = gate(tmp_path, env, {
        "package.json": root_manifest, "package-lock.json": lock, "packages/a/package.json": DEPS,
    }, SHIM_CI_EXIT="1")
    assert audit.returncode == 1
    assert "out of sync" in audit.stdout
    assert "`.`: **NOT EXAMINED** (lockfile out of sync)" in summary
    assert calls == [], "no audit may run on a lockfile that is not the tree"


def test_the_sync_check_installs_nothing_and_runs_no_scripts(tmp_path, env):
    gate(tmp_path, env, {"web/package.json": DEPS, "web/package-lock.json": LOCK})
    log = Path(env["_log"]).read_text(encoding="utf-8").splitlines()
    assert log[0] == "npm-ci /web ci --dry-run --ignore-scripts --no-audit --no-fund"


def test_dependencies_without_a_lockfile_are_not_examined(tmp_path, env):
    _, audit, calls, summary = gate(tmp_path, env, {"frontend/package.json": DEPS})
    assert audit.returncode == 1
    assert "not examined" in audit.stdout
    assert "**NOT EXAMINED** (no lockfile)" in summary
    assert calls == []


@pytest.mark.parametrize("body", ["{}", json.dumps({"name": "x", "dependencies": {}, "scripts": {"a": "b"}})])
def test_a_manifest_with_no_dependencies_is_examined_and_clean(tmp_path, env, body):
    _, audit, calls, summary = gate(tmp_path, env, {"tools/package.json": body})
    assert audit.returncode == 0, audit.stdout + audit.stderr
    assert calls == []
    assert "`tools`: no dependencies declared" in summary


@pytest.mark.parametrize("lock,kind", [("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn")])
def test_a_non_npm_lockfile_is_not_examined(tmp_path, env, lock, kind):
    _, audit, calls, summary = gate(tmp_path, env, {"package.json": DEPS, lock: "x\n"})
    assert audit.returncode == 1
    assert f"**NOT EXAMINED** ({kind} lockfile)" in summary
    assert calls == []


def test_an_unreadable_manifest_is_not_examined(tmp_path, env):
    _, audit, _, summary = gate(tmp_path, env, {"web/package.json": "not json"})
    assert audit.returncode == 1
    assert "**NOT EXAMINED** (unreadable package.json)" in summary


def test_workspace_members_are_audited_through_their_root(tmp_path, env):
    root_manifest = json.dumps({"workspaces": ["packages/*"], "devDependencies": {"x": "1"}})
    lock = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "packages/a": {}}})
    _, audit, calls, summary = gate(tmp_path, env, {
        "package.json": root_manifest, "package-lock.json": lock, "packages/a/package.json": DEPS,
    })
    assert audit.returncode == 0, audit.stdout + audit.stderr
    assert calls == ["npm / audit --json --audit-level=high --package-lock-only"]
    assert "`packages/a`: workspace member, audited through `.`" in summary


@pytest.mark.skipif(os.name == "nt", reason="NTFS cannot hold a newline in a file name")
def test_a_hostile_directory_name_fails_detection(tmp_path, env):
    # A newline in a path could forge a `::command::` line when echoed.
    detect, audit, calls, _ = gate(tmp_path, env, {"a\nb/package.json": "{}"})
    assert detect.returncode != 0
    assert "control character" in detect.stdout + detect.stderr
    assert audit is None and calls == []


# --- cargo_audit ---------------------------------------------------------------

def cargo(tmp_path: Path, env: dict, files: dict[str, str]):
    repo = git_repo(tmp_path, files)
    detect = run(step("cargo_audit", "Detect Cargo manifests")["run"], repo, env,
                 GITHUB_OUTPUT=bash_path(tmp_path / "out"))
    assert detect.returncode == 0, detect.stdout + detect.stderr
    audit = run(step("cargo_audit", "Run cargo-audit on every manifest")["run"], repo, env)
    return audit, Path(env["_log"]).read_text(encoding="utf-8").splitlines()


def test_cargo_without_a_lockfile_is_not_examined(tmp_path, env):
    audit, calls = cargo(tmp_path, env, {"crate/Cargo.toml": "[package]\nname='x'\n"})
    assert audit.returncode == 1
    assert "not examined: no Cargo.lock" in audit.stdout
    assert calls == []


def test_cargo_workspace_members_share_the_root_lockfile(tmp_path, env):
    audit, calls = cargo(tmp_path, env, {
        "Cargo.toml": "[workspace]\n", "Cargo.lock": "", "crates/a/Cargo.toml": "[package]\n",
    })
    assert audit.returncode == 0, audit.stdout + audit.stderr
    assert calls == ["cargo-audit audit --file ./Cargo.lock"]
