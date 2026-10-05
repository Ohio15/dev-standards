"""security-audit.yml (Layer A): the gate must see every manifest and never pass unexamined.

audit-ai-console-2026-09-28 (MEDIUM, proposed SC-26): detection was
`[ -f package.json ]` at the repo root only. ai-console keeps its manifests in
console/ and console/clis/, so every audit job was `skipped`, and the summary
counted `skipped` as a pass. The gate was green on every PR having examined
nothing.

These tests run the SHIPPED scripts: the `run:` blocks are extracted from
templates/.github/workflows/security-audit.yml and executed under bash. The
detect step runs against throwaway git repos; the summary step runs with the
`${{ ... }}` expressions substituted the way Actions would. No network, and
no repo outside tmp_path.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATE = ROOT / "templates" / ".github" / "workflows" / "security-audit.yml"
OWN_COPY = ROOT / ".github" / "workflows" / "security-audit.yml"


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
WORKFLOW = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))
JOBS = WORKFLOW["jobs"]


def step_run(job: str, step_id: str | None = None) -> str:
    steps = [s for s in JOBS[job]["steps"] if "run" in s]
    if step_id is not None:
        steps = [s for s in steps if s.get("id") == step_id]
    assert len(steps) == 1, f"expected one run step in {job}"
    return steps[0]["run"]


def bash_path(p: Path) -> str:
    """A path bash can put on PATH. PATH is ':'-separated, so on Windows the
    drive letter must become Git-bash's /c/... form, not C:/..."""
    posix = p.resolve().as_posix()
    m = re.match(r"^([A-Za-z]):/(.*)$", posix)
    return f"/{m.group(1).lower()}/{m.group(2)}" if m else posix


@pytest.fixture
def shim_path(tmp_path: Path) -> str:
    """PATH with `python3` bound to this interpreter (the scripts call python3;
    on Windows that name is often the Store stub) and git reachable."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    shim = bindir / "python3"
    exe = Path(sys.executable).as_posix()
    shim.write_text(f'#!/usr/bin/env bash\nexec "{exe}" "$@"\n', encoding="utf-8", newline="\n")
    shim.chmod(0o755)
    git_dir = Path(shutil.which("git")).resolve().parent
    return f"{bash_path(bindir)}:{bash_path(git_dir)}:/usr/bin:/bin"


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


def run_detect(tmp_path: Path, shim_path: str, files: dict[str, str]):
    repo = git_repo(tmp_path, files)
    out = tmp_path / "github_output"
    out.write_text("", encoding="utf-8")
    env = {**os.environ, "PATH": shim_path, "GITHUB_OUTPUT": out.as_posix()}
    proc = subprocess.run([BASH, "-c", step_run("detect", "detect")], cwd=repo, env=env,
                          capture_output=True, text=True)
    outputs = dict(line.split("=", 1) for line in out.read_text(encoding="utf-8").splitlines() if "=" in line)
    return proc, outputs


# ─── detect ──────────────────────────────────────────────────────────────────

def test_subdirectory_manifests_are_found(tmp_path, shim_path):
    # The ai-console shape that the root-only check missed.
    proc, o = run_detect(tmp_path, shim_path, {
        "console/package.json": "{}", "console/package-lock.json": "{}",
        "console/clis/package.json": "{}", "README.md": "x",
    })
    assert proc.returncode == 0, proc.stderr
    assert o["has_npm"] == "true"
    assert o["npm_dirs"] == '["console", "console/clis"]'
    assert o["has_go"] == "false" and o["go_dirs"] == "[]"
    assert o["has_python"] == "false"


def test_root_manifests_map_to_dot(tmp_path, shim_path):
    proc, o = run_detect(tmp_path, shim_path, {
        "package.json": "{}", "go.mod": "module x\n", "requirements.txt": "", "svc/pyproject.toml": "",
    })
    assert proc.returncode == 0, proc.stderr
    assert o["npm_dirs"] == '["."]'
    assert o["go_dirs"] == '["."]'
    assert o["python_dirs"] == '[".", "svc"]'


def test_node_modules_is_never_a_manifest_directory(tmp_path, shim_path):
    proc, o = run_detect(tmp_path, shim_path, {
        "app/package.json": "{}", "app/node_modules/left-pad/package.json": "{}",
    })
    assert proc.returncode == 0, proc.stderr
    assert o["npm_dirs"] == '["app"]'


def test_untracked_manifests_do_not_count(tmp_path, shim_path):
    # Detection is from `git ls-files`: what CI checks out, not stray files.
    repo = git_repo(tmp_path, {"README.md": "x"})
    (repo / "package.json").write_text("{}", encoding="utf-8")
    out = tmp_path / "o"
    out.write_text("", encoding="utf-8")
    proc = subprocess.run([BASH, "-c", step_run("detect", "detect")], cwd=repo,
                          env={**os.environ, "PATH": shim_path, "GITHUB_OUTPUT": out.as_posix()},
                          capture_output=True, text=True)
    # Assert the REASON too: exit 1 alone is also what a missing git gives.
    assert proc.returncode == 1, "an untracked manifest must not satisfy detection"
    assert "nothing was audited" in proc.stdout + proc.stderr, proc.stderr


def test_no_manifest_fails_closed(tmp_path, shim_path):
    proc, _ = run_detect(tmp_path, shim_path, {"README.md": "x"})
    assert proc.returncode == 1
    assert "nothing was audited" in proc.stdout + proc.stderr


def test_no_manifest_passes_only_with_a_reasoned_declaration(tmp_path, shim_path):
    proc, _ = run_detect(tmp_path, shim_path, {
        "README.md": "x", ".github/security-audit-no-manifests": "docs-only repository; no dependencies\n",
    })
    assert proc.returncode == 0, proc.stderr


def test_an_empty_declaration_is_not_a_declaration(tmp_path, shim_path):
    proc, _ = run_detect(tmp_path, shim_path, {
        "README.md": "x", ".github/security-audit-no-manifests": "  \n\n",
    })
    assert proc.returncode == 1
    assert "nothing was audited" in proc.stdout + proc.stderr, proc.stderr


# ─── summary ─────────────────────────────────────────────────────────────────

EXPR = re.compile(r"^\$\{\{\s*([^}]+?)\s*\}\}$")


def run_summary(tmp_path: Path, shim_path: str, *, detect: str = "success",
                npm=("false", "skipped"), go=("false", "skipped"), py=("false", "skipped"),
                dirs=("[]", "[]", "[]")):
    """Run the summary step the way Actions does: each `env:` entry's
    expression is evaluated, and the script sees only environment variables."""
    values = {
        "needs.detect.result": detect,
        "needs.detect.outputs.has_npm": npm[0], "needs.npm-audit.result": npm[1],
        "needs.detect.outputs.has_go": go[0], "needs.go-vulncheck.result": go[1],
        "needs.detect.outputs.has_python": py[0], "needs.pip-audit.result": py[1],
        "needs.detect.outputs.npm_dirs": dirs[0], "needs.detect.outputs.go_dirs": dirs[1],
        "needs.detect.outputs.python_dirs": dirs[2],
    }
    [step] = [s for s in JOBS["summary"]["steps"] if "run" in s]
    env = {}
    for name, expr in step.get("env", {}).items():
        m = EXPR.match(str(expr))
        assert m and m.group(1) in values, f"summary env {name} uses an expression this test does not model: {expr}"
        env[name] = values[m.group(1)]
    summ = tmp_path / "summary.md"
    proc = subprocess.run([BASH, "-c", step["run"]], cwd=tmp_path,
                          env={**os.environ, **env, "PATH": shim_path, "GITHUB_STEP_SUMMARY": summ.as_posix()},
                          capture_output=True, text=True)
    proc.summary = summ.read_text(encoding="utf-8") if summ.exists() else ""
    return proc


@pytest.mark.parametrize("result", ["skipped", "failure", "cancelled", "timed_out"])
def test_a_detected_ecosystem_that_did_not_succeed_fails(tmp_path, shim_path, result):
    # `skipped` is the case that made the gate green having examined nothing.
    proc = run_summary(tmp_path, shim_path, npm=("true", result))
    assert proc.returncode == 1, f"npm detected + {result} must fail"
    assert f"npm was detected but its audit result is '{result}'" in proc.stdout


def test_detected_and_succeeded_passes(tmp_path, shim_path):
    proc = run_summary(tmp_path, shim_path, npm=("true", "success"), py=("true", "success"))
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_failed_detection_fails_even_if_every_audit_was_skipped(tmp_path, shim_path):
    proc = run_summary(tmp_path, shim_path, detect="failure")
    assert proc.returncode == 1
    assert "ecosystem detection did not succeed" in proc.stdout


def test_an_undetected_ecosystem_that_ran_is_a_disagreement(tmp_path, shim_path):
    proc = run_summary(tmp_path, shim_path, npm=("true", "success"), go=("false", "success"))
    assert proc.returncode == 1
    assert "go was not detected but its audit ran" in proc.stdout


# ─── injection ───────────────────────────────────────────────────────────────
# Directory names are repo content a pull request controls. Found by the
# security gate on this change: `${{ matrix.dir }}` inside a run: body was pasted
# into the script before bash parsed it.

def test_no_expression_is_pasted_into_any_run_body():
    offenders = [f"{name}: {step.get('name') or step.get('id') or '?'}"
                 for name, job in JOBS.items() for step in job.get("steps", [])
                 if "${{" in step.get("run", "")]
    assert offenders == [], "values must reach run: through env, never ${{ }}: " + ", ".join(offenders)


def test_a_hostile_directory_name_is_data_in_the_summary(tmp_path, shim_path):
    evil = '["$(touch PWNED)", "`touch PWNED2`"]'
    proc = run_summary(tmp_path, shim_path, npm=("true", "success"), dirs=(evil, "[]", "[]"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (tmp_path / "PWNED").exists() and not (tmp_path / "PWNED2").exists()
    assert "$(touch PWNED)" in proc.summary, "the name must appear verbatim, as data"


def test_a_control_character_in_a_manifest_path_fails_detection(tmp_path, shim_path):
    # Git's index accepts a newline in a path even where the filesystem does
    # not, so add the entry directly. Echoed later, such a name could start a
    # line with `::` and forge a workflow command.
    repo = git_repo(tmp_path, {"README.md": "x"})
    blob = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input="",
                          capture_output=True, text=True, check=True).stdout.strip()
    # core.protectNTFS=false: Git for Windows refuses such paths by default,
    # but a repo committed on Linux (where the runner lives) can carry them.
    subprocess.run(["git", "-C", str(repo), "-c", "core.protectNTFS=false", "update-index", "--add", "--cacheinfo",
                    f"100644,{blob},evil\n::error::forged/pyproject.toml"], check=True)
    out = tmp_path / "o"
    out.write_text("", encoding="utf-8")
    proc = subprocess.run([BASH, "-c", step_run("detect", "detect")], cwd=repo,
                          env={**os.environ, "PATH": shim_path, "GITHUB_OUTPUT": out.as_posix()},
                          capture_output=True, text=True)
    assert proc.returncode != 0
    assert "control character in manifest path" in proc.stderr, proc.stderr


# ─── structure ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("job,output", [
    ("npm-audit", "npm_dirs"), ("go-vulncheck", "go_dirs"), ("pip-audit", "python_dirs"),
])
def test_each_audit_job_runs_per_detected_directory(job, output):
    j = JOBS[job]
    assert j["strategy"]["matrix"]["dir"] == f"${{{{ fromJSON(needs.detect.outputs.{output}) }}}}"
    assert j["defaults"]["run"]["working-directory"] == "${{ matrix.dir }}"
    assert j["strategy"]["fail-fast"] is False


def test_summary_waits_on_every_audit_job_and_always_runs():
    s = JOBS["summary"]
    assert s["if"] == "always()"
    audit_jobs = {name for name, j in JOBS.items() if "strategy" in j}
    assert audit_jobs == {"npm-audit", "go-vulncheck", "pip-audit"}
    assert set(s["needs"]) == {"detect"} | audit_jobs


def test_no_run_step_exits_zero_on_a_skip():
    # The pip job used to `exit 0` when it found nothing to audit.
    for name, job in JOBS.items():
        for step in job.get("steps", []):
            body = step.get("run", "")
            assert not re.search(r"skipping\"?\s*\n\s*exit 0", body), f"{name}: a skip exits 0"


def test_dev_standards_own_copy_matches_the_template():
    assert OWN_COPY.read_bytes() == TEMPLATE.read_bytes()


# ─── yarn ────────────────────────────────────────────────────────────────────
# Yarn repos failed on every run: the audit step ran `npm audit`, which needs a
# package-lock.json. Each yarn flavour now runs its own audit, and the JSON it
# writes (not its exit code) decides between "found" and "could not run".
# The report lines below are real output, captured 2026-10-05 from yarn 4.18.1
# (`yarn npm audit --all --recursive --json`) and yarn 1.22.22
# (`yarn audit --json`) against lodash@4.17.20 / minimist@1.2.5.

BERRY_LOCK = "# This file is generated by running \"yarn install\" inside your project.\n\n__metadata:\n  version: 10\n  cacheKey: 10c0\n"
CLASSIC_LOCK = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n"
BERRY_HIGH = ('{"value":"lodash","children":{"ID":1106913,"Issue":"Command Injection in lodash",'
              '"URL":"https://github.com/advisories/GHSA-35jh-r3h4-6jhm","Severity":"high",'
              '"Vulnerable Versions":"<4.17.21","Tree Versions":["4.17.20"],"Dependents":["t@workspace:."]}}')
BERRY_MODERATE = BERRY_HIGH.replace('"Severity":"high"', '"Severity":"moderate"')
CLASSIC_SUMMARY = ('{"type":"auditSummary","data":{"vulnerabilities":{"info":0,"low":0,"moderate":%d,"high":%d,'
                   '"critical":0},"dependencies":1,"devDependencies":0,"optionalDependencies":0,"totalDependencies":1}}')


def npm_step(name_prefix: str) -> str:
    [s] = [s for s in JOBS["npm-audit"]["steps"] if s.get("name", "").startswith(name_prefix)]
    return s["run"]


def run_yarn(tmp_path: Path, shim_path: str, lock: str, out: str, rc: int, step: str = "Audit"):
    work = tmp_path / "work"
    work.mkdir()
    (work / "package.json").write_text("{}", encoding="utf-8")
    (work / "yarn.lock").write_text(lock, encoding="utf-8", newline="\n")
    (tmp_path / "yarn-out.txt").write_text(out, encoding="utf-8", newline="\n")
    bindir = tmp_path / "bin"  # the shim_path fixture's directory, first on PATH
    for name, body in {
        "yarn": f'echo "$*" >> "{(tmp_path / "yarn-calls").as_posix()}"\ncat "{(tmp_path / "yarn-out.txt").as_posix()}"\nexit {rc}\n',
        "corepack": f'echo "$*" >> "{(tmp_path / "corepack-calls").as_posix()}"\nexit 0\n',
        "npm": 'echo "npm must not run for a yarn repo: $*" >&2; exit 97\n',
    }.items():
        p = bindir / name
        p.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
        p.chmod(0o755)
    proc = subprocess.run([BASH, "-c", npm_step(step)], cwd=work, capture_output=True, text=True,
                          env={**os.environ, "PATH": shim_path})
    proc.calls = (tmp_path / "yarn-calls").read_text(encoding="utf-8") if (tmp_path / "yarn-calls").exists() else ""
    proc.corepack = (tmp_path / "corepack-calls").read_text(encoding="utf-8") if (tmp_path / "corepack-calls").exists() else ""
    return proc


def test_berry_high_finding_fails(tmp_path, shim_path):
    proc = run_yarn(tmp_path, shim_path, BERRY_LOCK, BERRY_HIGH + "\n" + BERRY_MODERATE + "\n", 1)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "npm audit --all --recursive --json" in proc.calls
    assert "found 1 high and 0 critical" in proc.stdout


def test_berry_moderate_only_passes(tmp_path, shim_path):
    proc = run_yarn(tmp_path, shim_path, BERRY_LOCK, BERRY_MODERATE + "\n", 1)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "moderate=1" in proc.stdout


def test_berry_clean_passes(tmp_path, shim_path):
    proc = run_yarn(tmp_path, shim_path, BERRY_LOCK, "", 0)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.parametrize("out", ["", "Internal Error: request to http://127.0.0.1:9 failed\n"])
def test_berry_that_could_not_audit_is_not_clean(tmp_path, shim_path, out):
    proc = run_yarn(tmp_path, shim_path, BERRY_LOCK, out, 1)
    assert proc.returncode == 1
    assert "could not run" in proc.stdout and "nothing was audited" in proc.stdout


@pytest.mark.parametrize("moderate,high,rc,ok", [(3, 2, 12, False), (3, 0, 4, True)])
def test_classic_gates_on_high(tmp_path, shim_path, moderate, high, rc, ok):
    proc = run_yarn(tmp_path, shim_path, CLASSIC_LOCK, CLASSIC_SUMMARY % (moderate, high) + "\n", rc)
    assert proc.calls.startswith("audit --json")
    assert (proc.returncode == 0) is ok, proc.stdout + proc.stderr
    if not ok:
        assert f"found {high} high" in proc.stdout


def test_classic_without_summary_is_not_clean(tmp_path, shim_path):
    # Real yarn 1 on an unreachable registry: exit 1, info lines, no summary.
    out = '{"type":"info","data":"No lockfile found."}\n{"type":"warning","data":"package.json: No license field"}\n'
    proc = run_yarn(tmp_path, shim_path, CLASSIC_LOCK, out, 1)
    assert proc.returncode == 1
    assert "no audit summary" in proc.stdout


def test_classic_exit_code_must_match_the_summary(tmp_path, shim_path):
    # Exit 1 is the INFO bit, but also what yarn 1 returns on an error.
    proc = run_yarn(tmp_path, shim_path, CLASSIC_LOCK, CLASSIC_SUMMARY % (0, 0) + "\n", 1)
    assert proc.returncode == 1
    assert "does not match" in proc.stdout


@pytest.mark.parametrize("lock,want", [(BERRY_LOCK, "yarn@4.18.1"), (CLASSIC_LOCK, "yarn@1.22.22")])
def test_install_picks_the_yarn_that_wrote_the_lockfile(tmp_path, shim_path, lock, want):
    proc = run_yarn(tmp_path, shim_path, lock, "", 0, step="Install")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"prepare {want} --activate" in proc.corepack
    assert ("--mode=skip-build" if want == "yarn@4.18.1" else "--ignore-scripts") in proc.calls


def test_install_refuses_an_unknown_yarn_lockfile(tmp_path, shim_path):
    proc = run_yarn(tmp_path, shim_path, "garbage\n", "", 0, step="Install")
    assert proc.returncode == 1
    assert "neither a yarn berry nor a yarn v1 lockfile" in proc.stdout
