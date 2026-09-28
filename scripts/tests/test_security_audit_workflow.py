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

def run_summary(tmp_path: Path, shim_path: str, *, detect: str = "success",
                npm=("false", "skipped"), go=("false", "skipped"), py=("false", "skipped")):
    values = {
        "needs.detect.result": detect,
        "needs.detect.outputs.has_npm": npm[0], "needs.npm-audit.result": npm[1],
        "needs.detect.outputs.has_go": go[0], "needs.go-vulncheck.result": go[1],
        "needs.detect.outputs.has_python": py[0], "needs.pip-audit.result": py[1],
        "needs.detect.outputs.npm_dirs": "[]", "needs.detect.outputs.go_dirs": "[]",
        "needs.detect.outputs.python_dirs": "[]",
    }
    script = step_run("summary")
    unknown = set(re.findall(r"\$\{\{\s*([^}]+?)\s*\}\}", script)) - set(values)
    assert not unknown, f"summary uses expressions this test does not model: {unknown}"
    script = re.sub(r"\$\{\{\s*([^}]+?)\s*\}\}", lambda m: values[m.group(1)], script)
    summ = tmp_path / "summary.md"
    return subprocess.run([BASH, "-c", script], cwd=tmp_path,
                          env={**os.environ, "PATH": shim_path, "GITHUB_STEP_SUMMARY": summ.as_posix()},
                          capture_output=True, text=True)


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
