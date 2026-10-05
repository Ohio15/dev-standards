"""dep-auto-apply.yml (Layer B): a test failure must reach the broken-PR path,
and a scanner that could not run must never read as "no changes".

Security gate 2026-10-05 (SC-07/SC-03/SC-04, MEDIUM):
- the npm/go/python steps wrote `tests_failed=true` and `exit 0` BEFORE writing
  `changed`, so `any_changed` stayed false, the run logged "No dependency
  changes", and the draft "broken" PR could never open;
- `govulncheck -json ... || true` / `pip-audit --fix ... || true` turned a
  scanner that could not run into `changed=false`;
- detection looked at the repo root only.

These tests run the SHIPPED `run:` blocks from
templates/.github/workflows/dep-auto-apply.yml under bash, inside throwaway
git repos, with the package managers and scanners replaced by shims on PATH
(this is a test file: the shims model the real tools' exit codes and report
shapes, which were probed against npm 11.7, pnpm 10.30, govulncheck 1.8.0 and
pip-audit 2.10.1 when this was written). No network.

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
TEMPLATE = ROOT / "templates" / ".github" / "workflows" / "dep-auto-apply.yml"
OWN_COPY = ROOT / ".github" / "workflows" / "dep-auto-apply.yml"
AUDIT_TEMPLATE = ROOT / "templates" / ".github" / "workflows" / "security-audit.yml"


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
STEPS = WORKFLOW["jobs"]["apply"]["steps"]
EXPR = re.compile(r"^\$\{\{\s*([^}]+?)\s*\}\}$")


def step(step_id: str) -> dict:
    [s] = [s for s in STEPS if s.get("id") == step_id]
    return s


def bash_path(p: Path) -> str:
    posix = p.resolve().as_posix()
    m = re.match(r"^([A-Za-z]):/(.*)$", posix)
    return f"/{m.group(1).lower()}/{m.group(2)}" if m else posix


# ─── shims ───────────────────────────────────────────────────────────────────
# Behaviour is chosen per test through FAKE_* environment variables.

SHIMS = {
    "corepack": "exit 0\n",
    "npm": r'''
case "$1" in
  ci) exit 0 ;;
  audit)
    case "${FAKE_NPM_FIX:-noop}" in
      error) printf '{"error":{"code":"ECONNREFUSED","summary":"no registry"}}\n'; exit 1 ;;
      bump) echo "bumped" >> package-lock.json ;;
    esac
    printf '{"added":0,"audit":{"auditReportVersion":2,"vulnerabilities":{},"metadata":{}}}\n'; exit 0 ;;
  test) exit "${FAKE_NPM_TEST_RC:-0}" ;;
esac
echo "npm shim: unexpected $*" >&2; exit 99
''',
    "pnpm": r'''
case "$1" in
  install) exit 0 ;;
  audit)
    case "${FAKE_PNPM_AUDIT:-clean}" in
      error) printf '{"error":{"code":"ECONNREFUSED","message":"no registry"}}\n'; exit 1 ;;
      vulns) printf '{"actions":[],"advisories":{"1":{"module_name":"lodash"}},"muted":[],"metadata":{}}\n'; exit 1 ;;
    esac
    printf '{"actions":[],"advisories":{},"muted":[],"metadata":{}}\n'; exit 0 ;;
  update) echo "updated $*" >> pnpm-lock.yaml; exit "${FAKE_PNPM_UPDATE_RC:-0}" ;;
  test) exit "${FAKE_PNPM_TEST_RC:-0}" ;;
esac
echo "pnpm shim: unexpected $*" >&2; exit 99
''',
    "govulncheck": r'''
case "${FAKE_GOV:-clean}" in
  error) echo "govulncheck: creating client: unreachable" >&2; exit 1 ;;
  module) printf '{"config":{}}\n{"finding":{"osv":"GO-1","trace":[{"module":"golang.org/x/text","version":"v0.3.5"}]}}\n' ;;
  stdlib) printf '{"finding":{"osv":"GO-2","trace":[{"module":"stdlib","version":"v1.22.0"}]}}\n' ;;
  *) printf '{"config":{}}\n' ;;
esac
exit 0
''',
    "go": r'''
case "$1" in
  get) echo "// bumped $*" >> go.mod; exit 0 ;;
  mod) exit 0 ;;
  build) exit "${FAKE_GO_BUILD_RC:-0}" ;;
  test) exit "${FAKE_GO_TEST_RC:-0}" ;;
esac
echo "go shim: unexpected $*" >&2; exit 99
''',
    "pip-audit": r'''
out=""; req=""
while [ $# -gt 0 ]; do
  case "$1" in --output) out=$2; shift ;; -r) req=$2; shift ;; esac
  shift
done
case "${FAKE_PA:-clean}" in
  error) echo "ERROR: Failed to install packages" >&2; exit 1 ;;
  bump) sed -i 's/requests==2.31.0/requests==2.33.0/' "$req"
        printf '{"dependencies":[],"fixes":[{"name":"requests"}]}' > "$out"; exit 0 ;;
esac
printf '{"dependencies":[],"fixes":[]}' > "$out"; exit 0
''',
}


@pytest.fixture
def shim_path(tmp_path: Path) -> str:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = Path(sys.executable).as_posix()
    bodies = dict(SHIMS)
    bodies["python3"] = f'exec "{exe}" "$@"\n'
    # The python step installs bumped pins and runs pytest through `python -m`;
    # both are modelled, everything else is the real interpreter.
    bodies["python"] = (
        'if [ "$1" = "-m" ] && [ "$2" = "pip" ]; then exit "${FAKE_PIP_RC:-0}"; fi\n'
        'if [ "$1" = "-m" ] && [ "$2" = "pytest" ]; then exit "${FAKE_PYTEST_RC:-5}"; fi\n'
        f'exec "{exe}" "$@"\n'
    )
    for name, body in bodies.items():
        p = bindir / name
        p.write_text("#!/usr/bin/env bash\n" + body.lstrip("\n"), encoding="utf-8", newline="\n")
        p.chmod(0o755)
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
    subprocess.run(["git", "-C", str(repo), "add", "-f", "--", *files], check=True)
    return repo


def parse_outputs(text: str) -> dict[str, str]:
    """$GITHUB_OUTPUT: `k=v` lines and `k<<DELIM ... DELIM` blocks, in order."""
    out: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*)<<(.+)$", line)
        if m:
            name, delim, body = m.group(1), m.group(2), []
            i += 1
            while lines[i] != delim:
                body.append(lines[i])
                i += 1
            out[name] = "\n".join(body)
        elif "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
        i += 1
    return out


def run_step(step_id: str, cwd: Path, shim_path: str, env_values: dict[str, str], **fake: str):
    """Run a step as Actions would: its `env:` expressions are evaluated from
    env_values, and the script sees only environment variables."""
    s = step(step_id)
    env = {}
    for name, expr in s.get("env", {}).items():
        m = EXPR.match(str(expr))
        assert m and m.group(1) in env_values, f"{step_id} env {name} uses an expression this test does not model: {expr}"
        env[name] = env_values[m.group(1)]
    gh_out = cwd.parent / f"out-{step_id}"
    gh_out.write_text("", encoding="utf-8")
    summary = cwd.parent / f"summary-{step_id}"
    proc = subprocess.run(
        [BASH, "-c", s["run"]], cwd=cwd, capture_output=True, text=True,
        env={**os.environ, **env, **fake, "PATH": shim_path,
             "GITHUB_OUTPUT": gh_out.as_posix(), "GITHUB_STEP_SUMMARY": summary.as_posix()},
    )
    raw = gh_out.read_text(encoding="utf-8")
    proc.outputs = parse_outputs(raw)
    proc.raw_outputs = raw
    proc.summary = summary.read_text(encoding="utf-8") if summary.exists() else ""
    return proc


def run_agg(tmp_path: Path, shim_path: str, **outs: str):
    values = {f"steps.{eco}.outputs.{k}": "" for eco in ("npm", "go", "python")
              for k in ("changed", "tests_failed", "tests", "notes")}
    values.update({f"steps.{k.replace('__', '.outputs.')}": v for k, v in outs.items()})
    work = tmp_path / "agg"
    work.mkdir()
    return run_step("agg", work, shim_path, values)


PKG = '{"name":"t","version":"1.0.0","scripts":{"test":"node test.js"}}'
PKG_NO_TEST = '{"name":"t","version":"1.0.0"}'


def npm_values(dirs: str) -> dict[str, str]:
    return {"steps.detect.outputs.npm_dirs": dirs}


# ─── the reported defect: a test failure must open the broken PR ─────────────

def test_npm_test_failure_reaches_the_broken_pr_path(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"package.json": PKG, "package-lock.json": "{}\n"})
    proc = run_step("npm", repo, shim_path, npm_values('["."]'), FAKE_NPM_FIX="bump", FAKE_NPM_TEST_RC="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.outputs["changed"] == "true"
    assert proc.outputs["tests_failed"] == "true"
    assert proc.outputs["tests"] == "failed"
    # `changed` is on record before the tests run.
    assert proc.raw_outputs.index("changed<<") < proc.raw_outputs.index("tests_failed<<")

    agg = run_agg(tmp_path, shim_path, npm__changed="true", npm__tests_failed="true", npm__tests="failed")
    assert agg.returncode == 0, agg.stdout + agg.stderr
    assert agg.outputs["any_changed"] == "true"
    assert agg.outputs["tests_failed"] == "true"
    assert "No dependency changes" not in agg.stdout


def test_broken_pr_step_is_gated_on_the_aggregate():
    broken = [s for s in STEPS if s.get("id") == "pr_broken"][0]["if"]
    ok = [s for s in STEPS if s.get("id") == "pr_ok"][0]["if"]
    assert "steps.agg.outputs.any_changed == 'true'" in broken
    assert "steps.agg.outputs.tests_failed == 'true'" in broken
    assert "steps.agg.outputs.tests_failed != 'true'" in ok


def test_a_test_failure_alone_still_counts_as_a_change(tmp_path, shim_path):
    agg = run_agg(tmp_path, shim_path, go__tests_failed="true")
    assert agg.outputs["any_changed"] == "true"


def test_no_change_is_reported_with_the_declined_count(tmp_path, shim_path):
    agg = run_agg(tmp_path, shim_path, npm__changed="false",
                  npm__notes="declined web: yarn lockfile (yarn 4 has no safe 'audit fix' equivalent)")
    assert agg.outputs["any_changed"] == "false"
    assert "1 manifest location(s) declined" in agg.stdout
    assert "declined web: yarn lockfile" in agg.summary


def test_npm_tests_pass_opens_the_normal_pr(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"package.json": PKG, "package-lock.json": "{}\n"})
    proc = run_step("npm", repo, shim_path, npm_values('["."]'), FAKE_NPM_FIX="bump")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.outputs["changed"] == "true"
    assert proc.outputs["tests_failed"] == "false"
    assert proc.outputs["tests"] == "passed"


def test_no_test_script_is_not_run_not_passed(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"package.json": PKG_NO_TEST, "package-lock.json": "{}\n"})
    proc = run_step("npm", repo, shim_path, npm_values('["."]'), FAKE_NPM_FIX="bump")
    assert proc.outputs["tests"] == "not_run"


# ─── a scanner that could not run is never "no changes" ──────────────────────

def test_npm_audit_fix_error_fails_the_step(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"package.json": PKG, "package-lock.json": "{}\n"})
    proc = run_step("npm", repo, shim_path, npm_values('["."]'), FAKE_NPM_FIX="error")
    assert proc.returncode != 0
    assert "::error::npm: npm audit fix could not examine ." in proc.stdout
    assert "changed" not in proc.outputs


def test_pnpm_audit_error_is_not_mistaken_for_findings(tmp_path, shim_path):
    # pnpm exits 1 for both; only the report shape separates them.
    repo = git_repo(tmp_path, {"package.json": PKG, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"})
    proc = run_step("npm", repo, shim_path, npm_values('["."]'), FAKE_PNPM_AUDIT="error")
    assert proc.returncode != 0
    assert "pnpm audit could not examine" in proc.stdout


def test_pnpm_findings_are_updated(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"package.json": PKG, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"})
    proc = run_step("npm", repo, shim_path, npm_values('["."]'), FAKE_PNPM_AUDIT="vulns")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.outputs["changed"] == "true"
    assert "updated update lodash" in (repo / "pnpm-lock.yaml").read_text(encoding="utf-8")


def test_pnpm_update_failure_fails_the_step(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"package.json": PKG, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"})
    proc = run_step("npm", repo, shim_path, npm_values('["."]'), FAKE_PNPM_AUDIT="vulns", FAKE_PNPM_UPDATE_RC="1")
    assert proc.returncode != 0


def test_govulncheck_error_fails_the_step(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"go.mod": "module example.com/t\n\ngo 1.22\n"})
    proc = run_step("go", repo, shim_path, {"steps.detect.outputs.go_dirs": '["."]'}, FAKE_GOV="error")
    assert proc.returncode != 0
    assert "govulncheck could not examine ." in proc.stdout
    assert "changed" not in proc.outputs


def test_go_findings_are_bumped_and_a_test_failure_is_recorded(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"svc/go.mod": "module example.com/t\n\ngo 1.22\n", "svc/x_test.go": "package t\n"})
    proc = run_step("go", repo, shim_path, {"steps.detect.outputs.go_dirs": '["svc"]'},
                    FAKE_GOV="module", FAKE_GO_TEST_RC="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.outputs["changed"] == "true"
    assert proc.outputs["tests_failed"] == "true"


def test_go_stdlib_findings_are_declined_not_go_got(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"go.mod": "module example.com/t\n\ngo 1.22\n"})
    proc = run_step("go", repo, shim_path, {"steps.detect.outputs.go_dirs": '["."]'}, FAKE_GOV="stdlib")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.outputs["changed"] == "false"
    assert "declined .: vulnerable Go standard library" in proc.outputs["notes"]
    assert "::warning::go auto-apply declined" in proc.stdout


def test_pip_audit_that_could_not_run_fails_the_step(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"requirements.txt": "requests==2.31.0\n"})
    proc = run_step("python", repo, shim_path, {"steps.detect.outputs.python_dirs": '["."]'}, FAKE_PA="error")
    assert proc.returncode != 0
    assert "pip-audit could not examine" in proc.stdout
    assert "changed" not in proc.outputs


def test_pip_audit_fix_is_applied(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"api/requirements.txt": "requests==2.31.0\n"})
    proc = run_step("python", repo, shim_path, {"steps.detect.outputs.python_dirs": '["api"]'}, FAKE_PA="bump")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.outputs["changed"] == "true"
    assert proc.outputs["tests"] == "not_run"  # pytest exit 5: nothing collected


def test_pip_bumped_pins_that_do_not_install_are_broken(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"requirements.txt": "requests==2.31.0\n"})
    proc = run_step("python", repo, shim_path, {"steps.detect.outputs.python_dirs": '["."]'},
                    FAKE_PA="bump", FAKE_PIP_RC="1")
    assert proc.outputs["changed"] == "true"
    assert proc.outputs["tests_failed"] == "true"


def test_python_policy_skips_are_declined_and_said(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"lib/pyproject.toml": "[project]\nname='x'\n", "requirements.txt": "requests\n"})
    proc = run_step("python", repo, shim_path, {"steps.detect.outputs.python_dirs": '[".", "lib"]'})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.outputs["changed"] == "false"
    assert "declined ./requirements.txt: unpinned lines present" in proc.outputs["notes"]
    assert "declined lib: pyproject.toml only" in proc.outputs["notes"]


# ─── multi-manifest: subdirectories, workspaces, lockfile-less ───────────────

def test_npm_subdirectory_and_workspace_member(tmp_path, shim_path):
    repo = git_repo(tmp_path, {
        "web/package.json": PKG, "web/package-lock.json": "{}\n",
        "web/packages/a/package.json": PKG_NO_TEST,     # member: fixed via web's lockfile
        "tools/package.json": PKG_NO_TEST,               # no lockfile anywhere above
    })
    proc = run_step("npm", repo, shim_path, npm_values('["tools", "web", "web/packages/a"]'), FAKE_NPM_FIX="bump")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.outputs["changed"] == "true"
    notes = proc.outputs["notes"]
    assert "bumped web" in notes
    assert "declined tools: no lockfile" in notes
    assert "web/packages/a" not in notes, "a workspace member is covered by its root, not declined"
    assert not (repo / "web/packages/a/package-lock.json").exists()


def test_yarn_is_declined_and_said(tmp_path, shim_path):
    repo = git_repo(tmp_path, {"package.json": PKG, "yarn.lock": "# yarn\n"})
    proc = run_step("npm", repo, shim_path, npm_values('["."]'))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "declined .: yarn lockfile" in proc.outputs["notes"]
    assert "::warning::npm auto-apply declined" in proc.stdout


def test_detect_matches_security_audit(tmp_path, shim_path):
    detect = step("detect")["run"]
    audit = yaml.safe_load(AUDIT_TEMPLATE.read_text(encoding="utf-8"))
    [audit_detect] = [s["run"] for s in audit["jobs"]["detect"]["steps"] if s.get("id") == "detect"]
    for spec in ("npm_dirs=$(dirs_of 'package.json' '**/package.json')",
                 "go_dirs=$(dirs_of 'go.mod' '**/go.mod')",
                 "python_dirs=$(dirs_of 'pyproject.toml' '**/pyproject.toml' 'requirements*.txt' '**/requirements*.txt')"):
        assert spec in detect and spec in audit_detect

    repo = git_repo(tmp_path, {
        "console/package.json": "{}", "console/clis/package.json": "{}",
        "svc/go.mod": "module x\n", "api/requirements-dev.txt": "x==1\n",
        "node_modules/dep/package.json": "{}", ".github/workflows/ci.yml": "on: push\n",
        "deploy/Dockerfile": "FROM x\n",
    })
    out = tmp_path / "gh_out"
    out.write_text("", encoding="utf-8")
    proc = subprocess.run([BASH, "-c", detect], cwd=repo, capture_output=True, text=True,
                          env={**os.environ, "PATH": shim_path, "GITHUB_OUTPUT": out.as_posix()})
    assert proc.returncode == 0, proc.stderr
    o = parse_outputs(out.read_text(encoding="utf-8"))
    assert o["npm_dirs"] == '["console", "console/clis"]'
    assert o["go_dirs"] == '["svc"]' and o["go_version_file"] == "svc/go.mod"
    assert o["python_dirs"] == '["api"]'
    assert o["has_docker"] == "true" and o["has_actions"] == "true"


# ─── structure ───────────────────────────────────────────────────────────────

def test_no_expression_is_pasted_into_any_run_body():
    offenders = [s.get("name") or s.get("id") for s in STEPS if "${{" in s.get("run", "")]
    assert offenders == [], "values must reach run: through env, never ${{ }}: " + ", ".join(offenders)


def test_no_scanner_error_is_swallowed():
    body = "\n".join(s.get("run", "") for s in STEPS)
    for pattern in (r"govulncheck[^\n]*\|\|\s*true", r"pip-audit[^\n]*\|\|\s*true",
                    r"pnpm update[^\n]*\|\|\s*true", r"go get[^\n]*\|\|\s*true"):
        assert not re.search(pattern, body), pattern


@pytest.mark.parametrize("path", [TEMPLATE, AUDIT_TEMPLATE])
def test_no_floating_tool_versions(path):
    code = [ln for ln in path.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#")]
    offenders = [ln.strip() for ln in code if re.search(r"@(latest|stable)\b", ln)]
    assert offenders == [], f"{path.name} installs a floating tool version: {offenders}"


@pytest.mark.parametrize("path", [TEMPLATE, AUDIT_TEMPLATE])
def test_checkouts_do_not_persist_the_token(path):
    wf = yaml.safe_load(path.read_text(encoding="utf-8"))
    for name, job in wf["jobs"].items():
        for s in job["steps"]:
            if str(s.get("uses", "")).startswith("actions/checkout@"):
                assert s.get("with", {}).get("persist-credentials") is False, f"{path.name}:{name}"


def test_ntfy_is_opt_in_and_never_the_public_topic():
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "ntfy.sh/nexus-alerts" not in text
    [notify] = [s for s in STEPS if "ntfy" in (s.get("name") or "").lower()]
    assert "vars.DEP_AUTO_APPLY_NTFY_URL != ''" in notify["if"]


def test_dev_standards_own_copy_matches_the_template():
    assert OWN_COPY.read_bytes() == TEMPLATE.read_bytes()
