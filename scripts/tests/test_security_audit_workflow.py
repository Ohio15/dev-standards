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
    # Trusted: these cases are about which yarn runs and how its report is
    # read; the untrusted (pull_request) install has its own tests below.
    proc = subprocess.run([BASH, "-c", npm_step(step)], cwd=work, capture_output=True, text=True,
                          env={**os.environ, "PATH": shim_path, "TRUSTED_EVENT": "true"})
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


# ─── runner and trust (audit-dev-standards-2026-10-10 HIGH 3; SC-37, SC-13) ──
# A repo variable may choose the runner only on a trusted event, and on an
# untrusted one (pull_request) no PR-controlled code runs. The runs-on
# expression is EVALUATED here with Actions' operand-returning &&/|| rules,
# for every job a pull_request reaches, with CI_RUNNER set to a self-hosted
# label: none may resolve to it.

import json

SIZE_GUARD_COPIES = [ROOT / "workflows" / "size-guard.yml", ROOT / ".github" / "workflows" / "size-guard.yml"]


def triggers(wf: dict) -> set[str]:
    on = wf.get("on", wf.get(True))  # PyYAML reads a bare `on:` key as True
    if isinstance(on, str):
        return {on}
    return set(on or [])


def _pr_workflows() -> list[Path]:
    """Every workflow a pull_request can start, wherever the repo keeps one."""
    found = []
    for d in (ROOT / ".github" / "workflows", ROOT / "workflows", ROOT / "templates" / ".github" / "workflows"):
        for f in sorted([*d.glob("*.yml"), *d.glob("*.yaml")]):
            if "pull_request" in triggers(yaml.safe_load(f.read_text(encoding="utf-8"))):
                found.append(f)
    return found


PR_WORKFLOWS = _pr_workflows()


# A small evaluator for the expression subset runs-on may use: string
# literals, dotted context lookups, ==, &&, ||, !, parentheses, format().
# &&/|| return an operand, as in Actions; == compares case-insensitively.
_TOK = re.compile(r"\s*(?:(\|\||&&|==|!=|[()!,])|'((?:[^']|'')*)'|([A-Za-z_][\w.\-]*))")


def eval_expr(text: str, ctx: dict):
    toks, pos = [], 0
    while pos < len(text.rstrip()):
        m = _TOK.match(text, pos)
        assert m and m.end() > pos, f"cannot parse {text[pos:]!r}"
        toks.append(("op", m.group(1)) if m.group(1) else ("str", m.group(2).replace("''", "'"))
                    if m.group(2) is not None else ("id", m.group(3)))
        pos = m.end()
    i = 0

    def peek():
        return toks[i] if i < len(toks) else (None, None)

    def take():
        nonlocal i
        i += 1
        return toks[i - 1]

    def primary():
        kind, val = take()
        if (kind, val) == ("op", "("):
            v = or_()
            assert take() == ("op", ")")
            return v
        if (kind, val) == ("op", "!"):
            return not primary()
        if kind == "str":
            return val
        assert kind == "id", (kind, val)
        if val in ("true", "false"):
            return val == "true"
        if peek() == ("op", "("):
            take()
            args = [or_()]
            while peek() == ("op", ","):
                take()
                args.append(or_())
            assert take() == ("op", ")")
            assert val == "format", f"function {val} not modelled"
            return re.sub(r"\{(\d+)\}", lambda mm: str(args[1 + int(mm.group(1))]), args[0])
        assert val in ctx, f"context {val} not modelled"
        return ctx[val]

    def cmp_():
        v = primary()
        while peek() in (("op", "=="), ("op", "!=")):
            op = take()[1]
            r = primary()
            eq = str(v).lower() == str(r).lower()
            v = eq if op == "==" else not eq
        return v

    def and_():
        v = cmp_()
        while peek() == ("op", "&&"):
            take()
            r = cmp_()
            v = r if v else v
        return v

    def or_():
        v = and_()
        while peek() == ("op", "||"):
            take()
            r = and_()
            v = v if v else r
        return v

    out = or_()
    assert i == len(toks), f"trailing tokens in {text!r}"
    return out


def resolve(expr, event: str, ref: str, ci_runner: str = "nexus-ci"):
    if not isinstance(expr, str) or "${{" not in expr:
        return expr
    m = re.fullmatch(r"\$\{\{(.*)\}\}", expr.strip(), re.S)
    assert m, expr
    return eval_expr(m.group(1), {
        "github.event_name": event, "github.ref": ref,
        "github.event.repository.default_branch": "main", "vars.CI_RUNNER": ci_runner,
    })


UNTRUSTED = [("pull_request", "refs/pull/7/merge"), ("pull_request_target", "refs/heads/main"),
             ("merge_group", "refs/heads/gh-readonly-queue/main/pr-7"), ("release", "refs/tags/v1"),
             ("push", "refs/heads/feature"), ("push", "refs/heads/master"), ("push", "refs/tags/v1"),
             ("workflow_dispatch", "refs/heads/feature")]
TRUSTED = [("schedule", "refs/heads/main"), ("push", "refs/heads/main"), ("workflow_dispatch", "refs/heads/main")]


def test_the_pull_request_workflow_list_is_derived_not_listed():
    names = {p.relative_to(ROOT).as_posix() for p in PR_WORKFLOWS}
    assert {".github/workflows/security-audit.yml", "templates/.github/workflows/security-audit.yml",
            ".github/workflows/size-guard.yml", "workflows/size-guard.yml",
            ".github/workflows/healthcheck-shape-lint.yml"} <= names, names


@pytest.mark.parametrize("path", PR_WORKFLOWS, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_no_pull_request_job_resolves_its_runner_from_a_variable(path):
    wf = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert wf["jobs"], "no jobs parsed"
    for name, job in wf["jobs"].items():
        for event, ref in UNTRUSTED:
            got = resolve(job["runs-on"], event, ref)
            assert got == "ubuntu-latest", f"{path.name}:{name} on {event} {ref} runs on {got!r}"
        if "${{" in str(job["runs-on"]):
            for event, ref in TRUSTED:
                assert resolve(job["runs-on"], event, ref) == "nexus-ci", (name, event)
                assert resolve(job["runs-on"], event, ref, ci_runner="") == "ubuntu-latest"


def test_trusted_event_flag_is_the_runner_predicate():
    flag = WORKFLOW["env"]["TRUSTED_EVENT"]
    pred = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", flag, re.S).group(1)
    for name, job in JOBS.items():
        assert pred in job["runs-on"], f"{name}: runs-on and TRUSTED_EVENT disagree"
    for event, ref in UNTRUSTED:
        assert resolve(flag, event, ref) is False, (event, ref)
    for event, ref in TRUSTED:
        assert resolve(flag, event, ref) is True, (event, ref)


@pytest.mark.parametrize("path", PR_WORKFLOWS, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_least_privilege_token(path):
    wf = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert wf["permissions"] == {"contents": "read"}
    for name, job in wf["jobs"].items():
        assert "permissions" not in job, f"{name} widens the token"
    assert "security-events" not in path.read_text(encoding="utf-8")


def test_no_execute_switches_are_present():
    npm_env = JOBS["npm-audit"]["env"]
    assert npm_env["COREPACK_ENV_FILE"] == "0"
    assert npm_env["COREPACK_ENABLE_UNSAFE_CUSTOM_URLS"] == "0"
    assert npm_env["npm_config_ignore_scripts"] == "true"
    assert npm_env["npm_config_git"] == "git" and npm_env["npm_config_script_shell"] == "/bin/sh"
    install, audit = npm_step("Install"), npm_step("Audit")
    assert "pnpm install --frozen-lockfile --ignore-scripts --ignore-pnpmfile" in install
    assert "pnpmfileChecksum" in install
    pnpm_audits = [l for l in audit.splitlines() if re.match(r"\s*pnpm audit", l)]
    assert pnpm_audits and all("--config.ignore-pnpmfile=true" in l for l in pnpm_audits), pnpm_audits
    assert "export YARN_IGNORE_PATH=1" in install and "YARN_RC_FILENAME" in install
    assert "del(.yarnPath) | del(.plugins) | .enableScripts = false" in install
    [pip] = [st["run"] for st in JOBS["pip-audit"]["steps"] if st.get("name", "").startswith("Run pip-audit")]
    untrusted = pip.split('if [ "${TRUSTED_EVENT:-}" = "true" ]; then', 1)[1].split("exit 0\n", 1)[1]
    calls = re.findall(r"^\s*pip-audit .*$", untrusted, re.M)
    assert len(calls) == 2, calls
    for c in calls:
        assert "--locked" in c or ("--no-deps" in c and "--disable-pip" in c), c


def test_size_guard_copies_agree():
    a, b = (p.read_bytes() for p in SIZE_GUARD_COPIES)
    assert a == b


# ─── untrusted install paths, executed ───────────────────────────────────────

def run_install(tmp_path: Path, shim_path: str, files: dict[str, str], trusted: str):
    work = tmp_path / "work"
    work.mkdir()
    for rel, body in files.items():
        (work / rel).write_text(body, encoding="utf-8", newline="\n")
    bindir = tmp_path / "bin"
    log = (tmp_path / "calls").as_posix()
    for name in ("yarn", "pnpm", "corepack", "npm", "yq"):
        body = f'echo "{name} $* | IGNORE_PATH=${{YARN_IGNORE_PATH:-}} RC=${{YARN_RC_FILENAME:-}}" >> "{log}"\n'
        if name == "yq":
            body += 'echo "{}"\n'
        p = bindir / name
        p.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
        p.chmod(0o755)
    genv = tmp_path / "github_env"
    proc = subprocess.run([BASH, "-c", npm_step("Install")], cwd=work, capture_output=True, text=True,
                          env={**os.environ, "PATH": shim_path, "TRUSTED_EVENT": trusted, "DIR": ".",
                               "GITHUB_ENV": genv.as_posix(), "GITHUB_WORKSPACE": work.as_posix()})
    proc.calls = Path(log).read_text(encoding="utf-8") if Path(log).exists() else ""
    proc.genv = genv.read_text(encoding="utf-8") if genv.exists() else ""
    return proc


def test_untrusted_berry_reads_only_the_rewritten_rc(tmp_path, shim_path):
    proc = run_install(tmp_path, shim_path, {"package.json": "{}", "yarn.lock": BERRY_LOCK,
                                             ".yarnrc.yml": "yarnPath: ./evil.cjs\n"}, "false")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    [install] = [l for l in proc.calls.splitlines() if l.startswith("yarn install")]
    assert "IGNORE_PATH=1" in install and "RC=.yarnrc-audit-" in install
    assert "YARN_IGNORE_PATH=1" in proc.genv and "YARN_RC_FILENAME=.yarnrc-audit-" in proc.genv
    assert "yq -o=json explode(.) | del(.yarnPath) | del(.plugins)" in proc.calls


def test_trusted_berry_keeps_the_repo_rc(tmp_path, shim_path):
    proc = run_install(tmp_path, shim_path, {"package.json": "{}", "yarn.lock": BERRY_LOCK}, "true")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "yq" not in proc.calls and proc.genv == ""


def test_untrusted_pnpm_lockfile_written_with_a_pnpmfile_is_not_examined(tmp_path, shim_path):
    proc = run_install(tmp_path, shim_path, {"package.json": "{}",
                                             "pnpm-lock.yaml": "lockfileVersion: '9.0'\npnpmfileChecksum: sha256-x\n"},
                       "false")
    assert proc.returncode == 1
    assert "not examined" in proc.stdout
    assert "pnpm install" not in proc.calls


@pytest.mark.parametrize("trusted,flag", [("false", True), ("true", False), ("", True)])
def test_pnpm_ignores_the_pnpmfile_unless_trusted(tmp_path, shim_path, trusted, flag):
    proc = run_install(tmp_path, shim_path, {"package.json": "{}", "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"},
                       trusted)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert ("--ignore-pnpmfile" in proc.calls) is flag


@pytest.mark.skipif(shutil.which("yq") is None, reason="real yq not on PATH")
def test_real_yq_strips_smuggled_keys(tmp_path):
    rc = tmp_path / "rc.yml"
    rc.write_text('nodeLinker: &nl node-modules\n"yarnPath": ./evil.cjs\nplugins:\n  - path: ./evil.cjs\n',
                  encoding="utf-8")
    out = subprocess.run(["yq", "-o=json", "explode(.) | del(.yarnPath) | del(.plugins) | .enableScripts = false",
                          str(rc)], capture_output=True, text=True, check=True).stdout
    got = json.loads(out)
    assert "yarnPath" not in got and "plugins" not in got and got["enableScripts"] is False
