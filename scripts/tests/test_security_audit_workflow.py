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

import json
import atexit
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


def bash_argv(script: str) -> list[str]:
    """Run a step body the way Actions does: from a file (`bash {0}`), not
    `bash -c`. Git-bash on Windows truncates a -c argument near 8 KiB, which
    cut the detect script mid-heredoc."""
    fd, path = tempfile.mkstemp(suffix=".sh", prefix="step-")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(script)
    atexit.register(lambda: os.path.exists(path) and os.remove(path))
    return [BASH, "--noprofile", "--norc", path]


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
    proc = subprocess.run(bash_argv(step_run("detect", "detect")), cwd=repo, env=env,
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
    proc = subprocess.run(bash_argv(step_run("detect", "detect")), cwd=repo,
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
                dirs=("[]", "[]", "[]"), covered: str = "{}"):
    """Run the summary step the way Actions does: each `env:` entry's
    expression is evaluated, and the script sees only environment variables."""
    values = {
        "needs.detect.result": detect,
        "needs.detect.outputs.has_npm": npm[0], "needs.npm-audit.result": npm[1],
        "needs.detect.outputs.has_go": go[0], "needs.go-vulncheck.result": go[1],
        "needs.detect.outputs.has_python": py[0], "needs.pip-audit.result": py[1],
        "needs.detect.outputs.npm_dirs": dirs[0], "needs.detect.outputs.go_dirs": dirs[1],
        "needs.detect.outputs.python_dirs": dirs[2],
        "needs.detect.outputs.npm_covered": covered,
    }
    [step] = [s for s in JOBS["summary"]["steps"] if "run" in s]
    env = {}
    for name, expr in step.get("env", {}).items():
        m = EXPR.match(str(expr))
        assert m and m.group(1) in values, f"summary env {name} uses an expression this test does not model: {expr}"
        env[name] = values[m.group(1)]
    summ = tmp_path / "summary.md"
    proc = subprocess.run(bash_argv(step["run"]), cwd=tmp_path,
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


# ─── workspace members ───────────────────────────────────────────────────────
# openclaw-1 (shared-brain discovery 54c58aa3): 36 pnpm workspace members had
# no lockfile of their own, so each got its own job, ran `npm install` and
# failed on `workspace:*`. A member is audited once, by the root whose lockfile
# resolves it, and only when that is provable from tracked files.

PNPM_LOCK = """lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

  extensions/slack:
    dependencies:
      openclaw:
        specifier: workspace:*
        version: link:../..

  'packages/core':
    dependencies: {}

  ui: {}

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-x}
"""


def workspace_repo(extra: dict[str, str] | None = None, workspace: str | None = None,
                   lock: str = PNPM_LOCK) -> dict[str, str]:
    files = {
        "package.json": '{"name": "root"}',
        "pnpm-lock.yaml": lock,
        "pnpm-workspace.yaml": workspace if workspace is not None else
            "packages:\n  - .\n  - 'packages/*'   # quoted\n  - \"ui\"\n  - extensions/*\n\nonlyBuiltDependencies:\n  - esbuild\n",
        "extensions/slack/package.json": "{}",
        "packages/core/package.json": "{}",
        "ui/package.json": "{}",
    }
    files.update(extra or {})
    return files


def test_pnpm_workspace_members_fold_into_the_root(tmp_path, shim_path):
    proc, o = run_detect(tmp_path, shim_path, workspace_repo({
        # Vendored code with its own lockfile is its own job.
        "vendor/lib/package.json": "{}", "vendor/lib/package-lock.json": '{"packages": {}}',
        # Not a workspace member at all: keeps its job (and fails loudly there).
        "tools/script/package.json": "{}",
    }))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert o["npm_dirs"] == '[".", "tools/script", "vendor/lib"]'
    assert json.loads(o["npm_covered"]) == {"extensions/slack": ".", "packages/core": ".", "ui": "."}
    assert "::warning::" not in proc.stdout, proc.stdout


def test_a_member_the_lockfile_does_not_name_keeps_its_own_job(tmp_path, shim_path):
    proc, o = run_detect(tmp_path, shim_path, workspace_repo({"extensions/new/package.json": "{}"}))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "extensions/new" in json.loads(o["npm_dirs"])
    assert "extensions/new" not in json.loads(o["npm_covered"])
    assert "extensions/new matches the workspace globs of . but that lockfile has no entry" in proc.stdout


def test_a_negated_glob_excludes(tmp_path, shim_path):
    proc, o = run_detect(tmp_path, shim_path, workspace_repo(
        workspace="packages:\n  - 'packages/*'\n  - ui\n  - 'extensions/**'\n  - '!**/slack'\n"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(o["npm_dirs"]) == [".", "extensions/slack"]
    assert json.loads(o["npm_covered"]) == {"packages/core": ".", "ui": "."}


def test_flow_sequence_globs_are_read(tmp_path, shim_path):
    proc, o = run_detect(tmp_path, shim_path, workspace_repo(workspace="packages: [ui, 'extensions/*']\n"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(o["npm_covered"]) == {"extensions/slack": ".", "ui": "."}
    assert "packages/core" in json.loads(o["npm_dirs"])


@pytest.mark.parametrize("workspace", [
    "packages:\n  key: value\n",                 # a map, not a sequence
    "packages: 'ui'\n",                          # a scalar
    "packages:\n  - ui\n  - '!{a,b}/**'\n",      # an exclusion this parser cannot read
])
def test_unreadable_workspace_folds_nothing(tmp_path, shim_path, workspace):
    proc, o = run_detect(tmp_path, shim_path, workspace_repo(workspace=workspace))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(o["npm_covered"]) == {}
    assert json.loads(o["npm_dirs"]) == [".", "extensions/slack", "packages/core", "ui"]
    assert "::warning::workspace: pnpm-workspace.yaml could not be read" in proc.stdout


def test_a_settings_only_workspace_file_declares_no_members(tmp_path, shim_path):
    # vendor/a2ui eval dirs: pnpm-workspace.yaml holding only
    # onlyBuiltDependencies. Nothing to fold, and nothing to warn about.
    proc, o = run_detect(tmp_path, shim_path, workspace_repo(workspace="onlyBuiltDependencies:\n  - esbuild\n"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(o["npm_covered"]) == {}
    assert json.loads(o["npm_dirs"]) == [".", "extensions/slack", "packages/core", "ui"]
    assert "::warning::" not in proc.stdout


def test_pnpm_ignores_package_json_workspaces(tmp_path, shim_path):
    # pnpm reads only pnpm-workspace.yaml; a `workspaces` field beside a
    # pnpm-lock.yaml declares nothing pnpm installs.
    files = workspace_repo()
    del files["pnpm-workspace.yaml"]
    files["package.json"] = '{"name": "root", "workspaces": ["ui", "extensions/*", "packages/*"]}'
    proc, o = run_detect(tmp_path, shim_path, files)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(o["npm_covered"]) == {}


def test_a_member_with_its_own_lockfile_is_its_own_job(tmp_path, shim_path):
    proc, o = run_detect(tmp_path, shim_path, workspace_repo({"ui/package-lock.json": '{"packages": {}}'}))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ui" in json.loads(o["npm_dirs"]) and "ui" not in json.loads(o["npm_covered"])


def test_untracked_workspace_file_declares_nothing(tmp_path, shim_path):
    files = workspace_repo()
    body = files.pop("pnpm-workspace.yaml")
    repo = git_repo(tmp_path, files)
    (repo / "pnpm-workspace.yaml").write_text(body, encoding="utf-8")
    out = tmp_path / "o"
    out.write_text("", encoding="utf-8")
    proc = subprocess.run(bash_argv(step_run("detect", "detect")), cwd=repo,
                          env={**os.environ, "PATH": shim_path, "GITHUB_OUTPUT": out.as_posix()},
                          capture_output=True, text=True)
    o = dict(line.split("=", 1) for line in out.read_text(encoding="utf-8").splitlines() if "=" in line)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(o["npm_covered"]) == {}


def test_npm_workspaces_fold_through_package_lock(tmp_path, shim_path):
    lock = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"workspaces": ["apps/*"]}, "apps/web": {"name": "web"}, "node_modules/web": {"link": True}}})
    proc, o = run_detect(tmp_path, shim_path, {
        "package.json": '{"workspaces": {"packages": ["apps/*"]}}', "package-lock.json": lock,
        "apps/web/package.json": "{}", "apps/cli/package.json": "{}",
    })
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(o["npm_covered"]) == {"apps/web": "."}
    assert json.loads(o["npm_dirs"]) == [".", "apps/cli"]
    assert "apps/cli matches the workspace globs of . but that lockfile has no entry" in proc.stdout


def test_yarn_berry_workspaces_need_a_workspace_locator(tmp_path, shim_path):
    lock = BERRY_LOCK + '\n"web@workspace:apps/web":\n  version: 0.0.0-use.local\n'
    proc, o = run_detect(tmp_path, shim_path, {
        "package.json": '{"workspaces": ["apps/*"]}', "yarn.lock": lock,
        "apps/web/package.json": "{}", "apps/webx/package.json": "{}",
    })
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(o["npm_covered"]) == {"apps/web": "."}
    assert json.loads(o["npm_dirs"]) == [".", "apps/webx"]


def test_the_nearest_declaring_root_covers_a_member(tmp_path, shim_path):
    inner_lock = "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  pkg/a: {}\n"
    proc, o = run_detect(tmp_path, shim_path, workspace_repo({
        "extensions/slack/pnpm-workspace.yaml": "packages:\n  - 'pkg/*'\n",
        "extensions/slack/pnpm-lock.yaml": inner_lock,
        "extensions/slack/pkg/a/package.json": "{}",
    }, workspace="packages:\n  - 'extensions/**'\n"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    covered = json.loads(o["npm_covered"])
    assert covered["extensions/slack/pkg/a"] == "extensions/slack"
    assert "extensions/slack" in json.loads(o["npm_dirs"])  # it has its own lockfile


def test_summary_lists_each_member_and_its_root(tmp_path, shim_path):
    proc = run_summary(tmp_path, shim_path, npm=("true", "success"), dirs=('[".", "vendor/lib"]', "[]", "[]"),
                       covered='{"extensions/slack": ".", "ui": "."}')
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "| extensions/slack | . | success |" in proc.summary
    assert "| ui | . | success |" in proc.summary
    assert "npm workspace members covered through a root: 2" in proc.stdout


@pytest.mark.parametrize("result", ["failure", "skipped", "cancelled"])
def test_a_member_whose_root_did_not_succeed_fails(tmp_path, shim_path, result):
    proc = run_summary(tmp_path, shim_path, npm=("true", result), dirs=('["."]', "[]", "[]"),
                       covered='{"ui": "."}')
    assert proc.returncode == 1
    assert f'npm workspace member "ui" is covered by ".", whose audit result is "{result}"' in proc.stdout
    assert f"| ui | . | {result} |" in proc.summary


def test_a_member_credited_to_an_unaudited_root_is_not_examined(tmp_path, shim_path):
    proc = run_summary(tmp_path, shim_path, npm=("true", "success"), dirs=('["vendor/lib"]', "[]", "[]"),
                       covered='{"ui": "."}')
    assert proc.returncode == 1
    assert "which no npm audit job ran for" in proc.stdout
    assert "| ui | . | NOT EXAMINED |" in proc.summary


@pytest.mark.parametrize("covered", ["not json", '["ui"]'])
def test_a_malformed_coverage_list_fails(tmp_path, shim_path, covered):
    proc = run_summary(tmp_path, shim_path, npm=("true", "success"), dirs=('["."]', "[]", "[]"), covered=covered)
    assert proc.returncode == 1
    assert "workspace coverage list from detect" in proc.stdout


def test_detect_publishes_the_coverage_list_to_the_summary():
    assert JOBS["detect"]["outputs"]["npm_covered"] == "${{ steps.detect.outputs.npm_covered }}"
    [step] = [s for s in JOBS["summary"]["steps"] if "run" in s]
    assert step["env"]["NPM_COVERED"] == "${{ needs.detect.outputs.npm_covered }}"


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
    proc = subprocess.run(bash_argv(step_run("detect", "detect")), cwd=repo,
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


RUNNER_PRED = ("${{ (github.event_name == 'push' || github.event_name == 'schedule' || "
               "github.event_name == 'workflow_dispatch' || github.event_name == 'release' || "
               "github.event_name == 'merge_group' || github.event_name == 'pull_request' && "
               "github.event.pull_request.head.repo.full_name == github.repository) && "
               "github.event.repository.private && vars.CI_RUNNER == 'nexus-ci' && 'nexus-ci' || 'ubuntu-latest' }}")


def hosted_variant(text: str) -> str:
    """What install.sh writes into a public repo for security-audit.yml and
    size-guard.yml, and what dev-standards (a public repo) runs for those two
    itself: every runs-on the hosted literal. dep-auto-apply.yml is NOT run
    through this here: dev-standards' own copy equals its template byte for
    byte and keeps the variable-guarded toggle on its three jobs, which is
    inert in a public repo and not pull_request-reachable (asserted below)."""
    return text.replace("runs-on: " + RUNNER_PRED, "runs-on: ubuntu-latest")


def test_own_dep_auto_apply_runner_is_guarded_and_not_pr_reachable():
    own = yaml.safe_load((ROOT / ".github" / "workflows" / "dep-auto-apply.yml").read_text(encoding="utf-8"))
    assert triggers(own) == {"schedule", "workflow_dispatch"}
    guarded = "${{ github.event.repository.private && vars.CI_RUNNER == 'nexus-ci' && 'nexus-ci' || 'ubuntu-latest' }}"
    for name, job in own["jobs"].items():
        assert job["runs-on"] == guarded, name
        assert resolve(job["runs-on"], "schedule", "refs/heads/main", private=False) == "ubuntu-latest"


def test_dev_standards_own_copy_matches_the_template():
    # This repo is public: its own copy is the template with the hosted literal
    # (audit 2026-10-27 LOW, SC-37: no variable-selected runner in a public repo).
    own = OWN_COPY.read_text(encoding="utf-8")
    assert own == hosted_variant(TEMPLATE.read_text(encoding="utf-8"))
    assert not re.search(r"runs-on:.*vars\.", own)


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
    proc = subprocess.run(bash_argv(npm_step(step)), cwd=work, capture_output=True, text=True,
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


def resolve(expr, event: str, ref: str, ci_runner: str = "nexus-ci", private: bool = True,
            head_repo: str = "o/r"):
    if not isinstance(expr, str) or "${{" not in expr:
        return expr
    m = re.fullmatch(r"\$\{\{(.*)\}\}", expr.strip(), re.S)
    assert m, expr
    return eval_expr(m.group(1), {
        "github.event_name": event, "github.ref": ref,
        "github.event.repository.default_branch": "main", "vars.CI_RUNNER": ci_runner,
        "github.event.repository.private": private, "github.repository": "o/r",
        "github.event.pull_request.head.repo.full_name": head_repo if event == "pull_request" else "",
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


# SC-37 allow-list (amended 2026-10-27) plus the visibility guard and literal
# toggle (audit-dev-standards-2026-10-27 MEDIUM): nexus-ci only for an
# allow-listed event in a PRIVATE repo with CI_RUNNER exactly 'nexus-ci'.
ALLOWED_EVENTS = ["push", "schedule", "workflow_dispatch", "release", "merge_group", "pull_request"]
NEVER = [("pull_request_target", "refs/heads/main"), ("workflow_run", "refs/heads/main"),
         ("issue_comment", "refs/heads/main")]


@pytest.mark.parametrize("path", PR_WORKFLOWS, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_no_pull_request_job_resolves_its_runner_from_a_variable(path):
    wf = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert wf["jobs"], "no jobs parsed"
    for name, job in wf["jobs"].items():
        expr = job["runs-on"]
        assert expr == "ubuntu-latest" or expr == RUNNER_PRED, f"{path.name}:{name}: non-canonical runs-on {expr!r}"
        for event in ALLOWED_EVENTS + [e for e, _ in NEVER]:
            for private in (True, False):
                for var in ("nexus-ci", "", "nexus-deploy", "self-hosted"):
                    for head in ("o/r", "fork/r"):
                        got = resolve(expr, event, "refs/heads/main", ci_runner=var, private=private, head_repo=head)
                        want = ("nexus-ci" if expr != "ubuntu-latest" and private and var == "nexus-ci"
                                and event in ALLOWED_EVENTS and not (event == "pull_request" and head != "o/r")
                                else "ubuntu-latest")
                        assert got == want, (path.name, name, event, private, var, head, got)


def test_every_template_job_carries_the_guarded_predicate():
    for name, job in JOBS.items():
        assert job["runs-on"] == RUNNER_PRED, name
    sg = yaml.safe_load((ROOT / "workflows" / "size-guard.yml").read_text(encoding="utf-8"))
    for name, job in sg["jobs"].items():
        assert job["runs-on"] == RUNNER_PRED, name


def test_trusted_event_flag_is_narrower_than_the_runner():
    # A same-repo PR may run on nexus-ci, but its code stays untrusted.
    flag = WORKFLOW["env"]["TRUSTED_EVENT"]
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
    assert "del(.yarnPath) | del(.plugins) | with_entries(" in install and ".enableScripts = false" in install
    for key in ("npm[A-Z]", "[Pp]roxy", "[Cc]aFilePath", "enableStrictSsl"):
        assert key in install, key
    [pip] = [st["run"] for st in JOBS["pip-audit"]["steps"] if st.get("name", "").startswith("Run pip-audit")]
    untrusted = pip.split('if [ "${TRUSTED_EVENT:-}" = "true" ]; then', 1)[1].split("exit 0\n", 1)[1]
    calls = re.findall(r"^\s*pip-audit .*$", untrusted, re.M)
    assert len(calls) == 2, calls
    for c in calls:
        assert "--locked" in c or ("--no-deps" in c and "--disable-pip" in c), c


def test_size_guard_copies_agree():
    template, own = (p.read_text(encoding="utf-8") for p in SIZE_GUARD_COPIES)
    assert own == hosted_variant(template) and not re.search(r"runs-on:.*vars\.", own)


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
    proc = subprocess.run(bash_argv(npm_step("Install")), cwd=work, capture_output=True, text=True,
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



# ─── interpreter isolation (gate pass 2 on #41) ──────────────────────────────
# Python run with the checkout as cwd puts '' first on sys.path; a PR could
# plant packaging/__init__.py and own the coverage check. Every python
# invocation in a run: body must be isolated (-I).

def test_every_python_in_a_run_body_is_isolated():
    bad = []
    for name, job in JOBS.items():
        for step in job.get("steps", []):
            for line in step.get("run", "").splitlines():
                if line.strip().startswith("#"):
                    continue
                for m in re.finditer(r"\bpython3?\s+(-\S*|\S+\.py\b)", line):
                    if m.group(1) != "-I":
                        bad.append(f"{name}: {line.strip()}")
    assert bad == [], bad


def _has(mod: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(mod) is not None


@pytest.mark.skipif(not (_has("packaging") and _has("pip_requirements_parser")),
                    reason="needs packaging + pip-requirements-parser (pip-audit's own deps)")
def test_planted_packaging_in_the_checkout_is_not_imported(tmp_path, shim_path):
    work = tmp_path / "work"
    (work / "packaging").mkdir(parents=True)
    (work / "packaging" / "__init__.py").write_text("raise SystemExit('PLANTED packaging imported')\n", encoding="utf-8")
    (work / "tomllib.py").write_text("raise SystemExit('PLANTED tomllib imported')\n", encoding="utf-8")
    (work / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "1"\ndependencies = ["idna>=3"]\n', encoding="utf-8")
    (work / "requirements.txt").write_text("idna==3.10\n", encoding="utf-8")
    bindir = tmp_path / "bin"
    (bindir / "python").write_text(f'#!/usr/bin/env bash\nexec "{Path(sys.executable).as_posix()}" "$@"\n',
                                   encoding="utf-8", newline="\n")
    (bindir / "pip-audit").write_text(f'#!/usr/bin/env bash\necho "pip-audit $*" >> "{(tmp_path / "calls").as_posix()}"\n',
                                      encoding="utf-8", newline="\n")
    for f in ("python", "pip-audit"):
        (bindir / f).chmod(0o755)
    [run] = [st["run"] for st in JOBS["pip-audit"]["steps"] if st.get("name", "").startswith("Run pip-audit")]
    proc = subprocess.run(bash_argv(run), cwd=work, capture_output=True, text=True,
                          env={**os.environ, "PATH": shim_path, "TRUSTED_EVENT": "false", "DIR": "."})
    out = proc.stdout + proc.stderr
    assert "PLANTED" not in out, out
    assert proc.returncode == 0, out
    assert "1 declared dependencies, each audited" in out


# ─── audit-dev-standards-2026-10-27 MEDIUM (proposed R-B): PR-controlled ─────
# package-manager config must not redirect or narrow the audit ───────────────

@pytest.mark.parametrize("files,expect", [
    ({".npmrc": "registry=https://attacker.example/\n"}, "'registry'"),
    ({".npmrc": "@acme:registry=https://attacker.example/\n"}, "'@acme:registry'"),
    ({".npmrc": "omit=dev\n"}, "'omit'"),
    ({".npmrc": "https-proxy=http://attacker.example:8080\n"}, "'https-proxy'"),
    ({".npmrc": "strict-ssl=false\n"}, "'strict-ssl'"),
    ({".npmrc": "[section]\nx=1\n"}, "'[section]'"),
    ({".yarnrc": 'registry "https://attacker.example/"\n'}, "'registry'"),
    ({"pnpm-workspace.yaml": "packages:\n  - a\nauditConfig:\n  ignoreCves: [CVE-1]\n"}, "'auditConfig'"),
    ({"pnpm-workspace.yaml": "registry: https://attacker.example/\n"}, "'registry'"),
    ({"package.json": '{"pnpm": {"auditConfig": {"ignoreGhsas": ["GHSA-x"]}}}'}, "pnpm.auditConfig"),
])
def test_untrusted_config_that_steers_the_audit_is_not_examined(tmp_path, shim_path, files, expect):
    proc = run_install(tmp_path, shim_path, {"package.json": "{}", "package-lock.json": "{}", **files}, "false")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "not examined" in proc.stdout and expect in proc.stdout, proc.stdout
    assert "npm ci" not in proc.calls


def test_untrusted_config_is_checked_up_to_the_checkout_root(tmp_path, shim_path):
    """A workspace member's job reads the root .npmrc too (npm's localPrefix)."""
    work = tmp_path / "work"
    (work / "pkg").mkdir(parents=True)
    (work / ".npmrc").write_text("registry=https://attacker.example/\n", encoding="utf-8")
    (work / "pkg" / "package.json").write_text("{}", encoding="utf-8")
    (work / "pkg" / "package-lock.json").write_text("{}", encoding="utf-8")
    proc = subprocess.run(bash_argv(npm_step("Install")), cwd=work / "pkg", capture_output=True, text=True,
                          env={**os.environ, "PATH": shim_path, "TRUSTED_EVENT": "false", "DIR": "pkg",
                               "GITHUB_ENV": (tmp_path / "genv").as_posix(), "GITHUB_WORKSPACE": work.as_posix()})
    assert proc.returncode == 1 and "'registry'" in proc.stdout, proc.stdout + proc.stderr


# Gate pass 1 on #62 (SC-04): a package.json that cannot be read is NOT
# EXAMINED on an untrusted event, never "no pnpm config". pnpm reads a BOM.
@pytest.mark.parametrize("body,expect", [
    ('\ufeff{"pnpm": {"auditConfig": {"ignoreGhsas": ["GHSA-x"]}}}', "pnpm.auditConfig"),
    ('{"pnpm": {"auditConfig": ', "unreadable (JSONDecodeError)"),
    ('["not", "an", "object"]', "not a JSON object"),
    ('{"pnpm": "auditConfig"}', "'pnpm' is not an object"),
])
def test_untrusted_package_json_that_cannot_be_read_is_not_examined(tmp_path, shim_path, body, expect):
    proc = run_install(tmp_path, shim_path, {"package.json": body, "package-lock.json": "{}"}, "false")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "not examined" in proc.stdout and expect in proc.stdout, proc.stdout


def test_bom_package_json_without_pnpm_config_is_audited(tmp_path, shim_path):
    proc = run_install(tmp_path, shim_path, {"package.json": '\ufeff{"name": "x"}', "package-lock.json": "{}"}, "false")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_config_report_paths_are_repr_escaped():
    install = npm_step("Install")
    assert install.count("bad.append(f\"{f!r}:") >= 5
    assert "logFilters" in install


@pytest.mark.parametrize("files", [
    {".npmrc": "# comment\ninstall-links=true\nallow-build-scripts=esbuild,sharp\n"},
    {"pnpm-workspace.yaml": "packages:\n  - 'packages/*'\nonlyBuiltDependencies:\n  - esbuild\npatchedDependencies:\n  x: p.patch\n"},
])
def test_untrusted_benign_config_is_audited_with_the_registry_pinned(tmp_path, shim_path, files):
    proc = run_install(tmp_path, shim_path, {"package.json": "{}", "package-lock.json": "{}", **files}, "false")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "npm_config_registry=https://registry.npmjs.org/" in proc.genv
    user = re.search(r"^npm_config_userconfig=(.+)$", proc.genv, re.M).group(1)
    glob = re.search(r"^npm_config_globalconfig=(.+)$", proc.genv, re.M).group(1)
    assert user != glob, "npm aborts when one file is both user and global config"


def test_trusted_event_honours_the_repo_config(tmp_path, shim_path):
    proc = run_install(tmp_path, shim_path, {"package.json": "{}", "package-lock.json": "{}",
                                             ".npmrc": "registry=https://npm.internal.example/\n"}, "true")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "npm_config_registry" not in proc.genv


def _stub_registry():
    import http.server
    import threading
    hits: list[str] = []

    class H(http.server.BaseHTTPRequestHandler):
        def _answer(self):
            hits.append(f"{self.command} {self.path}")
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                self.rfile.read(n)
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        do_GET = do_POST = _answer

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, hits


@pytest.mark.skipif(shutil.which("npm") is None, reason="real npm not on PATH")
def test_real_npm_env_registry_beats_the_project_npmrc(tmp_path):
    """Probe of the real dependency, as reviewer 1 did (npm 11.7.0 at the
    audit): a project .npmrc names the 'attacker' registry; with the pin the
    workflow exports, the advisory POST goes to the pinned one instead.
    Both registries are local stubs; no network."""
    attacker, attacker_hits = _stub_registry()
    pinned, pinned_hits = _stub_registry()
    try:
        work = tmp_path / "proj"
        work.mkdir()
        (work / "package.json").write_text('{"name":"p","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}',
                                           encoding="utf-8")
        (work / "package-lock.json").write_text(json.dumps({
            "name": "p", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
            "packages": {"": {"name": "p", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
                         "node_modules/lodash": {"version": "4.17.15",
                                                 "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"}}}),
            encoding="utf-8")
        (work / ".npmrc").write_text(f"registry=http://127.0.0.1:{attacker.server_port}/\n", encoding="utf-8")
        # Distinct files, as the workflow uses: npm 11 refuses one file as both.
        empty, empty_g = tmp_path / "empty-user-npmrc", tmp_path / "empty-global-npmrc"
        empty.write_text("", encoding="utf-8")
        empty_g.write_text("", encoding="utf-8")
        base_env = {k: v for k, v in os.environ.items() if not k.lower().startswith("npm_config_")}
        npm = shutil.which("npm")

        # Control: without the pin the project .npmrc wins (the audit's finding).
        subprocess.run([npm, "audit", "--json"], cwd=work, capture_output=True, text=True, timeout=120,
                       env={**base_env, "npm_config_userconfig": str(empty), "npm_config_globalconfig": str(empty_g)})
        assert any("advisories/bulk" in h for h in attacker_hits), ("control did not reach the .npmrc registry",
                                                                    attacker_hits)
        attacker_hits.clear()

        subprocess.run([npm, "audit", "--json"], cwd=work, capture_output=True, text=True, timeout=120,
                       env={**base_env, "npm_config_registry": f"http://127.0.0.1:{pinned.server_port}/",
                            "npm_config_userconfig": str(empty), "npm_config_globalconfig": str(empty_g)})
        assert any("advisories/bulk" in h for h in pinned_hits), pinned_hits
        assert attacker_hits == [], attacker_hits
    finally:
        attacker.shutdown()
        pinned.shutdown()


# ─── audit-dev-standards-2026-10-27 MEDIUM: workspace folding ────────────────

CLASSIC_WS_LOCK = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n"


def test_yarn_classic_never_folds_a_member(tmp_path, shim_path):
    proc, o = run_detect(tmp_path, shim_path, {
        "package.json": '{"workspaces": ["packages/*"]}', "yarn.lock": CLASSIC_WS_LOCK,
        "packages/a/package.json": "{}", "packages/.x/package.json": '{"dependencies":{"lodash":"4.17.15"}}',
    })
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(o["npm_covered"]) == {}
    assert json.loads(o["npm_dirs"]) == [".", "packages/.x", "packages/a"]


def test_a_dot_directory_is_never_a_glob_member(tmp_path, shim_path):
    """npm/pnpm/yarn globs do not match dot segments; neither does detect."""
    lock = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "packages/a": {}, "packages/.x": {}}})
    proc, o = run_detect(tmp_path, shim_path, {
        "package.json": '{"workspaces": ["packages/*", "apps/**"]}', "package-lock.json": lock,
        "packages/a/package.json": "{}", "packages/.x/package.json": "{}",
        "apps/.hidden/b/package.json": "{}",
    })
    assert proc.returncode == 0, proc.stdout + proc.stderr
    covered = json.loads(o["npm_covered"])
    assert covered == {"packages/a": "."}, covered
    assert "packages/.x" in json.loads(o["npm_dirs"]) and "apps/.hidden/b" in json.loads(o["npm_dirs"])


def _glob_re():
    body = step_run("detect", "detect").split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    import textwrap
    src = textwrap.dedent(body)
    fn = "def glob_re(pat):" + src.split("def glob_re(pat):", 1)[1].split("\ndef ", 1)[0]
    ns: dict = {"re": re}
    exec(fn, ns)
    return ns["glob_re"]


@pytest.mark.parametrize("pat,path,want", [
    ("packages/*", "packages/a", True), ("packages/*", "packages/.x", False),
    ("packages/.x", "packages/.x", True), ("packages/.*", "packages/.x", True),
    ("**/pkg", "a/b/pkg", True), ("**/pkg", ".a/pkg", False), ("apps/**", "apps/a/b", True),
    ("apps/**", "apps/.h/b", False), ("apps/**", "apps/a/.h", False), ("p?", "p1", True), ("p?", "p/x", False),
    ("packages/*", "packages/a/b", False),
])
def test_glob_re_follows_dot_false(pat, path, want):
    rx = _glob_re()(pat)
    assert bool(rx and rx.match(path)) is want, (pat, path)


# Gate pass 2 on #62 (SC-19/SC-04): a pnpm-workspace.yaml whose top-level
# mapping is indented (valid YAML) used to skip every key check.
@pytest.mark.parametrize("body", [
    " registry: https://attacker.example/\n packages:\n   - a\n",
    "\tregistry: https://attacker.example/\n",
    "- registry\n",
    "# c\n\n   auditConfig:\n     ignoreCves: [CVE-1]\n",
])
def test_untrusted_indented_workspace_document_is_not_examined(tmp_path, shim_path, body):
    proc = run_install(tmp_path, shim_path, {"package.json": "{}", "package-lock.json": "{}",
                                             "pnpm-workspace.yaml": body}, "false")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "not examined" in proc.stdout and "cannot be read safely" in proc.stdout, proc.stdout
