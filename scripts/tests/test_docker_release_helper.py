"""docker-release.yml helper mode: the `helper` step's stack-name guard and its
nexus-deploy exit-code mapping, plus a mutation battery proving the suite
notices when either is weakened.

Security gate 2026-10-10 (PR #38, SC-14 NOT EXAMINED): the guard shipped with
only an ad hoc fake-sudo run. These tests run the SHIPPED `run:` block of the
deploy job's `helper` step under bash exactly as Actions does for
`shell: bash` (`bash --noprofile --norc -eo pipefail <file>`), with `sudo`
replaced by a shim on PATH that records its argv and exits with a chosen code.
This is a test file: the shim models the helper's exit-code contract from
Ohio15/infra nexus-deploy/README.md (0 ok, 2 usage, 3 denied, 4 rolled back,
5 rollback failed, 6 locked, 7 drift, 8 rate bound, 1 anything else).
No network, no real sudo.

Run:      python -m pytest scripts/tests/test_docker_release_helper.py -q
Mutants:  python scripts/tests/test_docker_release_helper.py --mutants
"""
from __future__ import annotations

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
WORKFLOW_FILE = ROOT / ".github" / "workflows" / "docker-release.yml"
HELPER = "/usr/local/sbin/nexus-deploy"


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


def bash_path(p: Path) -> str:
    """A path bash can put on PATH. PATH is ':'-separated, so on Windows the
    drive letter must become Git-bash's /c/... form, not C:/..."""
    posix = p.resolve().as_posix()
    m = re.match(r"^([A-Za-z]):/(.*)$", posix)
    return f"/{m.group(1).lower()}/{m.group(2)}" if m else posix


BASH = bash_exe()
WORKFLOW = yaml.safe_load(WORKFLOW_FILE.read_text(encoding="utf-8"))
DEPLOY = WORKFLOW["jobs"]["deploy"]
[HELPER_STEP] = [s for s in DEPLOY["steps"] if s.get("id") == "helper"]
SCRIPT = HELPER_STEP["run"]

FAKE_SUDO = """#!/usr/bin/env bash
# Test shim for sudo: record argv NUL-separated, exit with FAKE_RC.
printf '%s\\0' "$@" > "$FAKE_SUDO_LOG"
echo "fake-sudo called"
exit "${FAKE_RC:-0}"
"""

# rc -> (status, rolled_back, fragment of the ::error:: meaning)
EXIT_MAP = {
    0: ("healthy", "false", None),
    1: ("failed", "false", "unexpected failure"),
    2: ("usage", "false", "usage error"),
    3: ("denied", "false", "denied (authorization, policy, source or pre-flight)"),
    4: ("unhealthy", "true", "rolled back"),
    5: ("unhealthy", "failed", "rollback failed"),
    6: ("locked", "false", "stack lock"),
    7: ("drift", "false", "status drift"),
    8: ("rate-limited", "false", "rate bound"),
    42: ("failed", "false", "unexpected failure"),
}

INVALID_STACKS = [
    "",
    "APM",
    "1apm",
    "apm;id",
    "a$(id)",
    "apm x",
    "a" * 33,
    "apm\nx",
    "-apm",
    "apm-\u00e9",
]
VALID_STACKS = ["a", "a" * 32, "game-manager2"]
VERSION = "0.13.5"


def run_script(script: str, workdir: Path, stack: str, rc: int = 0) -> dict:
    """Run one helper-step script; return exit status, parsed outputs, log
    and the argv the sudo shim saw (None when sudo was never called)."""
    bindir = workdir / "bin"
    bindir.mkdir(exist_ok=True)
    shim = bindir / "sudo"
    shim.write_text(FAKE_SUDO, encoding="utf-8", newline="\n")
    shim.chmod(0o755)
    script_file = workdir / "step.sh"
    script_file.write_text(script, encoding="utf-8", newline="\n")
    out_file = workdir / "github_output"
    out_file.write_text("", encoding="utf-8")
    sudo_log = workdir / "sudo.argv"
    if sudo_log.exists():
        sudo_log.unlink()
    git_dir = Path(shutil.which("git")).resolve().parent
    env = {
        **os.environ,
        "PATH": f"{bash_path(bindir)}:{bash_path(git_dir)}:/usr/bin:/bin",
        "STACK": stack,
        "VERSION": VERSION,
        "GITHUB_OUTPUT": out_file.as_posix(),
        "FAKE_RC": str(rc),
        "FAKE_SUDO_LOG": sudo_log.as_posix(),
    }
    proc = subprocess.run(
        [BASH, "--noprofile", "--norc", "-eo", "pipefail", script_file.as_posix()],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
    )
    outputs = {}
    for line in out_file.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            outputs[k] = v
    argv = None
    if sudo_log.exists():
        argv = sudo_log.read_bytes().decode("utf-8").split("\0")[:-1]
    return {"exit": proc.returncode, "outputs": outputs, "log": proc.stdout + proc.stderr, "argv": argv}


def suite_failures(script: str) -> list[str]:
    """Every behavioural and static check, against one script text. Returns a
    list of failure descriptions; empty means green. Shared by the pytest
    tests (real script) and the mutation battery (mutated scripts)."""
    failures: list[str] = []
    # The spec forbids ${{ }} interpolation in run:; values arrive via env only.
    if "${{" in script:
        failures.append("static: run: contains a ${{ }} expression")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for rc, (status, rolled_back, meaning) in EXIT_MAP.items():
            r = run_script(script, work, "apm", rc)
            tag = f"rc={rc}"
            if r["argv"] != ["-n", HELPER, "apm", "deploy", f"v{VERSION}"]:
                failures.append(f"{tag}: sudo argv {r['argv']!r}")
            want = {"status": status, "rolled_back": rolled_back, "exit_code": str(rc)}
            got = {k: r["outputs"].get(k) for k in want}
            if got != want:
                failures.append(f"{tag}: outputs {got!r} != {want!r}")
            if rc == 0:
                if r["exit"] != 0:
                    failures.append(f"{tag}: step exited {r['exit']}, want 0")
                if "::error::" in r["log"]:
                    failures.append(f"{tag}: success printed ::error::")
            else:
                if r["exit"] == 0:
                    failures.append(f"{tag}: non-zero helper exit returned success")
                err = f"::error::nexus-deploy apm deploy v{VERSION} exited {rc}: "
                if err not in r["log"] or meaning not in r["log"]:
                    failures.append(f"{tag}: missing ::error:: line naming code and meaning")
        for bad in INVALID_STACKS:
            r = run_script(script, work, bad, 0)
            tag = f"stack={bad!r}"
            if r["argv"] is not None:
                failures.append(f"{tag}: sudo called with {r['argv']!r}")
            if r["exit"] == 0:
                failures.append(f"{tag}: invalid name returned success")
            if r["outputs"].get("status") != "invalid-stack":
                failures.append(f"{tag}: status {r['outputs'].get('status')!r} != 'invalid-stack'")
            if "::error::nexus_deploy_stack is not a valid stack name" not in r["log"]:
                failures.append(f"{tag}: missing ::error:: line")
            # The rejected value must never be echoed (workflow-command injection).
            if len(bad) > 3 and bad in r["log"]:
                failures.append(f"{tag}: rejected value echoed to the log")
        for good in VALID_STACKS:
            r = run_script(script, work, good, 0)
            tag = f"stack={good!r}"
            if r["argv"] != ["-n", HELPER, good, "deploy", f"v{VERSION}"]:
                failures.append(f"{tag}: sudo argv {r['argv']!r}")
            if r["exit"] != 0 or r["outputs"].get("status") != "healthy":
                failures.append(f"{tag}: valid name not accepted (exit {r['exit']}, {r['outputs']!r})")
    return failures


# (name, old, new): each is applied with an exact count==1 replace, so a
# workflow edit that moves the text fails the battery loudly instead of
# leaving a no-op mutant that "survives" for the wrong reason.
MUTANTS = [
    ("a1-drop-caret-anchor", "stack_re='^[a-z]", "stack_re='[a-z]"),
    ("a2-drop-dollar-anchor", "{0,31}$'", "{0,31}'"),
    ("b-regex-test-is-true", '[[ "${STACK}" =~ ${stack_re} ]]', "true"),
    ("c-exit4-not-rolled-back",
     'rolled back"; rolled_back=true ;;', 'rolled back"; rolled_back=false ;;'),
    ("d-no-exit-after-error",
     'exited ${rc}: ${meaning}"\n  exit 1\n', 'exited ${rc}: ${meaning}"\n'),
    ("e1-interpolate-stack-expression",
     'nexus-deploy "${STACK}" deploy', "nexus-deploy ${{ inputs.nexus_deploy_stack }} deploy"),
    ("e2-invalid-stack-falls-through",
     '} >> "$GITHUB_OUTPUT"\n  exit 1\nfi\n', '} >> "$GITHUB_OUTPUT"\nfi\n'),
]


def apply_mutant(script: str, old: str, new: str) -> str:
    # YAML strips the block's common indent, so the script text (and these
    # patterns) use the step's relative two-space indents.
    count = script.count(old)
    assert count == 1, f"mutant pattern matched {count} times: {old!r}"
    return script.replace(old, new)


def mutant_results() -> list[tuple[str, list[str]]]:
    return [(name, suite_failures(apply_mutant(SCRIPT, old, new))) for name, old, new in MUTANTS]


# ---------------------------------------------------------------------------
# pytest entry points
# ---------------------------------------------------------------------------


def test_helper_step_shape():
    assert HELPER_STEP.get("if") == "inputs.nexus_deploy_stack != ''"
    assert HELPER_STEP.get("shell") == "bash"
    assert HELPER_STEP.get("env") == {
        "STACK": "${{ inputs.nexus_deploy_stack }}",
        "VERSION": "${{ needs.build-and-push.outputs.version }}",
    }
    assert SCRIPT.startswith("set -euo pipefail\n")


def test_job_outputs_fall_back_to_helper():
    assert DEPLOY["outputs"] == {
        "deploy_status": "${{ steps.healthcheck.outputs.status || steps.helper.outputs.status }}",
        "rolled_back": "${{ steps.rollback.outputs.rolled_back || steps.helper.outputs.rolled_back }}",
    }


def test_legacy_steps_are_skipped_in_helper_mode():
    for s in DEPLOY["steps"]:
        name = s.get("name", s.get("uses"))
        if s.get("id") == "helper" or name == "Cleanup snapshot":
            continue
        if s.get("id") == "version_probe":
            assert '[ -n "${HELPER_STACK}" ]' in s["run"], "version probe must skip in helper mode"
            continue
        assert "inputs.nexus_deploy_stack == ''" in str(s.get("if")), f"{name} runs in helper mode"
    [rollback] = [s for s in DEPLOY["steps"] if s.get("id") == "rollback"]
    assert rollback["if"].startswith("failure() && ")


def test_shipped_script_is_green():
    failures = suite_failures(SCRIPT)
    assert failures == [], "\n".join(failures)


@pytest.mark.parametrize("name,old,new", MUTANTS, ids=[m[0] for m in MUTANTS])
def test_mutant_is_killed(name, old, new):
    mutated = apply_mutant(SCRIPT, old, new)
    assert mutated != SCRIPT
    assert suite_failures(mutated), f"mutant {name} survived: the suite stayed green"


if __name__ == "__main__":
    if "--mutants" not in sys.argv[1:]:
        sys.exit(pytest.main([__file__, "-q"]))
    survived = 0
    for name, failures in mutant_results():
        state = f"KILLED ({len(failures)} failing checks; first: {failures[0]})" if failures else "SURVIVED"
        survived += not failures
        print(f"{name}: {state}")
    sys.exit(1 if survived else 0)
