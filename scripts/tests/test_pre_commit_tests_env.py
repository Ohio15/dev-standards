"""hooks/pre-commit-tests.sh: the suite never sees git's hook environment.

git exports GIT_DIR / GIT_INDEX_FILE (and more GIT_*) to hooks. A test that
spawns `git init` / `git commit` in a temp dir obeys them, so its fixture
commits land on the branch being committed and `git init` sets
`core.bare=true` in the shared config (cortex-hooks 2026-09-14 and 2026-10-01;
shared-brain discovery 05d9bff3). The hook unsets every GIT_* before TEST_CMD.

Drives the REAL hook under Git's own bash in a throwaway repo under pytest's
tmp_path, with the environment git would hand a hook. The suite is a Python
one-liner that exits 7 and names the leak if ANY GIT_* variable reached it.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent.parent / "hooks" / "pre-commit-tests.sh"


def bash_exe() -> str:
    """Git's own bash (a bare "bash" on Windows resolves to the WSL stub)."""
    git = shutil.which("git")
    if os.name == "nt" and git:
        candidate = Path(git).resolve().parent.parent / "usr" / "bin" / "bash.exe"
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("bash")
    assert found, "bash not found"
    return found


BASH = bash_exe()
PY = Path(sys.executable).as_posix()

# One line, no newline escapes: TEST_CMD is a single config line. The marker is
# assembled at run time so the hook's echo of the command cannot contain it.
LEAK_PROBE = (
    "import os,sys;"
    "l=sorted(k for k in os.environ if k.upper().startswith('GIT_'));"
    "l and print('LEAK'+'ED:'+','.join(l),file=sys.stderr);"
    "sys.exit(7 if l else 0)"
)


def clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


def make_repo(tmp_path: Path, test_cmd: str) -> Path:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], env=clean_env(), check=True)
    (repo / ".pre-commit-tests").write_text(
        f"TEST_CMD={test_cmd}\nTEST_TIMEOUT=60\n", encoding="utf-8", newline="\n"
    )
    return repo


def run_hook(repo: Path, extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = {**clean_env(), **extra_env}
    return subprocess.run(
        [BASH, HOOK.as_posix()],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def hook_env(repo: Path) -> dict[str, str]:
    """What git hands a hook, with a BOGUS index and a non-git marker.

    GIT_DIR stays valid: the hook's own `git rev-parse --show-toplevel` runs
    before the strip and, with an unresolvable GIT_DIR, exits 0 without running
    the suite - which would make this test pass without testing anything.
    """
    return {
        "GIT_DIR": (repo / ".git").as_posix(),
        "GIT_INDEX_FILE": (repo / "no-such-dir" / "bogus-index").as_posix(),
        "GIT_EDITOR": ":",
        "GIT_PREFIX": "",
        "GIT_REFLOG_ACTION": "commit",
    }


def test_suite_runs_with_every_git_variable_stripped(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, f'"{PY}" -c "{LEAK_PROBE}"')
    proc = run_hook(repo, hook_env(repo))
    # Positive confirmation the suite actually ran; "no leak reported" from a
    # suite that never started is not a pass.
    assert "pre-commit-tests: running" in proc.stderr, proc.stderr
    assert "LEAKED:" not in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr


def test_probe_detects_a_leak_without_the_hook(tmp_path: Path) -> None:
    """The probe is not vacuous: run directly with the same env, it fails."""
    repo = make_repo(tmp_path, "true")
    env = {**clean_env(), **hook_env(repo)}
    proc = subprocess.run(
        [PY, "-c", LEAK_PROBE], env=env, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 7
    assert "GIT_DIR" in proc.stderr and "GIT_INDEX_FILE" in proc.stderr


def test_failing_suite_still_fails_after_the_strip(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, f'"{PY}" -c "import sys; sys.exit(5)"')
    proc = run_hook(repo, hook_env(repo))
    assert "pre-commit-tests: running" in proc.stderr, proc.stderr
    assert proc.returncode == 5, proc.stderr


def test_githooks_copy_matches_canonical() -> None:
    root = HOOK.parent.parent
    assert (root / ".githooks" / "pre-commit-tests.sh").read_bytes() == HOOK.read_bytes()
