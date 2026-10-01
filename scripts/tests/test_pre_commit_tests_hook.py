"""hooks/pre-commit-tests.sh: the suite never sees git's hook environment.

git exports GIT_DIR / GIT_INDEX_FILE to hooks. A test inside the suite that
spawns `git init` / `git commit` in a temp dir obeys them, so its fixture
commits land on the branch being committed and `git init` sets
core.bare=true in the repository's shared config. That happened twice in
cortex-hooks (2026-09-14, 2026-10-01; the second hit a live deploy tree). The
hook now unsets every GIT_* before running TEST_CMD.

Runs the real hook script under Git's bash in a throwaway repo, with a
hook-shaped environment. No network.

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
    """Git's own bash (never the WSL stub in System32); PATH bash elsewhere."""
    git = shutil.which("git")
    if os.name == "nt" and git:
        candidate = Path(git).resolve().parent.parent / "usr" / "bin" / "bash.exe"
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("bash")
    assert found, "bash not found"
    return found


def clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


def posix(p: Path) -> str:
    return p.as_posix()


def make_repo(tmp_path: Path, test_cmd: str) -> Path:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True, env=clean_env())
    (repo / ".pre-commit-tests").write_text(
        f"TEST_CMD={test_cmd}\nTEST_TIMEOUT=60\n", encoding="utf-8", newline="\n"
    )
    return repo


def run_hook(repo: Path, extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = {**clean_env(), **extra_env}
    return subprocess.run(
        [bash_exe(), posix(HOOK)],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


# The suite: exit 7 naming any GIT_* that reached it, 0 otherwise.
PROBE = (
    f'"{posix(Path(sys.executable))}" -c "import os,sys;'
    "l=[k for k in os.environ if k.upper().startswith('GIT_')];"
    "print('leaked:'+','.join(l),file=sys.stderr) if l else None;"
    'sys.exit(7 if l else 0)"'
)


def test_git_hook_env_never_reaches_the_suite(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, PROBE)
    r = run_hook(
        repo,
        {
            # what git hands a hook: a VALID GIT_DIR so the script's own
            # rev-parse still resolves the repo, the index, and friends
            "GIT_DIR": posix(repo / ".git"),
            "GIT_INDEX_FILE": posix(repo / ".git" / "index"),
            "GIT_EDITOR": ":",
            "GIT_PREFIX": "",
        },
    )
    assert "pre-commit-tests: running" in r.stderr, r.stderr
    assert r.returncode == 0, f"GIT_* reached the suite:\n{r.stderr}"


def test_failing_suite_still_fails_the_hook_after_the_strip(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, f'"{posix(Path(sys.executable))}" -c "import sys;sys.exit(5)"')
    r = run_hook(repo, {"GIT_DIR": posix(repo / ".git")})
    assert r.returncode == 5, r.stderr
