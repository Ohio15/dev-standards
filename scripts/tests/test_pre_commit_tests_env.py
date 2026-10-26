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


# --- CRLF / BOM tolerance ---------------------------------------------------
# Windows-authored configs (ai-console, craft-tools, infra,
# patriot-browser-policy-reconciler, PDFManager; shared-brain a0649d94) carry
# CRLF, which used to leave a trailing CR on TEST_CMD.

BOM = b"\xef\xbb\xbf"


def make_repo_raw(tmp_path: Path, config_bytes: bytes) -> Path:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], env=clean_env(), check=True)
    (repo / ".pre-commit-tests").write_bytes(config_bytes)
    return repo


def strict_cmd() -> str:
    # Fails (exit 9) unless the final argument is exactly "ok" - a trailing CR
    # on TEST_CMD makes it "ok\r".
    code = "import sys; sys.exit(0 if sys.argv[-1]=='ok' else 9)"
    return f'"{PY}" -c "{code}" ok'


def test_crlf_config_behaves_like_lf(tmp_path: Path) -> None:
    cfg = f"# gate\r\nTEST_CMD={strict_cmd()}\r\nTEST_TIMEOUT=60\r\nTEST_PATHS=*\r\n\r\n"
    repo = make_repo_raw(tmp_path, cfg.encode())
    (repo / "a.txt").write_text("x")
    subprocess.run(["git", "add", "a.txt"], cwd=repo, env=clean_env(), check=True)
    proc = run_hook(repo, {})
    assert "pre-commit-tests: running" in proc.stderr, proc.stderr
    assert proc.returncode == 0, proc.stderr
    # text=True folds CR into LF, so the echoed command is checked as bytes.
    # (Git for Windows bash drops a trailing CR when it executes the command,
    # so the exit code alone cannot prove the fix there; the echo can.)
    raw = subprocess.run(
        [BASH, HOOK.as_posix()], cwd=repo, env=clean_env(),
        capture_output=True, timeout=120, check=False,
    )
    assert b"\r" not in raw.stderr, raw.stderr


def test_crlf_failing_command_still_fails(tmp_path: Path) -> None:
    cfg = f'TEST_CMD="{PY}" -c "import sys; sys.exit(5)"\r\n'
    repo = make_repo_raw(tmp_path, cfg.encode())
    proc = run_hook(repo, {})
    assert proc.returncode == 5, proc.stderr


def test_utf8_bom_on_first_line_is_tolerated(tmp_path: Path) -> None:
    for eol in ("\n", "\r\n"):
        sub = tmp_path / ("crlf" if eol == "\r\n" else "lf")
        sub.mkdir()
        repo = make_repo_raw(sub, BOM + f"TEST_CMD={strict_cmd()}{eol}".encode())
        proc = run_hook(repo, {})
        assert "ignoring unknown key" not in proc.stderr, proc.stderr
        assert "pre-commit-tests: running" in proc.stderr, proc.stderr
        assert proc.returncode == 0, proc.stderr


def test_bom_only_stripped_on_first_line(tmp_path: Path) -> None:
    """A BOM mid-file is data, not a marker: that key stays unknown."""
    cfg = f"TEST_CMD={strict_cmd()}\n".encode() + BOM + b"TEST_TIMEOUT=60\n"
    repo = make_repo_raw(tmp_path, cfg)
    proc = run_hook(repo, {})
    assert "ignoring unknown key" in proc.stderr, proc.stderr


def test_lf_config_unchanged_including_value_spacing(tmp_path: Path) -> None:
    # Internal spacing of the command stays significant; TEST_PATHS skip works.
    repo = make_repo_raw(
        tmp_path,
        f"TEST_CMD={strict_cmd()}\nTEST_TIMEOUT=60\nTEST_PATHS=src/**\n".encode(),
    )
    (repo / "a.txt").write_text("x")
    subprocess.run(["git", "add", "a.txt"], cwd=repo, env=clean_env(), check=True)
    proc = run_hook(repo, {})
    assert "suite skipped" in proc.stderr, proc.stderr
    assert proc.returncode == 0
    (repo / ".pre-commit-tests").write_bytes(
        f"TEST_CMD={strict_cmd()}\n".encode()
    )
    proc = run_hook(repo, {})
    assert "pre-commit-tests: running" in proc.stderr and proc.returncode == 0, proc.stderr
