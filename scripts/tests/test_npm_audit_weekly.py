"""npm-audit-weekly.sh must never turn a failed audit into zero counts.

"Unknown is never clean" (SC-07, fail closed on I/O and parse errors SC-04):
every way `npm audit` can fail has to surface as status "error" with null
counts, a non-zero exit, and totals that exclude the repo. A fake `npm` on PATH
makes the real audit fail in each of those ways; the script and jq are real.

Run:  python -m pytest scripts/tests/test_npm_audit_weekly.py -q
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "npm-audit-weekly.sh"
IS_WINDOWS = sys.platform == "win32"
BASH = "C:/Program Files/Git/bin/bash.exe" if IS_WINDOWS else shutil.which("bash")

needs_jq = pytest.mark.skipif(shutil.which("jq") is None, reason="jq not installed")

# The fake npm picks its behaviour from a per-repo file so one run can mix
# healthy and broken repos. `.fake-mode-prod` overrides it for `--omit=dev`.
FAKE_NPM = r"""#!/usr/bin/env bash
mode_file=.fake-mode
for a in "$@"; do
  if [ "$a" = "--omit=dev" ] && [ -f .fake-mode-prod ]; then mode_file=.fake-mode-prod; fi
done
mode="$(cat "$mode_file" 2>/dev/null || echo clean)"
vuln() {
  printf '{"auditReportVersion":2,"vulnerabilities":{},"metadata":{"vulnerabilities":{"info":0,"low":%s,"moderate":%s,"high":%s,"critical":%s,"total":0}}}' "$1" "$2" "$3" "$4"
}
case "$mode" in
  clean)     vuln 0 0 0 0; exit 0 ;;
  findings)  vuln 1 2 3 4; exit 1 ;;
  enolock)   echo '{"error":{"code":"ENOLOCK","summary":"This command requires an existing lockfile.","detail":"x"}}'; exit 1 ;;
  network)   echo '{"error":{"code":"EAI_AGAIN","summary":"request to registry failed"}}'; exit 1 ;;
  garbage)   echo 'npm ERR! this is not json'; exit 0 ;;
  truncated) printf '{"auditReportVersion":2,"metadata":{"vulnerabi'; exit 0 ;;
  empty)     exit 1 ;;
  nosummary) echo '{"auditReportVersion":2,"vulnerabilities":{}}'; exit 0 ;;
  partial)   echo '{"metadata":{"vulnerabilities":{"high":0,"critical":0}}}'; exit 0 ;;
  stringy)   echo '{"metadata":{"vulnerabilities":{"info":"0","low":"0","moderate":"0","high":"0","critical":"0"}}}'; exit 0 ;;
  array)     echo '[]'; exit 0 ;;
  errwithmeta) echo '{"error":{"code":"E500","summary":"s"},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0}}}'; exit 1 ;;
  hang)      sleep 30; exit 0 ;;
esac
exit 99
"""

FAKE_CURL = "#!/usr/bin/env bash\nexit 1\n"  # KEV fetch fails fast; the script tolerates it.


def _make_repo(root: Path, name: str, mode: str, *, lockfile: bool = True, prod_mode: str | None = None) -> None:
    repo = root / name
    (repo / ".git").mkdir(parents=True)
    (repo / "package.json").write_text("{}", encoding="utf-8")
    if lockfile:
        (repo / "package-lock.json").write_text("{}", encoding="utf-8")
    (repo / ".fake-mode").write_text(mode, encoding="utf-8")
    if prod_mode is not None:
        (repo / ".fake-mode-prod").write_text(prod_mode, encoding="utf-8")


def _fake_bin(tmp_path: Path) -> Path:
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    for name, body in (("npm", FAKE_NPM), ("curl", FAKE_CURL)):
        path = bindir / name
        path.write_text(body, encoding="utf-8", newline="\n")
        path.chmod(0o755)
    return bindir


def _run(tmp_path: Path, repos: dict[str, str | tuple], *, env_extra: dict[str, str] | None = None,
         path_override: str | None = None):
    root = tmp_path / "root"
    root.mkdir()
    for name, spec in repos.items():
        if isinstance(spec, tuple):
            _make_repo(root, name, spec[0], **spec[1])
        else:
            _make_repo(root, name, spec)
    out = tmp_path / "out"
    bindir = _fake_bin(tmp_path)
    env = dict(os.environ)
    env["PATH"] = path_override if path_override is not None else f"{bindir.as_posix()}{os.pathsep}{env['PATH']}"
    env["HOME"] = str(tmp_path / "home")
    env.update(env_extra or {})
    proc = subprocess.run(
        [BASH, str(SCRIPT), "--root", root.as_posix(), "--output-dir", out.as_posix()],
        env=env, capture_output=True, text=True, timeout=120,
    )
    reports = list(out.glob("npm-audit-*.json"))
    assert len(reports) == 1, f"no single report written; rc={proc.returncode}\n{proc.stderr}"
    return proc, json.loads(reports[0].read_text(encoding="utf-8"))


def _entry(report: dict, name: str) -> dict:
    return next(r for r in report["repos"] if r["repo"] == name)


COUNT_KEYS = ("critical", "high", "moderate", "low", "info", "prod_critical", "prod_high")


def _assert_unexamined(entry: dict, reason_part: str) -> None:
    assert entry["status"] == "error"
    assert reason_part in entry["reason"], entry["reason"]
    for key in COUNT_KEYS:
        assert entry[key] is None, f"{key} must be null for an unexamined repo, got {entry[key]!r}"


# One script run per scenario, not per case: bash on Windows pays a process
# spawn per jq call, so the failure modes share a single run as sibling repos.
FAILURE_MODES = {
    "enolock": "audit-error:ENOLOCK",
    "network": "audit-error:EAI_AGAIN",
    "garbage": "audit-output-unparseable",
    "truncated": "audit-output-unparseable",
    "empty": "audit-no-output",
    "nosummary": "audit-summary-missing",
    "partial": "audit-summary-missing",
    "stringy": "audit-summary-missing",
    "array": "audit-output-unparseable",
    "errwithmeta": "audit-error:E500",
}


@pytest.fixture(scope="module")
def mixed_run(tmp_path_factory: pytest.TempPathFactory):
    repos: dict[str, str | tuple] = {"good": "clean"}
    repos.update({mode: mode for mode in FAILURE_MODES})
    repos["prodonly"] = ("clean", {"prod_mode": "enolock"})
    repos["nolock"] = ("clean", {"lockfile": False})
    return _run(tmp_path_factory.mktemp("mixed"), repos)


@needs_jq
def test_every_failure_mode_is_unexamined_not_zero(mixed_run) -> None:
    proc, report = mixed_run
    for mode, reason in FAILURE_MODES.items():
        _assert_unexamined(_entry(report, mode), reason)
    _assert_unexamined(_entry(report, "prodonly"), "prod:audit-error:ENOLOCK")
    _assert_unexamined(_entry(report, "nolock"), "missing-lockfile")
    assert "UNEXAMINED" in proc.stdout


@needs_jq
def test_mixed_run_keeps_good_repo_and_flags_the_rest(mixed_run) -> None:
    proc, report = mixed_run
    assert proc.returncode == 4, (proc.returncode, proc.stderr)
    good = _entry(report, "good")
    assert good["status"] == "ok" and good["reason"] is None
    assert all(good[k] == 0 for k in COUNT_KEYS)
    assert report["status"] == "error"
    assert (report["repos_ok"], report["repos_error"]) == (1, len(FAILURE_MODES) + 2)
    assert report["repo_count"] == len(FAILURE_MODES) + 3
    assert report["reason"] == f"{len(FAILURE_MODES) + 2}-of-{len(FAILURE_MODES) + 3}-repos-unexamined"
    # Totals cover examined repos only: nothing from an unexamined repo leaks in.
    assert report["totals"] == {"critical": 0, "high": 0, "moderate": 0, "low": 0, "info": 0}


@needs_jq
def test_clean_run_is_ok_exit_0_with_real_zeros(tmp_path: Path) -> None:
    proc, report = _run(tmp_path, {"good": "clean"})
    assert proc.returncode == 0, proc.stderr
    assert report["status"] == "ok" and report["repos_error"] == 0 and report["reason"] == ""


@needs_jq
def test_findings_counted_threshold_exit_wins_and_unexamined_still_reported(tmp_path: Path) -> None:
    proc, report = _run(tmp_path, {"vuln": "findings", "bad": "network"})
    assert proc.returncode == 3
    e = _entry(report, "vuln")
    assert (e["status"], e["critical"], e["high"], e["moderate"], e["low"]) == ("ok", 4, 3, 2, 1)
    assert report["totals"]["critical"] == 4
    _assert_unexamined(_entry(report, "bad"), "EAI_AGAIN")
    assert report["status"] == "error"


@needs_jq
def test_no_repos_found_is_not_ok(tmp_path: Path) -> None:
    proc, report = _run(tmp_path, {})
    assert proc.returncode == 4
    assert report["status"] == "error" and report["reason"] == "no-repos-discovered"


@needs_jq
@pytest.mark.skipif(shutil.which("timeout") is None, reason="timeout(1) not installed")
def test_audit_timeout_is_unexamined(tmp_path: Path) -> None:
    proc, report = _run(tmp_path, {"slow": "hang"}, env_extra={"AUDIT_TIMEOUT": "1"})
    assert proc.returncode == 4
    _assert_unexamined(_entry(report, "slow"), "audit-timeout")


def _tools_dir(tmp_path: Path, *, jq: bool) -> Path:
    """A PATH directory of symlinks to just the real tools the script needs, so
    one dependency (jq or npm) can be genuinely absent whatever else is installed."""
    tools = tmp_path / "tools"
    tools.mkdir()
    wanted = ["bash", "mktemp", "date", "mkdir", "rm", "sort", "comm", "sed", "tr", "cut", "basename",
              "uname", "cat", "dirname", "sleep", "timeout", "env", "head"]
    if jq:
        wanted.append("jq")
    for tool in wanted:
        found = shutil.which(tool)
        if found:
            (tools / tool).symlink_to(found)
    return tools


@pytest.mark.skipif(IS_WINDOWS, reason="symlinked tool dir; msys exes need their own DLL directory")
def test_missing_jq_is_unexamined_and_report_is_valid_json(tmp_path: Path) -> None:
    tools = _tools_dir(tmp_path, jq=False)
    assert shutil.which("jq", path=str(tools)) is None
    proc, report = _run(tmp_path, {"good": "clean"},
                        path_override=f"{tmp_path / 'fakebin'}{os.pathsep}{tools}")
    assert proc.returncode == 4
    _assert_unexamined(_entry(report, "good"), "jq-missing")


@pytest.mark.skipif(IS_WINDOWS or shutil.which("jq") is None, reason="symlinked tool dir + jq needed")
def test_missing_npm_is_unexamined(tmp_path: Path) -> None:
    tools = _tools_dir(tmp_path, jq=True)
    assert shutil.which("npm", path=str(tools)) is None
    curl_only = tmp_path / "curlonly"
    curl_only.mkdir()
    (curl_only / "curl").write_text(FAKE_CURL, encoding="utf-8", newline="\n")
    (curl_only / "curl").chmod(0o755)
    proc, report = _run(tmp_path, {"good": "clean"}, path_override=f"{curl_only}{os.pathsep}{tools}")
    assert proc.returncode == 4
    _assert_unexamined(_entry(report, "good"), "npm-missing")
