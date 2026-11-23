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
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "npm-audit-weekly.sh"
IS_WINDOWS = sys.platform == "win32"
BASH = "C:/Program Files/Git/bin/bash.exe" if IS_WINDOWS else shutil.which("bash")

needs_jq = pytest.mark.skipif(shutil.which("jq") is None, reason="jq not installed")

# The fake npm picks its behaviour from the package.json it is run against so
# one run can mix healthy and broken repos: npm runs in a staged copy of the
# repo (package.json + lockfile only, audit 2026-11-10.2 M3), so the mode must
# travel inside package.json. `fake_mode_prod` overrides it for `--omit=dev`.
# With FAKE_NPM_LOG set, each call records its cwd, its npm_config_* env and
# the cwd listing; with REAL_NPM also set, it records real npm's resolved
# config sources for that cwd and env (the precedence is npm's, not assumed).
FAKE_NPM = r"""#!/usr/bin/env bash
pj="$(cat package.json 2>/dev/null)"
mode="$(printf '%s' "$pj" | sed -n 's/.*"fake_mode":"\([a-z]*\)".*/\1/p')"
prod="$(printf '%s' "$pj" | sed -n 's/.*"fake_mode_prod":"\([a-z]*\)".*/\1/p')"
for a in "$@"; do
  if [ "$a" = "--omit=dev" ] && [ -n "$prod" ]; then mode="$prod"; fi
done
mode="${mode:-clean}"
if [ -n "${FAKE_NPM_LOG:-}" ]; then
  log="$FAKE_NPM_LOG/$$.log"
  { echo "cwd=$(pwd)"; env | grep -i '^npm_config_' | sort; echo "--- ls"; ls -A
    if [ -f packages/a/package.json ]; then echo "--- ws"; cat packages/a/package.json; echo; fi; } > "$log"
  if [ -n "${REAL_NPM:-}" ]; then echo "--- npm config ls" >> "$log"; "$REAL_NPM" config ls >> "$log" 2>&1; fi
fi
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

# The fake pnpm reads its mode from the staged lockfile, the one file staged
# verbatim (package.json is rebuilt from its dependency fields, so a mode key
# there would be dropped). Same JSON shape as pnpm 12.21.0's `audit --json`
# (advisories + metadata.vulnerabilities); failures go to stderr only, as real
# pnpm's do (probed 2026-11-22).
FAKE_PNPM = r"""#!/usr/bin/env bash
mode="$(sed -n 's/^# fake_mode: *\([a-z]*\).*/\1/p' pnpm-lock.yaml 2>/dev/null | head -1)"
prod="$(sed -n 's/^# fake_mode_prod: *\([a-z]*\).*/\1/p' pnpm-lock.yaml 2>/dev/null | head -1)"
for a in "$@"; do
  if [ "$a" = "--prod" ] && [ -n "$prod" ]; then mode="$prod"; fi
done
mode="${mode:-clean}"
if [ -n "${FAKE_NPM_LOG:-}" ]; then
  log="$FAKE_NPM_LOG/pnpm-$$.log"
  { echo "cwd=$(pwd)"; echo "args=$*"; env | grep -E '^(npm_config_|pnpm_config_|COREPACK_|XDG_CONFIG_HOME=)' | sort
    echo "--- ls"; ls -A; echo "--- manifest"; cat package.json; echo; echo "--- workspace"; cat pnpm-workspace.yaml
    if [ -n "${XDG_CONFIG_HOME:-}" ]; then echo "--- xdg"; ls -A "$XDG_CONFIG_HOME"; fi; } > "$log"
fi
vuln() {
  printf '{"advisories":{},"metadata":{"vulnerabilities":{"info":0,"low":%s,"moderate":%s,"high":%s,"critical":%s},"dependencies":1,"devDependencies":0,"optionalDependencies":0,"totalDependencies":1}}' "$1" "$2" "$3" "$4"
}
case "$mode" in
  clean)      vuln 0 0 0 0; exit 0 ;;
  findings)   vuln 1 2 3 4; exit 1 ;;
  devonly)    vuln 0 0 0 0; exit 0 ;;
  brokenlock) printf 'Error: ERR_PNPM_BROKEN_LOCKFILE\n\n  x load the lockfile\n' >&2; exit 1 ;;
  silent)     exit 1 ;;
esac
exit 99
"""


def _make_pnpm_repo(root: Path, name: str, mode: str, *, prod_mode: str | None = None,
                    manifest_extra: dict | None = None) -> Path:
    repo = root / name
    (repo / ".git").mkdir(parents=True)
    manifest = {"name": name, "version": "1.0.0", "dependencies": {"a": "^1.0.0"},
                "devDependencies": {"b": "^2.0.0"}}
    manifest.update(manifest_extra or {})
    (repo / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    lock = f"lockfileVersion: '9.0'\n# fake_mode: {mode}\n"
    if prod_mode is not None:
        lock += f"# fake_mode_prod: {prod_mode}\n"
    (repo / "pnpm-lock.yaml").write_text(lock, encoding="utf-8")
    return repo


def _make_repo(root: Path, name: str, mode: str, *, lockfile: bool = True, prod_mode: str | None = None) -> None:
    repo = root / name
    (repo / ".git").mkdir(parents=True)
    manifest = {"name": name, "fake_mode": mode}
    if prod_mode is not None:
        manifest["fake_mode_prod"] = prod_mode
    (repo / "package.json").write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
    if lockfile:
        (repo / "package-lock.json").write_text("{}", encoding="utf-8")


def _fake_bin(tmp_path: Path) -> Path:
    bindir = tmp_path / "fakebin"
    bindir.mkdir()
    for name, body in (("npm", FAKE_NPM), ("pnpm", FAKE_PNPM), ("curl", FAKE_CURL)):
        path = bindir / name
        path.write_text(body, encoding="utf-8", newline="\n")
        path.chmod(0o755)
    return bindir


def _run(tmp_path: Path, repos: dict[str, object], *, env_extra: dict[str, str] | None = None,
         path_override: str | None = None):
    root = tmp_path / "root"
    root.mkdir()
    for name, spec in repos.items():
        if callable(spec):
            spec(root, name)
        elif isinstance(spec, tuple):
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
    _assert_unexamined(_entry(report, "nolock"), "no-lockfile")
    assert _entry(report, "nolock")["reason"] == "no-lockfile"
    assert _entry(report, "nolock")["lockfile"] is None
    assert _entry(report, "good")["lockfile"] == "package-lock.json"
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
              "uname", "cat", "dirname", "sleep", "timeout", "env", "head", "cp", "grep", "ls", "find"]
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


# ── audit 2026-11-10.2 M3: a repo .npmrc never configures the audit ──

HOSTILE_NPMRC = ("registry=http://127.0.0.1:9/\nhttps-proxy=http://127.0.0.1:9/\nproxy=http://127.0.0.1:9/\n"
                 "strict-ssl=false\ncafile=./evil.pem\nnoproxy=*\n@x:registry=http://127.0.0.1:9/\n")


def _from_bash(path: str) -> Path:
    """A path `pwd` printed under msys bash (/c/x) as a native Path (C:/x)."""
    path = path.strip()
    m = re.match(r"^/([a-zA-Z])/(.*)$", path) if IS_WINDOWS else None
    return Path(f"{m.group(1)}:/{m.group(2)}") if m else Path(path)


def _logs(log_dir: Path) -> list[str]:
    return [p.read_text(encoding="utf-8", errors="replace") for p in sorted(log_dir.glob("*.log"))]


def _real_npm() -> str | None:
    found = shutil.which("npm")
    if not found:
        return None
    if IS_WINDOWS:  # npm.cmd sits next to the `npm` sh launcher bash can run
        sh = Path(found).with_name("npm")
        return sh.as_posix() if sh.is_file() else None
    return found


@needs_jq
def test_npm_never_runs_in_the_repo_and_its_config_is_pinned(tmp_path: Path) -> None:
    log_dir = tmp_path / "npmlog"
    log_dir.mkdir()
    env = {"FAKE_NPM_LOG": log_dir.as_posix()}
    real = _real_npm()
    if real:
        env["REAL_NPM"] = real
    # The .npmrc is written by the hook below, after _make_repo created the repo.
    orig = _make_repo

    def make_with_npmrc(root: Path, name: str, mode: str, **kw) -> None:
        orig(root, name, mode, **kw)
        (root / name / ".npmrc").write_text(HOSTILE_NPMRC, encoding="utf-8")
        (root / name / "evil.pem").write_text("not a ca", encoding="utf-8")

    globals()["_make_repo"] = make_with_npmrc
    try:
        proc, report = _run(tmp_path, {"hostile": "clean"}, env_extra=env)
    finally:
        globals()["_make_repo"] = orig
    assert proc.returncode == 0, proc.stderr
    assert _entry(report, "hostile")["status"] == "ok"
    logs = _logs(log_dir)
    assert len(logs) == 2, logs  # full + --omit=dev
    for log in logs:
        cwd = _from_bash(log.splitlines()[0].removeprefix("cwd="))
        # The staged tree is removed when the script exits, so compare paths, not inodes.
        norm = (lambda q: q.as_posix().lower()) if IS_WINDOWS else (lambda q: q.as_posix())
        assert not norm(cwd).startswith(norm(tmp_path / "root")), f"npm ran inside the scanned tree: {cwd}"
        listing = log.split("--- ls\n", 1)[1].split("--- npm config ls", 1)[0].split("--- ws", 1)[0].split()
        assert ".npmrc" not in listing and "evil.pem" not in listing, listing
        assert set(listing) == {"package.json", "package-lock.json"}, listing
        assert "npm_config_registry=https://registry.npmjs.org/" in log
        assert "npm_config_strict_ssl=true" in log
        assert "npm_config_proxy=false" in log and "npm_config_https_proxy=false" in log
        assert "npm_config_ignore_scripts=true" in log
        for key in ("npm_config_userconfig=", "npm_config_globalconfig="):
            line = next(ln for ln in log.splitlines() if ln.startswith(key))
            assert line.split("=", 1)[1], f"{key} not pinned"
        if real:
            # Real npm, same cwd and env: no project config and nothing hostile resolved.
            npm_ls = log.split("--- npm config ls", 1)[1]
            assert '"project" config from' not in npm_ls, npm_ls
            assert "127.0.0.1:9" not in npm_ls and "evil.pem" not in npm_ls, npm_ls


def _lock_with_workspace(key: str) -> str:
    return json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "w", "workspaces": ["packages/*"]},
        f"node_modules/a": {"resolved": key, "link": True},
        "node_modules/lodash": {"version": "4.17.21"},
        key: {"name": "a", "version": "1.0.0"},
    }})


@needs_jq
def test_workspace_manifests_named_by_the_lockfile_are_staged(tmp_path: Path) -> None:
    log_dir = tmp_path / "npmlog"
    log_dir.mkdir()
    orig = _make_repo

    def make_ws(root: Path, name: str, mode: str, **kw) -> None:
        orig(root, name, mode, **kw)
        (root / name / "package-lock.json").write_text(_lock_with_workspace("packages/a"), encoding="utf-8")
        (root / name / "packages" / "a").mkdir(parents=True)
        (root / name / "packages" / "a" / "package.json").write_text('{"name":"a"}', encoding="utf-8")

    globals()["_make_repo"] = make_ws
    try:
        proc, report = _run(tmp_path, {"ws": "clean"}, env_extra={"FAKE_NPM_LOG": log_dir.as_posix()})
    finally:
        globals()["_make_repo"] = orig
    assert proc.returncode == 0, proc.stderr
    assert _entry(report, "ws")["status"] == "ok"
    logs = _logs(log_dir)
    assert len(logs) == 2, logs
    for log in logs:
        assert '--- ws\n{"name":"a"}' in log, log


@needs_jq
def test_a_workspace_path_outside_the_repo_is_unexamined(tmp_path: Path) -> None:
    orig = _make_repo

    def make_escape(root: Path, name: str, mode: str, **kw) -> None:
        orig(root, name, mode, **kw)
        (root / name / "package-lock.json").write_text(_lock_with_workspace("../outside"), encoding="utf-8")

    globals()["_make_repo"] = make_escape
    try:
        proc, report = _run(tmp_path, {"esc": "clean"})
    finally:
        globals()["_make_repo"] = orig
    assert proc.returncode == 4
    _assert_unexamined(_entry(report, "esc"), "workspace-path-outside-repo")


@needs_jq
@pytest.mark.skipif(IS_WINDOWS, reason="needs a real symlink, which msys cp/test -L handle differently")
def test_a_symlinked_lockfile_is_unexamined_never_read(tmp_path: Path) -> None:
    secret = tmp_path / "secret.json"
    secret.write_text("{}", encoding="utf-8")
    orig = _make_repo

    def make_link(root: Path, name: str, mode: str, **kw) -> None:
        orig(root, name, mode, **kw)
        (root / name / "package-lock.json").unlink()
        (root / name / "package-lock.json").symlink_to(secret)

    globals()["_make_repo"] = make_link
    try:
        proc, report = _run(tmp_path, {"lnk": "clean"})
    finally:
        globals()["_make_repo"] = orig
    assert proc.returncode == 4
    _assert_unexamined(_entry(report, "lnk"), "package-lock.json-not-a-regular-file")


# ── pnpm-lock.yaml repos (Steward blind-scan, 2026-11-22) ──
# The same isolation as npm: pnpm never runs in the repo, and none of the repo's
# pnpm config (pnpm-workspace.yaml, package.json "pnpm"/"packageManager",
# .npmrc, .pnpmfile.cjs) reaches the audit.

HOSTILE_WORKSPACE = ("packages:\n  - 'packages/*'\nregistry: http://127.0.0.1:9/\n"
                     "auditConfig:\n  ignoreGhsas:\n    - GHSA-xxxx-xxxx-xxxx\n")


def _pnpm(mode: str, **kw):
    return lambda root, name: _make_pnpm_repo(root, name, mode, **kw)


@pytest.fixture(scope="module")
def lockfile_kinds_run(tmp_path_factory: pytest.TempPathFactory):
    def yarn(root: Path, name: str) -> None:
        _make_repo(root, name, "clean", lockfile=False)
        (root / name / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")

    def bun(root: Path, name: str) -> None:
        _make_repo(root, name, "clean", lockfile=False)
        (root / name / "bun.lock").write_text("{}", encoding="utf-8")

    def both(root: Path, name: str) -> None:
        _make_repo(root, name, "findings")  # npm lockfile, npm fake reports findings
        (root / name / "pnpm-lock.yaml").write_text("# fake_mode: clean\n", encoding="utf-8")

    def badmanifest(root: Path, name: str) -> None:
        _make_pnpm_repo(root, name, "clean")
        (root / name / "package.json").write_text("{not json", encoding="utf-8")

    repos = {
        "pclean": _pnpm("clean"),
        "pfind": _pnpm("findings", prod_mode="devonly"),
        "pbroken": _pnpm("brokenlock"),
        "psilent": _pnpm("silent"),
        "pprodbroken": _pnpm("clean", prod_mode="brokenlock"),
        "pbadmanifest": badmanifest,
        "yarnrepo": yarn,
        "bunrepo": bun,
        "bothlocks": both,
        "nolock": ("clean", {"lockfile": False}),
    }
    return _run(tmp_path_factory.mktemp("kinds"), repos)


@needs_jq
def test_pnpm_lockfile_is_audited_with_prod_counts(lockfile_kinds_run) -> None:
    _, report = lockfile_kinds_run
    clean = _entry(report, "pclean")
    assert (clean["status"], clean["reason"], clean["lockfile"]) == ("ok", None, "pnpm-lock.yaml")
    assert all(clean[k] == 0 for k in COUNT_KEYS)
    found = _entry(report, "pfind")
    assert found["status"] == "ok"
    assert (found["critical"], found["high"], found["moderate"], found["low"], found["info"]) == (4, 3, 2, 1, 0)
    # --prod is a separate audit: dev-only findings drop out of the prod counts.
    assert (found["prod_critical"], found["prod_high"]) == (0, 0)


@needs_jq
def test_pnpm_failures_are_unexamined(lockfile_kinds_run) -> None:
    _, report = lockfile_kinds_run
    _assert_unexamined(_entry(report, "pbroken"), "full:audit-error:ERR_PNPM_BROKEN_LOCKFILE")
    _assert_unexamined(_entry(report, "psilent"), "full:audit-no-output")
    _assert_unexamined(_entry(report, "pprodbroken"), "prod:audit-error:ERR_PNPM_BROKEN_LOCKFILE")
    _assert_unexamined(_entry(report, "pbadmanifest"), "stage-manifest-unparseable")


@needs_jq
def test_lockfile_reasons_are_distinct(lockfile_kinds_run) -> None:
    proc, report = lockfile_kinds_run
    assert _entry(report, "nolock")["reason"] == "no-lockfile"
    _assert_unexamined(_entry(report, "nolock"), "no-lockfile")
    assert _entry(report, "yarnrepo")["reason"] == "unsupported-lockfile:yarn"
    _assert_unexamined(_entry(report, "yarnrepo"), "unsupported-lockfile:yarn")
    assert _entry(report, "yarnrepo")["lockfile"] == "yarn.lock"
    _assert_unexamined(_entry(report, "bunrepo"), "unsupported-lockfile:bun")
    assert proc.returncode == 3  # pfind/bothlocks findings exceed thresholds; unexamined still reported
    assert report["status"] == "error"


@needs_jq
def test_npm_lockfile_wins_over_pnpm(lockfile_kinds_run) -> None:
    _, report = lockfile_kinds_run
    both = _entry(report, "bothlocks")
    assert both["lockfile"] == "package-lock.json"
    assert (both["status"], both["critical"]) == ("ok", 4)  # the npm fake's findings, not pnpm's clean


@needs_jq
def test_pnpm_never_runs_in_the_repo_and_repo_config_never_reaches_it(tmp_path: Path) -> None:
    log_dir = tmp_path / "npmlog"
    log_dir.mkdir()

    def hostile(root: Path, name: str) -> None:
        repo = _make_pnpm_repo(root, name, "clean", manifest_extra={
            "packageManager": "pnpm@1.0.0+sha512.deadbeef",
            "devEngines": {"packageManager": {"name": "pnpm", "version": "1.0.0"}},
            "pnpm": {"auditConfig": {"ignoreGhsas": ["GHSA-xxxx-xxxx-xxxx"]}, "overrides": {"a": "9"}},
            "scripts": {"preaudit": "touch pwned"},
        })
        (repo / "pnpm-workspace.yaml").write_text(HOSTILE_WORKSPACE, encoding="utf-8")
        (repo / ".npmrc").write_text(HOSTILE_NPMRC, encoding="utf-8")
        (repo / ".pnpmfile.cjs").write_text("module.exports = {}", encoding="utf-8")
        (repo / "packages" / "a").mkdir(parents=True)
        (repo / "packages" / "a" / "package.json").write_text('{"name":"a"}', encoding="utf-8")

    proc, report = _run(tmp_path, {"hostile": hostile}, env_extra={"FAKE_NPM_LOG": log_dir.as_posix()})
    assert proc.returncode == 0, proc.stderr
    assert _entry(report, "hostile")["status"] == "ok"
    logs = [p.read_text(encoding="utf-8", errors="replace") for p in sorted(log_dir.glob("pnpm-*.log"))]
    assert len(logs) == 2, logs  # full + --prod
    assert sorted("--prod" in log.splitlines()[1] for log in logs) == [False, True]
    norm = (lambda q: q.as_posix().lower()) if IS_WINDOWS else (lambda q: q.as_posix())
    for log in logs:
        cwd = _from_bash(log.splitlines()[0].removeprefix("cwd="))
        assert not norm(cwd).startswith(norm(tmp_path / "root")), f"pnpm ran inside the scanned tree: {cwd}"
        listing = log.split("--- ls\n", 1)[1].split("--- manifest", 1)[0].split()
        assert set(listing) == {"package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml"}, listing
        manifest = json.loads(log.split("--- manifest\n", 1)[1].split("\n--- workspace", 1)[0])
        assert manifest == {"name": "hostile", "version": "1.0.0", "dependencies": {"a": "^1.0.0"},
                            "devDependencies": {"b": "^2.0.0"}}, manifest
        workspace = log.split("--- workspace\n", 1)[1].split("--- xdg", 1)[0]
        assert workspace.strip() == "packages: []", workspace
        for pin in ("pnpm_config_registry=https://registry.npmjs.org/", "pnpm_config_strict_ssl=true",
                    "pnpm_config_proxy=false", "pnpm_config_https_proxy=false", "pnpm_config_ignore_scripts=true",
                    "pnpm_config_manage_package_manager_versions=false",
                    "npm_config_registry=https://registry.npmjs.org/", "npm_config_ignore_scripts=true",
                    "COREPACK_ENABLE_PROJECT_SPEC=0", "COREPACK_ENABLE_AUTO_PIN=0"):
            assert pin in log.splitlines(), f"{pin} missing\n{log}"
        for key in ("npm_config_userconfig=", "XDG_CONFIG_HOME="):
            line = next(ln for ln in log.splitlines() if ln.startswith(key))
            assert line.split("=", 1)[1], f"{key} not pinned"
        # XDG_CONFIG_HOME is a fresh, empty, operator-owned dir.
        assert log.split("--- xdg\n", 1)[1].split() == [], log
        assert "127.0.0.1:9" not in log and "GHSA-xxxx" not in log and "deadbeef" not in log


@needs_jq
@pytest.mark.skipif(IS_WINDOWS, reason="needs a real symlink, which msys cp/test -L handle differently")
@pytest.mark.parametrize("target", ["pnpm-lock.yaml", "package.json"])
def test_a_symlinked_pnpm_file_is_unexamined_never_read(tmp_path: Path, target: str) -> None:
    secret = tmp_path / "secret"
    secret.write_text(json.dumps({"name": "s"}) + "\n# fake_mode: clean\n", encoding="utf-8")
    log_dir = tmp_path / "npmlog"
    log_dir.mkdir()

    def linked(root: Path, name: str) -> None:
        repo = _make_pnpm_repo(root, name, "clean")
        (repo / target).unlink()
        (repo / target).symlink_to(secret)

    proc, report = _run(tmp_path, {"lnk": linked}, env_extra={"FAKE_NPM_LOG": log_dir.as_posix()})
    assert proc.returncode == 4
    _assert_unexamined(_entry(report, "lnk"), f"stage-refused:{target}-not-a-regular-file")
    assert list(log_dir.glob("pnpm-*.log")) == [], "pnpm ran against a symlinked input"


@pytest.mark.skipif(IS_WINDOWS or shutil.which("jq") is None, reason="symlinked tool dir + jq needed")
def test_missing_pnpm_is_unexamined(tmp_path: Path) -> None:
    tools = _tools_dir(tmp_path, jq=True)
    assert shutil.which("pnpm", path=str(tools)) is None
    npm_only = tmp_path / "npmonly"
    npm_only.mkdir()
    for name, body in (("npm", FAKE_NPM), ("curl", FAKE_CURL)):
        (npm_only / name).write_text(body, encoding="utf-8", newline="\n")
        (npm_only / name).chmod(0o755)
    proc, report = _run(tmp_path, {"p": _pnpm("clean"), "n": "clean"},
                        path_override=f"{npm_only}{os.pathsep}{tools}")
    assert proc.returncode == 4
    _assert_unexamined(_entry(report, "p"), "pnpm-missing")
    assert _entry(report, "n")["status"] == "ok", _entry(report, "n")["reason"]


# ── item 0323e3cc: every lockfile in a repo is audited, not only the root's ──
# Measured case: nexus-realervnc deploy/op-auth-proxy/pnpm-lock.yaml (installed
# --ignore-workspace, 26 prod highs) sat beside a clean root and the repo read
# prod-clean. A repo is ok only when every package directory was examined.

def _nested_pnpm(root: Path, rel: str, mode: str, *, prod_mode: str | None = None) -> None:
    d = root / rel
    d.mkdir(parents=True, exist_ok=True)
    (d / "package.json").write_text(json.dumps({"name": d.name, "dependencies": {"a": "^1.0.0"}}),
                                    encoding="utf-8")
    lock = f"lockfileVersion: '9.0'\n# fake_mode: {mode}\n"
    if prod_mode is not None:
        lock += f"# fake_mode_prod: {prod_mode}\n"
    (d / "pnpm-lock.yaml").write_text(lock, encoding="utf-8")


def _nested_npm(root: Path, rel: str, mode: str) -> None:
    d = root / rel
    d.mkdir(parents=True, exist_ok=True)
    (d / "package.json").write_text(json.dumps({"name": d.name, "fake_mode": mode}, separators=(",", ":")),
                                    encoding="utf-8")
    (d / "package-lock.json").write_text("{}", encoding="utf-8")


@pytest.fixture(scope="module")
def nested_run(tmp_path_factory: pytest.TempPathFactory):
    def realervnc(root: Path, name: str) -> None:
        _make_repo(root, name, "clean")
        _nested_pnpm(root / name, "deploy/op-auth-proxy", "findings")

    def nestedonly(root: Path, name: str) -> None:
        (root / name / ".git").mkdir(parents=True)
        _nested_npm(root / name, "frontend", "clean")
        _nested_npm(root / name, "server", "findings")

    def nestedbroken(root: Path, name: str) -> None:
        _make_repo(root, name, "findings")
        _nested_pnpm(root / name, "tools/x", "brokenlock")

    def nestedyarn(root: Path, name: str) -> None:
        _make_repo(root, name, "clean")
        (root / name / "web").mkdir()
        (root / name / "web" / "package.json").write_text("{}", encoding="utf-8")
        (root / name / "web" / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")

    def installed(root: Path, name: str) -> None:
        # Lockfiles inside node_modules and .git are installed or VCS state, not packages.
        _make_repo(root, name, "clean")
        _nested_npm(root / name, "node_modules/dep", "enolock")
        _nested_npm(root / name, ".git/x", "enolock")

    def workspacemember(root: Path, name: str) -> None:
        # A member with a package.json and no lockfile is the root's to resolve.
        _make_repo(root, name, "clean")
        (root / name / "packages" / "a").mkdir(parents=True)
        (root / name / "packages" / "a" / "package.json").write_text("{}", encoding="utf-8")

    def nopkg(root: Path, name: str) -> None:
        (root / name / ".git").mkdir(parents=True)
        (root / name / "README.md").write_text("go repo\n", encoding="utf-8")

    def toomany(root: Path, name: str) -> None:
        _make_repo(root, name, "clean")
        for i in range(3):
            _nested_npm(root / name, f"p{i}", "clean")

    repos = {"realervnc": realervnc, "nestedonly": nestedonly, "nestedbroken": nestedbroken,
             "nestedyarn": nestedyarn, "installed": installed, "workspacemember": workspacemember,
             "nopkg": nopkg, "toomany": toomany}
    return _run(tmp_path_factory.mktemp("nested"), repos, env_extra={"MAX_PACKAGE_DIRS": "3"})


@needs_jq
def test_nested_lockfile_findings_reach_the_repo_prod_counts(nested_run) -> None:
    _, report = nested_run
    e = _entry(report, "realervnc")
    assert (e["status"], e["reason"]) == ("ok", None)
    assert e["lockfile"] == "package-lock.json"
    assert e["lockfiles"] == ["package-lock.json", "deploy/op-auth-proxy/pnpm-lock.yaml"]
    # Root clean, nested findings: the repo is NOT prod-clean.
    assert (e["prod_critical"], e["prod_high"]) == (4, 3)
    assert (e["critical"], e["high"], e["moderate"], e["low"]) == (4, 3, 2, 1)
    units = {u["path"]: u for u in e["units"]}
    assert set(units) == {".", "deploy/op-auth-proxy"}
    assert units["."]["prod_high"] == 0 and units["deploy/op-auth-proxy"]["prod_high"] == 3


@needs_jq
def test_a_repo_with_only_nested_packages_is_discovered_and_summed(nested_run) -> None:
    _, report = nested_run
    e = _entry(report, "nestedonly")
    assert e["status"] == "ok" and e["lockfile"] is None
    assert e["lockfiles"] == ["frontend/package-lock.json", "server/package-lock.json"]
    assert (e["critical"], e["high"], e["prod_critical"], e["prod_high"]) == (4, 3, 4, 3)
    assert all(r["repo"] != "nopkg" for r in report["repos"])  # no npm package anywhere: out of scope


@needs_jq
def test_one_unexamined_nested_lockfile_makes_the_repo_unexamined(nested_run) -> None:
    _, report = nested_run
    e = _entry(report, "nestedbroken")
    _assert_unexamined(e, "tools/x:full:audit-error:ERR_PNPM_BROKEN_LOCKFILE")
    units = {u["path"]: u for u in e["units"]}
    assert units["."]["status"] == "ok" and units["tools/x"]["status"] == "error"
    _assert_unexamined(_entry(report, "nestedyarn"), "web:unsupported-lockfile:yarn")
    # Totals cover wholly examined repos only: the root findings of nestedbroken stay out.
    assert report["totals"]["critical"] == 4 + 4  # realervnc nested + nestedonly server


@needs_jq
def test_installed_trees_and_workspace_members_are_not_package_dirs(nested_run) -> None:
    _, report = nested_run
    for name in ("installed", "workspacemember"):
        e = _entry(report, name)
        assert e["status"] == "ok", e
        assert e["lockfiles"] == ["package-lock.json"] and [u["path"] for u in e["units"]] == ["."]


@needs_jq
def test_a_repo_over_the_package_dir_cap_is_unexamined_not_truncated(nested_run) -> None:
    proc, report = nested_run
    _assert_unexamined(_entry(report, "toomany"), "too-many-package-dirs:4>3")
    assert proc.returncode == 3  # findings exceed thresholds; unexamined still reported
    assert report["status"] == "error"


@needs_jq
@pytest.mark.skipif(IS_WINDOWS, reason="needs a real directory symlink")
def test_a_symlinked_directory_is_never_walked(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    _nested_npm(outside, "pkg", "findings")

    def linked(root: Path, name: str) -> None:
        _make_repo(root, name, "clean")
        (root / name / "vendor").symlink_to(outside, target_is_directory=True)

    proc, report = _run(tmp_path, {"linked": linked})
    e = _entry(report, "linked")
    assert e["status"] == "ok" and e["lockfiles"] == ["package-lock.json"]
    assert proc.returncode == 0


@needs_jq
@pytest.mark.skipif(IS_WINDOWS, reason="NTFS refuses a newline in a file name")
@pytest.mark.parametrize("dirname", ["a\nb", "a‮b", "a​b", "café"])
def test_a_non_ascii_or_control_character_lockfile_path_is_unexamined(tmp_path: Path, dirname: str) -> None:
    # SC-54/SC-60: a newline would split the list; a bidi override or a
    # zero-width character would reorder or hide report and brain text.
    def hostile(root: Path, name: str) -> None:
        _make_repo(root, name, "clean")
        _nested_npm(root / name, dirname, "clean")

    proc, report = _run(tmp_path, {"hostile": hostile})
    _assert_unexamined(_entry(report, "hostile"), "unsafe-lockfile-path")
    assert proc.returncode == 4
