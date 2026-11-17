"""npm audit exceptions: one declarative, expiring, loud exception list honoured by both npm gates.

Incident ab044000 (2026-11-17): picomatch GHSA-fc5q-39xc-vjpf (HIGH ReDoS,
`<= 4.0.7`, no patched version) reached the npm advisory feed, and every repo
whose dev tooling pulls picomatch through vite/vitest (Keystone frontend/)
failed both `npm audit --audit-level=high` gates with nothing it could do.
npm has no ignore list of its own; pnpm has auditConfig.ignoreGhsas,
cargo-audit `[advisories] ignore`, pip-audit `--ignore-vuln`, audit-ci an
allowlist. `.github/npm-audit-exceptions.json` is that list, read by ONE
shell function (the `# >>> shared npm audit exceptions` block) that is
byte-identical in release-gates.yml, security-audit.yml and the fleet
template copy of security-audit.yml.

These tests prove the copies agree, then run the SHIPPED block under bash
against fixture audit reports. `npm` is a shim that prints the report it is
given and exits as told, so nothing touches the network.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import atexit
import datetime
import json
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
GATES = ROOT / ".github" / "workflows" / "release-gates.yml"
OWN_AUDIT = ROOT / ".github" / "workflows" / "security-audit.yml"
TEMPLATE_AUDIT = ROOT / "templates" / ".github" / "workflows" / "security-audit.yml"
COPIES = (GATES, OWN_AUDIT, TEMPLATE_AUDIT)

BEGIN = "# >>> shared npm audit exceptions"
END = "# <<< shared npm audit exceptions\n"

PICOMATCH = "GHSA-fc5q-39xc-vjpf"
OTHER = "GHSA-aaaa-bbbb-cccc"


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


def bash_path(p: Path) -> str:
    posix = p.resolve().as_posix()
    m = re.match(r"^([A-Za-z]):/(.*)$", posix)
    return f"/{m.group(1).lower()}/{m.group(2)}" if m else posix


def block_of(text: str) -> str:
    assert text.count(BEGIN) == 1 and text.count(END) == 1, "one marked shared block expected"
    start = text.index(BEGIN)
    return text[start:text.index(END, start) + len(END)]


def run_body(path: Path, job: str, step_name: str) -> str:
    wf = yaml.safe_load(path.read_text(encoding="utf-8"))
    [body] = [s["run"] for s in wf["jobs"][job]["steps"] if s.get("name", "").startswith(step_name)]
    return body


def gate_bodies() -> dict[Path, str]:
    return {
        GATES: run_body(GATES, "npm-audit", "Run npm audit on every manifest"),
        OWN_AUDIT: run_body(OWN_AUDIT, "npm-audit", "Audit"),
        TEMPLATE_AUDIT: run_body(TEMPLATE_AUDIT, "npm-audit", "Audit"),
    }


BLOCK = block_of(gate_bodies()[GATES])


def today() -> datetime.date:
    return datetime.datetime.now(datetime.timezone.utc).date()


def days(n: int) -> str:
    return (today() + datetime.timedelta(days=n)).isoformat()


# The real report npm 11.7 wrote for tinyglobby 0.2.15 -> fdir/picomatch 4.0.7
# (`npm audit --json --package-lock-only --audit-level=high`, exit 1, 2026-11-17).
PICOMATCH_ADVISORY = {
    "source": 1247710, "name": "picomatch", "dependency": "picomatch",
    "title": "picomatch vulnerable to ReDoS through single-branch repeated extglobs",
    "url": f"https://github.com/advisories/{PICOMATCH}", "severity": "high",
    "cwe": ["CWE-1333"], "range": "<=4.0.7",
}


def entry(name: str, severity: str, via: list) -> dict:
    return {"name": name, "severity": severity, "isDirect": False, "via": via, "effects": [],
            "range": "*", "nodes": [f"node_modules/{name}"], "fixAvailable": False}


def report(vulns: dict) -> dict:
    return {"auditReportVersion": 2, "vulnerabilities": vulns, "metadata": {"vulnerabilities": {}}}


PICOMATCH_REPORT = report({
    "fdir": entry("fdir", "high", ["picomatch"]),
    "picomatch": entry("picomatch", "high", [PICOMATCH_ADVISORY]),
    "tinyglobby": entry("tinyglobby", "high", ["fdir", "picomatch"]),
})
CLEAN = report({})


def advisory(ghsa: str, severity: str, name: str = "x") -> dict:
    return {"source": 7, "name": name, "title": f"{name} advisory", "severity": severity,
            "url": f"https://github.com/advisories/{ghsa}"}


def exception(ghsa: str = PICOMATCH, **extra) -> dict:
    return {"ghsa": ghsa, "reason": "picomatch ReDoS, devDependency via vite/vitest, not in image, no patched version",
            "expires": days(30), **extra}


@pytest.fixture
def harness(tmp_path: Path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = Path(sys.executable).as_posix()
    log = tmp_path / "calls.log"
    shims = {
        "python3": f'#!/usr/bin/env bash\nexec "{exe}" "$@"\n',
        "npm": ('#!/usr/bin/env bash\nprintf "%s|%s\\n" "$(basename "$PWD")" "$*" >> "$CALL_LOG"\n'
                '[ -n "${SHIM_REPORT:-}" ] && cat "$SHIM_REPORT"\nexit "${SHIM_EXIT:-0}"\n'),
    }
    for name, body in shims.items():
        p = bindir / name
        p.write_text(body, encoding="utf-8", newline="\n")
        p.chmod(0o755)
    repo = tmp_path / "repo"
    (repo / "frontend").mkdir(parents=True)
    (repo / ".github").mkdir()
    summary = tmp_path / "summary.md"
    summary.write_text("", encoding="utf-8")
    git_dir = Path(shutil.which("git")).resolve().parent

    def run(rep, rc: int | None = None, exceptions=None, *, raw: str | None = None, dir_: str = "frontend",
            level: str = "high", args: tuple[str, ...] = (), keep: bool = False):
        exc = repo / ".github" / "npm-audit-exceptions.json"
        if keep:
            pass
        elif raw is not None:
            exc.write_text(raw, encoding="utf-8", newline="\n")
        elif exceptions is not None:
            exc.write_text(json.dumps({"exceptions": exceptions}), encoding="utf-8", newline="\n")
        elif exc.exists():
            exc.unlink()
        env = {**os.environ, "PATH": f"{bash_path(bindir)}:{bash_path(git_dir)}:/usr/bin:/bin",
               "CALL_LOG": bash_path(log), "GITHUB_STEP_SUMMARY": bash_path(summary)}
        env.pop("SHIM_REPORT", None)
        if rep is not None:
            rp = tmp_path / "report.json"
            rp.write_text(rep if isinstance(rep, str) else json.dumps(rep), encoding="utf-8", newline="\n")
            env["SHIM_REPORT"] = bash_path(rp)
        if rc is None:
            rc = 1 if isinstance(rep, dict) and rep.get("vulnerabilities") else 0
        env["SHIM_EXIT"] = str(rc)
        quoted = " ".join("'" + a + "'" for a in args)
        script = f'set -euo pipefail\n{BLOCK}npm_audit_gate "$GATE_ROOT" \'{dir_}\' \'{level}\' {quoted}\n'
        env["GATE_ROOT"] = bash_path(repo)
        fd, path = tempfile.mkstemp(suffix=".sh", prefix="npm-exc-")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(script)
        atexit.register(lambda: os.path.exists(path) and os.remove(path))
        summary.write_text("", encoding="utf-8")
        log.write_text("", encoding="utf-8")
        proc = subprocess.run([BASH, "--noprofile", "--norc", path], cwd=repo, env=env,
                              capture_output=True, text=True, encoding="utf-8")
        proc.summary = summary.read_text(encoding="utf-8")
        proc.calls = log.read_text(encoding="utf-8").splitlines()
        proc.out = proc.stdout + proc.stderr
        return proc

    return run


# --- shape -------------------------------------------------------------------

def test_the_three_copies_are_byte_identical():
    raw = {p: block_of(p.read_text(encoding="utf-8")) for p in COPIES}
    assert len(set(raw.values())) == 1, "the shared npm audit exceptions block differs between copies"
    parsed = {p: block_of(body) for p, body in gate_bodies().items()}
    assert len(set(parsed.values())) == 1


def test_each_gate_calls_the_block_and_nothing_else_gates_npm():
    bodies = gate_bodies()
    rest = {p: b.replace(block_of(b), "") for p, b in bodies.items()}
    assert 'npm_audit_gate "$(pwd -P)" "$dir" "$NPM_AUDIT_LEVEL" --package-lock-only' in rest[GATES]
    for p in (OWN_AUDIT, TEMPLATE_AUDIT):
        assert 'npm_audit_gate "$(cd "${GITHUB_WORKSPACE:-$PWD}" && pwd -P)" "$DIR" high' in rest[p]
    for p, b in rest.items():
        assert not re.search(r"^\s*npm audit .*--audit-level", b, re.M), f"{p.name}: an npm audit gates outside the block"
        assert "npm_audit_gate()" not in b, f"{p.name}: the function is redefined outside the block"
        assert "${{" not in bodies[p], f"{p.name}: an expression is pasted into run:"


def test_the_block_reads_ids_from_the_report_only():
    code = BLOCK.split("<<'PY'", 1)[1]
    assert "package.json" not in code and ".npmrc" not in code and "auditConfig" not in code
    assert "--json" in BLOCK and "python3 -I" in BLOCK
    assert "curl" not in BLOCK and "urlopen" not in BLOCK, "the block makes no network call of its own"


# --- behaviour ---------------------------------------------------------------

def test_no_exception_file_fails_on_a_high_advisory(harness):
    proc = harness(PICOMATCH_REPORT)
    assert proc.returncode == 1, proc.out
    assert f"::error::npm audit in frontend: picomatch (high): {PICOMATCH}" in proc.out
    assert "3 package(s) at or above high: 3 failing" in proc.out


def test_an_excepted_advisory_passes_loudly(harness):
    proc = harness(PICOMATCH_REPORT, exceptions=[exception()])
    assert proc.returncode == 0, proc.out
    warn = [l for l in proc.stdout.splitlines() if l.startswith("::warning::")]
    assert len(warn) == 1 and PICOMATCH in warn[0] and days(30) in warn[0]
    assert "excuses: fdir, picomatch, tinyglobby" in warn[0] and "not in image" in warn[0]
    assert "| Advisory | Reason | Expires | Packages excused |" in proc.summary
    assert f"[{PICOMATCH}](https://github.com/advisories/{PICOMATCH})" in proc.summary
    assert "fdir, picomatch, tinyglobby" in proc.summary and days(30) in proc.summary
    assert "3 excused by exception" in proc.out


def test_npm_is_called_with_json_and_the_level_and_the_callers_args(harness):
    proc = harness(CLEAN, level="moderate", args=("--package-lock-only",))
    assert proc.returncode == 0, proc.out
    assert proc.calls == ["frontend|audit --json --audit-level=moderate --package-lock-only"]


def test_a_high_advisory_not_listed_fails_and_the_unused_exception_is_stale(harness):
    proc = harness(PICOMATCH_REPORT, exceptions=[exception(OTHER)])
    assert proc.returncode == 1, proc.out
    assert "::warning::" not in proc.out
    assert f"::notice::stale npm audit exception: {OTHER}" in proc.out
    assert f"stale npm audit exception `{OTHER}`" in proc.summary


def test_an_exception_that_matches_nothing_is_reported_stale(harness):
    proc = harness(CLEAN, exceptions=[exception()])
    assert proc.returncode == 0, proc.out
    assert f"::notice::stale npm audit exception: {PICOMATCH} excused nothing at or above high in frontend" in proc.out


def test_an_expired_exception_fails_and_is_not_honoured(harness):
    proc = harness(PICOMATCH_REPORT, exceptions=[exception(expires=days(-1))])
    assert proc.returncode == 1, proc.out
    assert f"npm audit exception {PICOMATCH} expired on {days(-1)}" in proc.out
    assert "::warning::" not in proc.out and "3 failing" in proc.out
    assert "expired on" in proc.summary


def test_an_expired_exception_fails_even_with_nothing_to_excuse(harness):
    proc = harness(CLEAN, exceptions=[exception(expires=days(-1))])
    assert proc.returncode == 1, proc.out


@pytest.mark.parametrize("offset", [0, 180])
def test_today_and_the_180_day_bound_are_valid(harness, offset):
    proc = harness(PICOMATCH_REPORT, exceptions=[exception(expires=days(offset))])
    assert proc.returncode == 0, proc.out


def test_an_exception_beyond_180_days_fails(harness):
    proc = harness(PICOMATCH_REPORT, exceptions=[exception(expires=days(181))])
    assert proc.returncode == 1, proc.out
    assert "more than 180 days out" in proc.out


@pytest.mark.parametrize("raw, why", [
    ("{not json", "not valid JSON"),
    ("[]", 'only key is "exceptions"'),
    (json.dumps({"exceptions": [], "extra": 1}), 'only key is "exceptions"'),
    (json.dumps({"exceptions": {}}), 'only key is "exceptions"'),
    ('{"exceptions": [], "exceptions": []}', "unique keys"),
    (json.dumps({"exceptions": ["GHSA-fc5q-39xc-vjpf"]}), "is not an object"),
    (json.dumps({"exceptions": [{**exception(), "severity": "high"}]}), "nothing else"),
    (json.dumps({"exceptions": [{"ghsa": PICOMATCH, "expires": "2030-01-01"}]}), "nothing else"),
    (json.dumps({"exceptions": [exception("GHSA-FC5Q-39XC-VJPF")]}), "is not a GHSA"),
    (json.dumps({"exceptions": [exception("CVE-2026-0001")]}), "is not a GHSA"),
    (json.dumps({"exceptions": [exception(reason="  ")]}), "reason must be"),
    (json.dumps({"exceptions": [exception(reason="a\n::error::forged")]}), "reason must be"),
    (json.dumps({"exceptions": [exception(reason=1)]}), "reason must be"),
    (json.dumps({"exceptions": [exception(expires="2026-13-01")]}), "is not a YYYY-MM-DD date"),
    (json.dumps({"exceptions": [exception(expires="17/12/2026")]}), "is not a YYYY-MM-DD date"),
    (json.dumps({"exceptions": [exception(), exception()]}), "listed twice"),
    (json.dumps({"exceptions": [exception(dirs=["frontend"]), exception(dirs=["."])]}), "listed twice"),
    (json.dumps({"exceptions": [exception(dirs=[])]}), "dirs must be"),
    (json.dumps({"exceptions": [exception(dirs="frontend")]}), "dirs must be"),
    (json.dumps({"exceptions": [exception(dirs=["../frontend"])]}), "not a plain relative directory"),
    (json.dumps({"exceptions": [exception(dirs=["/frontend"])]}), "not a plain relative directory"),
    (json.dumps({"exceptions": [exception(dirs=[""])]}), "not a plain relative directory"),
    (json.dumps({"exceptions": [exception(dirs=["a b"])]}), "not a plain relative directory"),
    (json.dumps({"exceptions": [exception(dirs=["frontend", "frontend/"])]}), "or a duplicate"),
])
def test_a_malformed_file_is_not_examined(harness, raw, why):
    proc = harness(PICOMATCH_REPORT, raw=raw)
    assert proc.returncode == 1, proc.out
    assert "::error::not examined:" in proc.out and why in proc.out, proc.out
    assert "**NOT EXAMINED**" in proc.summary
    assert "::warning::" not in proc.out


def test_a_malformed_file_fails_even_on_a_clean_report(harness):
    proc = harness(CLEAN, raw="{not json")
    assert proc.returncode == 1 and "not examined" in proc.out


@pytest.mark.parametrize("dirs, audit_dir, ok", [
    (["frontend"], "frontend", True),
    (["./frontend/"], "frontend", True),
    (["frontend"], ".", False),
    (["."], "frontend", False),
    (["."], ".", True),
    (["web", "frontend"], "frontend", True),
])
def test_scoped_dirs_are_honoured(harness, dirs, audit_dir, ok):
    proc = harness(PICOMATCH_REPORT, exceptions=[exception(dirs=dirs)], dir_=audit_dir)
    assert (proc.returncode == 0) == ok, proc.out


def test_transitive_via_is_followed_to_every_root_advisory(harness):
    # tinyglobby reaches picomatch (excepted) AND fdir's own high advisory (not).
    rep = report({
        "vite": entry("vite", "high", ["tinyglobby"]),
        "tinyglobby": entry("tinyglobby", "high", ["fdir", "picomatch"]),
        "fdir": entry("fdir", "high", ["picomatch", advisory(OTHER, "high", "fdir")]),
        "picomatch": entry("picomatch", "high", [PICOMATCH_ADVISORY]),
    })
    proc = harness(rep, exceptions=[exception()])
    assert proc.returncode == 1, proc.out
    failing = re.findall(r"^::error::npm audit in frontend: (\S+) ", proc.stdout, re.M)
    assert failing == ["fdir", "tinyglobby", "vite"], proc.stdout
    # Only the package whose every root advisory is excused.
    assert re.search(r"^::warning::.*; excuses: picomatch$", proc.stdout, re.M), proc.stdout
    proc = harness(rep, exceptions=[exception(), exception(OTHER)])
    assert proc.returncode == 0, proc.out
    assert "excuses: fdir, picomatch, tinyglobby, vite" in proc.stdout


def test_a_via_cycle_terminates(harness):
    rep = report({
        "a": entry("a", "high", ["b"]),
        "b": entry("b", "high", ["a", PICOMATCH_ADVISORY]),
    })
    proc = harness(rep, exceptions=[exception()])
    assert proc.returncode == 0, proc.out


def test_a_via_to_an_unlisted_package_is_not_examined(harness):
    rep = report({"vite": entry("vite", "high", ["ghost"])})
    proc = harness(rep, exceptions=[exception()])
    assert proc.returncode == 1 and "which the report does not list" in proc.out, proc.out


def test_an_advisory_below_the_level_needs_no_exception(harness):
    rep = report({"x": entry("x", "high", [PICOMATCH_ADVISORY, advisory(OTHER, "moderate")])})
    assert harness(rep, exceptions=[exception()]).returncode == 0
    # ...but at a moderate level it does.
    proc = harness(rep, exceptions=[exception()], level="moderate")
    assert proc.returncode == 1 and OTHER in proc.out


def test_an_advisory_without_a_ghsa_url_cannot_be_excepted(harness):
    adv = {**PICOMATCH_ADVISORY, "url": "https://npmjs.com/advisories/1247710"}
    proc = harness(report({"picomatch": entry("picomatch", "high", [adv])}), exceptions=[exception()])
    assert proc.returncode == 1 and "advisory source 1247710" in proc.out, proc.out


def test_findings_below_the_level_pass_without_exceptions(harness):
    rep = report({"x": entry("x", "moderate", [advisory(OTHER, "moderate")])})
    proc = harness(rep, rc=0)
    assert proc.returncode == 0, proc.out


@pytest.mark.parametrize("rep, rc, why", [
    (None, 1, "wrote no JSON report"),
    ("", 0, "wrote no JSON report"),
    ("not json", 1, "wrote no JSON report"),
    ({"error": {"code": "ENOLOCK", "summary": "This command requires an existing lockfile."}}, 1, "ENOLOCK"),
    ({"auditReportVersion": 1, "vulnerabilities": {}}, 0, "unrecognised npm audit report"),
    ({"advisories": {}}, 0, "unrecognised npm audit report"),
    (CLEAN, 1, "disagrees with its report"),
    (PICOMATCH_REPORT, 0, "disagrees with its report"),
    (CLEAN, 2, "unrecognised npm audit report"),
    (report({"x": entry("x", "severe", [])}), 1, "no known severity"),
    (report({"x": entry("x", "high", [])}), 1, "no advisory at or above high reaches it"),
])
def test_an_audit_that_did_not_run_cleanly_is_not_examined(harness, rep, rc, why):
    proc = harness(rep, rc=rc, exceptions=[exception()])
    assert proc.returncode == 1, proc.out
    assert "::error::not examined:" in proc.out and why in proc.out, proc.out


def test_an_unknown_level_is_not_examined(harness):
    proc = harness(CLEAN, level="medium")
    assert proc.returncode == 1 and "not one of info" in proc.out


def test_pr_controlled_text_cannot_forge_a_workflow_command(harness):
    reason = "100% safe ::error::x | `y` <b>z</b>"
    proc = harness(PICOMATCH_REPORT, exceptions=[exception(reason=reason)])
    assert proc.returncode == 0, proc.out
    [warn] = [l for l in proc.stdout.splitlines() if l.startswith("::warning::")]
    assert "100%25 safe" in warn
    assert "&lt;b&gt;" in proc.summary and "\\|" in proc.summary and "`y`" not in proc.summary


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_a_symlinked_exception_file_is_not_examined(harness, tmp_path):
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({"exceptions": [exception()]}), encoding="utf-8")
    (tmp_path / "repo" / ".github" / "npm-audit-exceptions.json").symlink_to(target)
    proc = harness(PICOMATCH_REPORT, keep=True)
    assert proc.returncode == 1 and "is not a regular file inside the checkout" in proc.out, proc.out


# --- the shipped steps, end to end -------------------------------------------

def step_env(tmp_path: Path, rep: dict, rc: int) -> dict:
    """PATH with python3 and an npm that answers `ci` with success and every
    audit with `rep` and exit `rc`."""
    bindir = tmp_path / "stepbin"
    bindir.mkdir()
    rp = tmp_path / "step-report.json"
    rp.write_text(json.dumps(rep), encoding="utf-8")
    exe = Path(sys.executable).as_posix()
    for name, body in {
        "python3": f'#!/usr/bin/env bash\nexec "{exe}" "$@"\n',
        "npm": f'#!/usr/bin/env bash\n[ "$1" = ci ] && exit 0\ncat "{bash_path(rp)}"\nexit {rc}\n',
    }.items():
        p = bindir / name
        p.write_text(body, encoding="utf-8", newline="\n")
        p.chmod(0o755)
    summary = tmp_path / "step-summary.md"
    summary.write_text("", encoding="utf-8")
    git_dir = Path(shutil.which("git")).resolve().parent
    return {**os.environ, "PATH": f"{bash_path(bindir)}:{bash_path(git_dir)}:/usr/bin:/bin",
            "GITHUB_STEP_SUMMARY": bash_path(summary), "RUNNER_TEMP": bash_path(tmp_path),
            "NPM_AUDIT_LEVEL": "high", "_summary": str(summary)}


def run_step(body: str, cwd: Path, env: dict) -> subprocess.CompletedProcess:
    fd, path = tempfile.mkstemp(suffix=".sh", prefix="npm-exc-step-")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)
    atexit.register(lambda: os.path.exists(path) and os.remove(path))
    return subprocess.run([BASH, "--noprofile", "--norc", path], cwd=cwd, env=env,
                          capture_output=True, text=True, encoding="utf-8")


def keystone_repo(tmp_path: Path, exceptions: list | None) -> Path:
    repo = tmp_path / "ks"
    files = {"frontend/package.json": json.dumps({"devDependencies": {"vite": "6.4.6"}}),
             "frontend/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {"": {}}})}
    if exceptions is not None:
        files[".github/npm-audit-exceptions.json"] = json.dumps({"exceptions": exceptions})
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text, encoding="utf-8", newline="\n")
    subprocess.run(["git", "-C", str(repo), "add", "-f", "--", *files], check=True)
    return repo


@pytest.mark.parametrize("exceptions, ok", [(None, False), ([exception(dirs=["frontend"])], True)])
def test_release_gates_step_honours_the_file(tmp_path, exceptions, ok):
    repo = keystone_repo(tmp_path, exceptions)
    env = step_env(tmp_path, PICOMATCH_REPORT, 1)
    wf = yaml.safe_load(GATES.read_text(encoding="utf-8"))
    [detect] = [s["run"] for s in wf["jobs"]["npm-audit"]["steps"] if s.get("name") == "Detect npm manifests"]
    assert run_step(detect, repo, env).returncode == 0
    proc = run_step(gate_bodies()[GATES], repo, env)
    assert (proc.returncode == 0) == ok, proc.stdout + proc.stderr
    summary = Path(env["_summary"]).read_text(encoding="utf-8")
    assert ("`frontend`: clean at high" in summary) == ok
    assert (PICOMATCH in summary) == ok


@pytest.mark.parametrize("path", [OWN_AUDIT, TEMPLATE_AUDIT], ids=lambda p: p.relative_to(ROOT).as_posix())
@pytest.mark.parametrize("exceptions, ok", [(None, False), ([exception(dirs=["frontend"])], True),
                                            ([exception(dirs=["."])], False)])
def test_security_audit_step_honours_the_file(tmp_path, path, exceptions, ok):
    repo = keystone_repo(tmp_path, exceptions)
    env = {**step_env(tmp_path, PICOMATCH_REPORT, 1), "DIR": "frontend", "GITHUB_WORKSPACE": bash_path(repo)}
    proc = run_step(gate_bodies()[path], repo / "frontend", env)
    assert (proc.returncode == 0) == ok, proc.stdout + proc.stderr
