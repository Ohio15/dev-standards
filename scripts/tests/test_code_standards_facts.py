"""code-standards-facts.py: the Prometheus textfile contract Steward consumes.

Synthetic inputs under tmp_path (roster, mirror status, hygiene report, npm
audit report); the exporter's output is compared line for line against the
contract: series and label shapes, the scanned gate, the check allow-list,
the npm success requirement, the size budget, and the atomic write.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "code-standards-facts.py"
spec = importlib.util.spec_from_file_location("cs_facts", SCRIPT)
facts = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(facts)

SHA = "a" * 40
SERIES_RE = re.compile(
    r'^(code_standards_[a-z_]+)(\{repo="[a-z0-9][a-z0-9._-]{0,63}"(,(check|severity)="[a-z0-9-]+")?\})? (\d+)$'
)


def finding(code: str, severity: str = "MEDIUM") -> dict:
    return {"code": code, "severity": severity}


class Estate:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.mirror = tmp_path / "repos"
        self.mirror.mkdir()
        self.roster = tmp_path / "roster.txt"
        self.status = tmp_path / "status.txt"
        self.report = tmp_path / "hygiene.json"
        self.npm = tmp_path / "npm.json"
        self.out_dir = tmp_path / "textfile"
        self.out_dir.mkdir()
        self.out = self.out_dir / "code_standards.prom"

    def repo_dir(self, name: str, package_json: bool = False) -> str:
        d = self.mirror / name
        d.mkdir(exist_ok=True)
        if package_json:
            (d / "package.json").write_text("{}", encoding="utf-8")
        return str(d)

    def write(self, roster: str, status: str, repos: list[dict], npm: list[dict] | None = None) -> None:
        self.roster.write_text(roster, encoding="utf-8")
        self.status.write_text(status, encoding="utf-8")
        self.report.write_text(json.dumps({"repos": repos}), encoding="utf-8")
        if npm is not None:
            self.npm.write_text(json.dumps({"repos": npm}), encoding="utf-8")

    def run(self, npm: bool = True) -> int:
        argv = ["--roster", str(self.roster), "--mirror-status", str(self.status),
                "--hygiene-report", str(self.report), "--output", str(self.out)]
        if npm:
            argv += ["--npm-audit", str(self.npm)]
        return facts.main(argv)

    def series(self) -> dict[str, int]:
        out = {}
        for line in self.out.read_text(encoding="ascii").splitlines():
            if line.startswith("#"):
                continue
            name, value = line.rsplit(" ", 1)
            out[name] = int(value)
        return out


@pytest.fixture()
def estate(tmp_path: Path) -> Estate:
    return Estate(tmp_path)


def standard(estate: Estate) -> None:
    estate.write(
        roster="# comment\nSteward-Core\nAPM  # trailing comment\nghost\nstale\n",
        status=f"steward-core ok {SHA}\napm ok {SHA}\nghost fail -\nstale fail -\n",
        repos=[
            {"name": "steward-core", "path": estate.repo_dir("steward-core"),
             "findings": [finding("stub-marker"), finding("tests-undeclared", "LOW"),
                          finding("idle-repo", "LOW"), finding("hooks-path-misconfigured")]},
            {"name": "apm", "path": estate.repo_dir("apm", package_json=True),
             "findings": [finding("version-divergence"), finding("independence-runbook-missing", "HIGH")]},
            # present in the report but its mirror refresh failed this run
            {"name": "stale", "path": estate.repo_dir("stale"), "findings": [finding("stub-marker")]},
            {"name": "repos [layout]", "path": str(estate.mirror), "findings": [finding("layout-orphan")]},
        ],
        npm=[{"repo": "apm", "path": "/x/apm", "status": "ok", "prod_critical": 2, "prod_high": 0}],
    )


def test_contract_output_end_to_end(estate: Estate, monkeypatch: pytest.MonkeyPatch) -> None:
    standard(estate)
    monkeypatch.setattr(facts.time, "time", lambda: 1762790400.7)
    assert estate.run() == 0
    text = estate.out.read_text(encoding="ascii")
    body = [line for line in text.splitlines() if not line.startswith("#")]
    assert body == [
        'code_standards_repo_scanned{repo="apm"} 1',
        'code_standards_repo_scanned{repo="ghost"} 0',
        'code_standards_repo_scanned{repo="stale"} 0',
        'code_standards_repo_scanned{repo="steward-core"} 1',
        'code_standards_violation{repo="apm",check="s13-release-runbook"} 1',
        'code_standards_violation{repo="apm",check="s3-version-sync"} 1',
        'code_standards_violation{repo="steward-core",check="no-stubs"} 1',
        'code_standards_violation{repo="steward-core",check="s2-tests-declared"} 1',
        'code_standards_deps_scanned{repo="apm"} 1',
        'code_standards_deps_prod_vulns{repo="apm",severity="critical"} 2',
        "code_standards_last_run_timestamp_seconds 1762790400",
    ]


def test_format_rules(estate: Estate) -> None:
    standard(estate)
    assert estate.run() == 0
    raw = estate.out.read_bytes()
    assert b"\r" not in raw and raw.endswith(b"\n")
    raw.decode("ascii")
    names_seen: set[str] = set()
    help_lines = type_lines = 0
    series_keys: list[str] = []
    for line in raw.decode("ascii").splitlines():
        if line.startswith("# HELP "):
            help_lines += 1
            continue
        if line.startswith("# TYPE "):
            _, _, name, kind = line.split(" ")
            assert kind == "gauge"
            assert name not in names_seen
            names_seen.add(name)
            type_lines += 1
            continue
        m = SERIES_RE.match(line)
        assert m, line
        series_keys.append(line.rsplit(" ", 1)[0])
    assert help_lines == type_lines == 5
    assert len(series_keys) == len(set(series_keys))
    assert raw.decode("ascii").splitlines()[-1].startswith("code_standards_last_run_timestamp_seconds ")


def test_every_roster_repo_appears_even_when_absent_everywhere(estate: Estate) -> None:
    estate.write(roster="a\nb\n", status="", repos=[])
    assert estate.run(npm=False) == 0
    s = estate.series()
    assert s['code_standards_repo_scanned{repo="a"}'] == 0
    assert s['code_standards_repo_scanned{repo="b"}'] == 0


def test_unmapped_codes_never_export(estate: Estate) -> None:
    local_state = ["hooks-path-legacy", "hooks-path-misconfigured", "stale-working-tree", "hook-missing",
                   "idle-repo", "noise-files", "layout-worktree", "submodule-pointer-lag",
                   "auto-apply-cache-restore", "independence-unexamined", "independence-mode-invalid"]
    estate.write(roster="r\n", status=f"r ok {SHA}\n",
                 repos=[{"name": "r", "path": estate.repo_dir("r"), "findings": [finding(c) for c in local_state]}])
    assert estate.run(npm=False) == 0
    assert not any(k.startswith("code_standards_violation") for k in estate.series())


def test_every_mapped_code_exports_its_check(estate: Estate) -> None:
    estate.write(roster="r\n", status=f"r ok {SHA}\n",
                 repos=[{"name": "r", "path": estate.repo_dir("r"),
                         "findings": [finding(c) for c in facts.CHECK_MAP]}])
    assert estate.run(npm=False) == 0
    got = {k for k in estate.series() if k.startswith("code_standards_violation")}
    assert got == {f'code_standards_violation{{repo="r",check="{c}"}}' for c in facts.CHECK_MAP.values()}


def test_npm_entry_without_ok_status_is_not_scanned(estate: Estate) -> None:
    # npm-audit-weekly.sh today writes zeros for an errored audit and no status
    # field: indistinguishable from clean, so it must read as not scanned.
    estate.write(roster="web\n", status=f"web ok {SHA}\n",
                 repos=[{"name": "web", "path": estate.repo_dir("web", package_json=True), "findings": []}],
                 npm=[{"repo": "web", "critical": 0, "high": 0, "prod_critical": 0, "prod_high": 0}])
    assert estate.run() == 0
    s = estate.series()
    assert s['code_standards_deps_scanned{repo="web"}'] == 0
    assert not any(k.startswith("code_standards_deps_prod_vulns") for k in s)


def test_missing_npm_report_and_unparseable_npm_report(estate: Estate) -> None:
    estate.write(roster="web\n", status=f"web ok {SHA}\n",
                 repos=[{"name": "web", "path": estate.repo_dir("web", package_json=True), "findings": []}])
    assert estate.run(npm=False) == 0
    assert estate.series()['code_standards_deps_scanned{repo="web"}'] == 0
    estate.npm.write_text('{"critical":,}', encoding="utf-8")  # what the script emits when npm is absent
    assert estate.run() == 0
    assert estate.series()['code_standards_deps_scanned{repo="web"}'] == 0


def test_deps_series_only_for_repos_with_root_package_json(estate: Estate) -> None:
    estate.write(roster="lib\n", status=f"lib ok {SHA}\n",
                 repos=[{"name": "lib", "path": estate.repo_dir("lib"), "findings": []}],
                 npm=[{"repo": "lib", "status": "ok", "prod_critical": 1, "prod_high": 1}])
    assert estate.run() == 0
    assert not any(k.startswith("code_standards_deps") for k in estate.series())


def test_zero_vuln_counts_are_omitted(estate: Estate) -> None:
    estate.write(roster="web\n", status=f"web ok {SHA}\n",
                 repos=[{"name": "web", "path": estate.repo_dir("web", package_json=True), "findings": []}],
                 npm=[{"repo": "web", "status": "ok", "prod_critical": 0, "prod_high": 4}])
    assert estate.run() == 0
    s = estate.series()
    assert s['code_standards_deps_scanned{repo="web"}'] == 1
    assert s['code_standards_deps_prod_vulns{repo="web",severity="high"}'] == 4
    assert 'code_standards_deps_prod_vulns{repo="web",severity="critical"}' not in s


@pytest.mark.parametrize("roster,status", [
    ("Bad Name\n", ""),
    ("UPPER\nupper\n", ""),
    ("ok\n", "ok maybe -\n"),
    ("ok\n", "ok ok -\n"),
    ("# only comments\n", ""),
])
def test_invalid_inputs_write_nothing(estate: Estate, roster: str, status: str) -> None:
    estate.write(roster=roster, status=status, repos=[])
    assert estate.run(npm=False) == facts.EXIT_INVALID_INPUT
    assert not estate.out.exists()


def test_unreadable_hygiene_report_writes_nothing(estate: Estate) -> None:
    estate.write(roster="r\n", status=f"r ok {SHA}\n", repos=[])
    estate.report.write_text("not json", encoding="utf-8")
    assert estate.run(npm=False) == facts.EXIT_INVALID_INPUT
    assert not estate.out.exists()


def test_budget_exceeded_writes_nothing_and_keeps_previous(estate: Estate, monkeypatch: pytest.MonkeyPatch) -> None:
    estate.out.write_text("previous\n", encoding="ascii")
    roster = "".join(f"r{i}\n" for i in range(1100))
    estate.write(roster=roster, status="", repos=[])
    assert estate.run(npm=False) == facts.EXIT_BUDGET
    assert estate.out.read_text(encoding="ascii") == "previous\n"
    monkeypatch.setattr(facts, "MAX_BYTES", 100)
    estate.write(roster="r\n", status="", repos=[])
    assert estate.run(npm=False) == facts.EXIT_BUDGET


def test_write_is_atomic_and_leaves_no_temp(estate: Estate, monkeypatch: pytest.MonkeyPatch) -> None:
    standard(estate)
    estate.out.write_text("previous\n", encoding="ascii")

    def boom(src, dst):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(facts.os, "replace", boom)
    with pytest.raises(OSError):
        estate.run()
    assert estate.out.read_text(encoding="ascii") == "previous\n"
    assert sorted(p.name for p in estate.out_dir.iterdir()) == ["code_standards.prom"]
    monkeypatch.undo()
    assert estate.run() == 0
    assert sorted(p.name for p in estate.out_dir.iterdir()) == ["code_standards.prom"]
    if sys.platform != "win32":
        assert (os.stat(estate.out).st_mode & 0o777) == 0o644


@pytest.mark.parametrize("code", ["stub-marker-unexamined", "independence-unexamined", "version-unexamined"])
def test_a_check_that_did_not_run_exports_the_repo_as_not_scanned(estate: Estate, code: str) -> None:
    # Security gate pass 1, SC-07: "did not run" must never export as clean.
    estate.write(
        roster="steward-core\n",
        status=f"steward-core ok {SHA}\n",
        repos=[{"name": "steward-core", "path": estate.repo_dir("steward-core"),
                "findings": [finding("stub-marker"), finding(code, "LOW")]}],
    )
    assert estate.run() == 0
    body = [line for line in estate.out.read_text(encoding="ascii").splitlines() if not line.startswith("#")]
    assert 'code_standards_repo_scanned{repo="steward-core"} 0' in body
    assert not any(line.startswith("code_standards_violation") for line in body)


def test_an_npm_error_entry_with_null_counts_reads_as_not_scanned(estate: Estate) -> None:
    # npm-audit-weekly.sh (fix/audit-unexamined, 2e17bd88): exit 4, status "error", null counts.
    estate.write(
        roster="apm" + chr(10) + "web" + chr(10),
        status=f"apm ok {SHA}" + chr(10) + f"web ok {SHA}" + chr(10),
        repos=[
            {"name": "apm", "path": estate.repo_dir("apm", package_json=True), "findings": []},
            {"name": "web", "path": estate.repo_dir("web", package_json=True), "findings": []},
        ],
        npm=[
            {"repo": "apm", "path": "/x/apm", "status": "error", "reason": "ENOLOCK",
             "prod_critical": None, "prod_high": None},
            {"repo": "web", "path": "/x/web", "status": "ok", "prod_critical": 0, "prod_high": 1},
        ],
    )
    assert estate.run() == 0
    body = [line for line in estate.out.read_text(encoding="ascii").splitlines() if not line.startswith("#")]
    assert 'code_standards_deps_scanned{repo="apm"} 0' in body
    assert 'code_standards_deps_scanned{repo="web"} 1' in body
    assert 'code_standards_deps_prod_vulns{repo="web",severity="high"} 1' in body
    assert not any('deps_prod_vulns{repo="apm"' in line for line in body)
