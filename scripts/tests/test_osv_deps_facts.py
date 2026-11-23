"""osv-deps-facts.py: the code_deps.prom contract and its fail-closed rules.

The scanner is replaced by an executable test double whose output shapes and
exit codes were copied from the real OSV-Scanner 2.7.1 on NEXUS (2026-11-23:
exit 0 = none, 1 = advisories, 128 = no manifest, 127 = error; groups[] with
ids/aliases/max_severity, empty max_severity on GO-/RUSTSEC- advisories). The
real binary is exercised by the deploy verification, not here.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "osv-deps-facts.py"
spec = importlib.util.spec_from_file_location("osv_facts", SCRIPT)
osv = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(osv)

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the scanner double is a POSIX executable")

SHA = "b" * 40
SERIES_RE = re.compile(
    r'^(code_deps_[a-z_]+)(\{repo="[a-z0-9][a-z0-9._-]{0,63}"'
    r'(,ecosystem="[a-z0-9][a-z0-9._-]{0,31}")?(,severity="(critical|high|medium|low|unknown)")?\})? (\d+)$'
)

# The double: prints the version, or replays <repo>/.osv-double.json
# ({"rc": int, "out": <json or raw string>, "sleep": seconds}).
DOUBLE = r'''#!/usr/bin/env python3
import json, os, sys, time
if sys.argv[1:] == ["--version"]:
    print("osv-scanner version: " + os.environ.get("DOUBLE_VERSION", "VERSION"))
    print("osv-scalibr version: 0.5.3")
    sys.exit(0)
assert sys.argv[1:3] == ["scan", "source"], sys.argv
for flag in ("--offline", "--no-resolve", "--no-call-analysis=all", "--all-packages", "--recursive"):
    assert flag in sys.argv, flag
assert os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"), "db dir not passed"
assert "GITHUB_TOKEN" not in os.environ and "GH_TOKEN" not in os.environ
assert "/usr/local/bin" not in os.environ["PATH"].split(":"), "Go toolchain dir on PATH"
with open(os.path.join(os.environ["DOUBLE_LOG"], "calls"), "a") as fh:
    fh.write(os.getcwd() + "\t" + sys.argv[-1] + "\n")
spec = json.load(open(os.path.join(sys.argv[-1], ".osv-double.json")))
time.sleep(spec.get("sleep", 0))
out = spec.get("out", "")
sys.stdout.write(out if isinstance(out, str) else json.dumps(out))
sys.stderr.write("End status: double\n")
sys.exit(spec["rc"])
'''


def pkg(eco: str, name: str, version: str, groups: list[dict] | None = None) -> dict:
    p: dict = {"package": {"name": name, "version": version, "ecosystem": eco}}
    if groups is not None:
        p["groups"] = groups
        p["vulnerabilities"] = [{"id": g["ids"][0]} for g in groups]
    return p


def grp(ident: str, sev: str = "", aliases: list[str] | None = None) -> dict:
    return {"ids": [ident], "aliases": aliases or [ident], "max_severity": sev}


def result(path: str, packages: list[dict]) -> dict:
    return {"source": {"path": path, "type": "lockfile"}, "packages": packages}


class Estate:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: str = "2.7.1") -> None:
        self.tmp = tmp_path
        self.mirror = tmp_path / "repos"
        self.mirror.mkdir()
        self.roster = tmp_path / "roster.txt"
        self.status = tmp_path / "status.txt"
        self.pin = tmp_path / "osv-scanner.version"
        self.pin.write_text("2.7.1\n", encoding="utf-8")
        self.mirrors = tmp_path / "osv-mirrors.txt"
        self.mirrors.write_text("# none\n", encoding="utf-8")
        self.out_dir = tmp_path / "textfile"
        self.out_dir.mkdir()
        self.out = self.out_dir / "code_deps.prom"
        self.report = tmp_path / "osv-report.json"
        self.db = tmp_path / "db"
        self.log = tmp_path / "log"
        self.log.mkdir()
        self.binary = tmp_path / "bin" / "osv-scanner"
        self.binary.parent.mkdir()
        self.binary.write_text(DOUBLE, encoding="utf-8")
        self.binary.chmod(self.binary.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setenv("DOUBLE_VERSION", version)
        monkeypatch.setenv("DOUBLE_LOG", str(self.log))
        monkeypatch.setenv("GITHUB_TOKEN", "must-not-reach-the-scanner")
        # The scrubbed env drops DOUBLE_*; re-add them for the double only.
        real_env = osv.scanner_env

        def env(db_dir: Path, home: Path) -> dict:
            e = real_env(db_dir, home)
            e["PATH"] = os.path.dirname(sys.executable) + ":" + e["PATH"]
            e["DOUBLE_VERSION"] = version
            e["DOUBLE_LOG"] = str(self.log)
            return e

        monkeypatch.setattr(osv, "scanner_env", env)

    def repo(self, name: str, rc: int, out: object = "", sleep: float = 0) -> None:
        d = self.mirror / name
        d.mkdir()
        (d / ".osv-double.json").write_text(json.dumps({"rc": rc, "out": out, "sleep": sleep}), encoding="utf-8")

    def write(self, roster: list[str], ok: list[str]) -> None:
        self.roster.write_text("".join(f"{r}\n" for r in roster), encoding="utf-8")
        self.status.write_text("".join(f"{r} {'ok ' + SHA if r in ok else 'fail -'}\n" for r in roster),
                               encoding="utf-8")

    def run(self, *extra: str) -> int:
        return osv.main([
            "--roster", str(self.roster), "--mirror", str(self.mirror), "--mirror-status", str(self.status),
            "--osv-scanner", str(self.binary), "--db-dir", str(self.db), "--output", str(self.out),
            "--report", str(self.report), "--pin-file", str(self.pin), "--mirrors", str(self.mirrors), *extra,
        ])

    def series(self) -> dict[str, int]:
        text = self.out.read_text(encoding="ascii")
        assert text.endswith("\n") and "\r" not in text
        out: dict[str, int] = {}
        for line in text.splitlines():
            if line.startswith("#"):
                continue
            m = SERIES_RE.match(line)
            assert m, f"line outside the contract: {line!r}"
            key = line.rsplit(" ", 1)[0]
            assert key not in out, f"series twice: {key}"
            out[key] = int(m.group(6))
        assert text.splitlines()[-1].startswith("code_deps_last_run_timestamp_seconds ")
        return out


@pytest.fixture
def estate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Estate:
    return Estate(tmp_path, monkeypatch)


def test_counts_packages_and_advisories_by_ecosystem_and_severity(estate: Estate) -> None:
    estate.repo("svc", 1, {"results": [
        result("/m/svc/Cargo.lock", [
            pkg("crates.io", "rsa", "0.9.10", [grp("RUSTSEC-2023-0071", "5.9", ["CVE-2023-49092"])]),
            pkg("crates.io", "serde", "1.0.0"),
        ]),
        result("/m/svc/web/package-lock.json", [
            pkg("npm", "a", "1.0.0", [grp("GHSA-aaaa", "9.8"), grp("GHSA-bbbb", "7.5")]),
            pkg("npm", "b", "2.0.0", [grp("GHSA-cccc", "")]),
        ]),
    ]})
    estate.write(["svc"], ["svc"])
    assert estate.run() == 0
    s = estate.series()
    assert s['code_deps_repo_scanned{repo="svc"}'] == 1
    assert s['code_deps_packages{repo="svc",ecosystem="crates.io"}'] == 2
    assert s['code_deps_packages{repo="svc",ecosystem="npm"}'] == 2
    assert s['code_deps_vulns{repo="svc",ecosystem="crates.io",severity="medium"}'] == 1
    assert s['code_deps_vulns{repo="svc",ecosystem="npm",severity="critical"}'] == 1
    assert s['code_deps_vulns{repo="svc",ecosystem="npm",severity="high"}'] == 1
    assert s['code_deps_vulns{repo="svc",ecosystem="npm",severity="unknown"}'] == 1
    report = json.loads(estate.report.read_text(encoding="utf-8"))
    adv = report["repos"]["svc"]["advisories"]
    assert [a["ids"][0] for a in adv][:1] == ["GHSA-aaaa"]
    assert report["scanner"] == "osv-scanner 2.7.1"


def test_same_package_in_two_lockfiles_counts_once(estate: Estate) -> None:
    dup = pkg("npm", "a", "1.0.0", [grp("GHSA-aaaa", "7.0")])
    estate.repo("svc", 1, {"results": [result("/x/package-lock.json", [dup]), result("/y/package-lock.json", [dup])]})
    estate.write(["svc"], ["svc"])
    assert estate.run() == 0
    s = estate.series()
    assert s['code_deps_packages{repo="svc",ecosystem="npm"}'] == 1
    assert s['code_deps_vulns{repo="svc",ecosystem="npm",severity="high"}'] == 1


def test_clean_repo_is_a_confirmed_examination(estate: Estate) -> None:
    estate.repo("clean", 0, {"results": [result("/m/clean/go.mod", [pkg("Go", "golang.org/x/net", "0.40.0")])]})
    estate.write(["clean"], ["clean"])
    assert estate.run() == 0
    s = estate.series()
    assert s['code_deps_repo_scanned{repo="clean"}'] == 1
    assert s['code_deps_packages{repo="clean",ecosystem="go"}'] == 1
    assert not any(k.startswith("code_deps_vulns") for k in s)


def test_no_manifest_is_scanned_with_no_packages(estate: Estate) -> None:
    estate.repo("docs", 128, "")
    estate.write(["docs"], ["docs"])
    assert estate.run() == 0
    s = estate.series()
    assert s['code_deps_repo_scanned{repo="docs"}'] == 1
    assert not any(k.startswith("code_deps_packages") for k in s)


@pytest.mark.parametrize("rc,out", [
    (127, "boom"),                               # scanner error
    (1, "not json"),                             # unparseable
    (1, {"results": "x"}),                       # wrong shape
    (1, {"results": [result("/p", [pkg("npm", "a", "1")])]}),  # exit 1, no advisory: disagreement
    (2, {"results": []}),                        # undocumented exit code
])
def test_anything_short_of_a_completed_scan_is_not_scanned(estate: Estate, rc: int, out: object) -> None:
    estate.repo("bad", rc, out)
    estate.repo("good", 0, {"results": []})
    estate.write(["bad", "good"], ["bad", "good"])
    assert estate.run() == 0
    s = estate.series()
    assert s['code_deps_repo_scanned{repo="bad"}'] == 0
    assert s['code_deps_repo_scanned{repo="good"}'] == 1
    assert not any('repo="bad",' in k for k in s)
    report = json.loads(estate.report.read_text(encoding="utf-8"))
    assert report["repos"]["bad"]["status"] == "error"


def test_timeout_is_not_scanned(estate: Estate) -> None:
    estate.repo("slow", 0, {"results": []}, sleep=5)
    estate.write(["slow"], ["slow"])
    assert estate.run("--timeout", "1") == 0
    assert estate.series()['code_deps_repo_scanned{repo="slow"}'] == 0


def test_mirror_not_refreshed_is_not_scanned_and_never_invoked(estate: Estate) -> None:
    estate.repo("stale", 0, {"results": []})
    estate.write(["stale"], [])
    assert estate.run() == 0
    assert estate.series()['code_deps_repo_scanned{repo="stale"}'] == 0
    assert not (estate.log / "calls").exists()


def test_wrong_scanner_version_exports_every_repo_as_not_scanned(tmp_path: Path, monkeypatch) -> None:
    e = Estate(tmp_path, monkeypatch, version="2.6.0")
    e.repo("svc", 0, {"results": []})
    e.write(["svc"], ["svc"])
    assert e.run() == 0
    assert e.series()['code_deps_repo_scanned{repo="svc"}'] == 0
    assert not (e.log / "calls").exists()


def test_scanner_runs_outside_the_repo_with_a_scrubbed_env(estate: Estate) -> None:
    estate.repo("svc", 0, {"results": []})
    estate.write(["svc"], ["svc"])
    assert estate.run() == 0  # the double asserts flags, db dir and no GitHub token
    cwd, target = (estate.log / "calls").read_text().strip().split("\t")
    assert not Path(cwd).resolve().is_relative_to((estate.mirror / "svc").resolve())
    assert Path(target) == estate.mirror / "svc"


def test_hostile_ecosystem_label_is_normalised(estate: Estate) -> None:
    estate.repo("svc", 1, {"results": [result("/p", [pkg('Ubuntu:22.04"}x', "openssl", "3", [grp("X-1", "8")])])]})
    estate.write(["svc"], ["svc"])
    assert estate.run() == 0
    s = estate.series()  # every line matched the contract regex
    assert s['code_deps_vulns{repo="svc",ecosystem="ubuntu-22.04--x",severity="high"}'] == 1


def test_invalid_roster_writes_nothing(estate: Estate) -> None:
    estate.roster.write_text("Bad Name\n", encoding="utf-8")
    estate.status.write_text("", encoding="utf-8")
    assert estate.run() == osv.EXIT_INVALID_INPUT
    assert not estate.out.exists()


def test_budget_exceeded_writes_nothing(estate: Estate, monkeypatch) -> None:
    estate.repo("svc", 0, {"results": []})
    estate.write(["svc"], ["svc"])
    monkeypatch.setattr(osv, "MAX_LINES", 3)
    assert estate.run() == osv.EXIT_BUDGET
    assert not estate.out.exists()


@pytest.mark.parametrize("raw,bucket", [
    ("9.8", "critical"), ("9.0", "critical"), ("8.9", "high"), ("7.0", "high"), ("6.9", "medium"),
    ("4.0", "medium"), ("3.9", "low"), ("0.1", "low"), ("0", "unknown"), ("", "unknown"),
    (None, "unknown"), ("CVSS:3.1/AV:N", "unknown"), ("11", "unknown"),
])
def test_severity_buckets(raw, bucket) -> None:
    assert osv.severity_of(raw) == bucket


def test_mirror_is_labelled_and_its_advisories_still_exported(estate: Estate) -> None:
    estate.repo("frozen", 1, {"results": [result("/m/frozen/go.mod", [
        pkg("Go", "github.com/labstack/echo/v4", "4.11.1", [grp("GHSA-cxf3-9h37-7rr8", "9.1")])])]})
    estate.repo("live", 0, {"results": []})
    estate.write(["frozen", "live"], ["frozen", "live"])
    estate.mirrors.write_text("# kept on purpose\nFrozen\n", encoding="utf-8")
    assert estate.run() == 0
    s = estate.series()
    assert s['code_deps_repo_mirror{repo="frozen"}'] == 1
    assert 'code_deps_repo_mirror{repo="live"}' not in s
    assert s['code_deps_repo_scanned{repo="frozen"}'] == 1
    assert s['code_deps_vulns{repo="frozen",ecosystem="go",severity="critical"}'] == 1
    report = json.loads(estate.report.read_text(encoding="utf-8"))
    assert report["repos"]["frozen"]["mirror"] is True and report["repos"]["live"]["mirror"] is False


@pytest.mark.parametrize("content", ["ghost\n", "frozen\nfrozen\n", "Bad Name\n"])
def test_bad_mirror_list_writes_nothing(estate: Estate, content: str) -> None:
    estate.repo("frozen", 0, {"results": []})
    estate.write(["frozen"], ["frozen"])
    estate.mirrors.write_text(content, encoding="utf-8")
    assert estate.run() == osv.EXIT_INVALID_INPUT
    assert not estate.out.exists()


def test_shipped_mirror_list_is_a_subset_of_the_roster() -> None:
    roster = osv.cs_facts.read_roster(osv.HERE.parent / "estate" / "code-standards-roster.txt")
    mirrors = osv.read_mirrors(osv.MIRRORS_FILE, roster)
    assert {"ceremony", "juicebox-hsm-realm", "juicebox-software-realm"} <= mirrors
    assert {"cadcraft", "craft-libs", "wordcraft"} <= mirrors
    assert "craft-tools" not in mirrors  # Ron's own tooling, not a mirror
