#!/usr/bin/env python3
"""
Estate dependency-vulnerability facts: OSV-Scanner over the code-standards
mirror -> a Prometheus textfile (code_deps.prom) and a JSON report.

This is the local replacement for GitHub Dependabot alerts as a data source
(docs/github-dependencies.md): every ecosystem OSV-Scanner reads from a
lockfile or manifest (npm, pnpm, yarn, Go, crates.io, PyPI, NuGet, Maven, ...)
is matched against the OSV database, downloaded to NEXUS, with no GitHub API
and no per-package query leaving the box.

Inputs (produced by scripts/code-standards-cron.sh in the same run):
    --roster         estate/code-standards-roster.txt
    --mirror         the mirror root (<mirror>/<repo>)
    --mirror-status  estate-mirror.sh status file: `<repo> ok|fail <sha|->`
    --osv-scanner    the pinned binary (scripts/install-osv-scanner.sh)
    --db-dir         OSV offline database cache (refreshed by the scanner)
    --output         textfile, e.g. /var/lib/node_exporter/textfile_collector/code_deps.prom
    --report         JSON report with every advisory per repo (optional)
    --mirrors        estate/osv-mirrors.txt: roster repos kept as unmodified mirrors

Output contract (a SEPARATE file from code_standards.prom, whose series set
Steward allow-lists and refuses whole on any unknown series):
    code_deps_repo_scanned{repo}                   0|1, every roster repo
    code_deps_repo_mirror{repo}                    1, preservation mirrors only (still scanned)
    code_deps_packages{repo,ecosystem}             >0 distinct packages examined
    code_deps_vulns{repo,ecosystem,severity}       >0 distinct advisories
    code_deps_last_run_timestamp_seconds           unix seconds, last line
  severity is critical|high|medium|low|unknown (CVSS base score from the
  advisory; "unknown" when the advisory carries none, e.g. most GO-/RUSTSEC-
  entries). All gauges; integral; ASCII; LF; each series once; repo first.

"Unknown is never clean": scanned=1 only when the repo's mirror refreshed
this run AND the pinned scanner ran to completion on it (exit 0 = no
advisories, 1 = advisories, 128 = no package manifest at all) with output
that parses. Anything else (timeout, crash, wrong binary version, bad JSON)
is scanned=0. code_deps_packages is the positive confirmation of what was
examined: a scanned repo with no packages line had no manifest to read.

Safety: the scanner runs with --offline (no network beyond the database
download), --no-call-analysis=all and --no-resolve (no repo code is built, loaded or
run, including Go toolchain directives and Rust build scripts; no transitive
resolution against a remote registry), cwd outside the repo, and a scrubbed
environment whose PATH holds no Go toolchain. Counts are therefore conservative: an
advisory in code a Go program never calls is still counted.

Exit codes: 0 written; 1 invalid input (nothing written); 3 output budget
exceeded (nothing written).

Stdlib only. Python 3.8+.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PIN_FILE = HERE.parent / "estate" / "osv-scanner.version"
MIRRORS_FILE = HERE.parent / "estate" / "osv-mirrors.txt"

_spec = importlib.util.spec_from_file_location("cs_facts", HERE / "code-standards-facts.py")
assert _spec is not None and _spec.loader is not None
cs_facts = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs_facts)

InputError = cs_facts.InputError
REPO_LABEL_RE = cs_facts.REPO_LABEL_RE
ECOSYSTEM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
MAX_BYTES = 128 * 1024
MAX_LINES = 2048
MAX_SCANNER_OUTPUT = 64 * 1024 * 1024
EXIT_INVALID_INPUT = 1
EXIT_BUDGET = 3
RC_OK, RC_VULNS, RC_NO_PACKAGES = 0, 1, 128

METRICS: tuple[tuple[str, str], ...] = (
    ("code_deps_repo_scanned",
     "1 when the repo's mirror refreshed this run and the pinned OSV-Scanner completed on it, else 0."),
    ("code_deps_repo_mirror",
     "1 for a roster repo kept as an unmodified preservation mirror (estate/osv-mirrors.txt); still scanned."),
    ("code_deps_packages",
     "Distinct packages OSV-Scanner examined, by ecosystem (scanned repos only, counts above 0)."),
    ("code_deps_vulns",
     "Distinct OSV advisories affecting the repo's dependencies, by ecosystem and severity (counts above 0)."),
    ("code_deps_last_run_timestamp_seconds",
     "Unix time at which this export was computed."),
)


class ScanError(Exception):
    """One repo could not be examined; it exports as scanned 0."""


def read_mirrors(path: Path, roster: list[str]) -> set[str]:
    """Mirror repo labels. Every one must be a roster repo: a mirror list that
    names something the roster does not is a stale config, refused whole."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"mirror list {path} unreadable: {exc}") from exc
    known = set(roster)
    out: set[str] = set()
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        label = line.lower()
        if not REPO_LABEL_RE.match(label):
            raise InputError(f"mirror list {path}:{n}: {line!r} is not a valid repo label")
        if label not in known:
            raise InputError(f"mirror list {path}:{n}: {line!r} is not in the roster")
        if label in out:
            raise InputError(f"mirror list {path}:{n}: {line!r} listed twice")
        out.add(label)
    return out


def read_pin(path: Path = PIN_FILE) -> str:
    try:
        pin = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise InputError(f"scanner pin {path} unreadable: {exc}") from exc
    if not re.fullmatch(r"\d+\.\d+\.\d+", pin):
        raise InputError(f"scanner pin {path} is not a version: {pin!r}")
    return pin


def scanner_env(db_dir: Path, home: Path) -> dict[str, str]:
    """A scrubbed environment: no inherited proxies, tokens or git config."""
    return {
        # No /usr/local/bin: the Go toolchain lives there on NEXUS, and a
        # scanner that can find `go` may run it inside a mirrored repo, where
        # the repo's go.mod `toolchain` line picks what GOTOOLCHAIN downloads.
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(db_dir),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GOFLAGS": "-mod=mod",
        "GOTOOLCHAIN": "local",
        "GOPROXY": "off",
    }


def scanner_version(binary: Path, env: dict[str, str], cwd: Path) -> str | None:
    try:
        proc = subprocess.run([str(binary), "--version"], env=env, cwd=str(cwd),
                              capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"^osv-scanner version: (\S+)$", proc.stdout, re.M)
    return m.group(1) if m and proc.returncode == 0 else None


def scan_args(binary: Path, repo_dir: Path) -> list[str]:
    return [str(binary), "scan", "source", "--recursive",
            "--offline", "--download-offline-databases", "--no-resolve",
            "--no-call-analysis=all", "--all-packages",
            "--format", "json", str(repo_dir)]


def severity_of(raw: Any) -> str:
    """CVSS base score string -> bucket. Empty/absent/unparseable -> unknown."""
    if not isinstance(raw, str) or not raw.strip():
        return "unknown"
    try:
        score = float(raw)
    except ValueError:
        return "unknown"
    if not 0.0 < score <= 10.0:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def ecosystem_label(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ScanError("package without an ecosystem")
    label = re.sub(r"[^a-z0-9._-]", "-", raw.strip().lower())
    return label if ECOSYSTEM_RE.match(label) else "other"


def parse_scan(text: str) -> dict[str, Any]:
    """OSV-Scanner JSON -> {"packages": {eco: n}, "vulns": {(eco, sev): n},
    "advisories": [...]}, deduplicated per repo (one package in several
    lockfiles counts once; one advisory on one package version counts once)."""
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ScanError(f"scanner output is not JSON ({exc})") from exc
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise ScanError("scanner output has no results[] list")
    packages: set[tuple[str, str, str]] = set()
    hits: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for res in results:
        if not isinstance(res, dict) or not isinstance(res.get("packages"), list):
            raise ScanError("result without a packages[] list")
        source = res.get("source", {}).get("path", "") if isinstance(res.get("source"), dict) else ""
        for pkg in res["packages"]:
            info = pkg.get("package") if isinstance(pkg, dict) else None
            if not isinstance(info, dict):
                raise ScanError("package entry without package{}")
            eco = ecosystem_label(info.get("ecosystem"))
            name, version = str(info.get("name", "")), str(info.get("version", ""))
            packages.add((eco, name, version))
            groups = pkg.get("groups") or []
            if not isinstance(groups, list):
                raise ScanError("groups is not a list")
            for g in groups:
                ids = g.get("ids") if isinstance(g, dict) else None
                if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
                    raise ScanError("advisory group without ids")
                key = (eco, name, version, sorted(ids)[0])
                if key not in hits:
                    hits[key] = {
                        "ecosystem": eco, "package": name, "version": version,
                        "ids": sorted(ids),
                        "aliases": sorted(a for a in g.get("aliases", []) if isinstance(a, str)),
                        "severity": severity_of(g.get("max_severity")),
                        "cvss": g.get("max_severity") or None,
                        "source": source,
                    }
    pkg_counts: dict[str, int] = {}
    for eco, _, _ in packages:
        pkg_counts[eco] = pkg_counts.get(eco, 0) + 1
    vuln_counts: dict[tuple[str, str], int] = {}
    for h in hits.values():
        k = (h["ecosystem"], h["severity"])
        vuln_counts[k] = vuln_counts.get(k, 0) + 1
    advisories = sorted(hits.values(), key=lambda h: (SEVERITIES.index(h["severity"]), h["ecosystem"],
                                                      h["package"], h["ids"][0]))
    return {"packages": pkg_counts, "vulns": vuln_counts, "advisories": advisories}


def scan_repo(binary: Path, repo_dir: Path, env: dict[str, str], cwd: Path, timeout: int) -> dict[str, Any]:
    with tempfile.TemporaryFile(dir=str(cwd)) as out, tempfile.TemporaryFile(dir=str(cwd)) as err:
        try:
            proc = subprocess.run(scan_args(binary, repo_dir), env=env, cwd=str(cwd),
                                  stdout=out, stderr=err, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ScanError(f"timed out after {timeout}s") from exc
        except OSError as exc:
            raise ScanError(f"could not start the scanner ({exc})") from exc
        if proc.returncode == RC_NO_PACKAGES:
            return {"packages": {}, "vulns": {}, "advisories": []}
        if proc.returncode not in (RC_OK, RC_VULNS):
            err.seek(0)
            tail = err.read()[-400:].decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
            raise ScanError(f"scanner exit {proc.returncode}: {tail[0][:200]}")
        size = out.seek(0, os.SEEK_END)
        if size > MAX_SCANNER_OUTPUT:
            raise ScanError(f"scanner output {size} bytes exceeds {MAX_SCANNER_OUTPUT}")
        out.seek(0)
        parsed = parse_scan(out.read().decode("utf-8", "replace"))
    # Exit 0 with advisories listed (ones the scanner itself marks unimportant)
    # is counted, conservatively. Exit 1 with none listed means the output and
    # the verdict disagree: that is not an examination, so it is not clean.
    if proc.returncode == RC_VULNS and not parsed["vulns"]:
        raise ScanError("scanner exit 1 but no advisory in the output")
    return parsed


def build_series(roster: list[str], scans: dict[str, dict[str, Any]],
                 mirrors: set[str] | frozenset[str] = frozenset()) -> dict[str, list[tuple[str, int]]]:
    series: dict[str, list[tuple[str, int]]] = {name: [] for name, _ in METRICS}
    for repo in sorted(roster):
        scan = scans.get(repo)
        series["code_deps_repo_scanned"].append((f'{{repo="{repo}"}}', 1 if scan is not None else 0))
        if repo in mirrors:
            series["code_deps_repo_mirror"].append((f'{{repo="{repo}"}}', 1))
        if scan is None:
            continue
        for eco in sorted(scan["packages"]):
            n = scan["packages"][eco]
            if n > 0:
                series["code_deps_packages"].append((f'{{repo="{repo}",ecosystem="{eco}"}}', n))
        for eco, sev in sorted(scan["vulns"], key=lambda k: (k[0], SEVERITIES.index(k[1]))):
            n = scan["vulns"][(eco, sev)]
            if n > 0:
                series["code_deps_vulns"].append(
                    (f'{{repo="{repo}",ecosystem="{eco}",severity="{sev}"}}', n))
    return series


def render(series: dict[str, list[tuple[str, int]]], now: int) -> str:
    lines: list[str] = []
    for name, help_text in METRICS:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        if name == "code_deps_last_run_timestamp_seconds":
            lines.append(f"{name} {now}")
            continue
        for labels, value in series[name]:
            lines.append(f"{name}{labels} {int(value)}")
    text = "\n".join(lines) + "\n"
    text.encode("ascii")
    return text


def write_json_atomic(path: Path, obj: Any) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".osv-report.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, indent=1, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Export estate dependency-vulnerability facts from OSV-Scanner")
    ap.add_argument("--roster", required=True, type=Path)
    ap.add_argument("--mirror", required=True, type=Path)
    ap.add_argument("--mirror-status", required=True, type=Path)
    ap.add_argument("--osv-scanner", required=True, type=Path)
    ap.add_argument("--db-dir", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--report", type=Path, default=None)
    ap.add_argument("--timeout", type=int, default=300, help="per-repo scanner timeout, seconds")
    ap.add_argument("--mirrors", type=Path, default=MIRRORS_FILE, help="preservation-mirror list")
    ap.add_argument("--pin-file", type=Path, default=PIN_FILE, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    try:
        pin = read_pin(args.pin_file)
        roster = cs_facts.read_roster(args.roster)
        mirror_ok = cs_facts.read_mirror_status(args.mirror_status)
        mirrors = read_mirrors(args.mirrors, roster)
        if not args.mirror.is_dir():
            raise InputError(f"mirror {args.mirror} is not a directory")
    except InputError as exc:
        print(f"osv-deps-facts: {exc}; nothing written", file=sys.stderr)
        return EXIT_INVALID_INPUT

    args.db_dir.mkdir(parents=True, exist_ok=True)
    scans: dict[str, dict[str, Any]] = {}
    errors: dict[str, str] = {}
    started = int(time.time())
    with tempfile.TemporaryDirectory(prefix="osv-deps-") as work:
        cwd = Path(work)
        home = cwd / "home"
        home.mkdir()
        env = scanner_env(args.db_dir, home)
        version = scanner_version(args.osv_scanner, env, cwd)
        if version != pin:
            msg = f"scanner {args.osv_scanner} reports version {version!r}, pin is {pin}"
            print(f"osv-deps-facts: {msg}; every repo exports as not scanned", file=sys.stderr)
            errors = {r: msg for r in roster}
        else:
            for repo in roster:
                repo_dir = args.mirror / repo
                if not mirror_ok.get(repo):
                    errors[repo] = "mirror not refreshed this run"
                    continue
                if not repo_dir.is_dir() or repo_dir.is_symlink():
                    errors[repo] = "mirror directory missing"
                    continue
                try:
                    scans[repo] = scan_repo(args.osv_scanner, repo_dir, env, cwd, args.timeout)
                except ScanError as exc:
                    errors[repo] = str(exc)
                    print(f"osv-deps-facts: {repo}: not scanned: {exc}", file=sys.stderr)

    series = build_series(roster, scans, mirrors)
    now = int(time.time())
    text = render(series, now)
    size, count = len(text.encode("ascii")), text.count("\n")
    if size > MAX_BYTES or count > MAX_LINES:
        print(f"osv-deps-facts: output {size} bytes / {count} lines exceeds the "
              f"{MAX_BYTES}-byte / {MAX_LINES}-line budget; nothing written", file=sys.stderr)
        return EXIT_BUDGET
    if args.report is not None:
        write_json_atomic(args.report, {
            "generated_at": now, "started_at": started, "scanner": f"osv-scanner {pin}",
            "repos": {r: {"mirror": r in mirrors,
                          **({"status": "ok", **{k: v for k, v in scans[r].items() if k != "vulns"},
                              "vuln_counts": {f"{e}/{s}": n for (e, s), n in scans[r]["vulns"].items()}}
                             if r in scans else {"status": "error", "error": errors.get(r, "not scanned")})}
                      for r in sorted(roster)},
        })
    cs_facts.write_atomic(args.output, text)
    n_vulns = sum(v for _, v in series["code_deps_vulns"])
    print(f"osv-deps-facts: wrote {args.output} ({count} lines, {size} bytes; {len(scans)}/{len(roster)} "
          f"repos scanned, {n_vulns} advisories)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
