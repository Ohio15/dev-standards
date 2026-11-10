"""Code-standards checks in repo-hygiene-scan.py: version-divergence (§3),
tests-undeclared (§2), stub-marker (no-stubs rule), security-register-missing
and security-register-stale (REVIEW-MODEL.md).

Each shape is proven in both directions (present -> finding, absent -> no
finding). Most tests build a throwaway repo under tmp_path and pass the
tracked-file list explicitly (no git, no network); the CLI and discovery tests
at the end build real git repos the way the estate mirror lays them out.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "repo-hygiene-scan.py"
spec = importlib.util.spec_from_file_location("hygiene_cs", SCRIPT)
hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(hygiene)


def write(repo: Path, rel: str, body: str) -> str:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8", newline="\n")
    return rel


def codes(findings: list[dict]) -> dict[str, dict]:
    return {f["code"]: f for f in findings}


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    return r


# --- version-divergence (§3) -------------------------------------------------

def test_single_version_source_is_clean(repo: Path) -> None:
    tracked = [write(repo, "version.json", '{"version": "1.2.3"}')]
    assert hygiene.scan_version_divergence(repo, tracked) == []


def test_agreeing_root_sources_are_clean(repo: Path) -> None:
    tracked = [
        write(repo, "version.json", '{"version": "1.2.3"}'),
        write(repo, "package.json", '{"name": "x", "version": "1.2.3"}'),
        write(repo, "Cargo.toml", '[package]\nname = "x"\nversion = "1.2.3"\n'),
        write(repo, "pyproject.toml", '[project]\nname = "x"\nversion = "1.2.3"\n'),
        write(repo, "VERSION", "v1.2.3\n"),
    ]
    assert hygiene.scan_version_divergence(repo, tracked) == []


def test_divergent_root_sources_are_a_medium_finding(repo: Path) -> None:
    tracked = [
        write(repo, "version.json", '{"version": "1.2.3"}'),
        write(repo, "package.json", '{"version": "1.2.2"}'),
    ]
    found = codes(hygiene.scan_version_divergence(repo, tracked))
    f = found["version-divergence"]
    assert f["severity"] == "MEDIUM"
    assert {"path": "version.json", "version": "1.2.3"} in f["items"]
    assert {"path": "package.json", "version": "1.2.2"} in f["items"]


def test_cargo_reads_package_table_only(repo: Path) -> None:
    cargo = (
        '[workspace.package]\nversion = "9.9.9"\n\n'
        '[package]\nname = "x"\nversion = "1.0.0"\n\n'
        '[dependencies]\nserde = { version = "1" }\nversion = "7.7.7"\n'
    )
    tracked = [write(repo, "Cargo.toml", cargo), write(repo, "VERSION", "1.0.0\n")]
    assert hygiene.scan_version_divergence(repo, tracked) == []
    write(repo, "VERSION", "1.0.1\n")
    assert "version-divergence" in codes(hygiene.scan_version_divergence(repo, tracked))


@pytest.mark.parametrize("line", ["version.workspace = true", "version = { workspace = true }"])
def test_cargo_workspace_inherited_version_is_not_a_source(repo: Path, line: str) -> None:
    tracked = [
        write(repo, "Cargo.toml", f'[package]\nname = "x"\n{line}\n'),
        write(repo, "version.json", '{"version": "2.0.0"}'),
    ]
    assert hygiene.scan_version_divergence(repo, tracked) == []


def test_pyproject_poetry_table_is_read(repo: Path) -> None:
    tracked = [
        write(repo, "pyproject.toml", '[tool.poetry]\nname = "x"\nversion = "0.3.0"\n'),
        write(repo, "version.json", '{"version": "0.4.0"}'),
    ]
    items = codes(hygiene.scan_version_divergence(repo, tracked))["version-divergence"]["items"]
    assert {"path": "pyproject.toml", "version": "0.3.0"} in items


def test_untracked_declaration_is_not_a_source(repo: Path) -> None:
    tracked = [write(repo, "version.json", '{"version": "1.0.0"}')]
    write(repo, "package.json", '{"version": "0.0.1"}')  # on disk, not tracked
    assert hygiene.scan_version_divergence(repo, tracked) == []


def test_nested_version_json_divergence_is_the_apm_scar(repo: Path) -> None:
    tracked = [
        write(repo, "version.json", '{"version": "0.9.2"}'),
        write(repo, "server/version.json", '{"version": "0.9.1"}'),
    ]
    f = codes(hygiene.scan_version_divergence(repo, tracked))["version-divergence"]
    assert {"path": "server/version.json", "version": "0.9.1"} in f["items"]
    assert {"path": "version.json", "version": "0.9.2"} in f["items"]


def test_nested_version_json_matching_root_is_clean(repo: Path) -> None:
    tracked = [
        write(repo, "version.json", '{"version": "0.9.2"}'),
        write(repo, "server/version.json", '{"version": "0.9.2"}'),
    ]
    assert hygiene.scan_version_divergence(repo, tracked) == []


@pytest.mark.parametrize("seg", ["node_modules", "vendor", "dist", "build", "target"])
def test_nested_version_json_in_skipped_dirs_is_ignored(repo: Path, seg: str) -> None:
    tracked = [
        write(repo, "version.json", '{"version": "1.0.0"}'),
        write(repo, f"{seg}/pkg/version.json", '{"version": "0.1.0"}'),
    ]
    assert hygiene.scan_version_divergence(repo, tracked) == []


# --- tests-undeclared (§2) ---------------------------------------------------

def test_source_repo_without_declaration_is_low(repo: Path) -> None:
    tracked = [write(repo, "src/main.rs", "fn main() {}\n")]
    f = codes(hygiene.scan_tests_declared(repo, tracked))["tests-undeclared"]
    assert f["severity"] == "LOW"


def test_declared_tests_are_clean(repo: Path) -> None:
    tracked = [write(repo, "src/main.rs", "fn main() {}\n"), write(repo, ".pre-commit-tests", "TEST_CMD=cargo test\n")]
    assert hygiene.scan_tests_declared(repo, tracked) == []


def test_config_and_docs_only_repo_is_skipped(repo: Path) -> None:
    tracked = [
        write(repo, "README.md", "# x\n"),
        write(repo, "config.json", "{}\n"),
        write(repo, "a.yml", "a: 1\n"),
        write(repo, "b.toml", "a = 1\n"),
        write(repo, "c.ini", "[a]\n"),
    ]
    assert hygiene.scan_tests_declared(repo, tracked) == []


# --- stub-marker (no-stubs rule) ---------------------------------------------

@pytest.mark.parametrize("rel,body", [
    ("src/lib.rs", "pub fn f() -> u8 {\n    todo!()\n}\n"),
    ("src/lib.rs", "pub fn f() -> u8 {\n    unimplemented!(\"later\")\n}\n"),
    ("app/svc.py", "def f():\n    raise NotImplementedError\n"),
    ("app/svc.py", "def f():\n    raise NotImplementedError('x')\n"),
    ("src/a.ts", "export function f() { throw new Error(\"not implemented\"); }\n"),
    ("src/a.js", "function f() { throw new Error('Not Implemented'); }\n"),
    ("src/a.tsx", "const f = () => { throw new Error(`NOT IMPLEMENTED`) };\n"),
    ("Svc/A.cs", "public int F() => throw new NotImplementedException();\n"),
])
def test_each_stub_shape_is_a_medium_finding(repo: Path, rel: str, body: str) -> None:
    tracked = [write(repo, rel, body)]
    f = codes(hygiene.scan_stub_markers(repo, tracked))["stub-marker"]
    assert f["severity"] == "MEDIUM"
    expected = [f"{rel}:2"] if body.count("\n") > 1 else [f"{rel}:1"]
    assert f["items"] == expected


@pytest.mark.parametrize("rel,body", [
    ("src/lib.rs", "// todo!() once the API settles\nfn f() {}\n"),
    ("src/lib.rs", "/// unimplemented!() is never used here\nfn f() {}\n"),
    ("app/svc.py", "# raise NotImplementedError\nx = 1\n"),
    ("app/svc.py", "msg = 'raise NotImplementedError'\n"),
    ("src/a.ts", "throw new Error('not implemented yet: see #12');\n"),
    ("src/a.ts", "// throw new Error('not implemented')\n"),
    ("src/a.py", "todo!()\n"),  # Rust shape in a Python file: wrong language
    ("README.md", "todo!()\nraise NotImplementedError\n"),
])
def test_non_matching_shapes_are_clean(repo: Path, rel: str, body: str) -> None:
    tracked = [write(repo, rel, body)]
    assert "stub-marker" not in codes(hygiene.scan_stub_markers(repo, tracked))


@pytest.mark.parametrize("header", ["import abc\n", "from abc import ABC\n", "class B:\n    @abstractmethod\n    def g(self): ...\n"])
def test_python_abstract_base_files_are_excluded(repo: Path, header: str) -> None:
    tracked = [write(repo, "app/base.py", header + "def f():\n    raise NotImplementedError\n")]
    assert hygiene.scan_stub_markers(repo, tracked) == []


@pytest.mark.parametrize("rel", ["tests/test_a.py", "src/__tests__/a.ts", "src/a.test.ts", "pkg/a_test.py"])
def test_test_files_are_exempt(repo: Path, rel: str) -> None:
    body = "raise NotImplementedError\n" if rel.endswith(".py") else "throw new Error('not implemented');\n"
    tracked = [write(repo, rel, body)]
    assert hygiene.scan_stub_markers(repo, tracked) == []


def test_stub_items_are_capped_at_20_with_full_count(repo: Path) -> None:
    body = "".join("todo!()\n" for _ in range(25))
    tracked = [write(repo, "src/lib.rs", body)]
    f = codes(hygiene.scan_stub_markers(repo, tracked))["stub-marker"]
    assert f["count"] == 25 and len(f["items"]) == 20


def test_oversized_source_is_unexamined_not_clean(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tracked = [write(repo, "src/lib.rs", "todo!()\n")]
    monkeypatch.setattr(hygiene, "MAX_RUNTIME_SOURCE_BYTES", 2)
    found = codes(hygiene.scan_stub_markers(repo, tracked))
    assert "stub-marker" not in found
    assert found["stub-marker-unexamined"]["items"][0]["path"] == "src/lib.rs"


# --- security register -------------------------------------------------------

CANON_TEXT = "# Register\n\n### SC-01 · one\n\n### SC-02 · two\n\nbody mentions SC-99 only in prose\n\n### SC-10 · ten\n"


@pytest.fixture()
def canonical(tmp_path: Path) -> tuple[Path, set[str]]:
    p = tmp_path / "canon" / "security" / "SECURITY-CHECKS.md"
    p.parent.mkdir(parents=True)
    p.write_text(CANON_TEXT, encoding="utf-8")
    return hygiene.load_canonical_register(p)


def test_register_ids_come_from_heading_lines_only() -> None:
    assert hygiene.register_rule_ids(CANON_TEXT) == {"SC-01", "SC-02", "SC-10"}


def test_rostered_repo_without_register_is_missing(repo: Path) -> None:
    found = codes(hygiene.scan_security_register(repo, [], security_roster={"repo"}))
    assert found["security-register-missing"]["severity"] == "MEDIUM"


def test_roster_match_is_case_insensitive(tmp_path: Path) -> None:
    r = tmp_path / "Shared-Brain"
    r.mkdir()
    assert "security-register-missing" in codes(hygiene.scan_security_register(r, [], security_roster={"shared-brain"}))


@pytest.mark.parametrize("rel", ["SECURITY-CHECKS.md", "security/SECURITY-CHECKS.md"])
def test_rostered_repo_with_register_is_clean(repo: Path, rel: str) -> None:
    tracked = [write(repo, rel, CANON_TEXT)]
    assert hygiene.scan_security_register(repo, tracked, security_roster={"repo"}) == []


def test_unrostered_repo_is_not_judged(repo: Path) -> None:
    assert hygiene.scan_security_register(repo, [], security_roster={"other"}) == []


def test_without_roster_the_missing_check_is_absent(repo: Path) -> None:
    assert hygiene.scan_security_register(repo, [], security_roster=None) == []


def test_stale_copy_lists_missing_ids_sorted(repo: Path, canonical: tuple[Path, set[str]]) -> None:
    tracked = [write(repo, "SECURITY-CHECKS.md", "### SC-02 · two\n")]
    f = codes(hygiene.scan_security_register(repo, tracked, canonical=canonical))["security-register-stale"]
    assert f["severity"] == "MEDIUM"
    assert f["items"] == ["SC-01", "SC-10"]
    assert f["paths"] == ["SECURITY-CHECKS.md"]


def test_current_copy_is_clean(repo: Path, canonical: tuple[Path, set[str]]) -> None:
    tracked = [write(repo, "security/SECURITY-CHECKS.md", CANON_TEXT + "### SC-11 · local extra\n")]
    assert hygiene.scan_security_register(repo, tracked, canonical=canonical) == []


def test_canonical_file_itself_is_skipped(tmp_path: Path, canonical: tuple[Path, set[str]]) -> None:
    ds = tmp_path / "canon"  # the canonical lives at canon/security/SECURITY-CHECKS.md
    tracked = ["security/SECURITY-CHECKS.md"]
    assert hygiene.scan_security_register(ds, tracked, canonical=canonical) == []


def test_without_canonical_the_stale_check_is_absent(repo: Path) -> None:
    tracked = [write(repo, "SECURITY-CHECKS.md", "### SC-02 · two\n")]
    assert hygiene.scan_security_register(repo, tracked, canonical=None) == []


def test_malformed_roster_and_empty_canonical_raise(tmp_path: Path) -> None:
    bad = tmp_path / "roster.json"
    bad.write_text('{"repos": "nope"}', encoding="utf-8")
    with pytest.raises(ValueError):
        hygiene.load_security_roster(bad)
    with pytest.raises(ValueError):
        hygiene.load_security_roster(tmp_path / "absent.json")
    empty = tmp_path / "canon.md"
    empty.write_text("# no rules here\n", encoding="utf-8")
    with pytest.raises(ValueError):
        hygiene.load_canonical_register(empty)


def test_roster_names_are_lowercased(tmp_path: Path) -> None:
    p = tmp_path / "roster.json"
    p.write_text(json.dumps({"repos": [{"name": "Shared-Brain"}, {"name": "e38flash"}]}), encoding="utf-8")
    assert hygiene.load_security_roster(p) == {"shared-brain", "e38flash"}


# --- CLI + mirror-shaped root (real git) -------------------------------------

def git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *args], cwd=cwd, check=True, capture_output=True)


def make_clone(root: Path, name: str, files: dict[str, str]) -> Path:
    r = root / name
    r.mkdir(parents=True)
    git("init", "-q", cwd=r)
    for rel, body in files.items():
        write(r, rel, body)
    git("add", "-A", cwd=r)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "init", cwd=r)
    return r


def test_mirror_root_discovers_lowercase_clones_and_skips_in_progress(tmp_path: Path) -> None:
    mirror = tmp_path / "repos"
    make_clone(mirror, "steward-core", {"src/main.rs": "fn main() {}\n"})
    make_clone(mirror, "shared-brain", {"a.py": "x = 1\n"})
    (mirror / ".tmp-apm" / ".git").mkdir(parents=True)  # a clone mid-flight
    found = sorted(p.name for p in hygiene.discover_repos([mirror]))
    assert found == ["shared-brain", "steward-core"]


def test_cli_runs_new_checks_against_a_mirror(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mirror = tmp_path / "repos"
    make_clone(mirror, "shared-brain", {
        "src/main.rs": "fn main() { todo!() }\n",
        "version.json": '{"version": "1.0.0"}',
        "package.json": '{"version": "1.0.1"}',
    })
    make_clone(mirror, "dev-standards", {"security/SECURITY-CHECKS.md": CANON_TEXT, "x.py": "y = 1\n"})
    roster = tmp_path / "security-repos.json"
    roster.write_text(json.dumps({"repos": [{"name": "Shared-Brain"}]}), encoding="utf-8")
    out = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", [
        "repo-hygiene-scan.py", "--root", str(mirror), "--no-layout", "--output-dir", str(out),
        "--security-roster", str(roster),
        "--canonical-register", str(mirror / "dev-standards" / "security" / "SECURITY-CHECKS.md"),
    ])
    assert hygiene.run_main() == 2  # HIGH: the fixtures carry no release runbook (independence)
    report = json.loads(next(out.glob("hygiene-scan-*.json")).read_text(encoding="utf-8"))
    by_name = {r["name"]: {f["code"] for f in r["findings"]} for r in report["repos"]}
    assert {"stub-marker", "version-divergence", "security-register-missing", "tests-undeclared"} <= by_name["shared-brain"]
    assert "security-register-stale" not in by_name["dev-standards"]
    assert "[layout]" not in " ".join(by_name)


def test_cli_rejects_an_unreadable_roster(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", [
        "repo-hygiene-scan.py", "--root", str(tmp_path), "--no-layout", "--output-dir", str(tmp_path / "o"),
        "--security-roster", str(tmp_path / "absent.json"),
    ])
    with pytest.raises(SystemExit) as exc:
        hygiene.run_main()
    assert exc.value.code == 2


def test_render_handles_new_item_shapes(repo: Path) -> None:
    rendered = [hygiene.render_item(i) for i in ({"path": "package.json", "version": "1.0.1"}, "SC-07", "src/a.rs:3")]
    assert rendered == ["package.json version=1.0.1", "SC-07", "src/a.rs:3"]


def test_toml_header_parse_is_linear_on_a_long_unterminated_line() -> None:
    # Security gate pass 1, SC-10: the earlier regex was super-linear here.
    import time
    line = "[" + " " * 1_000_000
    t = time.perf_counter()
    assert hygiene._toml_table_header(line) is None
    assert time.perf_counter() - t < 1.0
    assert hygiene._toml_table_header("[package]") == "package"
    assert hygiene._toml_table_header("  [ tool.poetry ]  # c") == "tool.poetry"
    assert hygiene._toml_table_header("[[bin]]") is None
    assert hygiene._toml_table_header("[a] b") is None


def test_py_abstract_detection_is_linear_on_blank_lines() -> None:
    # Security gate pass 2, SC-10.
    import time
    t = time.perf_counter()
    assert not hygiene._py_declares_abc("\n" * 1_000_000)
    assert time.perf_counter() - t < 2.0
    assert hygiene._py_declares_abc("x = 1\n    import abc\n")
    assert hygiene._py_declares_abc("from abc import ABC\n")
    assert hygiene._py_declares_abc("class A:\n    @abstractmethod\n    def f(self): ...\n")
    assert not hygiene._py_declares_abc("import abcd\n")


def test_a_failed_ls_files_is_unexamined_not_clean(tmp_path) -> None:
    # Security gate pass 2, SC-04: not a git repo, so `git ls-files` fails.
    (tmp_path / "x").mkdir()
    r = hygiene.scan_repo(tmp_path / "x", 30)
    assert [f["code"] for f in r["findings"]] == ["tracked-files-unexamined"]
