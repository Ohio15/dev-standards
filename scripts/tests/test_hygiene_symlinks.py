"""repo-hygiene-scan.py does not follow a symlink inside a scanned repo for any
access these tests cover, and never trusts st_size (audit 2026-11-10.2 M4,
proposed SC-58; gate pass 1 on #87).

A scanned repo is third-party content. A committed `VERSION -> <secret>` used
to put the secret's first line into the report (and the shared-brain post) as
a "version"; `src/a.py -> /dev/zero` passed the size cap (st_size 0) and was
read without bound; a `SECURITY-CHECKS.md -> <canonical>` was skipped as "the
canonical file itself"; a symlinked `.gitmodules` was handed to `git config -f`.
Every repo-relative metadata probe goes through lstat_repo_path (lstat on every
component, no link followed) and every read through read_repo_file (that, plus
S_ISREG and a bounded read(cap + 1)). The boundary tests below plant each link;
test_every_repo_access_goes_through_the_helpers pins the class at the source:
it enumerates every filesystem access and subprocess argument in the script
(AST), and each one must be a helper or an operator path named in its allow-list.

Run:  python -m pytest scripts/tests/test_hygiene_symlinks.py -q
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "repo-hygiene-scan.py"
spec = importlib.util.spec_from_file_location("hygiene_symlinks", SCRIPT)
hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(hygiene)

SECRET = "ghp_TOPSECRETTOKENVALUE0123456789"


def _can_symlink(tmp: Path) -> bool:
    try:
        (tmp / ".probe-target").write_text("x", encoding="utf-8")
        os.symlink(tmp / ".probe-target", tmp / ".probe-link")
        return True
    except (OSError, NotImplementedError):
        return False


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    if not _can_symlink(tmp_path):
        pytest.skip("this account cannot create symlinks")
    r = tmp_path / "repo"
    r.mkdir()
    return r


@pytest.fixture
def secret(tmp_path: Path) -> Path:
    s = tmp_path / "outside" / ".git-credentials"
    s.parent.mkdir()
    s.write_text(SECRET + "\n", encoding="utf-8")
    return s


def write(repo: Path, rel: str, body: str) -> str:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8", newline="\n")
    return rel


# ── the helper itself ──

def test_regular_file_is_read(repo: Path) -> None:
    write(repo, "a/b.txt", "hello")
    assert hygiene.read_repo_file(repo, "a/b.txt") == (b"hello", None)


def test_symlinked_leaf_is_refused(repo: Path, secret: Path) -> None:
    os.symlink(secret, repo / "VERSION")
    data, reason = hygiene.read_repo_file(repo, "VERSION")
    assert data is None and "symlink" in reason


def test_symlinked_parent_directory_is_refused(repo: Path, secret: Path) -> None:
    os.symlink(secret.parent, repo / "src", target_is_directory=True)
    data, reason = hygiene.read_repo_file(repo, "src/.git-credentials")
    assert data is None and "symlink" in reason


@pytest.mark.parametrize("rel", ["../outside/.git-credentials", "a/../../outside/.git-credentials"])
def test_path_escaping_the_repo_is_refused(repo: Path, secret: Path, rel: str) -> None:
    data, reason = hygiene.read_repo_file(repo, rel)
    assert data is None and "escapes" in reason


def test_absolute_path_is_refused(repo: Path, secret: Path) -> None:
    data, reason = hygiene.read_repo_file(repo, str(secret))
    assert data is None and "escapes" in reason


def test_directory_is_not_a_regular_file(repo: Path) -> None:
    (repo / "d").mkdir()
    data, reason = hygiene.read_repo_file(repo, "d")
    assert data is None and "regular file" in reason


def test_cap_is_enforced_on_bytes_read_not_st_size(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(repo, "big.py", "x" * 100)
    real_fstat = os.fstat

    class Lying:
        def __init__(self, st: os.stat_result) -> None:
            self._st = st

        def __getattr__(self, name: str):
            return 0 if name == "st_size" else getattr(self._st, name)

    # st_size 0 (what /dev/zero and a FIFO report) must not let 100 bytes past a 64-byte cap.
    monkeypatch.setattr(hygiene.os, "fstat", lambda fd: Lying(real_fstat(fd)))
    monkeypatch.setattr(hygiene.os, "lstat", lambda p, _l=os.lstat: Lying(_l(p)))
    data, reason = hygiene.read_repo_file(repo, "big.py", cap=64)
    assert data is None and "exceeds 64-byte cap" in reason
    assert hygiene.read_repo_file(repo, "big.py", cap=100) == (b"x" * 100, None)


@pytest.mark.skipif(sys.platform == "win32" or not Path("/dev/zero").exists(), reason="needs /dev/zero")
def test_symlink_to_dev_zero_is_not_read(repo: Path) -> None:
    os.symlink("/dev/zero", repo / "a.py")
    data, reason = hygiene.read_repo_file(repo, "a.py")
    assert data is None and "symlink" in reason


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_fifo_is_refused_without_blocking(repo: Path) -> None:
    os.mkfifo(repo / "pipe.py")
    data, reason = hygiene.read_repo_file(repo, "pipe.py")
    assert data is None and "regular file" in reason


# ── the scan passes: no content from a symlink target reaches a finding ──

def test_version_symlink_leaks_nothing_into_the_report(repo: Path, secret: Path) -> None:
    write(repo, "package.json", '{"version": "1.0.0"}')
    os.symlink(secret, repo / "VERSION")
    findings = hygiene.scan_version_divergence(repo, ["package.json", "VERSION"])
    assert SECRET not in repr(findings)
    [unexamined] = [f for f in findings if f["code"] == "version-unexamined"]
    assert unexamined["items"] == [{"path": "VERSION", "reason": "symlink: not followed"}]
    assert not [f for f in findings if f["code"] == "version-divergence"]


def test_symlinked_runtime_source_is_unexamined_not_read(repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "outside" / "vendor.ts"
    target.parent.mkdir(exist_ok=True)
    target.write_text("fetch('https://api.openai.com')\n", encoding="utf-8")
    (repo / "src").mkdir()
    os.symlink(target, repo / "src" / "a.ts")
    findings = hygiene.scan_stub_markers(repo, ["src/a.ts"])
    [f] = findings
    assert f["code"] == "stub-marker-unexamined"
    assert f["items"] == [{"path": "src/a.ts", "kind": "runtime-source", "reason": "symlink: not followed"}]


def test_cache_restore_walk_reports_symlinked_workflows_and_dirs(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside-wf"
    outside.mkdir()
    (outside / "evil.yml").write_text("jobs: {}\n", encoding="utf-8")
    wf = repo / ".github" / "workflows"
    wf.mkdir(parents=True)
    (repo / ".github" / "auto-apply-enabled").write_text("", encoding="utf-8")
    (wf / "ok.yml").write_text("name: ok\non: push\njobs: {}\n", encoding="utf-8")
    os.symlink(outside / "evil.yml", wf / "linked.yml")
    os.symlink(outside, wf / "sub", target_is_directory=True)
    [finding] = hygiene.scan_cache_restore(repo)
    got = {(i["path"], i["form"]) for i in finding["items"]}
    assert got == {(".github/workflows/linked.yml", "symlink: not followed"),
                   (".github/workflows/sub", "symlink: not followed")}, got


def test_symlinked_workflows_dir_is_reported_not_passed(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside-wf2"
    outside.mkdir()
    (outside / "x.yml").write_text("jobs: {}\n", encoding="utf-8")
    (repo / ".github").mkdir()
    (repo / ".github" / "auto-apply-enabled").write_text("", encoding="utf-8")
    os.symlink(outside, repo / ".github" / "workflows", target_is_directory=True)
    [finding] = hygiene.scan_cache_restore(repo)
    assert [(i["path"], i["form"]) for i in finding["items"]] == [(".github/workflows", "symlink: not followed")]


def test_symlinked_installed_hook_is_drift_not_a_match(repo: Path, tmp_path: Path) -> None:
    canon = tmp_path / "canon"
    canon.mkdir()
    (canon / "pre-commit").write_bytes(b"#!/bin/sh\nexit 0\n")
    (repo / ".githooks").mkdir()
    os.symlink(canon / "pre-commit", repo / ".githooks" / "pre-commit")  # identical content via the link
    [f] = hygiene.scan_hook_drift(repo, canon)
    assert f["code"] == "hook-drift"
    assert "symlink" in f["items"][0]["installed"]


def test_symlinked_release_config_reads_as_strictest_mode(repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "rc.yml"
    target.write_text("independence: harness\n", encoding="utf-8")
    os.symlink(target, repo / "release-config.yml")
    assert hygiene.read_independence_mode(repo) == ("full", None)


def test_compose_file_outside_the_repo_is_not_read(repo: Path, tmp_path: Path) -> None:
    (tmp_path / "compose.yml").write_text("services:\n  x:\n    image: a/b:1\n", encoding="utf-8")
    assert hygiene.parse_compose_services(repo, "../compose.yml") == {}


def test_tracked_symlink_has_no_size_and_the_target_is_not_measured(repo: Path, tmp_path: Path) -> None:
    big = tmp_path / "big.bin"
    big.write_bytes(bytes(64 * 1024))
    os.symlink(big, repo / "link")
    assert hygiene.file_size(repo, "link") is None
    write(repo, "real.txt", "abc")
    assert hygiene.file_size(repo, "real.txt") == 3


# ── gate pass 1 on #87: the accesses the first cut missed ──

def _canonical(tmp_path: Path) -> tuple[Path, set[str]]:
    canon = tmp_path / "canon" / "security" / "SECURITY-CHECKS.md"
    canon.parent.mkdir(parents=True)
    canon.write_text("### SC-01 · one\n\n### SC-02 · two\n", encoding="utf-8")
    return hygiene.load_canonical_register(canon)


@pytest.mark.parametrize("rel", ["SECURITY-CHECKS.md", "security/SECURITY-CHECKS.md"])
def test_register_symlinked_to_the_canonical_is_judged_not_skipped(repo: Path, tmp_path: Path, rel: str) -> None:
    canonical = _canonical(tmp_path)
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(canonical[0], repo / rel)
    [f] = hygiene.scan_security_register(repo, [rel], canonical=canonical)
    assert f["code"] == "security-register-stale"
    assert f["items"] == ["SC-01", "SC-02"]
    assert f["paths"] == [f"{rel} (symlink: not followed)"]


def test_register_in_a_symlinked_directory_is_judged_not_skipped(repo: Path, tmp_path: Path) -> None:
    canonical = _canonical(tmp_path)
    os.symlink(canonical[0].parent, repo / "security", target_is_directory=True)
    [f] = hygiene.scan_security_register(repo, ["security/SECURITY-CHECKS.md"], canonical=canonical)
    assert f["code"] == "security-register-stale"


def test_the_canonical_checkout_itself_is_still_skipped(tmp_path: Path) -> None:
    canonical = _canonical(tmp_path)
    assert hygiene.scan_security_register(tmp_path / "canon", ["security/SECURITY-CHECKS.md"],
                                          canonical=canonical) == []


GITMODULES = '[submodule "x"]\n\tpath = child\n\turl = https://example.invalid/leak.git\n'


def test_symlinked_gitmodules_is_unexamined_and_never_parsed(repo: Path, tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "outside" / "gitmodules"
    target.parent.mkdir(exist_ok=True)
    target.write_text(GITMODULES, encoding="utf-8")
    os.symlink(target, repo / ".gitmodules")
    calls: list[list[str]] = []
    real_run = hygiene.run
    monkeypatch.setattr(hygiene, "run", lambda cmd, *a, **k: (calls.append(cmd), real_run(cmd, *a, **k))[1])
    assert hygiene.read_gitmodules(repo) == ([], "symlink: not followed")
    assert calls == [], "git was run over a symlinked .gitmodules"
    [f] = hygiene.scan_submodule_pointer_lag(repo)
    assert f["code"] == "submodule-unexamined" and f["severity"] == "LOW"
    assert "example.invalid" not in repr(f)


def test_regular_gitmodules_is_parsed_from_a_private_copy(repo: Path, monkeypatch) -> None:
    write(repo, ".gitmodules", GITMODULES)
    seen: list[list[str]] = []
    real_run = hygiene.run
    monkeypatch.setattr(hygiene, "run", lambda cmd, *a, **k: (seen.append(cmd), real_run(cmd, *a, **k))[1])
    mods, why = hygiene.read_gitmodules(repo)
    assert why is None
    assert [(m["path"], m["url"]) for m in mods] == [("child", "https://example.invalid/leak.git")]
    for cmd in seen:
        assert not any(str(repo) in arg for arg in cmd), cmd  # git never sees a repo path
    assert hygiene.read_gitmodules(repo.parent / "nope") == ([], None)  # absent is benign


def test_walk_reports_an_unlistable_directory(repo: Path, monkeypatch) -> None:
    wf = repo / ".github" / "workflows"
    (wf / "sub").mkdir(parents=True)
    (wf / "a.yml").write_text("x: 1\n", encoding="utf-8")
    real_walk = os.walk

    def walk(top, onerror=None, followlinks=False):
        for entry in real_walk(top, onerror=onerror, followlinks=followlinks):
            yield entry
            if Path(entry[0]) == wf and onerror is not None:
                onerror(PermissionError(13, "denied", str(wf / "sub")))
                entry[1].remove("sub")

    monkeypatch.setattr(hygiene.os, "walk", walk)
    assert hygiene.walk_repo_files(repo, ".github/workflows") == [
        (".github/workflows/a.yml", None),
        (".github/workflows/sub", "unreadable: PermissionError"),
    ]


def test_walk_reports_an_entry_it_cannot_lstat(repo: Path, monkeypatch) -> None:
    wf = repo / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "a.yml").write_text("x: 1\n", encoding="utf-8")
    real_lstat = os.lstat

    def lstat(path, *a, **k):
        if Path(path).name == "a.yml":
            raise PermissionError(13, "denied")
        return real_lstat(path, *a, **k)

    monkeypatch.setattr(hygiene.os, "lstat", lstat)
    assert hygiene.walk_repo_files(repo, ".github/workflows") == [
        (".github/workflows/a.yml", "unreadable: PermissionError")]


def test_walk_root_errors_are_reported_absence_is_not(repo: Path) -> None:
    assert hygiene.walk_repo_files(repo, ".github/workflows") == []
    write(repo, ".github/workflows", "not a dir")
    assert hygiene.walk_repo_files(repo, ".github/workflows") == [
        (".github/workflows", "not a directory: not read")]


def _git_repo(path: Path) -> Path:
    (path / ".git").mkdir(parents=True)
    return path


def test_enrolment_records_every_candidate_it_drops(tmp_path: Path, monkeypatch) -> None:
    if not _can_symlink(tmp_path):
        pytest.skip("this account cannot create symlinks")
    root = tmp_path / "projects"
    good = _git_repo(root / "good")
    (good / "release-config.yml").write_text("project: good\n", encoding="utf-8")
    linked = _git_repo(root / "linked")
    outside = tmp_path / "rc.yml"
    outside.write_text("project: stolen\n", encoding="utf-8")
    os.symlink(outside, linked / "release-config.yml")
    big = _git_repo(root / "big")
    (big / "release-config.yml").write_text("project: big\n" + "#" * 200 + "\n", encoding="utf-8")
    monkeypatch.setattr(hygiene, "MAX_RUNTIME_SOURCE_BYTES", 100)
    _git_repo(root / "none")
    skipped: list[dict[str, str]] = []
    enrolled = hygiene.discover_enrolled_repos([root], skipped)
    assert [c.name for c, _ in enrolled] == ["good"]
    got = {Path(s["path"]).parent.name: s["reason"] for s in skipped}
    assert got == {"linked": "symlink: not followed", "big": "exceeds 100-byte cap: not read"}, got
    md = hygiene.render_drift_markdown({"scanned_at": "t", "enrolled_count": 1, "drift_findings": 0,
                                        "repos": [], "enrolment_unexamined": skipped})
    assert "NOT examined" in md and "symlink: not followed" in md


# ── class check: every filesystem access and subprocess argument is accounted for ──
# Anchored on the ACCESS (gate pass 1 on #87), not on one spelling: every call
# that touches the filesystem by path (Path.resolve/is_file/is_dir/exists/stat/
# lstat/is_symlink/read_*/open/iterdir/glob/rglob, os.*, os.path.*) and every
# argument list handed to run()/subprocess.run() is enumerated from the AST.
# Each must be inside a helper, or on an operator path (the roots the operator
# passed, dev-standards' own checkout, the canonical register, a temp file this
# script created) named here with its reason. A new access to a scanned repo's
# content fails this test until it is routed through lstat_repo_path /
# read_repo_file or justified below.

PATH_METHODS = {"resolve", "is_file", "is_dir", "exists", "stat", "lstat", "is_symlink", "read_text",
                "read_bytes", "open", "iterdir", "rglob", "glob", "samefile", "readlink", "is_junction",
                "write_text", "write_bytes", "absolute", "owner", "touch"}
OS_FUNCS = {"lstat", "stat", "open", "walk", "scandir", "listdir", "readlink", "access"}
OS_PATH_FUNCS = {"exists", "lexists", "isfile", "isdir", "islink", "realpath", "abspath", "getsize",
                 "getmtime", "samefile"}

HELPERS = {"lstat_repo_path", "read_repo_file", "walk_repo_files", "walk_repo_files.walk_error"}
# (function, access, receiver) -> why it is not a scanned repo's content.
OPERATOR_ACCESS = {
    ("<module>", ".resolve", "Path(__file__)"): "this script's own checkout",
    ("main", ".resolve", "Path(__file__)"): "this script's own checkout",
    ("main", ".is_dir", "r"): "an operator-supplied root",
    ("main", ".is_dir", "scratch_root"): "operator-supplied root",
    ("main", ".is_dir", "worktrees_root"): "operator-supplied root",
    ("main", ".write_text", "out_file"): "the report the operator asked for",
    ("write_versions_yml", ".write_text", "out_path"): "dev-standards' own release/versions.yml",
    ("discover_repos", ".is_dir", "root"): "operator root",
    ("discover_repos", ".iterdir", "root"): "operator root",
    ("discover_repos", ".is_dir", "child"): "a repo directory under the operator root (git clone made it)",
    ("discover_repos", ".iterdir", "child"): "namespace directory under the operator root",
    ("discover_repos", ".is_dir", "grandchild"): "a repo directory one namespace down",
    ("discover_repos", ".resolve", "c"): "de-duplicating repo roots, not reading inside one",
    ("discover_enrolled_repos", ".is_dir", "root"): "operator root",
    ("discover_enrolled_repos", ".iterdir", "root"): "operator root",
    ("discover_enrolled_repos", ".is_dir", "child"): "a repo directory under the operator root",
    ("discover_enrolled_repos", ".resolve", "c"): "de-duplicating repo roots, not reading inside one",
    ("is_git_repo", ".is_dir", "path / '.git'"): "a repo's .git, written by git, never committable",
    ("is_git_repo", ".is_file", "path / '.git'"): "a worktree's .git file, written by git",
    ("is_namespace_dir", ".iterdir", "path"): "layout pass over the operator root (--no-layout on mirrors)",
    ("is_namespace_dir", ".is_dir", "c"): "layout pass over the operator root",
    ("is_worktree_checkout", ".is_file", "path / '.git'"): "a worktree's .git file, written by git",
    ("scan_root_layout", ".iterdir", "root"): "layout pass over the operator root",
    ("scan_root_layout.classify", ".is_file", "entry"): "layout pass over the operator root",
    ("scan_root_layout.classify", ".iterdir", "entry"): "layout pass over the operator root",
    ("scan_scratch_root", ".iterdir", "root"): "operator D:/Scratch",
    ("scan_scratch_root", ".stat", "entry"): "operator D:/Scratch",
    ("scan_worktrees_root", ".iterdir", "root"): "operator D:/Worktrees",
    ("scan_worktrees_root", ".iterdir", "repo_dir"): "operator D:/Worktrees",
    ("scan_worktrees_root", ".is_file", "repo_dir"): "operator D:/Worktrees",
    ("scan_worktrees_root", ".is_file", "leaf"): "operator D:/Worktrees",
    ("scan_worktrees_root", ".is_symlink", "leaf"): "operator D:/Worktrees (the link check itself)",
    ("scan_hook_drift", ".is_dir", "canonical_dir"): "dev-standards' own hooks/",
    ("scan_hook_drift", ".iterdir", "canonical_dir"): "dev-standards' own hooks/",
    ("scan_hook_drift", ".is_file", "p"): "dev-standards' own hooks/",
    ("scan_hook_drift", ".read_bytes", "canon"): "dev-standards' own hooks/",
    ("scan_cache_restore", ".read_text", "allowlist_path"): "dev-standards' own allow-list",
    ("scan_security_register", "os.stat", "canon_path"): "the canonical register (operator path)",
    ("load_security_roster", ".read_text", "path"): "operator roster file",
    ("load_canonical_register", ".read_text", "path"): "the canonical register",
    ("load_canonical_register", ".resolve", "path"): "the canonical register",
    ("post_to_brain", ".is_file", "key_path"): "operator key file",
    ("post_to_brain", ".read_text", "key_path"): "operator key file",
    ("read_gitmodules", ".write_bytes", "gm"): "a temp file this script created",
}
# run()/subprocess.run() arguments that name a path: only these may appear.
OPERATOR_ARGS = {
    ("read_gitmodules", "str(gm)"): "the private temp copy of .gitmodules",
    ("origin_url", "str(repo)"): "git -C <repo root> remote get-url: git reads its own config",
    ("scan_worktrees_root", "str(leaf)"): "operator D:/Worktrees",
}


def _inventory():
    import ast
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    accesses, args = [], []

    def visit(node, fn):
        for child in ast.iter_child_nodes(node):
            name = fn
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = child.name if fn == "<module>" else f"{fn}.{child.name}"
            if isinstance(child, ast.Call):
                f = child.func
                if isinstance(f, ast.Attribute):
                    base = ast.unparse(f.value)
                    first = ast.unparse(child.args[0]) if child.args else ""
                    if base == "os" and f.attr in OS_FUNCS:
                        accesses.append((name, f"os.{f.attr}", first))
                    elif base == "os.path" and f.attr in OS_PATH_FUNCS:
                        accesses.append((name, f"os.path.{f.attr}", first))
                    elif f.attr in PATH_METHODS and base not in ("os", "os.path", "re", "subprocess"):
                        accesses.append((name, f".{f.attr}", base))
                callee = ast.unparse(f)
                if callee in ("run", "subprocess.run") and child.args and isinstance(child.args[0], (ast.List, ast.Tuple)):
                    for el in child.args[0].elts:
                        # A filesystem path handed to the tool: str(<path>), os.fspath(<path>), <a> / <b>.
                        is_path = (isinstance(el, ast.BinOp) and isinstance(el.op, ast.Div)) or (
                            isinstance(el, ast.Call) and ast.unparse(el.func) in ("str", "os.fspath"))
                        if is_path:
                            args.append((name, ast.unparse(el)))
            visit(child, name)

    visit(tree, "<module>")
    return accesses, args


def test_every_repo_access_goes_through_the_helpers() -> None:
    accesses, args = _inventory()
    assert accesses, "the inventory no longer sees any access"
    unaccounted = sorted({a for a in accesses if a[0] not in HELPERS and a not in OPERATOR_ACCESS})
    assert unaccounted == [], unaccounted
    stray = sorted({a for a in args if a not in OPERATOR_ARGS})
    assert stray == [], stray
    # The helpers are the only openers and the only os.lstat / os.walk callers.
    for access in ("os.open", "os.lstat", "os.walk"):
        where = {fn for fn, acc, _ in accesses if acc == access}
        assert where <= HELPERS, (access, where)
    src = SCRIPT.read_text(encoding="utf-8")
    assert "rglob(" not in src, "a recursive glob follows symlinked files; use walk_repo_files"
    # The allow-lists carry no dead rows: each entry names an access that still exists.
    assert set(OPERATOR_ACCESS) <= set(accesses), sorted(set(OPERATOR_ACCESS) - set(accesses))
    assert set(OPERATOR_ARGS) <= set(args), sorted(set(OPERATOR_ARGS) - set(args))
