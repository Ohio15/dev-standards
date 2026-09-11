"""dev-standards #5: `hook-drift` / `hook-missing` findings in repo-hygiene-scan.py.

Each test builds a throwaway "repo" directory under pytest's tmp_path with a
.githooks/ populated from a throwaway canonical hooks/ dir, then mutates one
side. No real repo, no git, no network.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "repo-hygiene-scan.py"
spec = importlib.util.spec_from_file_location("hygiene", SCRIPT)
hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(hygiene)

CANON = {
    "commit-msg": "#!/usr/bin/env bash\nexit 0\n",
    "pre-commit": "#!/usr/bin/env bash\nexit 0\n",
    "pre-commit-size-guard.sh": "#!/usr/bin/env bash\necho guard\n",
}


def make_canonical(tmp_path: Path) -> Path:
    canon = tmp_path / "dev-standards" / "hooks"
    canon.mkdir(parents=True)
    for name, body in CANON.items():
        (canon / name).write_text(body, encoding="utf-8", newline="\n")
    return canon


def make_repo(tmp_path: Path, canon: Path, *, onboarded: bool = True) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    if onboarded:
        gh = repo / ".githooks"
        gh.mkdir()
        for f in canon.iterdir():
            (gh / f.name).write_bytes(f.read_bytes())
    return repo


def codes(findings: list[dict]) -> dict[str, dict]:
    return {f["code"]: f for f in findings}


def test_in_sync_repo_has_no_findings(tmp_path: Path) -> None:
    canon = make_canonical(tmp_path)
    repo = make_repo(tmp_path, canon)
    assert hygiene.scan_hook_drift(repo, canon) == []


def test_not_onboarded_repo_is_not_judged(tmp_path: Path) -> None:
    canon = make_canonical(tmp_path)
    repo = make_repo(tmp_path, canon, onboarded=False)
    assert hygiene.scan_hook_drift(repo, canon) == []


def test_hand_edited_hook_is_drift(tmp_path: Path) -> None:
    canon = make_canonical(tmp_path)
    repo = make_repo(tmp_path, canon)
    (repo / ".githooks" / "commit-msg").write_text(
        "#!/usr/bin/env bash\n# relaxed by hand\nexit 0\n", encoding="utf-8", newline="\n"
    )
    found = codes(hygiene.scan_hook_drift(repo, canon))
    assert set(found) == {"hook-drift"}
    f = found["hook-drift"]
    assert f["severity"] == "MEDIUM"
    assert f["count"] == 1
    assert f["items"][0]["hook"] == "commit-msg"
    assert f["items"][0]["canonical"] != f["items"][0]["installed"]
    assert "install.sh" in f["note"]


def test_crlf_checkout_is_not_drift(tmp_path: Path) -> None:
    canon = make_canonical(tmp_path)
    repo = make_repo(tmp_path, canon)
    installed = repo / ".githooks" / "pre-commit"
    installed.write_bytes(installed.read_bytes().replace(b"\n", b"\r\n"))
    assert hygiene.scan_hook_drift(repo, canon) == []


def test_uninstalled_canonical_hook_is_missing(tmp_path: Path) -> None:
    canon = make_canonical(tmp_path)
    repo = make_repo(tmp_path, canon)
    (repo / ".githooks" / "commit-msg").unlink()
    found = codes(hygiene.scan_hook_drift(repo, canon))
    assert set(found) == {"hook-missing"}
    assert found["hook-missing"]["severity"] == "MEDIUM"
    assert found["hook-missing"]["items"] == ["commit-msg"]


def test_extra_repo_local_hook_is_tolerated(tmp_path: Path) -> None:
    # A sub-hook the repo added itself (pre-commit-tests config, custom
    # pre-commit-*.sh) is not the canonical set's business.
    canon = make_canonical(tmp_path)
    repo = make_repo(tmp_path, canon)
    (repo / ".githooks" / "pre-commit-local-lint.sh").write_text("#!/usr/bin/env bash\n")
    assert hygiene.scan_hook_drift(repo, canon) == []


def test_drift_and_missing_are_reported_together(tmp_path: Path) -> None:
    canon = make_canonical(tmp_path)
    repo = make_repo(tmp_path, canon)
    (repo / ".githooks" / "commit-msg").unlink()
    (repo / ".githooks" / "pre-commit").write_text("changed\n")
    found = codes(hygiene.scan_hook_drift(repo, canon))
    assert set(found) == {"hook-drift", "hook-missing"}


def test_default_canonical_dir_is_the_repo_hooks_dir() -> None:
    assert hygiene.CANONICAL_HOOKS_DIR == SCRIPT.parent.parent / "hooks"
    assert (hygiene.CANONICAL_HOOKS_DIR / "commit-msg").is_file()
