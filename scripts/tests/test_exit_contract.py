"""Exit-code contract of repo-hygiene-scan.py (see its module docstring).

A crash must not exit 1 (that is "MEDIUM findings"), and a failed
--brain-store must not be masked by the findings code. Both were
indistinguishable from a normal week before this contract existed.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "repo-hygiene-scan.py"
spec = importlib.util.spec_from_file_location("hygiene_exit", SCRIPT)
hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(hygiene)


def _argv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *extra: str) -> None:
    monkeypatch.setattr(sys, "argv", [
        "repo-hygiene-scan.py", "--root", str(tmp_path), "--no-layout",
        "--output-dir", str(tmp_path / "out"), *extra,
    ])


def test_crash_exits_70_not_1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _argv(monkeypatch, tmp_path)

    def boom(_roots):
        raise RuntimeError("simulated scanner defect")

    monkeypatch.setattr(hygiene, "discover_repos", boom)
    assert hygiene.run_main() == hygiene.EXIT_CRASH == 70


def test_brain_store_failure_exits_3(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _argv(monkeypatch, tmp_path, "--brain-store")
    monkeypatch.setattr(hygiene, "post_to_brain", lambda md, date: (False, "simulated outage"))
    assert hygiene.run_main() == hygiene.EXIT_BRAIN_STORE_FAILED == 3


def test_brain_store_success_keeps_findings_code(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _argv(monkeypatch, tmp_path, "--brain-store")
    monkeypatch.setattr(hygiene, "post_to_brain", lambda md, date: (True, "{}"))
    # Empty root: no repos, no findings -> 0.
    assert hygiene.run_main() == 0


def test_usage_error_keeps_argparse_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["repo-hygiene-scan.py", "--no-such-flag"])
    with pytest.raises(SystemExit) as exc:
        hygiene.run_main()
    assert exc.value.code == 2
