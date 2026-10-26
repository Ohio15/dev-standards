"""post_to_brain must never put the shared-brain bearer on curl's argv (SC-11).

Any local uid can read /proc/<pid>/cmdline, so the key has to travel on stdin.
"""
import importlib.util
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "repo-hygiene-scan.py"
spec = importlib.util.spec_from_file_location("hygiene_argv", SCRIPT)
hygiene = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hygiene)

FAKE_KEY = "fake-test-key-not-real"


def _home_with_key(tmp_path, key):
    cfg = tmp_path / ".config" / "shared-brain"
    cfg.mkdir(parents=True)
    (cfg / "api-key").write_text(key + "\n")
    return tmp_path


def test_bearer_goes_on_stdin_not_argv(tmp_path, monkeypatch):
    monkeypatch.setattr(hygiene.Path, "home", lambda: _home_with_key(tmp_path, FAKE_KEY))
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["input"] = kwargs.get("input")
        return subprocess.CompletedProcess(cmd, 0, stdout='{"id":"x"}', stderr="")

    monkeypatch.setattr(hygiene.subprocess, "run", fake_run)
    ok, _ = hygiene.post_to_brain("summary", "2026-10-17")
    assert ok
    assert all(FAKE_KEY not in part for part in seen["cmd"]), "bearer leaked onto argv"
    assert "@-" in seen["cmd"]
    assert seen["input"] == f"Authorization: Bearer {FAKE_KEY}\n"


def test_key_with_line_break_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(hygiene.Path, "home", lambda: _home_with_key(tmp_path, "abc\rX-Injected: 1"))
    called = []
    monkeypatch.setattr(hygiene.subprocess, "run", lambda *a, **k: called.append(a))
    ok, msg = hygiene.post_to_brain("summary", "2026-10-17")
    assert not ok and "line break" in msg
    assert not called


def test_curl_failure_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(hygiene.Path, "home", lambda: _home_with_key(tmp_path, FAKE_KEY))
    monkeypatch.setattr(
        hygiene.subprocess, "run",
        lambda cmd, **k: subprocess.CompletedProcess(cmd, 7, stdout="", stderr="connect failed"),
    )
    ok, msg = hygiene.post_to_brain("summary", "2026-10-17")
    assert not ok and "rc=7" in msg
