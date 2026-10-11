"""STANDARDS.md §13 Application Independence Floor (IMPL-34): the
`independence-*` findings in repo-hygiene-scan.py.

Each test builds a throwaway repo directory under pytest's tmp_path and hands
the scanner an explicit tracked-file list, so no git, no network. The three
HIGH/MEDIUM shapes are each proven in both directions (present -> finding,
absent -> no finding), plus the mode selector and the ADR exemption.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "repo-hygiene-scan.py"
spec = importlib.util.spec_from_file_location("hygiene", SCRIPT)
hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(hygiene)

RELEASE_WF = "name: release\non:\n  push:\n    tags:\n      - 'v*'\njobs: {}\n"


def write(repo: Path, rel: str, body: str) -> str:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8", newline="\n")
    return rel


def conforming(tmp_path: Path, *, mode: str | None = None) -> tuple[Path, list[str]]:
    """A repo that satisfies every check: runbook, release workflow, clean source."""
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    tracked = [
        write(repo, "docs/RELEASE.md", "# Releasing\n"),
        write(repo, ".github/workflows/release.yml", RELEASE_WF),
        write(repo, "src/app.ts", "export const host = process.env.LLM_HOST;\n"),
    ]
    if mode is not None:
        tracked.append(write(repo, "release-config.yml", f"project: x\nsurface: lib\nindependence: {mode}\n"))
    return repo, tracked


def codes(findings: list[dict]) -> dict[str, dict]:
    return {f["code"]: f for f in findings}


# --- mode selector -----------------------------------------------------------

def test_mode_defaults_to_full_without_config(tmp_path: Path) -> None:
    repo, _ = conforming(tmp_path)
    assert hygiene.read_independence_mode(repo) == ("full", None)


def test_mode_defaults_to_full_when_key_absent(tmp_path: Path) -> None:
    repo, _ = conforming(tmp_path)
    write(repo, "release-config.yml", "project: x\nsurface: lib\n")
    assert hygiene.read_independence_mode(repo) == ("full", None)


@pytest.mark.parametrize("mode", ["full", "tooling", "harness"])
def test_mode_reads_each_legal_value(tmp_path: Path, mode: str) -> None:
    repo, _ = conforming(tmp_path, mode=mode)
    assert hygiene.read_independence_mode(repo) == (mode, None)


def test_unknown_mode_is_reported_and_scanned_as_full(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path, mode="exempt")
    tracked.append(write(repo, "src/llm.ts", "fetch('https://api.openai.com/v1/chat');\n"))
    found = codes(hygiene.scan_independence(repo, tracked))
    assert "independence-mode-invalid" in found
    # a typo never widens the exemption: the vendor check still ran
    assert "independence-ai-vendor-runtime" in found


# --- runbook (AI-4) ----------------------------------------------------------

def test_conforming_repo_has_no_findings(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    assert hygiene.scan_independence(repo, tracked) == []


def test_missing_runbook_is_high(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked = [t for t in tracked if t != "docs/RELEASE.md"]
    found = codes(hygiene.scan_independence(repo, tracked))
    assert found["independence-runbook-missing"]["severity"] == "HIGH"


def test_root_release_md_also_satisfies_runbook(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked = [t for t in tracked if t != "docs/RELEASE.md"]
    tracked.append(write(repo, "RELEASE.md", "# Releasing\n"))
    assert "independence-runbook-missing" not in codes(hygiene.scan_independence(repo, tracked))


def test_untracked_runbook_does_not_count(tmp_path: Path) -> None:
    """The file exists on disk but is not in the tracked list: not committed, not a runbook."""
    repo, tracked = conforming(tmp_path)
    tracked = [t for t in tracked if t != "docs/RELEASE.md"]
    assert (repo / "docs/RELEASE.md").is_file()
    assert "independence-runbook-missing" in codes(hygiene.scan_independence(repo, tracked))


def test_harness_mode_still_owes_runbook_and_workflow(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path, mode="harness")
    tracked = [t for t in tracked if t not in ("docs/RELEASE.md", ".github/workflows/release.yml")]
    found = codes(hygiene.scan_independence(repo, tracked))
    assert found["independence-runbook-missing"]["mode"] == "harness"
    assert found["independence-no-release-workflow"]["mode"] == "harness"


# --- release workflow (AI-5) -------------------------------------------------

def test_missing_release_workflow_is_high(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked = [t for t in tracked if t != ".github/workflows/release.yml"]
    found = codes(hygiene.scan_independence(repo, tracked))
    assert found["independence-no-release-workflow"]["severity"] == "HIGH"
    assert found["independence-no-release-workflow"]["workflows_present"] == 0


def test_workflow_named_otherwise_but_tag_triggered_counts(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked = [t for t in tracked if t != ".github/workflows/release.yml"]
    tracked.append(write(repo, ".github/workflows/publish.yml", RELEASE_WF))
    assert "independence-no-release-workflow" not in codes(hygiene.scan_independence(repo, tracked))


def test_workflow_consuming_dev_standards_release_gates_counts(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked = [t for t in tracked if t != ".github/workflows/release.yml"]
    tracked.append(write(repo, ".github/workflows/ship.yml",
                         "jobs:\n  gates:\n    uses: Ohio15/dev-standards/.github/workflows/release-gates.yml@v1\n"))
    assert "independence-no-release-workflow" not in codes(hygiene.scan_independence(repo, tracked))


def test_ci_only_workflow_does_not_count(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked = [t for t in tracked if t != ".github/workflows/release.yml"]
    tracked.append(write(repo, ".github/workflows/ci.yml", "name: ci\non:\n  push:\n    branches: [main]\njobs: {}\n"))
    found = codes(hygiene.scan_independence(repo, tracked))
    assert found["independence-no-release-workflow"]["workflows_present"] == 1


# --- AI-vendor host literals (AI-1) ------------------------------------------

def test_vendor_host_in_runtime_source_is_medium(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked.append(write(repo, "src/llm.cs", 'var url = "https://api.anthropic.com/v1/messages";\n'))
    found = codes(hygiene.scan_independence(repo, tracked))
    f = found["independence-ai-vendor-runtime"]
    assert f["severity"] == "MEDIUM"
    assert f["items"] == [{"path": "src/llm.cs", "line": 1, "host": "api.anthropic.com"}]


def test_vendor_host_in_test_code_is_not_flagged(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked.append(write(repo, "tests/llm_test.py", "URL = 'https://api.openai.com'\n"))
    tracked.append(write(repo, "src/llm.spec.ts", "const u = 'https://api.openai.com';\n"))
    assert "independence-ai-vendor-runtime" not in codes(hygiene.scan_independence(repo, tracked))


def test_vendor_host_in_docs_or_comment_is_not_flagged(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked.append(write(repo, "docs/THREATS.md", "We never call api.anthropic.com.\n"))
    tracked.append(write(repo, "src/allow.cs", "/// <item>https://api.anthropic.com - exact host match</item>\n"
                                               "// api.openai.com is listed for the allow-list, not called\n"
                                               "var x = 1;\n"))
    assert "independence-ai-vendor-runtime" not in codes(hygiene.scan_independence(repo, tracked))


def test_vendor_host_in_tooling_or_harness_repo_is_not_flagged(tmp_path: Path) -> None:
    for mode in ("tooling", "harness"):
        repo, tracked = conforming(tmp_path / mode, mode=mode)
        tracked.append(write(repo, "src/llm.ts", "fetch('https://api.openai.com');\n"))
        assert "independence-ai-vendor-runtime" not in codes(hygiene.scan_independence(repo, tracked)), mode


def test_adr_naming_the_host_exempts_it(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked.append(write(repo, "src/llm.ts", "fetch('https://api.openai.com');\nfetch('https://api.mistral.ai');\n"))
    tracked.append(write(repo, "docs/adr/0007-openai-provider.md",
                         "# ADR 7\nProvider abstraction; degraded mode when api.openai.com is unreachable.\n"))
    f = codes(hygiene.scan_independence(repo, tracked))["independence-ai-vendor-runtime"]
    assert f["exempt_by_adr"] == ["api.openai.com"]
    assert [i["host"] for i in f["items"]] == ["api.mistral.ai"]


def test_local_model_endpoint_counts_as_vendor_literal(tmp_path: Path) -> None:
    """A hard-wired Ollama port is still a hard-wired provider; owner choice means it comes from config."""
    repo, tracked = conforming(tmp_path)
    tracked.append(write(repo, "config/app.json", '{"llm": "http://localhost:11434/api/generate"}\n'))
    assert "independence-ai-vendor-runtime" in codes(hygiene.scan_independence(repo, tracked))


def test_github_workflow_files_are_not_runtime_source(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked.append(write(repo, ".github/workflows/eval.yml", "env:\n  HOST: api.openai.com\n"))
    assert "independence-ai-vendor-runtime" not in codes(hygiene.scan_independence(repo, tracked))


# --- wired into scan_repo ----------------------------------------------------

def test_scan_repo_includes_independence_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, tracked = conforming(tmp_path)
    tracked = [t for t in tracked if t != "docs/RELEASE.md"]
    monkeypatch.setattr(hygiene, "tracked_files", lambda r: tracked)
    monkeypatch.setattr(hygiene, "check_ignored", lambda r, p: [])
    monkeypatch.setattr(hygiene, "working_tree_drift", lambda r: [])
    monkeypatch.setattr(hygiene, "gitconfig", lambda r, k: None)
    monkeypatch.setattr(hygiene, "last_commit_age_days", lambda r: 1)
    monkeypatch.setattr(hygiene, "scan_submodule_pointer_lag", lambda r: [])
    monkeypatch.setattr(hygiene, "scan_hook_drift", lambda r: [])
    report = hygiene.scan_repo(repo, age_threshold=7)
    assert "independence-runbook-missing" in codes(report["findings"])
