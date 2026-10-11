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


# --- unexamined is not clean (gate pass 1 on PR #45, SC-07) -------------------

def test_oversized_runtime_file_is_reported_unexamined_not_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A file the scan could not read must surface as unexamined; silently
    skipping it would let a vendor literal inside it pass as clean."""
    monkeypatch.setattr(hygiene, "MAX_RUNTIME_SOURCE_BYTES", 64)
    repo, tracked = conforming(tmp_path)
    tracked.append(write(repo, "src/big.ts", "// " + "x" * 80 + "\nfetch('https://api.openai.com');\n"))
    found = codes(hygiene.scan_independence(repo, tracked))
    assert "independence-ai-vendor-runtime" not in found
    f = found["independence-unexamined"]
    assert f["severity"] == "LOW"
    assert f["count"] == 1
    assert f["items"][0]["path"] == "src/big.ts"
    assert f["items"][0]["kind"] == "runtime-source"
    assert "exceeds" in f["items"][0]["reason"]
    assert "not clean" in f["note"]


def test_unreadable_runtime_file_is_reported_unexamined(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked.append("src/missing.ts")  # tracked in the index, absent from the tree
    f = codes(hygiene.scan_independence(repo, tracked))["independence-unexamined"]
    assert f["items"] == [{"path": "src/missing.ts", "kind": "runtime-source", "reason": "unreadable: FileNotFoundError"}]


def test_oversized_adr_and_workflow_are_reported_unexamined(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A skipped ADR cannot grant an exemption and a skipped workflow body cannot
    prove a release path; both are named so the HIGH/MEDIUM verdicts are read
    with their blind spots."""
    monkeypatch.setattr(hygiene, "MAX_RUNTIME_SOURCE_BYTES", 64)
    repo, tracked = conforming(tmp_path)
    # no workflow named for release: the body read is the only way to prove one
    tracked = [t for t in tracked if t != ".github/workflows/release.yml"]
    tracked.append(write(repo, "docs/adr/0001-llm.md", "# ADR\n" + "api.openai.com " * 20))
    tracked.append(write(repo, ".github/workflows/ci.yml", "name: ci\n" + "# " + "y" * 80 + "\n"))
    found = codes(hygiene.scan_independence(repo, tracked))
    assert "independence-no-release-workflow" in found  # unproven, so still owed
    kinds = sorted((i["kind"], i["path"]) for i in found["independence-unexamined"]["items"])
    assert kinds == [("adr", "docs/adr/0001-llm.md"), ("workflow", ".github/workflows/ci.yml")]


def test_readable_clean_file_is_neither_flagged_nor_unexamined(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked.append(write(repo, "src/clean.ts", "export const n = 1;\n"))
    found = codes(hygiene.scan_independence(repo, tracked))
    assert "independence-ai-vendor-runtime" not in found
    assert "independence-unexamined" not in found


# --- suffix-aware comment rule ----------------------------------------------

def test_json_line_led_by_semicolon_or_hash_is_data_not_comment(tmp_path: Path) -> None:
    """JSON has no comment syntax; a `;`- or `#`-led line is a value and still a literal."""
    repo, tracked = conforming(tmp_path)
    tracked.append(write(repo, "config/a.json", '{\n; "llm": "https://api.openai.com"\n}\n'))
    tracked.append(write(repo, "config/b.json", '{\n# "llm": "https://api.anthropic.com"\n}\n'))
    f = codes(hygiene.scan_independence(repo, tracked))["independence-ai-vendor-runtime"]
    assert sorted(i["path"] for i in f["items"]) == ["config/a.json", "config/b.json"]


def test_semicolon_is_a_comment_only_in_ini(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked.append(write(repo, "config/app.ini", "; https://api.openai.com is documented, not used\nhost = ${LLM_HOST}\n"))
    tracked.append(write(repo, "src/llm.py", "; 'https://api.openai.com'\n"))
    f = codes(hygiene.scan_independence(repo, tracked))["independence-ai-vendor-runtime"]
    assert [i["path"] for i in f["items"]] == ["src/llm.py"]


def test_hash_is_not_a_comment_in_c_family_source(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked.append(write(repo, "src/llm.cs", '#region\nvar u = "https://api.openai.com";\n#endregion\n'))
    tracked.append(write(repo, "src/pre.ts", '# "https://api.mistral.ai"\n'))
    tracked.append(write(repo, "src/ok.py", "# https://api.cohere.com is never called\n"))
    f = codes(hygiene.scan_independence(repo, tracked))["independence-ai-vendor-runtime"]
    assert sorted(i["path"] for i in f["items"]) == ["src/llm.cs", "src/pre.ts"]


def test_xaml_comment_and_double_slash_in_xaml_data(tmp_path: Path) -> None:
    repo, tracked = conforming(tmp_path)
    tracked.append(write(repo, "src/ok.xaml", "<!-- https://api.openai.com documented -->\n"))
    tracked.append(write(repo, "src/bad.xaml", '<TextBlock Text="// https://api.openai.com"/>\n'))
    f = codes(hygiene.scan_independence(repo, tracked))["independence-ai-vendor-runtime"]
    assert [i["path"] for i in f["items"]] == ["src/bad.xaml"]
