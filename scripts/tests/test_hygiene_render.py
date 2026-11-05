"""render_markdown / render_item in repo-hygiene-scan.py: every item field is printed.

2026-11-05 (evidence: Ohio15/dev-standards#73, Ohio15/n3xus-notify#17):
`auto-apply-cache-restore` items are {path, line, form} and rendered as
`<path>: ` because the renderer only knew {path, reason}. These tests pin
every item shape the scan emits.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "repo-hygiene-scan.py"
spec = importlib.util.spec_from_file_location("hygiene_render", SCRIPT)
hygiene = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(hygiene)

WF = ".github/workflows/security-audit.yml"
GO = "setup-go without cache: false"
KEY = "cache: not false"


def report_with(*findings: dict) -> dict:
    return {
        "scan_date": "2026-11-05", "roots": ["/r"], "repo_count": 1,
        "total_findings": len(findings),
        "totals_by_severity": {"HIGH": 0, "MEDIUM": len(findings), "LOW": 0},
        "repos": [{"name": "n3xus-notify", "path": "/r/n3xus-notify", "tracked_count": 1,
                   "findings": list(findings)}],
    }


def item_lines(md: str) -> list[str]:
    return [ln.strip() for ln in md.splitlines() if ln.startswith("    - ")]


def test_cache_restore_items_render_path_line_and_form():
    md = hygiene.render_markdown(report_with({
        "severity": "MEDIUM", "code": "auto-apply-cache-restore", "count": 2, "note": "n",
        "items": [{"path": WF, "line": 370, "form": GO}, {"path": WF, "line": 373, "form": KEY}],
    }))
    assert item_lines(md) == [f"- {WF}:370 {GO}", f"- {WF}:373 {KEY}"]


def test_real_scan_finding_renders_with_line_and_form(tmp_path):
    """End to end: the finding scan_cache_restore actually emits, rendered."""
    repo = tmp_path / "r"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "auto-apply-enabled").write_text("", encoding="utf-8")
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/cache@0123456789abcdef0123456789abcdef01234567\n", encoding="utf-8")
    findings = hygiene.scan_cache_restore(repo)
    assert findings, "fixture must trigger the finding"
    lines = item_lines(hygiene.render_markdown(report_with(*findings)))
    assert lines == [f"- .github/workflows/ci.yml:{i['line']} {i['form']}" for i in findings[0]["items"]]
    assert all(i["line"] is not None and i["form"] for i in findings[0]["items"])


def test_item_without_a_line_renders_path_and_form():
    assert hygiene.render_item({"path": WF, "line": None, "form": "unreadable: denied"}) == \
        f"{WF} unreadable: denied"


def test_path_reason_items_keep_their_reason():
    assert hygiene.render_item({"path": "a.exe", "reason": "binary extension .exe"}) == \
        "a.exe binary extension .exe"


def test_extra_fields_render_as_key_value():
    assert hygiene.render_item({"path": "src/x.py", "line": 4, "host": "api.openai.com"}) == \
        "src/x.py:4 host=api.openai.com"
    assert hygiene.render_item({"path": "w.yml", "kind": "workflow", "reason": "too big"}) == \
        "w.yml too big kind=workflow"


def test_pathless_hook_drift_item_renders_every_field():
    got = hygiene.render_item({"hook": "pre-commit-tests.sh", "canonical": "5f3eb95f5942",
                               "installed": "6dc0c63a2932"})
    assert got == "hook=pre-commit-tests.sh canonical=5f3eb95f5942 installed=6dc0c63a2932"


def test_string_items_render_verbatim():
    assert hygiene.render_item("pre-push") == "pre-push"
    md = hygiene.render_markdown(report_with({
        "severity": "MEDIUM", "code": "hook-missing", "count": 1, "items": ["pre-push"]}))
    assert item_lines(md) == ["- pre-push"]
