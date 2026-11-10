"""estate/code-standards-roster.txt: Steward reviews its own code.

Steward's code-standards position covers the whole estate including Steward's
own repos (Ron, shared-brain 9d2d2d9e). A roster edit that drops or comments
out one of them would silently exempt Steward from its own review, so this
test fails on that. It also checks every entry is a label the exporter
accepts, so a bad line fails here rather than at 3am on NEXUS.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ROSTER = ROOT / "estate" / "code-standards-roster.txt"
STEWARD_REPOS = ("steward", "steward-core", "steward-sessionwatch", "steward-presence", "steward-governance")

FACTS = ROOT / "scripts" / "code-standards-facts.py"
spec = importlib.util.spec_from_file_location("cs_facts_roster", FACTS)
facts = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(facts)


def active_entries() -> list[str]:
    out = []
    for raw in ROSTER.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


@pytest.mark.parametrize("repo", STEWARD_REPOS)
def test_steward_repo_is_listed_and_active(repo: str) -> None:
    assert repo in {e.lower() for e in active_entries()}, f"{repo} missing or commented out of the roster"


def test_roster_parses_with_the_exporters_rules() -> None:
    labels = facts.read_roster(ROSTER)
    assert len(labels) == len(active_entries())
    assert all(re.match(r"^[a-z0-9][a-z0-9._-]{0,63}$", label) for label in labels)


def test_binary_update_channel_is_excluded_with_a_reason() -> None:
    assert "aibrowser-updates" not in {e.lower() for e in active_entries()}
    text = ROSTER.read_text(encoding="utf-8")
    assert re.search(r"^#\s*aibrowser-updates\s+--\s+\S", text, re.MULTILINE)


def test_scanner_inputs_are_mirrored() -> None:
    # code-standards-cron.sh reads the security roster and the canonical
    # register from these two mirrors and refuses to export without them.
    entries = {e.lower() for e in active_entries()}
    assert {"cortex-hooks", "dev-standards"} <= entries
