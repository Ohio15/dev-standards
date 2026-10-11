"""The detached-version-comment detector in test_action_pins.py, proven on
fixtures in both directions (security gate pass 1 on PR #45, SC-20: a detector
that is only ever run against a clean tree has not been shown to detect).

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("action_pins", Path(__file__).resolve().parent / "test_action_pins.py")
action_pins = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(action_pins)

PIN = "      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7"


def test_red_version_comment_directly_above_a_pin() -> None:
    assert action_pins.detached_version_comments(["      # actions/checkout v4.1.7", PIN]) == [
        "1: # actions/checkout v4.1.7"
    ]


def test_red_version_comment_separated_from_the_pin_by_another_comment() -> None:
    """The gate's SC-20 case: a comment block ending in a pin is still detached;
    the intervening comment line must not hide it."""
    lines = ["      # actions/checkout v4.1.7", "      # persist-credentials is off below", PIN]
    assert action_pins.detached_version_comments(lines) == ["1: # actions/checkout v4.1.7"]


def test_red_version_comment_separated_from_the_pin_by_a_blank_line() -> None:
    lines = ["      # v4.1.7", "", PIN]
    assert action_pins.detached_version_comments(lines) == ["1: # v4.1.7"]


def test_green_version_in_prose_above_more_prose() -> None:
    lines = [
        "      # govulncheck v1.1.3 needs Go 1.22; older toolchains are rejected",
        "      run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...",
        PIN,
    ]
    assert action_pins.detached_version_comments(lines) == []


def test_green_comment_block_without_a_version_above_a_pin() -> None:
    lines = ["      # checkout, token not kept", "      # (this job never pushes)", PIN]
    assert action_pins.detached_version_comments(lines) == []


def test_green_version_comment_at_end_of_file() -> None:
    assert action_pins.detached_version_comments(["# v4.1.7"]) == []
