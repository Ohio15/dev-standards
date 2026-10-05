"""Every action reference in the shipped and reusable workflows is pinned to a
commit, with its release on the SAME line, and no checkout leaves the token
behind unless the job pushes.

Dependabot rewrites a version comment only when it sits on the `uses:` line
(`uses: owner/repo@<40-hex> # vX.Y.Z`). A comment on its own line above the pin
is never touched, so after the first bump it names the wrong release. That is
how `# actions/checkout v4.1.7` came to describe pins nobody had re-read.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
FILES = sorted(
    [*ROOT.glob(".github/workflows/*.yml"), *ROOT.glob("templates/.github/workflows/*.yml"),
     *ROOT.glob("workflows/*.yml")]
)
IDS = [p.relative_to(ROOT).as_posix() for p in FILES]

USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?P<rest>.*)$")
PINNED = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$")
SAME_LINE_VERSION = re.compile(r"^\s+#\s+v\d+(\.\d+){0,2}\s*$")
# A comment line naming an action and a release, or a bare release: the
# detached-comment shape this test exists to keep out.
DETACHED_VERSION = re.compile(r"^\s*#\s*(?:[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\s+)?v\d+\.\d+(\.\d+)?\b")

# Jobs that push with the checkout's credential. Anything else must not keep it.
PUSHES_WITH_CHECKOUT_TOKEN = {
    # tag-rc pushes the v1-rcN tag; monitor/promote push the state commit and v1.
    ".github/workflows/promote-canary.yml",
}


def test_there_are_workflows_to_check():
    assert len(FILES) >= 10, IDS


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_every_action_is_sha_pinned_with_a_same_line_version(path: Path):
    bad = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = USES.match(line)
        if not m or m.group("ref").startswith("./"):
            continue
        if not PINNED.match(m.group("ref")) or not SAME_LINE_VERSION.match(m.group("rest")):
            bad.append(f"{n}: {line.strip()}")
    assert bad == [], "want `uses: owner/repo@<40-hex> # vX.Y.Z`:\n" + "\n".join(bad)


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_no_version_comment_on_a_line_of_its_own(path: Path):
    bad = [f"{n}: {line.strip()}" for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
           if DETACHED_VERSION.match(line)]
    assert bad == [], "a version comment above a pin goes stale on the first Dependabot bump:\n" + "\n".join(bad)


@pytest.mark.parametrize("path", FILES, ids=IDS)
def test_checkouts_do_not_persist_the_token_unless_the_job_pushes(path: Path):
    rel = path.relative_to(ROOT).as_posix()
    wf = yaml.safe_load(path.read_text(encoding="utf-8"))
    for name, job in wf.get("jobs", {}).items():
        for step in job.get("steps", []) or []:
            if not str(step.get("uses", "")).startswith("actions/checkout@"):
                continue
            persist = (step.get("with") or {}).get("persist-credentials")
            if rel in PUSHES_WITH_CHECKOUT_TOKEN:
                assert persist is True, f"{rel}:{name} pushes; say so explicitly"
            else:
                assert persist is False, f"{rel}:{name}: checkout must set persist-credentials: false"


def test_one_release_per_action_across_all_workflows():
    seen: dict[str, set[str]] = {}
    for path in FILES:
        for line in path.read_text(encoding="utf-8").splitlines():
            m = USES.match(line)
            if m and "@" in m.group("ref") and not m.group("ref").startswith("./"):
                action, ref = m.group("ref").split("@", 1)
                seen.setdefault(action, set()).add(f"{ref}{m.group('rest')}")
    split = {a: refs for a, refs in seen.items() if len(refs) > 1}
    assert split == {}, f"an action pinned to more than one release: {split}"


def test_detector_catches_the_old_shape():
    old = "      # actions/checkout v4.1.7\n      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332\n"
    first, second = old.splitlines()
    assert DETACHED_VERSION.match(first)
    m = USES.match(second)
    assert m and not SAME_LINE_VERSION.match(m.group("rest"))
    assert not PINNED.match("actions/checkout@v4")
