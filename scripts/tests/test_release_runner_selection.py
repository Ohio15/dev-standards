"""Runner selection and tool provenance in the reusable release workflows.

Work items ccfc277b and 67dbdbfb (GitHub-dependency audit 2026-11-17):

* every `runs-on` in docker-release.yml and release-gates.yml is either the
  explicit `[self-hosted, nexus-deploy]` list (deploy/notify, which must reach
  the host) or the fail-closed expression in which a PRIVATE repository can only
  resolve to `inputs.runs_on`, `vars.CI_RUNNER` or `nexus-ci`; the hosted literal
  is reachable only when `github.event.repository.private` is false;
* the gitleaks gate pins the archive's SHA-256 next to its version, verifies it
  with `sha256sum -c` before extracting, and never pipes a download into tar.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = [
    ROOT / ".github" / "workflows" / "docker-release.yml",
    ROOT / ".github" / "workflows" / "release-gates.yml",
]
FAIL_CLOSED = ("${{ inputs.runs_on || (github.event.repository.private && "
               "(vars.CI_RUNNER || 'nexus-ci')) || 'ubuntu-latest' }}")
HOST_ONLY = "[self-hosted, nexus-deploy]"


def _runs_on_values(text: str) -> list[tuple[int, str]]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*runs-on:\s*(.+?)\s*$", line)
        if m:
            out.append((i, m.group(1)))
    return out


def test_every_runs_on_fails_closed_for_private_repos():
    for wf in WORKFLOWS:
        values = _runs_on_values(wf.read_text(encoding="utf-8"))
        assert values, f"{wf.name}: no runs-on found (scan drifted)"
        for line, value in values:
            assert value in (FAIL_CLOSED, HOST_ONLY), (
                f"{wf.name}:{line}: runs-on {value!r} can resolve a private "
                f"repository to a hosted runner; use the fail-closed expression")


def test_hosted_literal_only_behind_private_check():
    # The only place 'ubuntu-latest' may appear in a runs-on is after the
    # private-repository predicate; comments and docs may mention it freely.
    for wf in WORKFLOWS:
        for line, value in _runs_on_values(wf.read_text(encoding="utf-8")):
            if "ubuntu-latest" in value:
                assert "github.event.repository.private" in value, f"{wf.name}:{line}"


def test_gates_call_passes_the_same_expression():
    text = WORKFLOWS[0].read_text(encoding="utf-8")
    m = re.search(r"^\s*runs_on:\s*(\$\{\{.+?\}\})\s*$", text, re.M)
    assert m and m.group(1) == FAIL_CLOSED, "docker-release gates call must forward the fail-closed label"


def test_gitleaks_is_pinned_and_verified_before_extract():
    text = WORKFLOWS[1].read_text(encoding="utf-8")
    m = re.search(r"- name: Install gitleaks\n(.*?)\n      - name:", text, re.S)
    assert m, "gitleaks install step not found"
    step = m.group(1)
    assert re.search(r"GL_VERSION=\d+\.\d+\.\d+", step)
    assert re.search(r"GL_SHA256=[0-9a-f]{64}", step), "pinned SHA-256 missing"
    assert "sha256sum -c" in step, "archive must be verified"
    assert "| tar" not in step, "download must not be piped into tar"
    verify = step.index("sha256sum -c")
    extract = step.index("tar -xz")
    assert verify < extract, "verification must precede extraction"
    assert "command -v gitleaks" in step, "baked binary must be preferred"
