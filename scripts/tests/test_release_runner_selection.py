"""Runner selection and tool provenance in the reusable release workflows.

Work items ccfc277b and 67dbdbfb (GitHub-dependency audit 2026-11-17):

* every `runs-on` in every `workflow_call` workflow under .github/workflows is
  either the explicit `[self-hosted, nexus-deploy]` list (deploy/notify, which
  must reach the host) or the fail-closed expression in which an UNSET
  `CI_RUNNER` can never put a PRIVATE repository on a hosted label; the hosted
  literal is reachable only when `github.event.repository.private` is false
  (an explicit `runs_on` or `CI_RUNNER` names whatever single label it holds);
* the one permitted exception is the electron-release build matrix (win and
  mac need a Windows or macOS host for the platform build and code signing),
  named here verbatim so any change to it is reviewed;
* the file list is derived, not hard-coded, and the YAML is parsed, so a
  block-form or commented `runs-on` cannot slip past the scan;
* the gitleaks gate pins the archive's SHA-256 next to its version, verifies it
  with `sha256sum -c` before extracting, and never pipes a download into tar.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
FAIL_CLOSED = ("${{ inputs.runs_on || (github.event.repository.private && "
               "(vars.CI_RUNNER || 'nexus-ci')) || 'ubuntu-latest' }}")
HOST_ONLY = ["self-hosted", "nexus-deploy"]
# The only hosted runs-on the release family keeps, and why: see the comment
# above it in electron-release.yml.
PERMITTED_HOSTED = {
    ("electron-release.yml", "build"): (
        "${{ matrix.target == 'win' && 'windows-latest' || "
        "(matrix.target == 'mac' && 'macos-latest' || 'ubuntu-latest') }}"),
}
EXPECTED_FAMILY = {"docker-release.yml", "release-gates.yml", "lib-release.yml",
                   "mcp-release.yml", "electron-release.yml"}


def _triggers(doc: dict) -> dict:
    # YAML 1.1 reads the bare key `on` as boolean True.
    return doc.get("on", doc.get(True)) or {}


def _workflow_call_files() -> list[Path]:
    out = []
    for wf in sorted(WORKFLOW_DIR.glob("*.yml")):
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        triggers = _triggers(doc)
        if isinstance(triggers, dict) and "workflow_call" in triggers:
            out.append(wf)
    return out


def _runs_on_sites(text: str) -> list[tuple[str, object]]:
    """(job name, runs-on value) for every job in the workflow text."""
    doc = yaml.safe_load(text)
    sites = []
    for job, spec in (doc.get("jobs") or {}).items():
        if isinstance(spec, dict) and "runs-on" in spec:
            sites.append((job, spec["runs-on"]))
    return sites


def _offending_sites(name: str, text: str) -> list[tuple[str, object]]:
    """Every runs-on that can put a private repository on a hosted runner."""
    bad = []
    for job, value in _runs_on_sites(text):
        if value == FAIL_CLOSED or value == HOST_ONLY:
            continue
        if PERMITTED_HOSTED.get((name, job)) == value:
            continue
        bad.append((job, value))
    return bad


def test_file_list_is_derived_and_covers_the_release_family():
    names = {wf.name for wf in _workflow_call_files()}
    assert EXPECTED_FAMILY <= names, f"release family drifted: {names}"


def test_every_runs_on_fails_closed_for_private_repos():
    total = 0
    for wf in _workflow_call_files():
        text = wf.read_text(encoding="utf-8")
        sites = _runs_on_sites(text)
        assert sites, f"{wf.name}: no runs-on found (scan drifted)"
        total += len(sites)
        bad = _offending_sites(wf.name, text)
        assert not bad, (
            f"{wf.name}: {bad} can resolve a private repository to a hosted "
            f"runner; use the fail-closed expression")
    # 15 (docker-release + release-gates) + 3 (lib) + 5 (mcp) + 3 (electron)
    assert total >= 26, f"only {total} runs-on sites found (scan drifted)"


def test_permitted_hosted_exception_is_exactly_the_electron_matrix():
    for (name, job), value in PERMITTED_HOSTED.items():
        sites = dict(_runs_on_sites((WORKFLOW_DIR / name).read_text(encoding="utf-8")))
        assert sites.get(job) == value, f"{name}:{job} exception text drifted"
    assert set(PERMITTED_HOSTED) == {("electron-release.yml", "build")}


def test_hosted_literal_only_behind_private_check():
    # The only place 'ubuntu-latest' may appear in a runs-on is after the
    # private-repository predicate, except the named electron matrix.
    for wf in _workflow_call_files():
        for job, value in _runs_on_sites(wf.read_text(encoding="utf-8")):
            if isinstance(value, str) and "ubuntu-latest" in value:
                if PERMITTED_HOSTED.get((wf.name, job)) == value:
                    continue
                assert "github.event.repository.private" in value, f"{wf.name}:{job}"


def test_every_family_workflow_declares_the_runs_on_input():
    for wf in _workflow_call_files():
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        call = _triggers(doc)["workflow_call"] or {}
        inputs = call.get("inputs") or {}
        assert "runs_on" in inputs, f"{wf.name}: workflow_call lacks the runs_on input"
        assert inputs["runs_on"].get("default") == "", f"{wf.name}: runs_on default must be ''"


def test_gates_call_passes_the_same_expression():
    text = (WORKFLOW_DIR / "docker-release.yml").read_text(encoding="utf-8")
    m = re.search(r"^\s*runs_on:\s*(\$\{\{.+?\}\})\s*$", text, re.M)
    assert m and m.group(1) == FAIL_CLOSED, "docker-release gates call must forward the fail-closed label"


def _mutant_workflow(runs_on_block: str) -> str:
    return "on:\n  workflow_call: {}\njobs:\n  gates:\n    " + runs_on_block + "\n    steps: []\n"


@pytest.mark.parametrize("mutant", [
    # the pre-1.1.10 expression: a missing variable falls through to hosted
    "runs-on: ${{ inputs.runs_on || vars.CI_RUNNER || 'ubuntu-latest' }}",
    "runs-on: ubuntu-latest",
    "runs-on: 'ubuntu-latest'   # trailing comment",
    "runs-on:\n      - ubuntu-latest",
    "runs-on:\n      - self-hosted\n      - linux",
    "runs-on: ${{ vars.CI_RUNNER || 'ubuntu-latest' }}",
    # the electron exception text is permitted only at its own site
    "runs-on: ${{ matrix.target == 'win' && 'windows-latest' || "
    "(matrix.target == 'mac' && 'macos-latest' || 'ubuntu-latest') }}",
])
def test_scan_goes_red_on_a_reverted_or_hosted_runs_on(mutant):
    assert _offending_sites("mutant.yml", _mutant_workflow(mutant)), mutant


def test_scan_accepts_only_the_two_safe_shapes():
    for ok in (f"runs-on: {FAIL_CLOSED}", "runs-on: [self-hosted, nexus-deploy]",
               "runs-on:\n      - self-hosted\n      - nexus-deploy"):
        assert not _offending_sites("x.yml", _mutant_workflow(ok)), ok


def test_gitleaks_is_pinned_and_verified_before_extract():
    text = (WORKFLOW_DIR / "release-gates.yml").read_text(encoding="utf-8")
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
