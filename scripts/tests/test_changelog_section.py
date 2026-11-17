"""CHANGELOG section detection shared by the release workflows.

Work item 36a8b0d6 (n3xus-identity v0.14.8 release run 44152729472,
2026-11-17): release-gates `independence-note` found a version's section only
under a Keep-a-Changelog `## [x.y.z]` heading, so a repo writing
`## 0.14.8 — title` (n3xus-identity, Keystone) got "CHANGELOG.md has no
'## [VERSION]' section" although the section and its `independence:` line
existed. The section also ran on to the next `## [` heading only, so in a
bracket-free changelog it swallowed every older release. lib-release.yml had
its own, different heading regex for the same job.

Both now carry ONE marked block, `changelog_section VERSION FILE`. These tests
extract it from the parsed workflow YAML, prove the two copies are
byte-identical, and execute it (and the whole shipped steps) under bash
against throwaway changelogs: the four heading styles with every suffix shape,
the bound at the next `## ` heading, near-miss versions, and fenced code.
Each case also runs under a POSIX-mode awk (and mawk when installed), since
ubuntu runners execute `awk` as mawk.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import textwrap
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
BEGIN = "# >>> shared changelog section\n"
END = "# <<< shared changelog section\n"


def bash_exe() -> str:
    """Git's own bash on Windows (a bare "bash" is the WSL stub), else PATH."""
    git = shutil.which("git")
    if os.name == "nt" and git:
        candidate = Path(git).resolve().parent.parent / "usr" / "bin" / "bash.exe"
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("bash")
    assert found, "bash not found"
    return found


BASH = bash_exe()


def bash_path(p: Path) -> str:
    posix = p.resolve().as_posix()
    m = re.match(r"^([A-Za-z]):/(.*)$", posix)
    return f"/{m.group(1).lower()}/{m.group(2)}" if m else posix


def step_run(workflow: str, job: str, name: str) -> str:
    doc = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    found = [s for s in doc["jobs"][job]["steps"] if s.get("name") == name]
    assert len(found) == 1, f"expected one step {name!r} in {workflow}:{job}"
    return found[0]["run"]


GATE_RUN = step_run("release-gates.yml", "independence-note",
                    "Runbook committed and release notes carry the independence line")
NOTES_RUN = step_run("lib-release.yml", "publish-release", "Generate release notes")


def shared_block(body: str) -> str:
    assert body.count(BEGIN) == 1 and body.count(END) == 1, "one marked shared block expected"
    start = body.index(BEGIN)
    return body[start:body.index(END, start) + len(END)]


BLOCK = shared_block(GATE_RUN)


def awk_variants() -> list[str]:
    """The awk the runner may resolve: the default, a POSIX-strict gawk when
    the default is gawk, and mawk (ubuntu's /usr/bin/awk) when installed."""
    variants = ["default"]
    probe = subprocess.run([BASH, "--noprofile", "--norc", "-c", "awk --version 2>/dev/null | head -1"],
                           capture_output=True, text=True)
    if "GNU Awk" in probe.stdout:
        variants.append("posix")
    if subprocess.run([BASH, "--noprofile", "--norc", "-c", "command -v mawk"],
                      capture_output=True).returncode == 0:
        variants.append("mawk")
    return variants


AWKS = awk_variants()


def run_script(script: str, cwd: Path, awk: str, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    shim = ""
    if awk == "posix":
        shim = 'awk() { command gawk --posix "$@"; }\n'
    elif awk == "mawk":
        shim = 'awk() { command mawk "$@"; }\n'
    fd, path = tempfile.mkstemp(suffix=".sh", prefix="changelog-")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(shim + script)
    try:
        return subprocess.run([BASH, "--noprofile", "--norc", path], cwd=cwd, capture_output=True,
                              text=True, encoding="utf-8", env={**os.environ, **(extra_env or {})})
    finally:
        os.remove(path)


def section(tmp_path: Path, awk: str, changelog: str, version: str) -> str:
    (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8", newline="\n")
    res = run_script(BLOCK + f'changelog_section "{version}" CHANGELOG.md\n', tmp_path, awk)
    assert res.returncode == 0, res.stderr
    return res.stdout


def changelog(heading: str) -> str:
    return ("# Changelog\n\n"
            "## [Unreleased]\n\n- pending work\n\n"
            f"{heading}\n\n- the change\n- independence: AI-1..AI-8 pass\n\n"
            "## 0.14.7 - 2026-11-10\n\n- older release\n- independence: AI-1..AI-8 pass\n")


STYLES = ["## [{v}]", "## {v}", "## v{v}", "## [v{v}]"]
SUFFIXES = ["", " — title", " - 2026-11-17", "(2026-11-17)", " (2026-11-17)"]


def test_the_two_workflows_share_one_block():
    assert shared_block(NOTES_RUN) == BLOCK


def test_no_other_changelog_heading_parser_remains():
    """Every CHANGELOG heading match in a workflow goes through the block."""
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        text = wf.read_text(encoding="utf-8")
        outside = text.replace(BLOCK.replace("\n", "\n" + " " * 10).rstrip(" "), "")
        for line in outside.splitlines():
            if line.lstrip().startswith("#"):
                continue
            assert not re.search(r"\^##|/\^## ", line), f"{wf.name}: heading parser outside the shared block: {line.strip()}"


@pytest.mark.parametrize("awk", AWKS)
@pytest.mark.parametrize("suffix", SUFFIXES)
@pytest.mark.parametrize("style", STYLES)
def test_every_heading_style_names_the_version(tmp_path, awk, style, suffix):
    heading = style.format(v="0.14.8") + suffix
    out = section(tmp_path, awk, changelog(heading), "0.14.8")
    assert out.splitlines()[0] == heading
    assert "- the change" in out and "independence: AI-1..AI-8 pass" in out
    # Bounded at the next `## ` heading, bracketed or not.
    assert "older release" not in out and "0.14.7" not in out and "pending work" not in out


@pytest.mark.parametrize("awk", AWKS)
@pytest.mark.parametrize("near_miss", ["## 0.14.80", "## [0.14.80]", "## v0.14.80 — title",
                                       "## 0.14.8-rc.1", "## [0.14.8-rc.1]", "## 0.14.8.1",
                                       "## 0x14y8", "## 10.14.8", "## [Unreleased] 0.14.8",
                                       "### 0.14.8"])
def test_a_near_miss_heading_does_not_name_the_version(tmp_path, awk, near_miss):
    body = f"# Changelog\n\n{near_miss}\n\n- not this one\n- independence: AI-1..AI-8 pass\n"
    assert section(tmp_path, awk, body, "0.14.8") == ""


@pytest.mark.parametrize("awk", AWKS)
def test_the_first_matching_section_only(tmp_path, awk):
    body = "## 1.0.0\n\n- first\n\n## 0.9.0\n\n- middle\n\n## 1.0.0\n\n- duplicate\n"
    out = section(tmp_path, awk, body, "1.0.0")
    assert "first" in out and "middle" not in out and "duplicate" not in out


@pytest.mark.parametrize("awk", AWKS)
@pytest.mark.parametrize("fence", ["```", "~~~", "```markdown"])
def test_a_heading_inside_a_code_fence_is_body_text(tmp_path, awk, fence):
    # A fenced example inside 1.2.3 neither ends 1.2.3 nor starts 0.14.8.
    body = ("## 1.2.3\n\n- example:\n\n" + fence + "\n## 0.14.8\n- independence: AI-1..AI-8 pass\n"
            + fence[:3] + "\n\n- still 1.2.3\n\n## 1.2.2\n\n- older\n")
    assert section(tmp_path, awk, body, "0.14.8") == ""
    out = section(tmp_path, awk, body, "1.2.3")
    assert "still 1.2.3" in out and "older" not in out


@pytest.mark.parametrize("awk", AWKS)
def test_version_metacharacters_are_literal(tmp_path, awk):
    assert section(tmp_path, awk, "## 1x2y3\n\n- no\n", "1.2.3") == ""
    assert section(tmp_path, awk, "## 1.2.3+build.5\n\n- yes\n", "1.2.3+build.5").startswith("## 1.2.3+build.5")
    assert section(tmp_path, awk, "## 1.2.3bbuild.5\n\n- no\n", "1.2.3+build.5") == ""


# --- the shipped steps, end to end -----------------------------------------

def gate(tmp_path: Path, awk: str, body: str, version: str = "0.14.8") -> tuple[subprocess.CompletedProcess, str]:
    (tmp_path / "RELEASE.md").write_text("# Release\n", encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(body, encoding="utf-8", newline="\n")
    summary = tmp_path / "summary.md"
    summary.write_text("", encoding="utf-8")
    res = run_script(GATE_RUN, tmp_path, awk, {"VERSION": version, "MODE": "full",
                                               "GITHUB_STEP_SUMMARY": bash_path(summary)})
    return res, summary.read_text(encoding="utf-8")


@pytest.mark.parametrize("awk", AWKS)
@pytest.mark.parametrize("style", STYLES)
def test_independence_note_passes_every_heading_style(tmp_path, awk, style):
    res, summary = gate(tmp_path, awk, changelog(style.format(v="0.14.8") + " — title"))
    assert res.returncode == 0, res.stdout + res.stderr
    assert "release notes: - independence: AI-1..AI-8 pass" in summary


@pytest.mark.parametrize("awk", AWKS)
def test_independence_note_reports_a_missing_section(tmp_path, awk):
    res, _ = gate(tmp_path, awk, "# Changelog\n\n## 0.14.80\n\n- independence: AI-1..AI-8 pass\n")
    assert res.returncode == 1
    assert "::error::CHANGELOG.md has no section for 0.14.8" in res.stdout


@pytest.mark.parametrize("awk", AWKS)
def test_independence_line_of_an_older_release_does_not_count(tmp_path, awk):
    # Before: in a bracket-free changelog the section ran on into 0.14.7 and
    # borrowed its independence line.
    body = "## 0.14.8 — title\n\n- the change\n\n## 0.14.7\n\n- independence: AI-1..AI-8 pass\n"
    res, _ = gate(tmp_path, awk, body)
    assert res.returncode == 1
    assert "::error::CHANGELOG.md section 0.14.8 has no 'independence:' line" in res.stdout


@pytest.mark.parametrize("awk", AWKS)
@pytest.mark.parametrize("style", STYLES)
def test_lib_release_notes_slice_every_heading_style(tmp_path, awk, style):
    (tmp_path / "CHANGELOG.md").write_text(changelog(style.format(v="0.14.8") + " - 2026-11-17"),
                                           encoding="utf-8", newline="\n")
    res = run_script(NOTES_RUN, tmp_path, awk, {"VERSION": "0.14.8", "CHANGELOG_PATH": "CHANGELOG.md"})
    assert res.returncode == 0, res.stdout + res.stderr
    notes = (tmp_path / "release-notes.md").read_text(encoding="utf-8")
    assert notes == "- the change\n- independence: AI-1..AI-8 pass\n"
