"""Every script that is run as an executable is mode 100755 in the git index.

2026-11-10: scripts/npm-audit-weekly.sh was committed 100644 while
code-standards-cron.sh runs it directly (`timeout ... "$here/npm-audit-weekly.sh"`).
On NEXUS every 6-hourly run got exit 126 and exported every dependency position
as not scanned (first exporter run 2026-11-10T18:26Z). This checkout is on
Windows, where the working-tree mode means nothing, so only the index mode
(`git ls-files -s`) decides what a Linux clone gets.

A file must be 100755 when:
  * it is a tracked shell script or hook with a shebang (*.sh, hooks/*, .githooks/*);
  * a tracked shell script invokes it directly as "$here/<name>" (no interpreter
    in front of it on that command);
  * a tracked doc or script tells the operator to run it directly
    (`./scripts/<name>` or `.../dev-standards/scripts/<name>` with no interpreter
    in front of it on that line), e.g. a crontab line.
Each failure names the file and why it must be executable.

Run:  python -m pytest scripts/tests/test_exec_bits.py -q
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

INTERPRETERS = {"python", "python3", "py", "bash", "sh", "pwsh", "powershell"}
HERE_CALL = re.compile(r'"\$here/([A-Za-z0-9_.-]+)"')
DOC_CALL = re.compile(r"(?:(?<![\w/.])\./|/dev-standards/)scripts/([A-Za-z0-9_.-]+\.(?:sh|py))\b")


def index_modes() -> dict[str, str]:
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-s", "-z"],
                         capture_output=True, check=True).stdout.decode("utf-8")
    modes: dict[str, str] = {}
    for rec in out.split("\0"):
        if rec:
            meta, path = rec.split("\t", 1)
            modes[path] = meta.split()[0]
    return modes


def _has_shebang(rel: str) -> bool:
    with open(ROOT / rel, "rb") as fh:
        return fh.read(2) == b"#!"


def _interpreted(line: str, start: int) -> bool:
    """True when the word before position `start` on the same command (options
    skipped) is an interpreter, i.e. the file is an argument, not the program."""
    command = re.split(r"[;&|(`]", line[:start])[-1]
    for token in reversed(command.split()):
        if token.startswith("-"):
            continue
        name = token.rsplit("/", 1)[-1].lower().removesuffix(".exe")
        return name in INTERPRETERS
    return False


def required_executables(modes: dict[str, str]) -> dict[str, str]:
    """{path: reason} for every tracked file that must be 100755."""
    need: dict[str, list[str]] = {}
    for rel in modes:
        if (rel.endswith(".sh") or rel.startswith(("hooks/", ".githooks/"))) and _has_shebang(rel):
            need.setdefault(rel, []).append("a shell script or hook with a shebang")
    for rel in modes:
        if not rel.endswith((".sh", ".md")) and not rel.startswith(("hooks/", ".githooks/")):
            continue
        text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        base = rel.rsplit("/", 1)[0] if "/" in rel else ""
        for n, line in enumerate(text.splitlines(), 1):
            if rel.endswith(".sh") or rel.startswith(("hooks/", ".githooks/")):
                for m in HERE_CALL.finditer(line):
                    target = f"{base}/{m.group(1)}" if base else m.group(1)
                    if target in modes and not _interpreted(line, m.start()):
                        need.setdefault(target, []).append(f'invoked directly as "$here/{m.group(1)}" at {rel}:{n}')
            for m in DOC_CALL.finditer(line):
                target = f"scripts/{m.group(1)}"
                if target in modes and not _interpreted(line, m.start()):
                    need.setdefault(target, []).append(f"run directly per {rel}:{n}")
    return {rel: "; ".join(why) for rel, why in need.items()}


def test_every_directly_run_script_is_executable_in_the_index() -> None:
    modes = index_modes()
    need = required_executables(modes)
    assert "scripts/code-standards-cron.sh" in need  # the inventory still sees the cron entry point
    wrong = sorted(f"{rel} is {modes[rel]} in the index, must be 100755: {why}"
                   for rel, why in need.items() if modes[rel] != "100755")
    assert wrong == [], "\n".join(wrong)


def test_the_cron_invocations_are_recognised() -> None:
    """The parser sees npm-audit-weekly.sh and estate-mirror.sh as direct runs,
    and the python3 -I runs of the .py scripts as interpreted (not required)."""
    need = required_executables(index_modes())
    assert need["scripts/npm-audit-weekly.sh"]
    assert need["scripts/estate-mirror.sh"]
    reasons = " ".join(need.values())
    assert '"$here/repo-hygiene-scan.py" at scripts/code-standards-cron.sh' not in reasons
    assert '"$here/code-standards-facts.py"' not in reasons


def test_interpreter_detection() -> None:
    cases = {
        'timeout --kill-after=60 3600 "$here/npm-audit-weekly.sh" --root x': False,
        '"$here/estate-mirror.sh" --roster r': False,
        'exec python3 "$here/repo-hygiene-scan.py" "$@"': True,
        '  timeout 3600 python3 -I "$here/repo-hygiene-scan.py" \\': True,
        'bash "$here/x.sh"': True,
        '0 5 * * 0 /home/ohio_/dev-standards/scripts/repo-hygiene-scan.py --root /h': False,
        'python scripts/sb.py health': True,
        'THRESH_CRIT=1 ./scripts/npm-audit-weekly.sh': False,
    }
    for line, want in cases.items():
        m = HERE_CALL.search(line) or DOC_CALL.search(line) or re.search(r"scripts/sb\.py", line)
        assert m is not None, line
        assert _interpreted(line, m.start()) is want, line
