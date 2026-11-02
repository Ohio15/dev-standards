"""The repo's own test dependencies install in pip hash-checking mode.

`pip install -r requirements-dev.txt` with version pins alone trusts the index
to serve the artifact that was pinned: a substituted upload of the same version
reaches the runner unchallenged. Hash-checking mode (`--require-hashes`) refuses
any artifact whose digest the manifest does not list, and pip only honours it
when EVERY requirement, transitive ones included, is pinned with `==` and
carries a `--hash`. `--no-deps` then makes the manifest the whole install.

This test keeps the three parts in step: the `.in` source names the direct
pins, the `.txt` is their pip-compile output with hashes, and every
`pip install -r requirements-dev.txt` in this repo's workflows asks for the
check.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE = ROOT / "requirements-dev.in"
LOCK = ROOT / "requirements-dev.txt"
WORKFLOWS = sorted(ROOT.glob(".github/workflows/*.yml"))

PIN = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9.!+]+)$")
HASH = re.compile(r"^--hash=sha256:[0-9a-f]{64}$")
INSTALLS_DEV = re.compile(r"pip install\b.*-r requirements-dev\.txt")


def _normal(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements(path: Path) -> dict[str, tuple[str, list[str]]]:
    """{normalised name: (version, hashes)} from a pip-compile style file.

    A requirement is one logical line; `\\` joins continuation lines. Comments
    and blank lines are not requirements. Anything else (an unpinned spec, a
    URL, a `-e`, an option line) fails the parse, because under
    `--require-hashes` pip refuses it too.
    """
    logical: list[str] = []
    buf = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        logical.append((buf + line).strip())
        buf = ""
    assert buf == "", f"{path.name}: dangling continuation"

    out: dict[str, tuple[str, list[str]]] = {}
    for entry in logical:
        spec, *opts = entry.split()
        m = PIN.match(spec)
        assert m, f"{path.name}: not an `==` pin: {entry!r}"
        bad = [o for o in opts if not HASH.match(o)]
        assert bad == [], f"{path.name}: {spec}: unexpected option(s) {bad}"
        name = _normal(m.group("name"))
        assert name not in out, f"{path.name}: {name} listed twice"
        out[name] = (m.group("version"), opts)
    return out


def test_source_file_is_direct_pins_only():
    src = _requirements(SOURCE)
    assert src, "requirements-dev.in names no requirement"
    assert all(hashes == [] for _, hashes in src.values()), "hashes belong in the .txt"


def test_lock_file_hashes_every_requirement():
    lock = _requirements(LOCK)
    assert lock, "requirements-dev.txt names no requirement"
    missing = [name for name, (_, hashes) in lock.items() if not hashes]
    assert missing == [], f"no --hash for: {missing}"


def test_lock_file_carries_every_direct_pin_at_the_same_version():
    src = _requirements(SOURCE)
    lock = _requirements(LOCK)
    drift = {
        name: (version, lock.get(name, ("<absent>", []))[0])
        for name, (version, _) in src.items()
        if lock.get(name, ("<absent>", []))[0] != version
    }
    assert drift == {}, f".in and .txt disagree (name: (.in, .txt)): {drift}"


def test_lock_file_declares_its_generator():
    head = LOCK.read_text(encoding="utf-8").splitlines()[:12]
    assert any("pip-compile --generate-hashes" in line for line in head), head


def test_every_workflow_install_of_the_dev_requirements_requires_hashes():
    seen = []
    bad = []
    for path in WORKFLOWS:
        text = path.read_text(encoding="utf-8")
        # A `run:` block may wrap the command with `\`; judge the joined form.
        joined = text.replace("\\\n", " ")
        for m in INSTALLS_DEV.finditer(joined):
            cmd = m.group(0)
            seen.append(f"{path.name}: {cmd}")
            if "--require-hashes" not in cmd or "--no-deps" not in cmd:
                bad.append(f"{path.name}: {cmd}")
    assert seen, "no workflow installs requirements-dev.txt; the test is dead"
    assert bad == [], "want --require-hashes --no-deps on:\n" + "\n".join(bad)
