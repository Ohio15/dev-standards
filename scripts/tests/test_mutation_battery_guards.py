"""Mutation battery for three guards whose tests had no red-on-revert proof
(security gate pass 1 on PR #62 left SC-14 NOT EXAMINED for them):

  (a) the dep-auto-apply publish validator: the pnpm edge binding (alias
      redirect refusal and the package-record check), the version direction
      check, the Go pseudo-version / +incompatible refusal and the flow_map
      mid-scalar quote refusal;
  (b) the install.sh runs-on classifier (the `unclassified=` block);
  (c) the security-audit config allow-list (NPMRC_OK / PNPM_WS_OK).

Mechanism (same as test_docker_release_helper.py's battery): each mutant is
the smallest textual edit that disables one guard, applied with an exact
count==1 replace so a source edit that moves the text fails the battery
loudly instead of leaving a no-op mutant that "survives" for the wrong
reason. The mutant is applied to a temp copy of the repository and the
guard's OWN tests (one test file, narrowed with -k) run against that copy in
a fresh interpreter: they must go red (pytest exit 1). The same selection is
run once against the unmutated copy and must be green (exit 0), so a red
mutant run means the guard, not the selection, is what broke.

Each guard's text lives in the dev-standards copy and the shipped template
(byte-identical guard lines); a mutant edits every copy, because the tests
read the template and a revert would touch both.

Run:  python -m pytest scripts/tests/test_mutation_battery_guards.py -q
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent

DEP_AUTO_APPLY = (".github/workflows/dep-auto-apply.yml", "templates/.github/workflows/dep-auto-apply.yml")
SECURITY_AUDIT = (".github/workflows/security-audit.yml", "templates/.github/workflows/security-audit.yml")
INSTALL = ("install.sh",)

DEP_TESTS = "scripts/tests/test_dep_auto_apply_workflow.py"
INSTALL_TESTS = "scripts/tests/test_install_and_secret_scan.py"
AUDIT_TESTS = "scripts/tests/test_security_audit_workflow.py"


class Mutant(NamedTuple):
    name: str
    files: tuple[str, ...]
    old: str
    new: str
    tests: str
    select: str


# Each -k selection names the guard's own refusal tests only.
SEL_ALIAS = "alias_redirect_is_refused or alias_message_names_the_alias"
SEL_RECORD = "importer_version_must_name_a_package_record or snapshot_edge_to_an_absent_record_is_refused"
SEL_DIRECTION = "downgrade_is_refused"
SEL_PSEUDO = "go_mod_pseudo_version_is_refused"
SEL_INCOMPAT = "go_mod_incompatible_is_refused"
SEL_QUOTE = "flow_map_refuses_quotes_yaml_reads_differently or mid_scalar_quote_is_refused"
SEL_RUNS_ON = "hosted_install_refuses_a_runs_on_it_cannot_classify"
SEL_CONFIG = "untrusted_config_that_steers_the_audit_is_not_examined"
SEL_NTFY_HTTP = "ntfy_non_2xx_fails_the_notify_step"
SEL_NTFY_CURL = "ntfy_curl_failure_fails_the_notify_step"

MUTANTS = [
    # (a) publish validator
    Mutant("a1-pnpm-alias-redirect-allowed", DEP_AUTO_APPLY,
           "if target[0] != dep and (dep, target[0]) not in base_aliases:",
           "if target[0] != dep and (dep, target[0]) in base_aliases:",
           DEP_TESTS, SEL_ALIAS),
    Mutant("a2-pnpm-edge-needs-no-package-record", DEP_AUTO_APPLY,
           "                  if target not in targets:\n",
           "                  if False:\n",
           DEP_TESTS, SEL_RECORD),
    Mutant("a3-version-direction-not-checked", DEP_AUTO_APPLY,
           "              if n[0] <= top[0]:\n",
           "              if False:\n",
           DEP_TESTS, SEL_DIRECTION),
    Mutant("a4-go-pseudo-version-allowed", DEP_AUTO_APPLY,
           "if go_pseudo(ver) and not any(go_pseudo(b) for b in olds):",
           "if False and not any(go_pseudo(b) for b in olds):",
           DEP_TESTS, SEL_PSEUDO),
    Mutant("a5-go-incompatible-allowed", DEP_AUTO_APPLY,
           'if ver.endswith("+incompatible") and not any(',
           "if False and not any(",
           DEP_TESTS, SEL_INCOMPAT),
    Mutant("a6-flow-map-mid-scalar-quote-allowed", DEP_AUTO_APPLY,
           'die(f"{path}: {key!r} resolution {value!r} has a quote inside a plain scalar")',
           'pass  # die(f"{path}: {key!r} resolution {value!r} has a quote inside a plain scalar")',
           DEP_TESTS, SEL_QUOTE),
    # (d) dep-auto-apply notify step: a failed ntfy delivery must fail the job
    Mutant("d1-ntfy-non-2xx-accepted", DEP_AUTO_APPLY,
           'if ! [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then',
           "if false; then",
           DEP_TESTS, SEL_NTFY_HTTP),
    Mutant("d2-ntfy-curl-error-accepted", DEP_AUTO_APPLY,
           'if [ "$curl_rc" -ne 0 ]; then',
           "if false; then",
           DEP_TESTS, SEL_NTFY_CURL),
    # (b) install.sh runs-on classifier
    Mutant("b1-unclassified-runs-on-installed", INSTALL,
           '  if [ -n "$unclassified" ]; then\n',
           "  if false; then\n",
           INSTALL_TESTS, SEL_RUNS_ON),
    Mutant("b2-hosted-literal-filter-dropped", INSTALL,
           "    | grep -vE '^[0-9]+:[[:space:]]*runs-on:[[:space:]]+ubuntu-latest[[:space:]]*$' || true)\"",
           "    | grep -vE 'runs-on' || true)\"",
           INSTALL_TESTS, SEL_RUNS_ON),
    Mutant("b3-escaped-key-scan-skipped", INSTALL,
           '  if [ -z "$unclassified" ]; then\n',
           "  if false; then\n",
           INSTALL_TESTS, SEL_RUNS_ON),
    # (c) config allow-list
    Mutant("c1-npmrc-allow-list-off", SECURITY_AUDIT,
           "if not m or m.group(1) not in NPMRC_OK:",
           "if not m:",
           AUDIT_TESTS, SEL_CONFIG),
    Mutant("c2-pnpm-workspace-allow-list-off", SECURITY_AUDIT,
           "if not m or m.group(2) not in PNPM_WS_OK:",
           "if not m:",
           AUDIT_TESTS, SEL_CONFIG),
]

_IGNORE = shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "node_modules")


def _copy_repo(dst: Path) -> Path:
    tree = dst / "repo"
    shutil.copytree(ROOT, tree, ignore=_IGNORE)
    return tree


def _mutate(tree: Path, mutant: Mutant) -> None:
    for rel in mutant.files:
        path = tree / rel
        text = path.read_bytes().decode("utf-8")
        count = text.count(mutant.old)
        assert count == 1, f"{mutant.name}: {rel} has {count} copies of the mutated text (want exactly 1)"
        path.write_bytes(text.replace(mutant.old, mutant.new, 1).encode("utf-8"))


def _run_selection(tree: Path, tests: str, select: str) -> subprocess.CompletedProcess:
    # A clean inner run: no inherited pytest options, no bytecode in the copy.
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", tests, "-k", select],
        cwd=tree, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=600,
    )


SELECTIONS = sorted({(m.tests, m.select) for m in MUTANTS})


@pytest.mark.parametrize("tests,select", SELECTIONS, ids=[f"{Path(t).stem}:{s}" for t, s in SELECTIONS])
def test_selection_is_green_on_the_unmutated_copy(tmp_path, tests, select):
    proc = _run_selection(_copy_repo(tmp_path), tests, select)
    assert proc.returncode == 0, proc.stdout[-4000:] + proc.stderr[-2000:]
    assert " passed" in proc.stdout, proc.stdout[-2000:]


@pytest.mark.parametrize("mutant", MUTANTS, ids=[m.name for m in MUTANTS])
def test_mutant_turns_the_guard_tests_red(tmp_path, mutant):
    tree = _copy_repo(tmp_path)
    _mutate(tree, mutant)
    proc = _run_selection(tree, mutant.tests, mutant.select)
    # Exit 1 is "tests ran and failed". 2 (collection error), 4 (usage) and
    # 5 (nothing selected) are a broken battery, never a killed mutant.
    assert proc.returncode == 1, (
        f"{mutant.name} SURVIVED (pytest exit {proc.returncode}): "
        + proc.stdout[-4000:] + proc.stderr[-2000:])
    assert " failed" in proc.stdout, proc.stdout[-2000:]


def test_mutants_are_distinct_and_target_real_files():
    names = [m.name for m in MUTANTS]
    assert len(names) == len(set(names))
    for m in MUTANTS:
        assert m.old != m.new, m.name
        for rel in m.files:
            assert (ROOT / rel).is_file(), (m.name, rel)
        assert (ROOT / m.tests).is_file(), m.name
