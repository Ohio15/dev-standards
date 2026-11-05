"""install.sh Dependabot seeding (SC-25) and the secret-scan hook's gitleaks
lookup (SC-12), from the 2026-10-05 security gate on the templates.

- SC-25: installed repos got SHA-pinned actions and no Dependabot config, so
  the pins went stale. install.sh now seeds .github/dependabot.yml when the
  target has none, and never touches an existing one.
- SC-12: with gitleaks off PATH the hook ran `${GOPATH:-$HOME/go}/bin/gitleaks`,
  a binary an inherited environment chooses. It now fails closed.

Runner predicate (SC-37, amended 2026-10-27; audit-dev-standards-2026-10-27):
install.sh writes the templates verbatim (the guarded allow-list predicate, and
dep-auto-apply's private-only toggle) into a private repo, and the hosted
literal into a public or unconfirmed one. A flag GitHub contradicts is an
error; visibility is settled before anything is written. Most tests pass
--no-gh; the GitHub-answer tests put a fake `gh` first on PATH, so no test
talks to GitHub.

Everything runs against throwaway repos and directories under tmp_path.

Run:  python -m pytest scripts/tests -q
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
INSTALL = ROOT / "install.sh"
SECRET_SCAN = ROOT / "hooks" / "pre-commit-secret-scan.sh"


def bash_exe() -> str:
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


def target_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "target"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    return repo


def install(repo: Path, *flags: str) -> subprocess.CompletedProcess[str]:
    """Run install.sh offline. Without flags the target is treated as a private
    repo (the case every pre-SC-37 test covered); pass flags to override."""
    if not flags:
        flags = ("--private", "--no-gh")
    return subprocess.run([BASH, INSTALL.as_posix(), *flags, repo.as_posix()], capture_output=True, text=True)


REGISTER = ROOT / "security" / "SECURITY-CHECKS.md"


def _sc37_predicates() -> list[str]:
    sc37 = REGISTER.read_text(encoding="utf-8").split("### SC-37", 1)[1].split("\n### ", 1)[0]
    found = re.findall(r"`(\(github\.event_name == 'push'.*?\|\| 'ubuntu-latest')`", sc37, re.S)
    assert found, "SC-37 canonical predicate not found in the register"
    return [" ".join(p.split()) for p in found]


GUARD_TAIL = "&& github.event.repository.private && vars.CI_RUNNER == 'nexus-ci' && 'nexus-ci' || 'ubuntu-latest'"


def canonical_predicate() -> str:
    """The guarded SC-37 Linux predicate the fleet templates carry, read from
    the register so the test and the installer cannot drift from it
    independently."""
    [guarded] = [p for p in _sc37_predicates() if p.endswith(GUARD_TAIL)]
    return guarded


# dep-auto-apply.yml runs on schedule/workflow_dispatch only; its jobs carry
# the bare private-only literal toggle rather than the event allow-list.
DEP_TOGGLE = "${{ github.event.repository.private && vars.CI_RUNNER == 'nexus-ci' && 'nexus-ci' || 'ubuntu-latest' }}"

PR_TEMPLATES = {
    "size-guard.yml": ROOT / "workflows" / "size-guard.yml",
    "security-audit.yml": ROOT / "templates" / ".github" / "workflows" / "security-audit.yml",
}
DEP_TEMPLATE = ROOT / "templates" / ".github" / "workflows" / "dep-auto-apply.yml"
ALL_TEMPLATES = {**PR_TEMPLATES, "dep-auto-apply.yml": DEP_TEMPLATE}


def hosted_copy(text: str) -> str:
    """What install.sh writes for a public or unconfirmed target."""
    return (text.replace("runs-on: ${{ " + canonical_predicate() + " }}", "runs-on: ubuntu-latest")
                .replace("runs-on: " + DEP_TOGGLE, "runs-on: ubuntu-latest"))


def runs_on_lines(text: str) -> list[str]:
    return [l.strip() for l in text.splitlines() if l.strip().startswith("runs-on:")]


# ─── SC-25: dependabot seeding ───────────────────────────────────────────────

def test_dependabot_is_seeded_when_absent(tmp_path):
    repo = target_repo(tmp_path)
    proc = install(repo)
    assert proc.returncode == 0, proc.stderr
    seeded = (repo / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert seeded == (ROOT / "templates" / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert "package-ecosystem: github-actions" in seeded
    assert "interval: weekly" in seeded and "groups:" in seeded
    assert "dependabot.yml                (seeded" in proc.stdout


@pytest.mark.parametrize("name", ["dependabot.yml", "dependabot.yaml"])
def test_existing_dependabot_config_is_never_overwritten(tmp_path, name):
    repo = target_repo(tmp_path)
    (repo / ".github").mkdir()
    mine = "version: 2\nupdates:\n  - package-ecosystem: \"github-actions\"\n    directory: /\n    schedule: {interval: daily}\n"
    (repo / ".github" / name).write_text(mine, encoding="utf-8", newline="\n")
    proc = install(repo)
    assert proc.returncode == 0, proc.stderr
    assert (repo / ".github" / name).read_text(encoding="utf-8") == mine
    others = {"dependabot.yml", "dependabot.yaml"} - {name}
    assert not any((repo / ".github" / o).exists() for o in others), "a second config must not be added"
    assert "covers github-actions" in proc.stdout
    assert "WARNING" not in proc.stderr


def test_existing_config_without_actions_is_reported_not_edited(tmp_path):
    repo = target_repo(tmp_path)
    (repo / ".github").mkdir()
    mine = "version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule: {interval: weekly}\n"
    (repo / ".github" / "dependabot.yml").write_text(mine, encoding="utf-8", newline="\n")
    proc = install(repo)
    assert proc.returncode == 0, proc.stderr
    assert (repo / ".github" / "dependabot.yml").read_text(encoding="utf-8") == mine
    assert "no 'package-ecosystem: github-actions' entry" in proc.stderr


# ─── SC-12: gitleaks is resolved from PATH only ──────────────────────────────

def test_secret_scan_fails_closed_instead_of_running_a_gopath_binary(tmp_path):
    # A hostile GOPATH carrying a "gitleaks" that would pass every commit.
    evil = tmp_path / "evil"
    (evil / "bin").mkdir(parents=True)
    marker = tmp_path / "PWNED"
    for name in ("gitleaks", "gitleaks.exe"):
        fake = evil / "bin" / name
        fake.write_text(f"#!/usr/bin/env bash\ntouch '{marker.as_posix()}'\nexit 0\n", encoding="utf-8", newline="\n")
        fake.chmod(0o755)
    repo = target_repo(tmp_path)
    (repo / "a.txt").write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "a.txt"], check=True)
    git_dir = Path(shutil.which("git")).resolve().parent
    env = {**os.environ, "GOPATH": evil.as_posix(), "HOME": tmp_path.as_posix(),
           "PATH": f"{bash_path(git_dir)}:/usr/bin:/bin"}
    proc = subprocess.run([BASH, SECRET_SCAN.as_posix()], cwd=repo, env=env, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "gitleaks not found on PATH" in proc.stderr
    assert not marker.exists(), "the hook executed a binary chosen by GOPATH"


def test_no_hook_resolves_an_executable_from_env_locations():
    for hook in sorted((ROOT / "hooks").iterdir()):
        text = hook.read_text(encoding="utf-8")
        assert not re.search(r"\$\{?(GOPATH|HOME)\b[^\n]*/bin/", text), f"{hook.name} locates an executable via env"


def test_installed_hook_copies_match_canonical():
    for name in ("pre-commit-secret-scan.sh", "commit-msg", "pre-commit"):
        assert (ROOT / ".githooks" / name).read_bytes() == (ROOT / "hooks" / name).read_bytes(), name


# ─── SC-37: runner predicate follows the target's visibility ─────────────────
# audit-dev-standards-2026-10-27 MEDIUM: a template that reaches a public repo
# carries the hosted literal; unconfirmed visibility counts as public.

def assert_hosted_install(repo: Path) -> None:
    for name, template in ALL_TEMPLATES.items():
        installed = (repo / ".github" / "workflows" / name).read_text(encoding="utf-8")
        lines = runs_on_lines(installed)
        assert lines and all(l == "runs-on: ubuntu-latest" for l in lines), (name, lines)
        assert "runs-on: ${{" not in installed
        # Only the runs-on lines differ from the template.
        assert installed == hosted_copy(template.read_text(encoding="utf-8")), name


def test_private_repo_gets_the_guarded_predicate_verbatim(tmp_path):
    repo = target_repo(tmp_path)
    proc = install(repo, "--private", "--no-gh")
    assert proc.returncode == 0, proc.stderr
    canon = "runs-on: ${{ " + canonical_predicate() + " }}"
    for name, template in ALL_TEMPLATES.items():
        installed = (repo / ".github" / "workflows" / name).read_bytes()
        assert installed == template.read_bytes(), f"{name} is not the template byte for byte"
        lines = runs_on_lines(installed.decode("utf-8"))
        want = canon if name in PR_TEMPLATES else "runs-on: " + DEP_TOGGLE
        assert lines and all(l == want for l in lines), (name, lines)
    assert "CI runner (private repository): nexus-ci onboarding INCOMPLETE" in proc.stdout
    assert "gh variable set CI_RUNNER --body nexus-ci" in proc.stdout
    assert "ci-vm/registrar/config.json" in proc.stdout


def test_public_repo_gets_the_hosted_literal_and_no_runs_on_expression(tmp_path):
    repo = target_repo(tmp_path)
    proc = install(repo, "--public", "--no-gh")
    assert proc.returncode == 0, proc.stderr
    assert_hosted_install(repo)
    assert "CI runner (public repository):" in proc.stdout
    assert "CI_RUNNER must stay unset" in proc.stdout
    assert "gh variable set CI_RUNNER" not in proc.stdout


def test_unconfirmed_visibility_installs_the_hosted_literal(tmp_path):
    repo = target_repo(tmp_path)  # no origin, and --no-gh: visibility cannot be learned
    proc = install(repo, "--no-gh")
    assert proc.returncode == 0, proc.stderr
    assert_hosted_install(repo)
    assert "visibility unconfirmed, treated as public" in proc.stdout
    assert "gh variable set CI_RUNNER" not in proc.stdout


def test_both_visibility_flags_is_a_usage_error(tmp_path):
    repo = target_repo(tmp_path)
    proc = install(repo, "--private", "--public", "--no-gh")
    assert proc.returncode == 2
    assert "Usage:" in proc.stderr
    assert not (repo / ".github").exists()


@pytest.mark.parametrize("flag", ["--visibility=private", "--visibility=internal", "--internal"])
def test_unknown_flag_is_a_usage_error(tmp_path, flag):
    repo = target_repo(tmp_path)
    proc = install(repo, flag, "--no-gh")
    assert proc.returncode == 2 and "Usage:" in proc.stderr
    assert not (repo / ".github").exists()


def test_installer_substitutes_only_the_register_predicate():
    """install.sh's CANON_RUNS_ON must be the register's guarded SC-37 text, so
    a public copy loses exactly that predicate and nothing else."""
    text = INSTALL.read_text(encoding="utf-8")
    m = re.search(r'^CANON_RUNS_ON="runs-on: \\\$\{\{ (.*?) \}\}"$', text, re.M)
    assert m, "CANON_RUNS_ON not found in install.sh"
    assert m.group(1).replace('\\"', '"') == canonical_predicate()
    m = re.search(r'^TOGGLE_RUNS_ON="runs-on: \\(\$\{\{ .*? \}\})"$', text, re.M)
    assert m and m.group(1) == DEP_TOGGLE, "TOGGLE_RUNS_ON is not dep-auto-apply's toggle"
    for template in PR_TEMPLATES.values():
        for line in runs_on_lines(template.read_text(encoding="utf-8")):
            assert line == "runs-on: ${{ " + canonical_predicate() + " }}", (template.name, line)
    for line in runs_on_lines(DEP_TEMPLATE.read_text(encoding="utf-8")):
        assert line == "runs-on: " + DEP_TOGGLE, line


def install_with_gh(tmp_path: Path, repo: Path, private: str, *flags: str) -> subprocess.CompletedProcess[str]:
    """install.sh with a fake `gh` first on PATH that reports the origin repo's
    `private` as <private> and fails every other call (variables unset,
    registrar config unreadable). The target gets a github.com origin."""
    subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", "https://github.com/o/r.git"], check=True)
    bindir = tmp_path / "ghbin"
    bindir.mkdir()
    gh = bindir / "gh"
    gh.write_text("#!/usr/bin/env bash\n"
                  'if [ "$1" = api ] && [ "$2" = repos/o/r ]; then printf \'%s\\tr\\to\\n\' ' + private + "; exit 0; fi\n"
                  'echo "gh: HTTP 404" >&2; exit 1\n', encoding="utf-8", newline="\n")
    gh.chmod(0o755)
    git_dir = Path(shutil.which("git")).resolve().parent
    env = {**os.environ, "PATH": f"{bash_path(bindir)}:{bash_path(git_dir)}:/usr/bin:/bin"}
    return subprocess.run([BASH, INSTALL.as_posix(), *flags, repo.as_posix()], capture_output=True, text=True, env=env)


@pytest.mark.parametrize("private,flag", [("false", "--private"), ("true", "--public")])
def test_flag_contradicting_github_is_an_error(tmp_path, private, flag):
    repo = target_repo(tmp_path)
    proc = install_with_gh(tmp_path, repo, private, flag)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "contradicts GitHub" in proc.stderr and "nothing installed" in proc.stderr
    assert not (repo / ".github").exists() and not (repo / ".githooks").exists(), \
        "nothing may be written before visibility is settled"
    assert subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath"],
                          capture_output=True, text=True).returncode != 0


@pytest.mark.parametrize("private,want_hosted", [("false", True), ("true", False)])
def test_github_answer_decides_without_a_flag(tmp_path, private, want_hosted):
    repo = target_repo(tmp_path)
    proc = install_with_gh(tmp_path, repo, private)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    if want_hosted:
        assert_hosted_install(repo)
        assert "CI runner (public repository):" in proc.stdout
    else:
        for name, template in ALL_TEMPLATES.items():
            assert (repo / ".github" / "workflows" / name).read_bytes() == template.read_bytes(), name
        assert "CI runner (private repository)" in proc.stdout


# ─── audit-dev-standards-2026-10-30 LOW (SC-20): the hosted-literal guard ────
# classifies runs-on positively. The old regex recognised only the one-line
# `runs-on: <value>` spelling, so a block-form, quoted, aliased or escaped
# runs-on in a template would have been installed into a public repository.

def kit_with_size_guard_suffix(tmp_path: Path, suffix: str) -> Path:
    """A copy of the installer and everything it reads, with `suffix`
    appended to workflows/size-guard.yml."""
    kit = tmp_path / "kit"
    kit.mkdir()
    shutil.copy2(INSTALL, kit / "install.sh")
    for sub in ("hooks", "security", "templates", "workflows"):
        shutil.copytree(ROOT / sub, kit / sub)
    guard = kit / "workflows" / "size-guard.yml"
    guard.write_bytes(guard.read_bytes() + suffix.encode("utf-8"))
    return kit


UNCLASSIFIABLE_RUNS_ON = {
    "block-sequence": "  extra:\n    runs-on:\n      - self-hosted\n",
    "block-group": "  extra:\n    runs-on:\n      group: nexus\n",
    "block-labels": "  extra:\n    runs-on:\n      labels: [self-hosted]\n",
    "double-quoted-key": '  extra:\n    "runs-on": self-hosted\n',
    "single-quoted-key": "  extra:\n    'runs-on': nexus-ci\n",
    "alias": "  extra:\n    runs-on: *runner\n",
    "flow-mapping": "  extra: {runs-on: self-hosted, steps: []}\n",
    "lookalike-label": "  extra:\n    runs-on: ubuntu-latest-gpu\n",
    "escaped-key": '  extra:\n    "runs\\u002don": self-hosted\n',
}


@pytest.mark.parametrize("spelling", UNCLASSIFIABLE_RUNS_ON)
def test_hosted_install_refuses_a_runs_on_it_cannot_classify(tmp_path, spelling):
    kit = kit_with_size_guard_suffix(tmp_path, UNCLASSIFIABLE_RUNS_ON[spelling])
    repo = target_repo(tmp_path)
    proc = subprocess.run([BASH, (kit / "install.sh").as_posix(), "--public", "--no-gh", repo.as_posix()],
                          capture_output=True, text=True)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "not the guarded predicate or the hosted literal" in proc.stderr, proc.stderr
    assert not (repo / ".github" / "workflows" / "size-guard.yml").exists()


def test_hosted_install_accepts_the_literal_and_comments(tmp_path):
    kit = kit_with_size_guard_suffix(
        tmp_path, "  extra:\n    # runs-on: self-hosted would be refused\n    runs-on: ubuntu-latest  \n")
    repo = target_repo(tmp_path)
    proc = subprocess.run([BASH, (kit / "install.sh").as_posix(), "--public", "--no-gh", repo.as_posix()],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    installed = (repo / ".github" / "workflows" / "size-guard.yml").read_text(encoding="utf-8")
    assert installed.endswith("    runs-on: ubuntu-latest  \n")


def test_private_install_is_verbatim_whatever_the_spelling(tmp_path):
    """The classification guards the public/unconfirmed copy only; a private
    repository gets the template byte for byte."""
    suffix = UNCLASSIFIABLE_RUNS_ON["block-sequence"]
    kit = kit_with_size_guard_suffix(tmp_path, suffix)
    repo = target_repo(tmp_path)
    proc = subprocess.run([BASH, (kit / "install.sh").as_posix(), "--private", "--no-gh", repo.as_posix()],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (repo / ".github" / "workflows" / "size-guard.yml").read_text(encoding="utf-8").endswith(suffix)


# Inbox 98571252: the SC-20 refusal is all-or-nothing. It used to fire inside
# the per-template install step, after .githooks/ had been copied and
# `git add`ed, so a refused target kept hooks and index entries. Every
# template is now classified before the first write, like the SC-52 check.
KIT_TEMPLATES = {
    "size-guard.yml": Path("workflows") / "size-guard.yml",
    "security-audit.yml": Path("templates") / ".github" / "workflows" / "security-audit.yml",
    "dep-auto-apply.yml": Path("templates") / ".github" / "workflows" / "dep-auto-apply.yml",
}


@pytest.mark.parametrize("template", KIT_TEMPLATES)
@pytest.mark.parametrize("flags", [("--public", "--no-gh"), ("--no-gh",)], ids=["public", "unconfirmed"])
def test_sc20_refusal_leaves_the_target_tree_and_index_untouched(tmp_path, template, flags):
    kit = kit_with_size_guard_suffix(tmp_path, "")
    poisoned = kit / KIT_TEMPLATES[template]
    poisoned.write_bytes(poisoned.read_bytes() + UNCLASSIFIABLE_RUNS_ON["block-sequence"].encode("utf-8"))
    repo = target_repo(tmp_path)
    proc = subprocess.run([BASH, (kit / "install.sh").as_posix(), *flags, repo.as_posix()],
                          capture_output=True, text=True)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    # Same message as before the fix: ERROR: <template path> has a runs-on ...
    assert re.fullmatch(rf"ERROR: \S*/{re.escape(template)} has a runs-on that is not the guarded predicate "
                        r"or the hosted literal \(line \d+\); refusing to install it into a repository not "
                        r"confirmed private\n", proc.stderr), proc.stderr
    assert proc.stdout == "", proc.stdout
    written = [p.relative_to(repo).as_posix() for p in repo.rglob("*") if p.relative_to(repo).parts[0] != ".git"]
    assert written == [], written
    assert not (repo / ".githooks").exists()
    assert subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all"],
                          capture_output=True, text=True, check=True).stdout == ""
    assert subprocess.run(["git", "-C", str(repo), "ls-files"],
                          capture_output=True, text=True, check=True).stdout == ""
    assert subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath"],
                          capture_output=True, text=True).returncode != 0


# ─── audit-dev-standards-2026-10-30 MEDIUM (SC-52): cache-restore refusal ────
# dep-auto-apply's apply job can write the default-branch Actions cache scope,
# so install.sh refuses a target whose other workflows restore a cache, and
# the fleet scan reports an enrolled repo that does. ONE fixture table runs
# through both matchers (install.sh's awk, scripts/cache_restore.py via the
# scan) and both must report exactly the (line, form) pairs listed, so the
# twins cannot drift apart.

_SCAN_SCRIPT = ROOT / "scripts" / "repo-hygiene-scan.py"
_SCAN_SPEC = importlib.util.spec_from_file_location("hygiene_cache", _SCAN_SCRIPT)
hygiene = importlib.util.module_from_spec(_SCAN_SPEC)
assert _SCAN_SPEC.loader is not None
_SCAN_SPEC.loader.exec_module(hygiene)

SHA = "0123456789abcdef0123456789abcdef01234567"
KEY, ACTIONS_CACHE, GHA = "cache: not false", "actions/cache", "type=gha"
GO, NODE = "setup-go without cache: false", "setup-node without package-manager-cache: false"
LOCAL, REUSABLE = "local composite action not inspected", "reusable workflow not inspected"
UNREV = "not on the reviewed allow-list security/enrolment-uses-allowlist.txt"
MALFORMED = "malformed allow-list entry"
ALLOWLIST = ROOT / "security" / "enrolment-uses-allowlist.txt"
ALLOWLIST_REL = "security/enrolment-uses-allowlist.txt"


def wf(*steps: str) -> str:
    """A workflow whose first step line is line 7."""
    return ("name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            + "".join("      " + s + "\n" for s in steps))


def job_wf(line: str) -> str:
    """A workflow whose one job is `line` (a job-level key), at line 5."""
    return "name: ci\non: push\njobs:\n  call:\n    " + line + "\n"


CACHE_RESTORE_CASES: dict[str, tuple[str, list[tuple[int, str]]]] = {
    # (a) a `cache:` key that is not false
    "setup-node-cache-npm": (wf(f"- uses: actions/setup-node@{SHA}", "  with:", "    node-version: 22",
                                "    cache: npm", "    package-manager-cache: false"), [(10, KEY)]),
    "setup-python-cache-quoted-pip": (wf(f"- uses: actions/setup-python@{SHA}", "  with:",
                                         "    python-version: '3.12'", "    cache: 'pip'"), [(10, KEY)]),
    "setup-go-cache-true": (wf(f"- uses: actions/setup-go@{SHA}", "  with:", "    go-version: '1.23'",
                               "    cache: true"), [(7, GO), (10, KEY)]),
    "uppercase-key-and-value": (wf("- name: Set up Go", f"  uses: actions/setup-go@{SHA}", "  with:",
                                   "    Cache: TRUE"), [(8, GO), (10, KEY)]),
    "flow-mapping-cache": (wf("- {uses: actions/setup-python@" + SHA + ", with: {python-version: '3.12', cache: pip}}"),
                           [(7, KEY)]),
    # (b) actions/cache and its sub-actions, any ref
    "actions-cache": (wf(f"- uses: actions/cache@{SHA}", "  with:", "    path: ~/.npm", "    key: npm"),
                      [(7, ACTIONS_CACHE)]),
    "actions-cache-restore": (wf(f"- uses: actions/cache/restore@{SHA}", "  with:", "    path: ~/.npm",
                                 "    key: npm"), [(7, ACTIONS_CACHE)]),
    "actions-cache-save-mixed-case": (wf("- uses: Actions/Cache/save@v4", "  with:", "    path: x", "    key: k"),
                                      [(7, ACTIONS_CACHE)]),
    # (c) the buildx GitHub Actions cache backend
    "buildx-type-gha": (wf(f"- uses: docker/build-push-action@{SHA}", "  with:", "    push: false",
                           "    cache-from: type=gha", "    cache-to: type=gha,mode=max"),
                        [(7, UNREV), (10, GHA), (11, GHA)]),
    # (d) setup-go defaults cache ON; (e) setup-node v5+ defaults npm cache ON
    "setup-go-default-cache": (wf(f"- uses: actions/setup-go@{SHA}", "  with:", "    go-version: '1.23'"),
                               [(7, GO)]),
    "setup-go-no-with": (wf(f"- uses: actions/setup-go@{SHA}", "- run: go test ./..."), [(7, GO)]),
    "setup-go-false-in-the-next-step": (wf(f"- uses: actions/setup-go@{SHA}", "  with:", "    go-version: '1.23'",
                                           f"- uses: actions/setup-node@{SHA}", "  with:", "    cache: false",
                                           "    package-manager-cache: false"), [(7, GO)]),
    "setup-node-default-cache": (wf(f"- uses: actions/setup-node@{SHA}", "  with:", "    node-version: 22"),
                                 [(7, NODE)]),
    "crlf-setup-go-default-cache": (wf(f"- uses: actions/setup-go@{SHA}", "  with:",
                                       "    go-version: '1.23'").replace("\n", "\r\n"), [(7, GO)]),
    # accepted: caching explicitly off, or only mentioned in a comment
    "cache-false-spellings": (wf(f"- uses: actions/setup-go@{SHA}", "  with:", "    go-version: '1.23'",
                                 "    cache: false", "- name: node", f"  uses: actions/setup-node@{SHA}",
                                 "  with:", '    cache: "false"   # explicit',
                                 "    package-manager-cache: 'false'"), []),
    "setup-go-with-before-uses": (wf("- name: go", "  with:", "    cache: false",
                                     f"  uses: actions/setup-go@{SHA}"), []),
    "forms-in-comment-lines": (wf(f"# - uses: actions/cache@{SHA}", "#   cache: npm", "  # cache-from: type=gha",
                                  f"# - uses: actions/setup-go@{SHA}", "- run: echo ok"), []),
    "no-cache-anywhere": (wf("- uses: actions/checkout@" + SHA, "- run: make test"), []),
    # gate pass 1 on #73: positive classification of every `uses:`
    "swatinem-rust-cache": (wf(f"- uses: Swatinem/rust-cache@{SHA}"), [(7, UNREV)]),
    "astral-setup-uv": (wf(f"- uses: astral-sh/setup-uv@{SHA}", "  with:", "    python-version: '3.12'"),
                        [(7, UNREV)]),
    "gradle-setup-gradle": (wf(f"- uses: gradle/actions/setup-gradle@{SHA}"), [(7, UNREV)]),
    "ruby-setup-ruby-bundler-cache": (wf(f"- uses: ruby/setup-ruby@{SHA}", "  with:", "    ruby-version: '3.3'",
                                         "    bundler-cache: true"), [(7, UNREV)]),
    "local-composite-action": (wf("- uses: ./.github/actions/setup", "- run: make"), [(7, LOCAL)]),
    "remote-reusable-workflow": (job_wf(f"uses: org/repo/.github/workflows/build.yml@{SHA}"), [(5, REUSABLE)]),
    "docker-image-action": (wf("- uses: docker://alpine:3.20"), [(7, UNREV)]),
    "allow-list-entry-is-exact": (wf(f"- uses: peter-evans/create-pull-request/sub@{SHA}"), [(7, UNREV)]),
    "allow-listed-action-with-cache": (wf(f"- uses: peter-evans/create-pull-request@{SHA}", "  with:",
                                          "    cache: true"), [(9, KEY)]),
    "malformed-allow-list": (wf(f"- uses: peter-evans/create-pull-request@{SHA}"), [(3, MALFORMED)]),
    "allow-listed-action": (wf(f"- uses: peter-evans/create-pull-request@{SHA}", "  with:", "    title: x"), []),
    "custom-allow-list-entry": (wf(f"- uses: Swatinem/rust-cache@{SHA}"), []),
    "local-reusable-workflow-is-read": (job_wf("uses: ./.github/workflows/build.yml"), []),
    "uses-text-in-a-run-line": (wf('- run: echo "uses: evil/x@1"'), []),
}
# Rows judged against an allow-list other than the committed one. A
# MALFORMED hit's line is the allow-list's, not the workflow's.
CASE_ALLOWLIST = {
    "custom-allow-list-entry": "# reviewed for this test only\nSwatinem/Rust-Cache   # trailing comment\n",
    "malformed-allow-list": "# list\npeter-evans/create-pull-request\nhttps://github.com/o/r\n",
}
REFUSED = [c for c, (_, want) in CACHE_RESTORE_CASES.items() if want]
ACCEPTED = [c for c, (_, want) in CACHE_RESTORE_CASES.items() if not want]
_HIT_RE = re.compile(r"^ERROR: (\S+?):(\d+): (?:restores|cannot be shown not to restore) an Actions cache "
                     r"\((.+?)\); dep-auto-apply's apply job "
                     r"can poison the default-branch cache scope, so the target must not restore one "
                     r"\(SC-52, audit 2026-10-30\)\. Fix the workflow and re-run install\.sh\.$", re.M)


_ALLOW_RE = re.compile(r"^ERROR: security/enrolment-uses-allowlist\.txt:(\d+): (malformed allow-list entry) in the "
                       r"dev-standards checkout \(.+\); nothing installed \(SC-52\)$", re.M)


def test_the_fixture_table_covers_every_form():
    forms = {f for _, want in CACHE_RESTORE_CASES.values() for _, f in want}
    assert forms == {KEY, ACTIONS_CACHE, GHA, GO, NODE, LOCAL, REUSABLE, UNREV, MALFORMED}
    assert set(CASE_ALLOWLIST) <= set(CACHE_RESTORE_CASES)


def kit_with(tmp_path: Path, *, allowlist: str | None = None, install_text: str | None = None) -> Path:
    """A copy of the installer and everything it reads, optionally with its
    allow-list (None: keep; "": delete) or install.sh text replaced."""
    kit = tmp_path / "kit"
    kit.mkdir()
    shutil.copy2(INSTALL, kit / "install.sh")
    for sub in ("hooks", "security", "templates", "workflows"):
        shutil.copytree(ROOT / sub, kit / sub)
    if install_text is not None:
        (kit / "install.sh").write_bytes(install_text.encode("utf-8"))
    if allowlist == "":
        (kit / ALLOWLIST_REL).unlink()
    elif allowlist is not None:
        (kit / ALLOWLIST_REL).write_bytes(allowlist.encode("utf-8"))
    return kit


def install_from(kit: Path, repo: Path, *flags: str) -> subprocess.CompletedProcess[str]:
    flags = flags or ("--private", "--no-gh")
    return subprocess.run([BASH, (kit / "install.sh").as_posix(), *flags, repo.as_posix()],
                          capture_output=True, text=True)


def install_case(tmp_path: Path, case: str, repo: Path, *flags: str) -> subprocess.CompletedProcess[str]:
    if case in CASE_ALLOWLIST:
        return install_from(kit_with(tmp_path, allowlist=CASE_ALLOWLIST[case]), repo, *flags)
    return install(repo, *flags)


def install_hits(stderr: str, rel: str = ".github/workflows/ci.yml") -> list[tuple[int, str]]:
    hits = [(int(line), form) for path, line, form in _HIT_RE.findall(stderr) if path == rel]
    hits += [(int(line), form) for line, form in _ALLOW_RE.findall(stderr)]
    return sorted(hits)


def target_with_workflows(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = target_repo(tmp_path)
    for rel, text in files.items():
        path = repo / ".github" / "workflows" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    return repo


def assert_untouched(repo: Path, files: dict[str, str]) -> None:
    """A refused install wrote nothing: no file, no config, no index entry."""
    present = {p.relative_to(repo).as_posix() for p in repo.rglob("*")
               if p.is_file() and p.relative_to(repo).parts[0] != ".git"}
    assert present == {f".github/workflows/{rel}" for rel in files}, present
    for rel, text in files.items():
        assert (repo / ".github" / "workflows" / rel).read_bytes() == text.encode("utf-8")
    assert subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath"],
                          capture_output=True, text=True).returncode != 0
    assert subprocess.run(["git", "-C", str(repo), "ls-files"], capture_output=True, text=True).stdout == ""


@pytest.mark.parametrize("case", REFUSED)
@pytest.mark.parametrize("flags", [("--private", "--no-gh"), ("--public", "--no-gh")], ids=["private", "public"])
def test_install_refuses_a_target_that_restores_an_actions_cache(tmp_path, case, flags):
    text, want = CACHE_RESTORE_CASES[case]
    files = {"ci.yml": text}
    repo = target_with_workflows(tmp_path, files)
    proc = install_case(tmp_path, case, repo, *flags)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert install_hits(proc.stderr) == sorted(want), proc.stderr
    assert "Installed into" not in proc.stdout
    assert_untouched(repo, files)


@pytest.mark.parametrize("case", ACCEPTED)
def test_install_accepts_a_target_that_restores_no_cache(tmp_path, case):
    text, _ = CACHE_RESTORE_CASES[case]
    repo = target_with_workflows(tmp_path, {"ci.yml": text})
    proc = install_case(tmp_path, case, repo)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "an Actions cache" not in proc.stderr
    assert (repo / ".github" / "workflows" / "ci.yml").read_bytes() == text.encode("utf-8")
    assert (repo / ".github" / "workflows" / "dep-auto-apply.yml").read_bytes() == DEP_TEMPLATE.read_bytes()


def test_install_accepts_a_target_with_no_workflows_dir(tmp_path):
    repo = target_repo(tmp_path)
    proc = install(repo)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "restores an Actions cache" not in proc.stderr


def test_install_refuses_when_the_allow_list_is_unreadable(tmp_path):
    repo = target_repo(tmp_path)  # no workflows: the allow-list is still required
    proc = install_from(kit_with(tmp_path, allowlist=""), repo)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "enrolment-uses-allowlist.txt could not be read for the cache-restore check" in proc.stderr
    assert_untouched(repo, {})


def test_install_reports_every_hit_in_every_file_and_still_writes_nothing(tmp_path):
    files = {"a-clean.yml": CACHE_RESTORE_CASES["no-cache-anywhere"][0],
             "b-node.yaml": CACHE_RESTORE_CASES["setup-node-cache-npm"][0],
             "nested/c-go.yml": CACHE_RESTORE_CASES["setup-go-default-cache"][0]}
    repo = target_with_workflows(tmp_path, files)
    proc = install(repo)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    got = sorted((p, int(line), f) for p, line, f in _HIT_RE.findall(proc.stderr))
    assert got == [(".github/workflows/b-node.yaml", 10, KEY), (".github/workflows/nested/c-go.yml", 7, GO)]
    assert_untouched(repo, files)


def test_install_skips_the_workflows_it_replaces(tmp_path):
    """A stale installed copy (n3xus-notify's security-audit.yml carried
    `cache: true` on setup-go) is overwritten by this run, so it is not a
    reason to refuse; the replacement restores no cache."""
    bad = CACHE_RESTORE_CASES["setup-go-cache-true"][0]
    repo = target_with_workflows(tmp_path, {n: bad for n in ALL_TEMPLATES})
    proc = install(repo)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for name, template in ALL_TEMPLATES.items():
        assert (repo / ".github" / "workflows" / name).read_bytes() == template.read_bytes(), name


# ── the fleet scan's twin: same table, same answers ──

@pytest.mark.parametrize("name", sorted(ALL_TEMPLATES))
def test_the_installed_templates_restore_no_cache(name):
    allowlist, errors = hygiene.cache_restore.load_allowlist(ALLOWLIST.read_text(encoding="utf-8"))
    assert errors == []
    assert hygiene.cache_restore.find_cache_restores(ALL_TEMPLATES[name].read_text(encoding="utf-8"), allowlist) == []


def test_the_allow_list_is_the_templates_third_party_actions():
    """Seeded with exactly the third-party actions the fleet templates use."""
    used = set()
    for template in ALL_TEMPLATES.values():
        for v in re.findall(r"^\s*-?\s*uses:\s*([^@\s]+)@", template.read_text(encoding="utf-8"), re.M):
            if not v.lower().startswith("actions/"):
                used.add(v.lower())
    allowlist, errors = hygiene.cache_restore.load_allowlist(ALLOWLIST.read_text(encoding="utf-8"))
    assert errors == [] and set(allowlist) == used == {"peter-evans/create-pull-request"}


def enrolled_repo(tmp_path: Path, files: dict[str, str], *, enrolled: bool = True) -> Path:
    repo = target_with_workflows(tmp_path, files)
    if enrolled:
        (repo / ".github" / "auto-apply-enabled").write_text("", encoding="utf-8")
    return repo


def scan_case(module, tmp_path: Path, case: str) -> list[dict]:
    text, _ = CACHE_RESTORE_CASES[case]
    allow = ALLOWLIST
    if case in CASE_ALLOWLIST:
        allow = tmp_path / "allowlist.txt"
        allow.write_bytes(CASE_ALLOWLIST[case].encode("utf-8"))
    return module.scan_cache_restore(enrolled_repo(tmp_path, {"ci.yml": text}), allow)


def scan_hits(findings: list[dict]) -> list[tuple[int, str]]:
    return sorted((i["line"], i["form"]) for f in findings for i in f["items"]
                  if i["path"] in (".github/workflows/ci.yml", ALLOWLIST_REL))


@pytest.mark.parametrize("case", list(CACHE_RESTORE_CASES))
def test_scan_matches_the_installer_on_every_fixture(tmp_path, case):
    _, want = CACHE_RESTORE_CASES[case]
    findings = scan_case(hygiene, tmp_path, case)
    if not want:
        assert findings == []
        return
    [finding] = findings
    assert finding["severity"] == "MEDIUM" and finding["code"] == "auto-apply-cache-restore"
    assert scan_hits(findings) == sorted(want) and finding["count"] == len(want)


def test_scan_reports_an_unreadable_allow_list(tmp_path):
    repo = enrolled_repo(tmp_path, {"ci.yml": CACHE_RESTORE_CASES["no-cache-anywhere"][0]})
    [finding] = hygiene.scan_cache_restore(repo, tmp_path / "missing.txt")
    [item] = finding["items"]
    assert item["path"] == ALLOWLIST_REL and item["form"].startswith("allow-list unreadable")


def test_scan_does_not_judge_a_repo_not_enrolled(tmp_path):
    repo = enrolled_repo(tmp_path, {"ci.yml": CACHE_RESTORE_CASES["actions-cache"][0]}, enrolled=False)
    assert hygiene.scan_cache_restore(repo) == []


def test_scan_reads_the_installed_copies_too(tmp_path):
    """Unlike install.sh (which is about to replace them), the scan judges the
    installed templates as they are: a stale copy that caches is drift."""
    repo = enrolled_repo(tmp_path, {"security-audit.yml": CACHE_RESTORE_CASES["setup-go-cache-true"][0],
                                    "sub/x.yaml": CACHE_RESTORE_CASES["actions-cache"][0]})
    [finding] = hygiene.scan_cache_restore(repo)
    assert sorted((i["path"], i["line"], i["form"]) for i in finding["items"]) == [
        (".github/workflows/security-audit.yml", 7, GO), (".github/workflows/security-audit.yml", 10, KEY),
        (".github/workflows/sub/x.yaml", 7, ACTIONS_CACHE)]


def test_scan_repo_reports_the_finding(tmp_path):
    repo = enrolled_repo(tmp_path, {"ci.yml": CACHE_RESTORE_CASES["buildx-type-gha"][0]})
    codes = {f["code"] for f in hygiene.scan_repo(repo, 7)["findings"]}
    assert "auto-apply-cache-restore" in codes


# ── SC-14 mutation battery: the refusal tests must kill a broken guard ──
# Same mechanism as test_docker_release_helper.py: each mutant is an exact
# count==1 replace on a temp copy, and the refusal rows of the shared table
# are run against the copy. A mutant that leaves them green "survived".

PY_MUTANTS = [
    ("py-allowlist-membership-flipped", "    if path in allowlist:\n        return None",
     "    if path not in allowlist:\n        return None"),
    ("py-local-composite-accepted", "        return FORM_LOCAL\n", "        return None\n"),
    ("py-reusable-accepted", "        return FORM_REUSABLE\n", "        return None\n"),
    ("py-unreviewed-accepted", "    return FORM_UNREVIEWED\n\n\ndef find", "    return None\n\n\ndef find"),
    ("py-malformed-entry-ignored", "            errors.append((n, FORM_ALLOWLIST_MALFORMED))", "            pass"),
]
SH_MUTANTS = [
    ("sh-allowlist-membership-flipped", '  if (p in ALLOW) return ""', '  if (!(p in ALLOW)) return ""'),
    ("sh-local-composite-accepted", '    return "local composite action not inspected"', '    return ""'),
    ("sh-reusable-accepted", '  if (p ~ /\\.ya?ml$/) return "reusable workflow not inspected"',
     '  if (p ~ /\\.ya?ml$/) return ""'),
    ("sh-refusal-neutralised", '[ "$cache_refused" -eq 0 ] || exit 1', "true"),
    ("sh-malformed-entry-ignored", '  else print "allowlist\\t" FNR "\\tmalformed allow-list entry"', "  else a = a"),
]
CACHE_RESTORE_PY = ROOT / "scripts" / "cache_restore.py"


def apply_cache_mutant(text: str, old: str, new: str) -> str:
    count = text.count(old)
    assert count == 1, f"mutant pattern matched {count} times: {old!r}"
    return text.replace(old, new)


def scan_battery_failures(module_text: str, tmp: Path) -> list[str]:
    """Every refusal row through a scan whose cache_restore.py is module_text."""
    work = tmp / "scan"
    work.mkdir()
    shutil.copy2(_SCAN_SCRIPT, work / "repo-hygiene-scan.py")
    (work / "cache_restore.py").write_bytes(module_text.encode("utf-8"))
    spec = importlib.util.spec_from_file_location("hygiene_mutant", work / "repo-hygiene-scan.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    failures = []
    for n, case in enumerate(REFUSED):
        row = tmp / f"row{n}"
        row.mkdir()
        got = scan_hits(scan_case(module, row, case))
        if got != sorted(CACHE_RESTORE_CASES[case][1]):
            failures.append(f"{case}: {got}")
    return failures


def install_battery_failures(install_text: str, tmp: Path) -> list[str]:
    """Every refusal row through an install.sh whose text is install_text: the
    committed-allow-list rows as files of one target, then the malformed one."""
    failures = []
    rows = [c for c in REFUSED if c not in CASE_ALLOWLIST]
    files = {f"{c}.yml": CACHE_RESTORE_CASES[c][0] for c in rows}
    (tmp / "a").mkdir()
    repo = target_with_workflows(tmp / "a", files)
    proc = install_from(kit_with(tmp / "a", install_text=install_text), repo)
    if proc.returncode != 1:
        failures.append(f"default allow-list: exit {proc.returncode}")
    for c in rows:
        got = install_hits(proc.stderr, f".github/workflows/{c}.yml")
        if got != sorted(CACHE_RESTORE_CASES[c][1]):
            failures.append(f"{c}: {got}")
    try:
        assert_untouched(repo, files)
    except AssertionError as exc:
        failures.append(f"default allow-list: target written: {exc}")
    for c in [c for c in REFUSED if c in CASE_ALLOWLIST]:
        (tmp / c).mkdir()
        files = {"ci.yml": CACHE_RESTORE_CASES[c][0]}
        repo = target_with_workflows(tmp / c, files)
        proc = install_from(kit_with(tmp / c, allowlist=CASE_ALLOWLIST[c], install_text=install_text), repo)
        if proc.returncode != 1 or install_hits(proc.stderr) != sorted(CACHE_RESTORE_CASES[c][1]):
            failures.append(f"{c}: exit {proc.returncode}, {install_hits(proc.stderr)}")
    return failures


def test_the_shipped_matchers_pass_the_battery(tmp_path):
    (tmp_path / "py").mkdir()
    (tmp_path / "sh").mkdir()
    assert scan_battery_failures(CACHE_RESTORE_PY.read_text(encoding="utf-8"), tmp_path / "py") == []
    assert install_battery_failures(INSTALL.read_text(encoding="utf-8"), tmp_path / "sh") == []


@pytest.mark.parametrize("name,old,new", PY_MUTANTS, ids=[m[0] for m in PY_MUTANTS])
def test_scan_matcher_mutant_is_killed(tmp_path, name, old, new):
    mutated = apply_cache_mutant(CACHE_RESTORE_PY.read_text(encoding="utf-8"), old, new)
    assert scan_battery_failures(mutated, tmp_path), f"mutant {name} survived: the refusal rows stayed green"


@pytest.mark.parametrize("name,old,new", SH_MUTANTS, ids=[m[0] for m in SH_MUTANTS])
def test_install_matcher_mutant_is_killed(tmp_path, name, old, new):
    mutated = apply_cache_mutant(INSTALL.read_text(encoding="utf-8"), old, new)
    assert install_battery_failures(mutated, tmp_path), f"mutant {name} survived: the refusal rows stayed green"
