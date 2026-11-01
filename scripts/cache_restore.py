"""Classify workflow lines that restore, or may restore, a GitHub Actions
cache (register SC-52).

dep-auto-apply.yml's `apply` job runs dependency-controlled code on the
default branch with a runtime token that reaches the Actions cache service, so
it can write the default-branch cache scope ("Cacheract", audit 2026-10-27).
The control is on the restore side: a repository enrolled in auto-apply must
not restore an Actions cache anywhere (audit-dev-standards-2026-10-30, MEDIUM;
gate pass 1 on #73: positive classification, not a list of known spellings).

This module is the Python matcher, used by scripts/repo-hygiene-scan.py.
install.sh carries the same matcher in awk (CACHE_RESTORE_AWK). The two are
kept equal by one shared fixture table in
scripts/tests/test_install_and_secret_scan.py, which runs every case through
both and asserts the same (line, form) hits.

Line-based on purpose (no YAML parser; the scan is stdlib-only and the
installer is bash). A comment line (`#` after optional whitespace) is never a
hit. Matching is case-insensitive.

Every `uses:` (a step's or a job's) is CLASSIFIED; it passes only as:
  - a first-party `actions/<name>@<ref>`, held to the cache rules below;
  - an exact `owner/repo[/path]` on the reviewed allow-list
    security/enrolment-uses-allowlist.txt (third-party actions read and found
    not to restore a cache; a `cache:` on one is still a hit);
  - `./.github/workflows/<file>.yml|yaml`, a local reusable workflow, which
    is itself read in the same pass.
Everything else is a hit with its own form:
  local composite action not inspected   `uses: ./...` (or ../...)
  reusable workflow not inspected        `owner/repo/<path>.yml@ref`
  not on the reviewed allow-list ...     any other action, a docker:// image
                                         or an unparseable value
The cache rules (restore forms), on every line:
  cache: not false        a `cache:` key (block, quoted or flow-mapping
                          spelling) whose value is not false / 'false' /
                          "false"
  actions/cache           `actions/cache@` or `actions/cache/` anywhere (the
                          action and its restore/save sub-actions, any ref)
  type=gha                the GitHub Actions cache backend of buildx
                          (`cache-from:`/`cache-to:`, a block scalar or a
                          `docker buildx --cache-from` command line)
  setup-go without cache: false
                          actions/setup-go v4+ caches by default
  setup-node without package-manager-cache: false
                          actions/setup-node v5+ caches npm by default
                          (Dependabot moves a v4 pin to v5 unprompted)
A setup-go/setup-node step counts as switched off only when its own block
`with:` mapping holds the key with a false value; any other spelling (a flow
mapping step, a key outside `with:`) is a hit.

The allow-list: one `owner/repo` or `owner/repo/path` per line, `#` comments
(whole-line or trailing). Any other non-comment line is a "malformed
allow-list entry", and a caller must then refuse rather than classify.

Stdlib only. Python 3.8+.
"""
from __future__ import annotations

import re

FORM_CACHE_KEY = "cache: not false"
FORM_ACTIONS_CACHE = "actions/cache"
FORM_GHA_BACKEND = "type=gha"
FORM_SETUP_GO = "setup-go without cache: false"
FORM_SETUP_NODE = "setup-node without package-manager-cache: false"
FORM_LOCAL = "local composite action not inspected"
FORM_REUSABLE = "reusable workflow not inspected"
FORM_UNREVIEWED = "not on the reviewed allow-list security/enrolment-uses-allowlist.txt"
FORM_ALLOWLIST_MALFORMED = "malformed allow-list entry"
# Not a restore seen, but a `uses:` that cannot be shown not to be one.
UNCLASSIFIED_FORMS = (FORM_LOCAL, FORM_REUSABLE, FORM_UNREVIEWED)

_COMMENT_OR_BLANK = re.compile(r"^[ \t]*(#|$)")
_CACHE_KEY = re.compile(r"""(^[ \t]*(-[ \t]+)?|[{,][ \t]*)["']?cache["']?[ \t]*:""")
_USES_KEY = re.compile(r"""(^[ \t]*(-[ \t]+)?|[{,][ \t]*)["']?uses["']?[ \t]*:[ \t]*["']?""")
_USES_VALUE = re.compile(r"""[^ \t"',}#]*""")
_LOCAL_REUSABLE = re.compile(r"^\./\.github/workflows/[^/]+\.ya?ml$")
_ALLOW_ENTRY = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+(/[a-z0-9_.-]+)*$")
_DOT_SEGMENT = re.compile(r"(^|/)\.\.?(/|$)")
_SEQ_ITEM = re.compile(r"^ *-[ \t]")
_WITH_KEY = re.compile(r"""^ *(-[ \t]+)?["']?with["']?[ \t]*:[ \t]*(#.*)?$""")
_SETUP_OFF_KEY = {"actions/setup-go": ("cache", FORM_SETUP_GO),
                  "actions/setup-node": ("package-manager-cache", FORM_SETUP_NODE)}


def _is_code(line: str) -> bool:
    return not _COMMENT_OR_BLANK.match(line)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_false(value: str) -> bool:
    value = re.sub(r"[ \t]+#.*$", "", value).strip(" \t")
    return value in ("false", "'false'", '"false"')


def _cache_key_hit(line: str) -> bool:
    m = _CACHE_KEY.search(line)
    if not m:
        return False
    rest = line[m.end():]
    if rest and rest[0] not in " \t":
        return False  # `cache:x` is one plain scalar, not a key
    if line[m.start()] in "{,":
        rest = re.split(r"[,}]", rest, maxsplit=1)[0]
    return not _is_false(rest)


def _setup_step_switched_off(lines: list[str], i: int, key: str) -> bool:
    """True when the step holding the `uses:` at lines[i] sets <key>: false
    in its block `with:` mapping."""
    use_indent = _indent(lines[i])
    start = -1
    if _SEQ_ITEM.match(lines[i]):
        start, dash = i, use_indent
    else:
        for j in range(i - 1, -1, -1):
            if not _is_code(lines[j]):
                continue
            ind = _indent(lines[j])
            if ind < use_indent:
                if _SEQ_ITEM.match(lines[j]):
                    start, dash = j, ind
                break
    if start < 0:
        return False
    end = start + 1
    while end < len(lines) and not (_is_code(lines[end]) and _indent(lines[end]) <= dash):
        end += 1
    off = re.compile(r"""^ *["']?""" + re.escape(key) + r"""["']?[ \t]*:(.*)$""")
    for w in range(start, end):
        m = _WITH_KEY.match(lines[w])
        if not m:
            continue
        with_col = _indent(lines[w]) + len(m.group(1) or "")
        for k in range(w + 1, end):
            if not _is_code(lines[k]):
                continue
            if _indent(lines[k]) <= with_col:
                break
            hit = off.match(lines[k])
            if hit and (not hit.group(1) or hit.group(1)[0] in " \t") and _is_false(hit.group(1)):
                return True
    return False


def load_allowlist(text: str) -> tuple[frozenset[str], list[tuple[int, str]]]:
    """(entries, errors): the reviewed `owner/repo[/path]` entries, lowercased,
    and a (1-based line, FORM_ALLOWLIST_MALFORMED) per line that is neither a
    comment, blank, nor a well-formed entry."""
    entries: set[str] = set()
    errors: list[tuple[int, str]] = []
    for n, raw in enumerate(text.split("\n"), 1):
        line = (raw[:-1] if raw.endswith("\r") else raw).lower()
        if not _is_code(line):
            continue
        line = re.sub(r"[ \t]+#.*$", "", line).strip(" \t")
        if _ALLOW_ENTRY.match(line) and not _DOT_SEGMENT.search(line):
            entries.add(line)
        else:
            errors.append((n, FORM_ALLOWLIST_MALFORMED))
    return frozenset(entries), errors


def _classify_uses(value: str, allowlist: frozenset[str]) -> str | None:
    """None when the `uses:` value passes classification, else its form."""
    if value.startswith("./") or value.startswith("../"):
        if _LOCAL_REUSABLE.match(value):
            return None  # read in the same pass as every other workflow
        return FORM_LOCAL
    path, at, _ = value.partition("@")
    if not at:
        return FORM_UNREVIEWED
    if path.endswith(".yml") or path.endswith(".yaml"):
        return FORM_REUSABLE
    if path.startswith("actions/"):
        return None  # first-party: the cache rules judge it
    if path in allowlist:
        return None
    return FORM_UNREVIEWED


def find_cache_restores(text: str, allowlist: frozenset[str]) -> list[tuple[int, str]]:
    """Every (1-based line, form) in a workflow's text that restores a cache
    or is a `uses:` that cannot be classified as not restoring one."""
    # Lowercased: Actions resolves `Actions/Cache@`, input names are
    # case-insensitive (INPUT_<NAME>) and getBooleanInput takes False/FALSE.
    lines = [(ln[:-1] if ln.endswith("\r") else ln).lower() for ln in text.split("\n")]
    hits: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        if not _is_code(line):
            continue
        if _cache_key_hit(line):
            hits.append((i + 1, FORM_CACHE_KEY))
        if "actions/cache@" in line or "actions/cache/" in line:
            hits.append((i + 1, FORM_ACTIONS_CACHE))
        if "type=gha" in line:
            hits.append((i + 1, FORM_GHA_BACKEND))
        m = _USES_KEY.search(line)
        if m:
            value = _USES_VALUE.match(line, m.end()).group(0)
            form = _classify_uses(value, allowlist)
            if form:
                hits.append((i + 1, form))
            setup = _SETUP_OFF_KEY.get(value.partition("@")[0])
            if setup and not _setup_step_switched_off(lines, i, setup[0]):
                hits.append((i + 1, setup[1]))
    return hits
