"""Find workflow lines that restore a GitHub Actions cache (register SC-52).

dep-auto-apply.yml's `apply` job runs dependency-controlled code on the
default branch with a runtime token that reaches the Actions cache service, so
it can write the default-branch cache scope ("Cacheract", audit 2026-10-27).
The control is on the restore side: a repository enrolled in auto-apply must
not restore an Actions cache anywhere (audit-dev-standards-2026-10-30, MEDIUM).

This module is the Python matcher, used by scripts/repo-hygiene-scan.py.
install.sh carries the same matcher in awk (CACHE_RESTORE_AWK). The two are
kept equal by one shared fixture table in
scripts/tests/test_install_and_secret_scan.py, which runs every case through
both and asserts the same (line, form) hits.

Line-based on purpose (no YAML parser; the scan is stdlib-only and the
installer is bash). Every rule errs towards a hit. A comment line (`#` after
optional whitespace) is never a hit. Matching is case-insensitive. The forms:

  cache: not false        a `cache:` key (block, quoted or flow-mapping
                          spelling) whose value is not false / 'false' /
                          "false": setup-node `cache: npm`, setup-python
                          `cache: pip`, setup-go `cache: true`, ...
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

Stdlib only. Python 3.8+.
"""
from __future__ import annotations

import re

FORM_CACHE_KEY = "cache: not false"
FORM_ACTIONS_CACHE = "actions/cache"
FORM_GHA_BACKEND = "type=gha"
FORM_SETUP_GO = "setup-go without cache: false"
FORM_SETUP_NODE = "setup-node without package-manager-cache: false"

_COMMENT_OR_BLANK = re.compile(r"^[ \t]*(#|$)")
_CACHE_KEY = re.compile(r"""(^[ \t]*(-[ \t]+)?|[{,][ \t]*)["']?cache["']?[ \t]*:""")
_SETUP_USES = re.compile(r"""(^|[ \t{,-])["']?uses["']?[ \t]*:[ \t]*["']?actions/setup-(go|node)@""")
_SEQ_ITEM = re.compile(r"^ *-[ \t]")
_WITH_KEY = re.compile(r"""^ *(-[ \t]+)?["']?with["']?[ \t]*:[ \t]*(#.*)?$""")
_SETUP_OFF_KEY = {"go": ("cache", FORM_SETUP_GO), "node": ("package-manager-cache", FORM_SETUP_NODE)}


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


def find_cache_restores(text: str) -> list[tuple[int, str]]:
    """Every (1-based line, form) in a workflow's text that restores a cache."""
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
        m = _SETUP_USES.search(line)
        if m:
            key, form = _SETUP_OFF_KEY[m.group(2)]
            if not _setup_step_switched_off(lines, i, key):
                hits.append((i + 1, form))
    return hits
