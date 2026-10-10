"""promote-canary.yml: promotion is bound to main and to the RC commit.

audit-dev-standards-2026-10-10 HIGH 1 (register SC-29, SC-13, SC-30, SC-08).
The release-promoter App key (it can move refs/tags/v1, which every @v1
consumer executes) was consumed by jobs gated only on event name, so a
`workflow_dispatch` of any pushed branch minted the token; tag-rc tagged HEAD of
whatever ref was dispatched; scoring counted ANY canary workflow whose
head_branch matched the RC and never compared head_sha; and the canary called
dev-standards @main, so it tested main at run time rather than the RC commit.

Two kinds of test here:
  * structural: parse the SHIPPED workflow and assert the controls are present
    on every job that touches the key, and that no secret is interpolated into
    a `run:` body or passed on a curl command line (SC-11);
  * behavioural: run the SHIPPED `run:` blocks of the pin and scoring steps
    under bash with a fake `curl` on PATH that serves fixture API responses and
    records argv and stdin. No network, nothing outside tmp_path. These need
    `jq` (present on the hosted runners); they skip, loudly, without it.

Run:  python -m pytest scripts/tests/test_promote_canary_workflow.py -q
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "promote-canary.yml"
WORKFLOW_TEXT = WORKFLOW_PATH.read_text(encoding="utf-8")
WORKFLOW = yaml.safe_load(WORKFLOW_TEXT)
JOBS = WORKFLOW["jobs"]
KEY_REF = "secrets.RELEASE_PROMOTER_PRIVATE_KEY"
MAIN_PREDICATE = "github.ref == 'refs/heads/main'"

RC_TAG = "v1-rc18"
RC_SHA = "37a7b3532aaa0a057a90c1f57a08e8daf8cddf44"
CANARY_HEAD = "1111111111111111111111111111111111111111"
CANARY_PINNED = "2222222222222222222222222222222222222222"
TOKEN = "ghs_FAKEtokenForTestsOnly0123456789"

CANARY_RELEASE_YML = """name: Release

# Schema: https://github.com/Ohio15/dev-standards/blob/main/release/SPEC.md
# (a comment naming dev-standards at another ref, as the real canary has)

on:
  push:
    tags: ['v*']
  workflow_dispatch:

permissions:
  contents: read
  packages: write

jobs:
  release:
    uses: Ohio15/dev-standards/.github/workflows/docker-release.yml@main
    secrets: inherit
"""


# ─── helpers ─────────────────────────────────────────────────────────────────

# Any way a job can reach a secret: `secrets.X` / `secrets['X']` /
# `secrets["X"]` in any case, `toJSON(secrets)`, or a `secrets: inherit` /
# `secrets:` mapping on a reusable-workflow call. Case-insensitive because
# Actions expressions are.
SECRET_TOKEN = re.compile(r"secrets\s*(\.\s*[A-Za-z0-9_-]+|\[\s*['\"][^'\"]*['\"]\s*\]|\)|\b)", re.I)


def secret_refs(obj) -> list[str]:
    """Every secret reference spelling in a parsed workflow fragment."""
    text = yaml.safe_dump(obj, width=10_000)
    refs = [m.group(0) for m in SECRET_TOKEN.finditer(text)]
    if isinstance(obj, dict) and "secrets" in obj:
        refs.append(f"secrets: {obj['secrets']}")
    return refs


def key_jobs() -> dict[str, dict]:
    found = {name: job for name, job in JOBS.items() if secret_refs(job)}
    assert found, "no job references any secret; the test is looking at the wrong file"
    return found


def step(job: str, name_prefix: str) -> dict:
    hits = [s for s in JOBS[job]["steps"] if s.get("name", "").startswith(name_prefix)]
    assert len(hits) == 1, f"expected one step starting {name_prefix!r} in {job}"
    return hits[0]


def all_steps():
    for job_name, job in JOBS.items():
        for s in job["steps"]:
            yield job_name, s


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


def bash_path(p: Path) -> str:
    posix = p.resolve().as_posix()
    m = re.match(r"^([A-Za-z]):/(.*)$", posix)
    return f"/{m.group(1).lower()}/{m.group(2)}" if m else posix


JQ = shutil.which("jq")
needs_jq = pytest.mark.skipif(JQ is None, reason="jq not on PATH: behavioural promote-canary tests NOT examined")

FAKE_CURL = r"""#!/usr/bin/env bash
# Test double for curl: records argv and the -K - config read from stdin, and
# serves fixture responses keyed on method + URL.
set -euo pipefail
d="$FAKE_DIR"
printf '%s\n' "$*" >> "$d/argv.log"
method=GET; data=""; url=""; cfg=""
while [ $# -gt 0 ]; do
  case "$1" in
    -K) if [ "$2" = "-" ]; then cfg=$(cat); fi; shift 2 ;;
    -H|-o|-w) shift 2 ;;
    -X) method="$2"; shift 2 ;;
    -d) data="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
printf '%s\n' "$cfg" >> "$d/stdin.log"
case "$method $url" in
  "GET "*/git/ref/heads/main)
    cat "$d/head.json" ;;
  "GET "*"/contents/.github/workflows/release.yml?ref=$CANARY_HEAD")
    cat "$d/get.json" ;;
  "GET "*/contents/.github/workflows/release.yml?ref=*)
    [ -f "$d/committed.yml" ] || { echo "no commit yet" >&2; exit 22; }
    python_b64=$(base64 -w0 "$d/committed.yml")
    printf '{"content":"%s"}' "$python_b64" ;;
  "PUT "*/contents/.github/workflows/release.yml)
    body="${data#@}"
    cp "$body" "$d/put.json"
    jq -r .content "$body" | base64 -d > "$d/committed.yml"
    printf '{"commit":{"sha":"%s"}}' "$CANARY_PINNED" ;;
  "GET "*/actions/workflows/release.yml/runs*)
    cat "$d/runs.json" ;;
  *)
    echo "fake curl: unrouted $method $url" >&2; exit 22 ;;
esac
"""


@pytest.fixture
def fake_env(tmp_path: Path):
    if JQ is None:
        pytest.skip("jq not on PATH")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = tmp_path / "fake"
    fake.mkdir()
    curl = bindir / "curl"
    curl.write_text(FAKE_CURL, encoding="utf-8", newline="\n")
    curl.chmod(0o755)
    jq_real = Path(JQ)
    if os.name == "nt":
        # Windows jq writes CRLF unless --binary; the runner's jq writes LF.
        shim = bindir / "jq"
        shim.write_text(f'#!/usr/bin/env bash\nexec "{bash_path(jq_real)}" -b "$@"\n',
                        encoding="utf-8", newline="\n")
        shim.chmod(0o755)
        jq_dir = ""
    else:
        jq_dir = ":" + bash_path(jq_real.parent)
    git_dir = Path(shutil.which("git")).resolve().parent
    out = tmp_path / "github_output"
    out.write_text("", encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{bash_path(bindir)}{jq_dir}:{bash_path(git_dir)}:/usr/bin:/bin",
        "FAKE_DIR": bash_path(fake),
        "GITHUB_OUTPUT": bash_path(out),
        "CANARY_HEAD": CANARY_HEAD,
        "CANARY_PINNED": CANARY_PINNED,
        "T": TOKEN,
        "CANARY_REPO": "Ohio15/dev-standards-canary",
        "WF_PATH": ".github/workflows/release.yml",
    }
    return {"env": env, "fake": fake, "out": out, "tmp": tmp_path}


def run_step(fx, script: str, extra_env: dict[str, str]):
    env = {**fx["env"], **extra_env}
    proc = subprocess.run([bash_exe(), "-c", script], cwd=fx["tmp"], env=env,
                          capture_output=True, text=True)
    outputs = dict(line.split("=", 1) for line in fx["out"].read_text(encoding="utf-8").splitlines() if "=" in line)
    return proc, outputs


def write_canary_file(fake: Path, body: str) -> None:
    (fake / "head.json").write_text(json.dumps({"object": {"sha": CANARY_HEAD}}), encoding="utf-8")
    # The contents API wraps base64 at 60 columns; reproduce that.
    content = base64.encodebytes(body.encode()).decode()
    (fake / "get.json").write_text(json.dumps({"sha": "f" * 40, "content": content}), encoding="utf-8")


def run_obj(run_id: int, path: str, sha: str, conclusion: str | None, name: str = "Release",
            status: str = "completed", minute: int = 0) -> dict:
    return {
        "id": run_id, "name": name, "path": path, "head_branch": RC_TAG, "head_sha": sha,
        "status": status, "conclusion": conclusion, "event": "workflow_dispatch",
        "html_url": f"https://github.com/Ohio15/dev-standards-canary/actions/runs/{run_id}",
        "created_at": f"2026-10-10T15:{minute:02d}:00Z", "updated_at": f"2026-10-10T15:{minute:02d}:30Z",
    }


REL = ".github/workflows/release.yml"


# ─── structural: the key is bound to main and an environment ────────────────

def test_secret_scan_finds_every_mint_site():
    # Self-test of the scanner: the workflow has three App-token mints (tag-rc
    # general + canary pin, monitor general). A scan finding fewer is broken.
    mints = [(j, s) for j, s in all_steps()
             if any(r == KEY_REF for r in secret_refs(s))]
    assert len(mints) >= 3, mints
    assert {j for j, _ in mints} == {"tag-rc", "monitor"}


def test_secret_scan_catches_other_spellings():
    for spelling in ("${{ secrets['RELEASE_PROMOTER_PRIVATE_KEY'] }}", '${{ SECRETS.release_promoter_private_key }}',
                     "${{ toJSON(secrets) }}", "${{ secrets[format('{0}', 'X')] }}"):
        assert secret_refs({"run": f"echo {spelling}"}), spelling
    assert secret_refs({"uses": "o/r/.github/workflows/x.yml@" + "a" * 40, "secrets": "inherit"})


def test_the_only_secret_reference_is_the_exact_promoter_key():
    # No job reaches a secret by any other spelling, nor any other secret.
    for name, job in JOBS.items():
        for ref in secret_refs(job):
            assert ref == KEY_REF, f"{name}: secret reached as {ref!r}"
    assert secret_refs(WORKFLOW.get("env", {})) == []


def test_github_token_gets_no_permissions():
    assert WORKFLOW["permissions"] == {}
    for name, job in JOBS.items():
        assert job.get("permissions") == {}, f"{name}: GITHUB_TOKEN permissions not dropped to none"


def test_every_key_job_requires_main_in_its_if():
    for name, job in key_jobs().items():
        cond = job.get("if", "")
        assert MAIN_PREDICATE in cond, f"{name}: job if: lacks {MAIN_PREDICATE}"
        # The predicate must gate the whole condition, not one disjunct.
        assert cond.strip().startswith(MAIN_PREDICATE + " && ("), f"{name}: main predicate is not a top-level conjunct"


def test_every_key_job_declares_the_release_promoter_environment():
    for name, job in key_jobs().items():
        assert job.get("environment") == "release-promoter", f"{name}: no environment: release-promoter"


def test_every_key_job_asserts_main_before_any_key_use():
    for name, job in key_jobs().items():
        first = job["steps"][0]
        assert "uses" not in first, f"{name}: first step is an action, not the ref assertion"
        assert 'if [ "${GITHUB_REF}" != "refs/heads/main" ]' in first["run"], f"{name}: first step does not assert main"
        assert "exit 1" in first["run"]
        key_steps = [i for i, s in enumerate(job["steps"]) if KEY_REF in yaml.safe_dump(s)]
        assert key_steps and min(key_steps) > 0


def test_key_jobs_use_only_first_party_actions():
    # SC-29: a job that materialises the key runs no third-party action.
    for name, job in key_jobs().items():
        for s in job["steps"]:
            if "uses" in s:
                assert s["uses"].startswith("actions/"), f"{name}: third-party action {s['uses']}"


def test_no_secret_expression_inside_any_run_body():
    for job_name, s in all_steps():
        if "run" in s:
            assert "${{ secrets." not in s["run"], f"{job_name}/{s.get('name')}: secret interpolated into run:"
            assert "secrets." not in s["run"], f"{job_name}/{s.get('name')}: secret referenced in run:"


def test_no_token_on_a_curl_command_line():
    # SC-11: the bearer token reaches curl on stdin (-K -), never in argv.
    for job_name, s in all_steps():
        body = s.get("run", "")
        assert not re.search(r'-H\s+"Authorization', body), f"{job_name}/{s.get('name')}: Authorization header in argv"
        code = [ln for ln in body.splitlines() if not ln.lstrip().startswith("#")]
        for ln in code:
            # Every real curl invocation is the stdin-fed helper; everything
            # else calls the helper (gh_curl), never bare curl.
            if re.search(r"(?<![\w-])curl\s", ln):
                assert "curl -K -" in ln, f"{job_name}/{s.get('name')}: bare curl: {ln.strip()}"


def test_every_uses_is_sha_pinned_with_same_line_version():
    pinned = re.compile(r"^\s*-?\s*uses:\s*[\w.-]+/[\w./-]+@[0-9a-f]{40} # v\d+(\.\d+)*\s*$")
    uses_lines = [ln for ln in WORKFLOW_TEXT.splitlines() if re.match(r"^\s*-?\s*uses:", ln)]
    assert uses_lines
    for ln in uses_lines:
        assert pinned.match(ln), f"not SHA-pinned with a same-line version: {ln.strip()}"


def test_no_ntfy_post_at_all():
    # Parsed YAML, so the header comment explaining the removal does not count.
    assert "NTFY_URL" not in WORKFLOW.get("env", {})
    for job_name, s in all_steps():
        code = "\n".join(ln for ln in s.get("run", "").splitlines() if not ln.lstrip().startswith("#"))
        assert "ntfy" not in code.lower(), f"{job_name}/{s.get('name')}: posts to ntfy"
        assert "ntfy" not in json.dumps(s.get("env", {})).lower(), f"{job_name}/{s.get('name')}: ntfy env"


def test_tag_rc_asserts_head_is_origin_main_before_selecting_a_tag():
    names = [s.get("name", "") for s in JOBS["tag-rc"]["steps"]]
    assert_idx = names.index("Assert HEAD is origin/main HEAD")
    select_idx = names.index("Select next v1-rcN")
    assert assert_idx < select_idx
    body = step("tag-rc", "Assert HEAD is origin/main HEAD")["run"]
    assert "git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main" in body
    assert 'if [ "$head" = "$main" ]' in body
    assert "refusing to tag" in body and "exit 1" in body


def test_tag_rc_pins_the_canary_before_any_tag_is_pushed():
    names = [s.get("name", "") for s in JOBS["tag-rc"]["steps"]]
    pin = names.index("Pin the canary to the RC commit")
    assert pin < names.index("Push v1-rcN tag") < names.index("Mirror tag to canary repo")
    mirror = step("tag-rc", "Mirror tag to canary repo")
    assert mirror["env"]["CANARY_SHA"] == "${{ steps.pin.outputs.canary_sha }}"
    prime = step("tag-rc", "Prime canary-state.json")
    assert ".current_rc_canary_sha = $csha" in prime["run"]
    assert ".schema_version = 2" in prime["run"]


def test_every_app_token_mint_names_its_permissions():
    mints = [(j, s) for j, s in all_steps() if s.get("uses", "").startswith("actions/create-github-app-token@")]
    assert len(mints) >= 3
    for job, s in mints:
        perms = {k: v for k, v in s["with"].items() if k.startswith("permission-")}
        assert perms, f"{job}/{s.get('name')}: no permission-* inputs; the token inherits every App permission"
        if s.get("id") == "app":
            assert perms == {"permission-contents": "write", "permission-actions": "write"}, (job, perms)
        assert "permission-workflows" not in perms or s["with"]["repositories"] == "dev-standards-canary"


def test_pin_token_is_scoped_to_the_canary_only():
    mint = step("tag-rc", "Mint canary workflow-pin token")
    assert mint["with"]["repositories"] == "dev-standards-canary"
    assert mint["with"]["permission-workflows"] == "write"
    assert mint["with"]["permission-contents"] == "write"


def test_scoring_step_filters_on_release_workflow_and_head_sha():
    body = step("monitor", "Query canary release.yml runs")["run"]
    assert "head_sha" in body
    assert ".path == $path" in body
    assert WORKFLOW["env"]["RELEASE_WORKFLOW_PATH"] == ".github/workflows/release.yml"
    wait = step("monitor", "Wait for the re-dispatched run")["run"]
    assert ".head_sha == $sha" in wait and ".path == $path" in wait


def test_promote_step_binds_rc_sha_to_its_tag_and_main():
    body = step("monitor", "Promote v1")["run"]
    assert 'refs/tags/${RC}^{commit}' in body
    assert "git merge-base --is-ancestor \"$RC_SHA\" refs/remotes/origin/main" in body
    # Both checks precede the v1 move.
    assert body.index("merge-base --is-ancestor") < body.index("-X PATCH")


def run_promote_guard(tmp_path: Path, canary_ref: str):
    env = {**os.environ, "T": TOKEN, "RC": RC_TAG, "RC_SHA": RC_SHA, "CANARY_REF": canary_ref,
           "STATE_FILE": "x", "STABLE_TAG": "v1", "GREEN_THRESHOLD": "3",
           # No git and no curl reachable: anything past the guard fails fast.
           "PATH": "/nonexistent"}
    return subprocess.run([bash_exe(), "-c", step("monitor", "Promote v1")["run"]], cwd=tmp_path,
                          env=env, capture_output=True, text=True)


@pytest.mark.parametrize("ref", ["main", "", "a" * 40])
def test_promote_refuses_evidence_that_did_not_run_the_rc_commit(tmp_path, ref):
    proc = run_promote_guard(tmp_path, ref)
    assert proc.returncode == 1
    assert "Refusing to promote" in proc.stdout


def test_promote_guard_passes_a_pinned_rc(tmp_path):
    proc = run_promote_guard(tmp_path, RC_SHA)
    assert "Refusing to promote" not in proc.stdout
    assert proc.returncode != 0  # reached the git fetch, which cannot run here


def test_state_schema_is_documented_at_version_2():
    doc = (ROOT / "release" / "canary-promotion.md").read_text(encoding="utf-8")
    assert '"schema_version": 2' in doc
    assert "current_rc_canary_sha" in doc


# ─── behavioural: the pin step ───────────────────────────────────────────────

def pin_env(pin: str = "true") -> dict[str, str]:
    return {"PIN_T": TOKEN, "PIN": pin, "RC_TAG": RC_TAG, "RC_SHA": RC_SHA}


@needs_jq
def test_pin_rewrites_only_the_uses_line_and_reports_the_new_canary_commit(fake_env):
    write_canary_file(fake_env["fake"], CANARY_RELEASE_YML)
    proc, o = run_step(fake_env, step("tag-rc", "Pin the canary to the RC commit")["run"], pin_env())
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert o["canary_sha"] == CANARY_PINNED
    assert o["canary_ref"] == RC_SHA
    committed = (fake_env["fake"] / "committed.yml").read_text(encoding="utf-8")
    expected = CANARY_RELEASE_YML.replace(
        "docker-release.yml@main", f"docker-release.yml@{RC_SHA} # {RC_TAG}")
    assert committed == expected
    put = json.loads((fake_env["fake"] / "put.json").read_text(encoding="utf-8"))
    assert put["sha"] == "f" * 40 and put["branch"] == "main"


@needs_jq
def test_pin_keeps_the_token_out_of_curl_argv(fake_env):
    write_canary_file(fake_env["fake"], CANARY_RELEASE_YML)
    proc, _ = run_step(fake_env, step("tag-rc", "Pin the canary to the RC commit")["run"], pin_env())
    assert proc.returncode == 0, proc.stderr
    assert TOKEN not in (fake_env["fake"] / "argv.log").read_text(encoding="utf-8")
    assert f'Authorization: Bearer {TOKEN}' in (fake_env["fake"] / "stdin.log").read_text(encoding="utf-8")


@needs_jq
@pytest.mark.parametrize("spelling", [
    '    uses: "Ohio15/dev-standards/.github/workflows/docker-release.yml@main"\n',
    "    - uses: Ohio15/dev-standards/.github/workflows/docker-release.yml@main\n",
    "    uses: 'Ohio15/dev-standards/.github/workflows/lib-release.yml@v1'\n",
])
def test_pin_fails_closed_on_an_unrewritten_dev_standards_reference(fake_env, spelling):
    # One normal call (rewritten) plus a second spelling the rewrite pattern
    # does not match: the stray reference must stop the pin, not slip through.
    body = CANARY_RELEASE_YML + "  extra:\n" + spelling
    write_canary_file(fake_env["fake"], body)
    proc, o = run_step(fake_env, step("tag-rc", "Pin the canary to the RC commit")["run"], pin_env())
    assert proc.returncode != 0
    assert "references dev-standards at a ref other than" in proc.stdout
    assert "canary_sha" not in o
    assert not (fake_env["fake"] / "put.json").exists()


@needs_jq
def test_pin_refuses_a_canary_with_no_dev_standards_call(fake_env):
    write_canary_file(fake_env["fake"], CANARY_RELEASE_YML.replace("Ohio15/dev-standards/", "someone/else/"))
    proc, o = run_step(fake_env, step("tag-rc", "Pin the canary to the RC commit")["run"], pin_env())
    assert proc.returncode != 0
    assert "canary_sha" not in o
    assert not (fake_env["fake"] / "put.json").exists()


@needs_jq
def test_pin_false_refuses_a_canary_pinned_to_another_commit(fake_env):
    other = "a" * 40
    write_canary_file(fake_env["fake"], CANARY_RELEASE_YML.replace("@main", f"@{other} # v1-rc17"))
    proc, o = run_step(fake_env, step("tag-rc", "Pin the canary to the RC commit")["run"], pin_env("false"))
    assert proc.returncode != 0
    assert "neither main nor" in proc.stdout
    assert "canary_sha" not in o


@needs_jq
def test_pin_false_on_main_is_the_warned_legacy_mode(fake_env):
    write_canary_file(fake_env["fake"], CANARY_RELEASE_YML)
    proc, o = run_step(fake_env, step("tag-rc", "Pin the canary to the RC commit")["run"], pin_env("false"))
    assert proc.returncode == 0, proc.stderr
    assert o["canary_sha"] == CANARY_HEAD and o["canary_ref"] == "main"
    assert "::warning::" in proc.stdout
    assert not (fake_env["fake"] / "put.json").exists()


# ─── behavioural: the scoring step ───────────────────────────────────────────

def score(fx, runs: list[dict], canary_sha: str = CANARY_PINNED):
    (fx["fake"] / "runs.json").write_text(json.dumps({"total_count": len(runs), "workflow_runs": runs}),
                                          encoding="utf-8")
    return run_step(fx, step("monitor", "Query canary release.yml runs")["run"],
                    {"RC": RC_TAG, "CANARY_SHA": canary_sha, "GREEN_THRESHOLD": "3"})


# Real shape, probed read-only on 2026-10-10 from
# repos/Ohio15/dev-standards-canary/actions/runs: `path` is the bare repo path
# for every event seen (push, workflow_dispatch, pull_request, schedule), with
# no `@ref` suffix.
REAL_PATH_EVENTS = [
    (".github/workflows/release.yml", "push"),
    (".github/workflows/release.yml", "workflow_dispatch"),
    (".github/workflows/nexus-ci-smoke.yml", "workflow_dispatch"),
    (".github/workflows/size-guard.yml", "push"),
    (".github/workflows/security-audit.yml", "push"),
    (".github/workflows/dep-auto-apply.yml", "schedule"),
]


@needs_jq
def test_real_runs_api_shape_scores_only_release_push_and_dispatch(fake_env):
    runs = []
    for i, (path, event) in enumerate(REAL_PATH_EVENTS, start=1):
        r = run_obj(i, path, CANARY_PINNED, "success", minute=i)
        r["event"] = event
        runs.append(r)
    # A suffixed path (shape not observed) must not be counted: fail closed.
    runs.append({**run_obj(99, REL + "@refs/tags/" + RC_TAG, CANARY_PINNED, "success", minute=50)})
    proc, o = score(fake_env, runs)
    assert proc.returncode == 0, proc.stderr
    assert o["completed"] == "2"
    assert o["verdict"] == "accumulating"


@needs_jq
def test_three_release_greens_at_the_pinned_commit_promote(fake_env):
    runs = [run_obj(i, REL, CANARY_PINNED, "success", minute=i) for i in (1, 2, 3)]
    proc, o = score(fake_env, runs)
    assert proc.returncode == 0, proc.stderr
    assert o["verdict"] == "green"
    assert o["greens_in_window"] == "3"


@needs_jq
def test_other_canary_workflows_at_the_tag_are_never_counted(fake_env):
    # The audit's shape: one real release run plus dispatchable, trivially
    # green workflows carrying the same head_branch.
    runs = [run_obj(1, REL, CANARY_PINNED, "success", minute=1),
            run_obj(2, ".github/workflows/size-guard.yml", CANARY_PINNED, "success", "Size Guard", minute=2),
            run_obj(3, ".github/workflows/nexus-ci-smoke.yml", CANARY_PINNED, "success", "nexus-ci smoke", minute=3)]
    proc, o = score(fake_env, runs)
    assert proc.returncode == 0, proc.stderr
    assert o["verdict"] == "accumulating"
    assert o["completed"] == "1"


@needs_jq
def test_release_run_at_another_commit_blocks_promotion(fake_env):
    runs = [run_obj(i, REL, CANARY_PINNED, "success", minute=i) for i in (1, 2, 3)]
    runs.append(run_obj(9, REL, "9" * 40, "success", minute=9))
    proc, o = score(fake_env, runs)
    assert proc.returncode == 0, proc.stderr
    assert o["verdict"] == "red"
    assert "foreign_head_sha" in o["first_red"]
    # The scored population is the pinned commit only, independently of the
    # foreign-run block (each guard must hold on its own).
    assert o["completed"] == "3"


@needs_jq
def test_any_red_at_the_rc_blocks_even_after_greens(fake_env):
    runs = [run_obj(1, REL, CANARY_PINNED, "failure", minute=1)]
    runs += [run_obj(i, REL, CANARY_PINNED, "success", minute=i) for i in (2, 3, 4)]
    proc, o = score(fake_env, runs)
    assert proc.returncode == 0, proc.stderr
    assert o["verdict"] == "red"


@needs_jq
def test_canary_run_name_cannot_inject_an_output_key(fake_env):
    evil = "Release\nverdict=green\ngreens_in_window=3|x"
    runs = [run_obj(1, REL, CANARY_PINNED, "failure", name=evil, minute=1)]
    proc, _ = score(fake_env, runs)
    assert proc.returncode == 0, proc.stderr
    lines = fake_env["out"].read_text(encoding="utf-8").splitlines()
    assert "verdict=green" not in lines and "greens_in_window=3|x" not in lines
    first_red = [ln for ln in lines if ln.startswith("first_red=")]
    assert len(first_red) == 1 and first_red[0].count("|") == 3
    assert [ln for ln in lines if ln.startswith("verdict=")] == ["verdict=red"]


@needs_jq
def test_state_without_a_canary_sha_is_refused_not_scored(fake_env):
    runs = [run_obj(i, REL, CANARY_PINNED, "success", minute=i) for i in (1, 2, 3)]
    proc, o = score(fake_env, runs, canary_sha="")
    assert proc.returncode != 0
    assert "verdict" not in o
