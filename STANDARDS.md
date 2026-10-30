# Ron's Dev/Deployment Standards

**Scope:** Canonical reference for how code moves from author keystrokes to production-validated state across all Ron-owned repos. Covers memory conventions, repo hygiene, versioning, release gates, reusable-workflow promotion, build provenance, deploy contracts, observability, maintenance cadences, cleanup, incident protocols, and explicit open questions.

**Audience:** Ron, future supervisors of any AI session, and any human collaborator inheriting a Ron-owned project.

**Status:** v1 draft. Living document. Phase 1 is mid-stabilization — most enrolled repos show 5/5 recent failed workflow runs as v1 churn settles. GA gate: 30 consecutive canary-green days (see section 5). Quarterly retrospective per section 9. Companion doc `STANDARDS-IMPLEMENTATION.md` tracks the AS-IS → TO-BE work items.

---

## 1. Memory & State Conventions

The shared-brain at `https://shared-brain.us` is the system of record for cross-session continuity. Local `MEMORY.md` is bootstrap-only.

**The `[REMEMBER]:` marker contract.** One line, declarative, no narrative. The cortex-hooks `Stop` chain (`remember.js`, async) auto-ingests these. Mandatory triggers:

| Trigger | Importance | Example |
|---------|------------|---------|
| Bug fixed | 0.7 | `[REMEMBER]: APM v0.9.2 had two version.json files; /api/health read server/ while gate read root. Drift caused gate-pass + runtime-mismatch.` |
| Config change | 0.7 | `[REMEMBER]: ntfy topic standardized to nexus-alerts.` |
| Architectural decision | 0.8 | |
| Deploy / version bump | 0.6 | |
| Lesson from correction | 0.8 | |
| Infra change (IP, port, DNS, firewall) | 0.8 | |
| Ron preference / rule | 0.9 | |
| New tool / script / capability | 0.7 | |

**Storage class taxonomy:**

| Class | Where | Lifetime | Example |
|-------|-------|----------|---------|
| `user` | shared-brain `user` namespace | permanent | "Ron prefers dark mode" |
| `feedback` | brain + ideally `~/.claude/projects/.../memory/feedback_*.md` | permanent, versioned | rigor-format, correct-over-easy |
| `project` | brain with `project:<name>` tag | until project retired | APM port mappings |
| `reference` | brain + `reference_*.md` where applicable | until invalidated | CF tunnel IDs |
| `session-handoff` | brain with `session:<date>` tag | rolling 90 days | "this session shipped APM v0.9.2" |

**Disk vs brain reality (current gap):** the `feedback_*.md` set on disk is incomplete. Only six files exist locally (`build-deployment-rule`, `capability-gap-build`, `correct-over-easy`, `rigor-format`, `shared-brain-token-burn`, `version-control-everything`). MEMORY.md and CLAUDE.md reference many additional rules (`proactive-brain-rules` / T1.x, `root-cause-analysis-required`, `realtime-brain-sync`, `data_preservation`, `dont_over_extend`, `measure_before_building`, `fix_self_review`, `shared-brain-updates`, `credential-rotation-protocol`, `implementation-guardrails`) — these survive only in shared-brain. Tracked as IMPL-1 in the implementation ledger.

**What does NOT get stored:**
- Transient command output, build logs, test failures fixed in-session
- Anything containing live secrets (use the credential-rotation flow)
- Speculation ("I think X might be true")
- Restating things already in `CLAUDE.md` verbatim

**Recall cadences (T1.x discipline, brain-resident):**
- T1.1 Session start: `get_context` + `recall` for current project tag
- T1.2 Topic shift mid-session: `recall` before responding
- T1.3 Decision point ("should we X or Y"): `recall` for both options
- T1.4 Apparent contradiction with prior decision: `recall`, surface conflict
- T1.5 Error encountered: `correlate_error` before debugging
- T1.6 Sub-agent dispatch: supervisor recalls, hands findings to agent as context — agents do NOT recall independently unless their mission is research
- T1.7 Session end: supervisor synthesizes, writes `[REMEMBER]:` markers — never the agents

**Sub-agent vs supervisor save responsibility.** Sub-agents return findings to the supervisor. Only the supervisor writes `[REMEMBER]:` markers, after synthesis. This prevents three agents writing three contradictory memories about the same finding. One exception: a discovered-issue agent stores its own outcome (§14.2).

**Conflict resolution.** When `recall` returns contradictory memories: newest wins by default, but always surface the conflict to Ron explicitly. Never silently overwrite. Old memory gets a `superseded_by:<new_id>` tag, never deleted (per `feedback_data_preservation`).

**Memory rot detection.** Quarterly: recall top-50 highest-importance memories, validate against current reality (does the IP still resolve? does the path still exist?). Mark stale `stale:true` rather than deleting. Auto-stale candidate: any memory referencing a path that no longer exists on disk.

---

## 2. Repo Hygiene Floor

Every Ron-owned repo, before it can be release-piloted via dev-standards reusable workflows, must have:

| Artifact | Purpose | Source of truth |
|----------|---------|-----------------|
| `.gitleaks.toml` | Secret-scan config, repo-specific allowlist | dev-standards `templates/.gitleaks.toml` |
| `.githooks/pre-commit` | Local gitleaks + size-guard chain | dev-standards `hooks/` (copied by `install.sh`) |
| `.large-files-allowlist` | Whitelist for legitimate large binaries | per-repo (template is comment-only stub) |
| `version.json` (root) | Single source of truth (see section 3) | repo root only |
| `.github/workflows/security-audit.yml` | Layer A always-on dep gate (PR + push) | dev-standards `templates/.github/workflows/` |
| `.github/workflows/dep-auto-apply.yml` (opt-in) | Layer B weekly cron auto-apply | dev-standards `templates/.github/workflows/` |
| `.github/workflows/size-guard.yml` | 10 MB tracked-file ceiling | dev-standards `workflows/size-guard.yml` |
| `LICENSE` | Required even for private repos | per-repo |
| `CONTRIBUTING.md` | Conventional-commits expectation, branch policy | per-repo, derives from dev-standards |

**`.gitleaks.toml` shape:** extends dev-standards' base config (with anchors for Ron-specific patterns: `ron-mcp-api-key`, `ron-brain-pg-password`, etc.); per-repo `[allowlist]` block only for genuine false-positives (test fixtures, public sample keys), each entry commented with the why.

**Pre-commit installation:** clone dev-standards (`main`) and run `./install.sh /path/to/repo`. There is no curl one-liner: `install.sh` copies `hooks/`, `workflows/`, `templates/` and `security/` from its own checkout, so a piped script has nothing to copy (the former `.../v1/install.sh` one-liner never worked and was removed 2026-09-11). The `v1` tag is for the reusable release workflows (`release-gates.yml@v1`, moved by `promote-canary.yml`), not for onboarding. Idempotent. Currently installs: `.githooks/commit-msg` (conventional subject + attribution scrub, always overwritten) + `.githooks/pre-commit` (dispatcher) + `pre-commit-secret-scan.sh` (gitleaks staged-diff) + `pre-commit-size-guard.sh` (10 MB ceiling) + `pre-commit-healthcheck-lint.sh` + `pre-commit-tests.sh`. Sets `core.hooksPath=.githooks`. `pre-commit-tests.sh` runs only what the repo declares in `.pre-commit-tests` (parsed, never sourced): `TEST_CMD` (required), `TEST_TIMEOUT` (seconds, default 300; a timeout fails the commit), `TEST_PATHS` (`|`-separated globs gating when the suite runs) and `TEST_CLEANUP_CMD` (optional; runs after the suite on every outcome, including a timeout kill, bounded at 120 s, and a non-zero exit fails the commit). The hook also snapshots the tree before and after the suite: each tracked file's work-tree difference from the index, each staged difference from HEAD, and the list of untracked, non-ignored files. The commit fails, naming the paths, whatever the suite's verdict, if the run changed a tracked file (edited, deleted, restored, or edited and staged) or created a new untracked file. State already there before the hook ran (unstaged edits, staged changes, untracked files) does not trip it, nor does a pre-existing untracked file the suite rewrites or removes; ignored files are never examined, so caches a suite legitimately leaves behind belong in `.gitignore` (truck-mcp PR #12, discovery a7a155d8). Version-bump-reminder hook is a TO-BE addition (IMPL-2).

**Conventional commits:** `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`, `perf:`, `security:`, `build:`, `ci:`, with optional `(scope)` and breaking `!` per the Conventional Commits spec (`chore(deps):` from Dependabot is valid). Enforced locally by `hooks/commit-msg` (block). Enforcement plan for the server side: PR titles via GitHub branch ruleset; CI gate on protected branches (block).

**Commit attribution (decided 2026-10-04, reversing the 2026-09-11 dev-standards #5 allowance):** commits carry no attribution. The hook deletes every `Co-Authored-By:` trailer (any author), every `Claude-Session:` trailer and the `Generated with … Claude …` line from the message in place — it scrubs, it does not reject, so `--no-verify` is never needed. The source is switched off too: Claude Code `attribution` in `~/.claude/settings.json` is `{"commit": "", "pr": "", "sessionUrl": false}`, and the CI templates write no trailer (hooks do not run in CI). Remaining PR-description boilerplate (`Generated with …`, `Auditor:`) is still rejected. Between 2026-04-27 and 2026-09-11 the hook had no versioned source and the per-repo copies diverged (some rejecting the trailers, some allowing them); `hooks/commit-msg` is now the only source and `install.sh` overwrites the copy on every run.

**`repo-hygiene-scan.py` (weekly NEXUS cron, Sun 5am UTC):** scans every Ron-owned repo for:
1. Missing required files (table above)
2. Tracked binaries / large files / `.gitignore`-tracked files / `core.hooksPath` misconfig
3. Idle repos (>180 days since last release, candidate for archive review)
4. Workflow files referencing deprecated dev-standards versions
5. Phase 1C drift: `gh release list` + GHCR API + NEXUS `docker inspect` → writes `release/versions.yml`
6. ntfy alert to `nexus-alerts` when N≥2 releases behind
7. Output: JSON to `<output-dir>/hygiene-scan-<YYYY-MM-DD>.json`, optional `--brain-store` for shared-brain ingestion
8. Workspace layout floor (synthetic `[layout]`, `[worktrees]`, `[scratch]` entries): linked worktrees and clutter/probe folders under the Projects root or one level inside a namespace dir (HIGH), duplicate clones of one origin and loose root files (MEDIUM), non-git orphan folders (LOW); clean+merged or orphan entries under `D:/Worktrees` (MEDIUM); `D:/Scratch` entries older than 30 days (LOW)
9. Submodule pointer lag (cortex-core ADR 0012, ratified 2026-09-09): for every superproject with a `.gitmodules`, each recorded pointer is compared read-only (`git ls-remote`, never a fetch) to the child's `origin/<branch>` head. Lag across a version bump in the child — a `bump`/semver commit subject or a changed `"version"` field in `package.json`/`version.json` — is MEDIUM (`submodule-pointer-lag`); any other lag, a pointer the remote branch does not contain, or an unreadable remote (`submodule-pointer-unverified`) is LOW. Interim rule that the finding enforces: a session that merges into a submodule child (e.g. `cortex-core`, `cortex-hooks`) bumps the `Ohio15/cortex` superproject pointer in the same session.

Findings are advisory, not blocking — Ron triages weekly.

**Version control everything (no opt-out):** any directory containing infra config, deployment config, or source code is a git repo with a private GitHub remote. Including `~/infra/`, `~/AdGuardHome/config/`, `D:/Projects/*`. Bootstrap: `dev-standards/scripts/init-repo.sh <path>` (TO-BE — IMPL-3).

**Hooks single-source-of-truth:** dev-standards itself currently has `hooks/` and `.githooks/` as byte-identical duplicates. `install.sh` reads from `hooks/`; dev-standards' own pre-commit chain runs from `.githooks/`. This is a drift hazard. Tracked as IMPL-4: collapse to one path with a build step or symlink.

**Workspace layout floor (machine-level, ratified 2026-09-09):** three roots, each with exactly one job. `D:/Projects` holds durable repos only — not a scratchpad. Enforced at action time by the `workspace-guard` Claude Code PreToolUse hook (cortex-hooks, rules WG1–WG4 below) and audited weekly by `repo-hygiene-scan.py` (finding 8 above). Rules:
- **One repo per folder.** Group same-namespace repos under a parent folder (`D:/Projects/<namespace>/<repo>`, e.g. `brain/Shared-Brain`, `aibrowser/AIWebBrowser`); never nest one repo working tree inside another (group, do not nest). A namespace dir contains repos and nothing else — no worktrees, no probes, no copies.
- **Worktrees live in `D:/Worktrees/<repo>/<branch-with-slashes-as-dashes>`**, never under `D:/Projects` at any depth (the 2026-08-04 `truck-mcp/worktrees/` convention is retired). Create with `git worktree add D:/Worktrees/<repo>/<branch> <branch>`; a finished worktree (clean, branch merged) is removed the same session with `git worktree remove` then `git worktree prune`. Worktrees a Claude session creates in its scratchpad are fine (they die with the session) but must be pruned from the repo afterwards. A repo whose `package.json` links a sibling by relative path (`"file:../cortex-core"`) gets ONE symlink beside its worktrees (`D:/Worktrees/cortex-hooks/cortex-core -> D:/Projects/cortex/cortex-core`) so every worktree resolves it; the symlink is the only non-worktree entry allowed there.
- **One-off scripts, probe copies, review mirrors and artifacts go in `D:/Scratch/<yyyy-mm-dd>-<topic>`**, never the Projects root or a namespace dir. Retention 30 days; the weekly scan lists expired entries and Ron purges them (recursive deletes are circuit-breaker blocked for agents — an agent quarantines to Scratch, it never `rm -rf`s).
- **No folder-copy clones** (`-c2`, `-copy`, `rb-mirror-*`, `probe-*`, ...) and no second full clone of an origin already under `D:/Projects`; a parallel checkout is a worktree.
- **Only non-repo root entries allowed:** `.archive`, `.staging-licenses`, `data`. Retired repos move to `.archive/<name>-<date>`. Every other folder at the root or inside a namespace is a git repo with a private `Ohio15` remote (loose docs get a repo of their own — cf. `aibrowser/chrome-ui-review`, 2026-09-09).
- **Repos launched by absolute path** (MCP servers, hooks, scheduled tasks) are referenced in `~/.claude.json`, `~/.mcp.json`, `~/.claude/settings.json` and Task Scheduler; update those (with a `*.bak` first) whenever such a repo moves, and re-verify the service starts.
- **Handoffs and brain memories cite paths.** When a worktree moves, store the old→new path map in shared-brain in the same session so a successor recalling a brief finds the tree (2026-09-09 map: brain `see tag layout-2026-09-09`).

`workspace-guard` rules (PreToolUse on Bash, PowerShell and the file tools; blocks, journals `workspace_guard_blocked` to hook-health): **WG1** `git worktree add` targeting any path under `D:/Projects`; **WG2** recursive copy (`cp -r`, `Copy-Item -Recurse`, `robocopy`, `xcopy`) whose destination is a new folder at the root or inside a namespace dir; **WG3** `mkdir`/`New-Item -ItemType Directory` creating a direct child of the root unless the same command also `git init`s or `git clone`s; **WG4** a file tool or shell redirection writing a loose file at the root. Config: `cortex-hooks/hooks/workspace-layout.json` (roots). Read-only commands never trip it.

---

## 3. Source-of-Truth & Versioning

**Motivating scar:** APM v0.9.2 shipped with `version.json` at root reading 0.9.2 (gate passed) and `server/version.json` reading 0.9.1 (runtime). `/api/health` reported 0.9.1. Gate-green + runtime-wrong is the worst possible outcome — it's invisible.

**Rule:** exactly one `version.json` per repo, at the root.

```json
{ "version": "0.9.2", "commit": "<sha>", "built_at": "<iso8601>" }
```

**All consumers of version derive from root `version.json`:**

| Consumer | Mechanism |
|----------|-----------|
| Release gate (`tag-matches-version`) | reads root file directly |
| Docker image tag | `IMAGE_TAG=$(jq -r .version version.json)` in workflow |
| Runtime `/health` endpoint | build-time injection or read at startup |
| Displayed UI version | imported from same file at build |

**Three mechanism options for runtime injection:**

| Option | Pros | Cons | When |
|--------|------|------|------|
| **A. Symlink** | Simplest. `server/version.json -> ../version.json` | Windows symlinks fragile; Docker COPY may not follow | POSIX-only repos |
| **B. Build-arg injection** | Works everywhere; baked into image at build | Requires Dockerfile discipline; rebuild needed for version-only change | Recommended default |
| **C. Generated file via pre-commit hook** | Edits propagate at commit time, no build coupling | Drift possible if hook skipped (`--no-verify`); CI must re-validate | When build pipeline can't easily inject |

**Decision rule:** prefer B (build-arg). When the language ecosystem makes it painful (Go embed expects a real file), use A on POSIX-only or C with a CI guard that fails if any non-root `version.json` exists with a value different from root.

**The forcing function:** add a release gate (section 4) — `version-uniqueness` — that fails if `find . -name version.json -not -path './node_modules/*'` returns >1 file with divergent content. This makes the APM bug structurally impossible. Tracked as IMPL-5.

**Semver bump cadence:**

| Bump | Trigger |
|------|---------|
| MAJOR | Breaking API change, breaking config change, mandatory migration |
| MINOR | Backwards-compatible feature, new gate added, new workflow input |
| PATCH | Bug fix, dep bump, docs-only |

Every code change bumps something. Per CLAUDE.md non-negotiable rule #1: no commit without version bump. Currently advisory; enforcement via pre-commit (warn) + CI gate is TO-BE (IMPL-6).

---

## 4. Release Gates (and their blind-spots)

dev-standards exposes gates in two layers:

**Layer A — `security-audit.yml` (always-on):** runs on `pull_request` and `push: [main, master]`. Detect-and-dispatch by ecosystem (npm / go / python). Fails on high/critical. Pinned to action SHAs.

**Layer B — `dep-auto-apply.yml` (weekly cron, opt-in):** Sunday 06:00 UTC via repo-side `schedule:` trigger. Per-repo opt-in via `.github/auto-apply-enabled` file. Auto-applies safe (patch / minor for non-breaking) bumps across npm / go / python / docker / gh-actions. Notifies ntfy + shared-brain. Two jobs: `apply` (read-only token, no secrets) runs every install, fix and test, and hands over a patch of allow-listed manifests/lockfiles as an artifact; `publish` (write token, no secrets) runs no dependency code, validates the patch fail-closed and commits only those files; `notify` (the two notification secrets, `run:` steps only, no third-party action) posts ntfy and shared-brain. Untrusted code and credentials never share a job. `publish` and `notify` declare environment `auto-apply-publish`; consumers create it with a default-branch-only deployment policy and keep `DEP_AUTO_APPLY_NTFY_TOKEN` / `SHARED_BRAIN_TOKEN` there as environment secrets. On a private repo without that policy (GitHub Free) the two secrets are not set at all; `notify` refuses them and fails if they are, unless `DEP_AUTO_APPLY_ENV_PROTECTED=true` attests the policy. The ntfy host is the literal `ntfy.nexus`, and the runner variable toggles only between the literals `nexus-ci` (private repos) and `ubuntu-latest`.

**CI runner policy (decided from the OpenSSF Scorecard / GitHub Actions hardening guidance, ratified 2026-10-11):**

- A `pull_request` job never sees a secret. A fork pull request runs only on GitHub-hosted runners, never on a self-hosted or `nexus-ci` runner; a same-repo pull request in a private repository served by ci-registrar >= 0.4.1 may run on `nexus-ci` (amended 2026-10-27 by Ron, decision `68d983a4`, register SC-37 amendment `288e5d95`), where `TRUSTED_EVENT` stays false so no PR-controlled code runs. Fork pull requests use `pull_request`, never `pull_request_target`; first-time contributors need approval before any workflow runs (repository setting "Require approval for all outside collaborators").
- Variables may select a runner only through the canonical SC-37 predicate, verbatim: `(github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || github.event_name == 'release' || github.event_name == 'merge_group' || github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository) && vars.CI_RUNNER || 'ubuntu-latest'`. The fleet templates (`workflows/size-guard.yml`, `templates/.github/workflows/security-audit.yml`) carry its guarded form (audit-dev-standards-2026-10-27; register SC-37 amendment PROPOSED on dev-standards #62, pending Ron's approval): the same allow-list, then `&& github.event.repository.private && vars.CI_RUNNER == 'nexus-ci' && 'nexus-ci' || 'ubuntu-latest'`, so the variable only toggles between the literals `nexus-ci` and `ubuntu-latest` (it never names another label) and a public repo always resolves to the hosted literal; `templates/.github/workflows/dep-auto-apply.yml` (schedule and `workflow_dispatch` only) carries the same private-only literal toggle without the event allow-list. The `nexus-ci` registrar refuses public repositories, so a template that reaches a public repo carries the hosted literal: `install.sh` settles the target's visibility before it writes anything. GitHub's answer wins, and a `--private`/`--public` that contradicts it is an error, never an override; without GitHub's answer the flag decides; with neither, the target is unconfirmed and treated as public. A public or unconfirmed repo's copy gets `runs-on: ubuntu-latest` in all three workflows, which is also what dev-standards (public) carries in its own `size-guard.yml` and `security-audit.yml` under `.github/workflows/`. Re-run the installer after a visibility change.
- New-repo onboarding to `nexus-ci`: for a private repo `install.sh` sets the repo variable `CI_RUNNER=nexus-ci` when unset and reports whether the repo is mapped in the tracked registrar config (Ohio15/infra `ci-vm/registrar/config.json`). Mapping it there (PR, gate, merge), applying it on NEXUS (`ci-vm/README.md`, apply-config) and adding the repo to the registrar's GitHub App installation stay explicit steps the installer prints; until all three are done the repo's PR jobs ask for `ubuntu-latest`.
- Production promotion keeps a required reviewer on its environment (separation of duties, NIST SSDF PO.3). With a single maintainer the reviewer is that maintainer plus the immutable deployment log; the control is batched, never dropped.
- Release signing material is scoped to the signing job alone: an environment secret on a job that runs no build or dependency code, on an ephemeral runner (SLSA Build L3 isolation, NIST SSDF PS.1). A build job never holds a signing key.

**Warn-mode ships (ratified 2026-10-29 by Ron after audit-infra-2026-10-29; register SC-47):** a warn, observe or report mode is a migration step, never a destination. The 2026-10-29 audit found one live twelve days after it shipped, because nothing forced the flip: the receiver's strict side was opt-in and its sender was never wired. A change that ships a warn mode therefore carries, in the same pull request:

- **The strict default in code.** An absent or empty mode variable selects enforce. The environment may only escalate; a value the code does not know refuses to start.
- **The counterpart wired.** Whatever makes enforce safe to turn on (the sender that carries the credential, the client that sends the header, the data that satisfies the new check) lands in the same PR or is already deployed. A warn mode whose counterpart does not exist yet is not shippable.
- **A dated flip commitment.** A work-queue item tagged `flip-<VARIABLE>` with a `due_at`, naming the evidence that ends the migration (for example "zero unauthenticated accepts across one repeat_interval"). Past its `due_at`, the warn state is a failing health check (an alert, not a log line), so the flip cannot be forgotten quietly.
- **Removal at the flip.** Once enforce is live, the lenient mode is removed unless a documented need keeps it. A mode the environment can still select is a mode that can come back.

TO-BE: the per-session security gate reports a change that introduces a permissive `*_MODE` default without an open `flip-<var>` commitment (cortex-hooks `security-gate`, warn tier first). Until it ships, SC-47's grep is the gate's check.

**Release-time gates (`release-gates.yml`, called by every surface workflow):**

| Gate | Catches | Correctly passes | **Blind spot** |
|------|---------|------------------|----------------|
| `tests` | Unit/integration test regressions | All tests green | Test coverage of changed code is not measured; uncovered code passes silently |
| `gitleaks` | Secret patterns in tracked files | Clean tree | Secrets baked into already-built Docker images; binary blobs; allowlist abuse |
| `size-guard` | Files >10 MB committed accidentally | All files under threshold | Git LFS objects; many medium files inflating clone size |
| `npm_audit` | npm-side high/critical vulns | Clean lockfile at root | **Go modules; Python; cargo; multiple package-locks in workspaces; pnpm/yarn lockfile shapes** |
| `tag-matches-version` | Tag/version drift | Tag equals root `version.json` | Multiple `version.json` files (the APM bug); built artifact embedded version |
| `conventional_commits` (default off) | PR title / commit-message lint | Commits follow format | Disabled by default; enforce path varies by repo |

**The "16 high Dependabot alerts" pattern** (current scar): the `npm_audit` gate counted only npm-side highs and missed every Go-side critical. APM had unscanned Go vulnerabilities the gate had no visibility into. Result: gate-green, repo-vulnerable.

**Required gate additions:**

| New gate | Purpose | Tool | Tracker |
|----------|---------|------|---------|
| `govulncheck` | Go module CVEs | `golang.org/x/vuln/cmd/govulncheck` | IMPL-7 |
| `pip-audit` | Python deps | `pypa/pip-audit` (when Python present) | IMPL-7 |
| `cargo-audit` | Rust deps | `rustsec/cargo-audit` (when Cargo.toml present) | IMPL-7 |
| `dependency-review-action` | PR-level diff of deps | GitHub-native, free | IMPL-7 |
| `version-uniqueness` | One version.json (section 3) | shell one-liner | IMPL-5 |
| `secrets-in-binary` | Strings-scan built Docker images | gitleaks against extracted layers | IMPL-8 |
| `healthcheck-shape-lint` | Healthcheck must be single-shot, no nested retries | yaml-lint custom rule | IMPL-9 |

**Workspace / monorepo lockfile handling (TO-BE — IMPL-10):** `npm_audit` (and equivalents) must walk the repo, find every lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `go.sum`, `requirements.txt`, `Pipfile.lock`, `Cargo.lock`, `poetry.lock`), run the matching auditor for each, report aggregated. Single threshold (high+critical) blocks merge. Currently `npm-audit-weekly.sh` and `release-gates.yml`'s `npm_audit` step both run at repo root only.

**SLA for gate runtime:** total gate suite under 10 minutes for a typical repo. Any single gate >5 minutes gets profiled and either parallelized or moved to a nightly cron with weekly aggregate. Tests are exempt from the 10-min ceiling but must surface progress logs.

**Open question (acknowledged blind spot):** even with all the above, a vulnerability in a transitive system library inside the base Docker image is invisible to language-level auditors. Mitigation candidate: Trivy or Grype scan of the built image. Not yet decided — see section 12.

---

## 5. Reusable Workflow Promotion (the canary)

**Motivating scar:** at v1, dev-standards had 28 commits forced onto the same `v1` ref over 2 days (Apr 30 + May 1, 2026). Each fix to dev-standards required retagging `v1`, which immediately propagated to every consumer; each consumer broke differently because no single repo exercised all input combinations. Specific bugs that escaped:

- `${{vars.X}}` f-string heredoc patterns triggered the GitHub workflow validator (0s startup_failure)
- `git fetch --tags` without `--force` aborted on local tag divergence
- Healthcheck nested 12×5s curl loop inside the workflow's outer 90s loop ate the budget
- `set -e` + `curl -fsS` in a "best effort" notify job poisoned deploy success
- Healthcheck path mismatch (`/health` vs actual `/api/health`)

**Proposed promotion flow (IMPL-11):**

```
dev-standards push to main
  -> tag v1-rcN (release-candidate, NOT v1)
  -> dev-standards-canary CI consumes @v1-rcN automatically
  -> if canary green for 3 consecutive runs across all matrix variants
  -> auto-fast-forward v1 to v1-rcN
  -> ntfy notice to nexus-alerts
```

**`dev-standards-canary` repo shape:**
- Smallest possible Docker repo (one nginx serving a static index.html)
- Smallest electron repo (boilerplate window)
- Smallest lib repo (single function, single test)
- Smallest MCP repo (one tool, returns "ok")

Each exercises every documented input of the matching reusable workflow as a CI matrix variant:

| Variant | Exercises |
|---------|-----------|
| `build_args_vars_only` | `${{vars.X}}` substitution path |
| `build_args_secrets_only` | `${{secrets.X}}` substitution path |
| `build_args_mixed` | Both, in same heredoc |
| `multi_image` | Two images per release |
| `missing_secret` | Expected to FAIL with a specific error string |
| `healthcheck_404_path` | Expected to FAIL with healthcheck error |
| `healthcheck_version_mismatch` | Expected to FAIL with version-match error |
| `tag_divergence` | Local tag exists but differs from remote — workflow must `--force` |
| `notify_unreachable` | ntfy down — deploy must still succeed |
| `mcp_pin_path_update` | mcp-release post-deploy `mcp.client_pin_paths` JSON edit |

**Canary failure modes & SLA:** any canary red blocks v1 promotion. Ron is notified by the promote-canary monitor run failing (GitHub's failed-run notification); there is no ntfy post, because the NEXUS ntfy is not reachable from hosted runners and a public ntfy.sh topic is not an acceptable sink (`release/canary-promotion.md`). Human review SLA: 24 hours to triage (fix forward, revert RC, or document as expected-fail). RCs older than 7 days without promotion auto-expire and get re-cut from latest main.

**Open question:** canary-as-subdir of dev-standards vs separate repo. Subdir wins on atomic commits + no cross-repo PR coordination. Separate repo wins on clean separation of "the standards" from "the test of the standards" + ability to open canary publicly without leaking nothing-yet-public dev-standards. Deferred — see section 12.

---

## 6. Build & Image Provenance

**The five surfaces:**

| Surface | Reusable workflow | What it builds |
|---------|------------------|----------------|
| `release-gates` | `release-gates.yml` | Composite gates, called by every surface |
| `electron-release` | `electron-release.yml` | Desktop NSIS installers + GitHub Release |
| `docker-release` | `docker-release.yml` | GHCR image push + NEXUS deploy |
| `mcp-release` | `mcp-release.yml` | docker-release + post-deploy `mcp.client_pin_paths` JSON updates |
| `lib-release` | `lib-release.yml` | GitHub Release notes + optional `npm publish` |

**OCI labels (mandatory on every image built by docker-release / mcp-release — TO-BE, IMPL-12):**

```
org.opencontainers.image.source       = https://github.com/Ohio15/<repo>
org.opencontainers.image.revision     = <git sha>
org.opencontainers.image.version      = <version.json value>
org.opencontainers.image.created      = <iso8601>
org.opencontainers.image.title        = <repo name>
org.opencontainers.image.description  = <one-line from package.json/README>
org.opencontainers.image.licenses     = <SPDX>
```

Set via `--label` flags in the reusable workflow, not in Dockerfile (so they reflect the build context, not source-of-truth drift).

**GHCR auth:** workflow uses default `GITHUB_TOKEN` with `packages: write` permission. No PAT. Tokens are workflow-scoped; cleanup is automatic.

**Layer caching strategy:**
- BuildKit cache mount for package managers (`--mount=type=cache,target=/root/.npm`, etc.)
- `cache-from: type=gha` and `cache-to: type=gha,mode=max` in the workflow
- Cache scope per-repo per-branch — main and PR caches isolated

**Build-arg vs runtime-env vs BuildKit secret:**

| Mechanism | Use when | Pitfall |
|-----------|----------|---------|
| `--build-arg` (vars) | Non-secret values needed at build (version, public URLs) | Visible in image history; never use for secrets |
| Runtime env | Secrets and config that vary per env | Visible in `docker inspect`; rotate carefully |
| BuildKit secret (`--mount=type=secret`) | Secrets needed at build time only (npm token for private registry, signing key) | Not in image history; not in final image; requires BuildKit |

**The existing `build_args` mechanism** in `docker-release.yml` (accepts `${{vars.X}}` and `${{secrets.X}}` interpolation): keep both code paths, but lint the input. The f-string heredoc pattern is forbidden in error messages — use string concatenation to build placeholder examples (the Apr 30 fix). Canary variant `build_args_mixed` enforces this at promotion time.

**Reproducibility:** same git sha + same base-image digest must produce byte-identical images. Achievable when: (a) no `apt update && apt upgrade` in Dockerfile, (b) base images pinned by digest not tag (`FROM nginx@sha256:...`), (c) build timestamp set via `SOURCE_DATE_EPOCH`. Aspirational — not all repos meet this today; track as quarterly migration target.

**GHCR retention:**
- Tagged releases (semver): retained indefinitely
- `latest`: always points at most recent successful release
- Branch-build images (PR previews): 30 days
- Untagged manifests: 7 days (auto-prune via scheduled workflow — IMPL-13)

---

## 7. Deploy Contracts

**Compose file shape (minimum):**

```yaml
services:
  app:
    image: ghcr.io/ohio15/<repo>:${IMAGE_TAG:-latest}
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:<port>/api/health"]
      interval: 10s
      timeout: 3s
      retries: 5
      start_period: 30s
```

**Healthcheck command rules (motivated by the nested-loop bug + the path-mismatch bug):**
1. Single request, no shell loop — let Docker's `retries` + `interval` (and the workflow's outer wait) handle retry
2. Must hit the actually-served path (`/api/health`, not `/`)
3. Must return JSON containing the version, and the workflow's post-deploy probe asserts that version equals the root `version.json` value (this catches version-mismatch deploys — section 8)
4. `timeout` ≤ `interval` always
5. Workflow's outer wait loop runs at most 90 s with a single `docker inspect` per iteration; never invokes `curl` itself

**`nexus_path` is a git working tree on `main`:** the deploy step does `git fetch --tags --force && git reset --hard origin/main && git pull --ff-only`, then `docker compose pull && docker compose up -d`. Never `git pull` without fetch+reset (avoids merge-conflict on dirty trees). Never `git fetch --tags` without `--force` (the divergence bug — fix landed in `c5c50d1`).

**Runner labels:**
- `nexus-deploy` — shared label, every NEXUS runner has it
- `<repo-lower>` — affinity label (e.g. `apm`, `toolvault`), ensures the right runner picks up
- Matrix: `runs-on: [self-hosted, nexus-deploy, <repo-lower>]`

One self-hosted runner per consumer repo. Each registered via `scripts/register-nexus-runner.sh` (idempotent with `--replace`). Currently 4 active: `nexus-apm`, `nexus-sentinel`, `nexus-toolvault`, `nexus-n3xus-notify`.

**Atomic swap:**
1. `docker compose pull` (fetches new image, doesn't replace)
2. `docker compose up -d` (stops old, starts new — Compose handles atomically per-service)
3. Wait for healthcheck (90 s budget)
4. If healthy: success, post `[REMEMBER]:` notice
5. If unhealthy: snapshot rollback (see below)

**Snapshot-then-rollback:** before `pull`, capture current digest: `PREV_DIGEST=$(docker inspect --format='{{.Image}}' <container>)`. On healthcheck failure, `docker tag $PREV_DIGEST <image>:rollback && docker compose up -d` with rollback tag.

**The "previous tag was `latest`" edge case:** if the previous deploy was via `latest` and `latest` has since been overwritten, `PREV_DIGEST` may already be gone from local cache. Rollback is then non-meaningful — must escalate to manual intervention (ntfy `urgent`, Ron pulls a known-good prior semver tag manually). Mitigation: deploys always pin to semver tag, never `latest`. `latest` is for humans browsing GHCR, not for deploys.

---

## 8. Notification & Observability

**ntfy is best-effort side-channel only.** Motivating scar: `curl -fsS` + `set -e` inside a notify step caused ntfy outage to fail the deploy job, even though the deploy itself succeeded. APM v0.9.2 hit this exact path. Fix landed in dev-standards `b443f89` (May 1, 2026). Rule:

```bash
# inside any notify step — wrap publish in if/else
if curl -fsS ... ; then
  echo "ntfy: $TITLE"
else
  echo "::warning::ntfy publish failed (exit $?). Deploy result is unaffected."
fi
```

`continue-on-error: true` at the job level is also acceptable. Either way: alert delivery is never in the critical path of the deploy success signal.

**Topic conventions** (live; see `notifications/ntfy-publish.md`):

| Topic | Purpose | Priority default |
|-------|---------|------------------|
| `nexus-alerts` | All deploy outcomes, hygiene-scan summaries, dependabot critical | `default` |
| `nexus-urgent` | Production-down, security incidents, canary red blocking v1 | `urgent` (TO-BE — IMPL-14) |
| `nexus-info` | Successful weekly cron summaries, version bumps | `low` (TO-BE — IMPL-14) |

Currently only `nexus-alerts` is in active use. ntfy host: `http://192.168.1.20:2586` (LAN) or via Tailscale. `NTFY_ENABLE_LOGIN=false`, default access read-write.

**Workflow log severity:**
- `::notice::` for normal milestones (image pushed, deploy started)
- `::warning::` for non-blocking issues (lint warnings, slow gate, ntfy unreachable)
- `::error::` for blocking failures only

**Post-deploy verification probes (TO-BE — IMPL-15):** after healthcheck-pass, the workflow runs an explicit assertion:

```bash
HEALTH=$(curl -fsS https://<host>/api/health)
RUNTIME_VERSION=$(echo "$HEALTH" | jq -r .version)
EXPECTED=$(jq -r .version version.json)
[[ "$RUNTIME_VERSION" == "$EXPECTED" ]] || exit 1
```

This is the single check that would have caught the APM dual-version.json bug at deploy time. Pairs with the `version-uniqueness` gate (IMPL-5) — gate prevents the static state, probe catches runtime drift.

**Dependabot critical alerts** are routed independently of the release pipeline. A nightly cron polls GitHub API for unresolved critical alerts across all Ron-owned repos and publishes an aggregate to `nexus-alerts` (TO-BE — IMPL-16). Decoupled from deploys so a critical alert doesn't block an unrelated deploy.

**What gets logged where:**

| Signal | Destination | Retention |
|--------|-------------|-----------|
| Workflow logs | GitHub Actions | 90 d (default) |
| Container stdout/stderr | Loki via security-promtail | 30 d |
| Deploy outcomes | `[REMEMBER]:` markers + brain | permanent |
| Hygiene-scan reports | `dev-standards/scans/` on NEXUS | permanent |
| Healthcheck failures | Loki + ntfy `nexus-urgent` | 30 d |

---

## 9. Maintenance Cadences

| Cadence | Task | Autonomous? | Output |
|---------|------|-------------|--------|
| Weekly Sun 05:00 UTC | `repo-hygiene-scan.py --root /home/ohio_ --brain-store` (NEXUS cron, live) | Yes | JSON report + ntfy summary + brain ingest |
| Weekly Sun 06:00 UTC | `npm-audit-weekly.sh --root /home/ohio_ --brain-store` (NEXUS cron, live) | Yes | Aggregate findings to `nexus-alerts` + brain |
| Weekly Sun 06:00 UTC | `dep-auto-apply.yml` (per-repo opt-in via `.github/auto-apply-enabled`) | Yes | Auto-PRs for safe patch / minor bumps |
| Weekly | Untagged GHCR manifest prune (TO-BE — IMPL-13) | Yes | Counts logged |
| Weekly | NEXUS Docker build-cache prune (`docker buildx prune -f --filter unused-for=168h`) — currently 45 GB / 100% reclaimable, never pruned (TO-BE — IMPL-17) | Yes | Reclamation log |
| Weekly | Version-drift scan (already part of `repo-hygiene-scan.py --check-drift`, writes `release/versions.yml`) | Yes | versions.yml + ntfy when N≥2 behind |
| Monthly (1st) | Dependency major-version bump review (manual triage from autonomous reports) | Manual | PRs proposed for Ron review |
| Monthly (1st) | Hygiene-script self-audit (do scripts still work? are exit codes meaningful?) | Yes (smoke test) | Pass/fail to brain |
| Quarterly | dev-standards retrospective: review session-handoff `[REMEMBER]:` markers, identify recurring bug classes, file canary variant for each | Manual (Ron + supervisor) | New canary variants, doc updates |
| Quarterly | Memory rot scan (section 1) | Yes (autonomous), human review of stale flags | Stale-flagged memories |
| Annual | License/copyright sweep (LICENSE present, headers consistent) | Yes (scan), manual remediation | Compliance report |

**Other live NEXUS cron** (not standards-related but worth noting for context): `0 2 * * 0` sentinel-e2e-weekly, `30 4 * * 0` shared-brain dedup audit, `0 3 * * *` daily DB backups + shared-brain backup, `30 4 * * *` suricata-update.

**Windows Task Scheduler:** `npm-audit-weekly.cmd` shim is staged but **not registered** as a scheduled task locally. Hygiene runs only from NEXUS cron. If desktop-side coverage is needed, IMPL-18.

**Autonomous vs human-review line:** anything advisory (reports, suggestions, flagged anomalies) runs autonomously and notifies. Anything mutating (PR merge, image delete, repo archive) requires human approval. The "Ron asks for status" pattern: `recall project:<name>` returns the most recent autonomous-cron output, supervisor presents.

---

## 10. Cleanup & Decommission

| Asset | Delete trigger | Archive trigger |
|-------|---------------|-----------------|
| Repo | Never deleted (per `feedback_data_preservation`) | No commits in 180 d + no release in 365 d → archive on GitHub |
| Failed-pilot tags | Retained 90 d, then pruned by cron | N/A |
| Stale GHCR images (untagged) | 7 d (cron prunes — IMPL-13) | N/A |
| Old GHCR semver tags | Retained indefinitely | Move to `archive/<repo>:<version>` namespace at 2 y |
| Untracked files on NEXUS deploy paths | `git clean -fdn` weekly (dry-run alert), `-fd` only on Ron's confirmation | N/A |
| Container resources | `docker system prune -f --filter until=168h` weekly | N/A — volumes never auto-pruned |
| Build cache | `docker buildx prune -f --filter unused-for=168h` weekly (IMPL-17) | N/A |
| Deprecated workflow versions | Delete `v0` 30 d after `v1` is stable + canary green for 30 consecutive runs | N/A |
| cortex-hooks scripts that no longer fire | Detect via instrumentation: each hook logs invocation; >60 d no invocations → flagged for removal | N/A |

**Volumes never auto-pruned.** Database volumes, persistent data — destruction requires explicit Ron confirmation per the credential-rotation-style protocol.

**Repo archival, not deletion.** GitHub archive is reversible; deletion is not.

**Failed-pilot tags:** if a release-pilot tag never made it to `latest` (deploy failed, rolled back), keep 90 d for forensics, then prune. The retention exists specifically so a recurring bug class can be traced back to its origin commit.

---

## 11. Incident & Rotation Protocols

**Credential rotation:** follow the 8-phase SOP at `dev-standards/credential-rotation/PROTOCOL.md`. No deviation. Watch-window cadence (see the Apr 27 entry in MEMORY.md as recent example).

**Phase 8 consumer-class checklist:** every rotation rollout must touch (a) every file-based `.env` / config consumer, (b) the 1Password vault item for the credential, (c) every MCP-client config (`headers.Authorization` value), and (d) every cron/systemd unit that reads the credential. Verify post-rotation by running `python dev-standards/scripts/sb.py status` on each consumer host and confirming the redacted prefix matches the new generation. Header scheme drift (e.g., legacy `X-API-Key:` on `/api/*` vs current `Authorization: Bearer` on `/mcp`) survives token-only updates and fails silently — `sb.py health` is the canonical post-rotation auth check because `/health` is unauthenticated and cannot detect it.

**Bug-class detection — when does a bug deserve a canary variant?**

A bug is "recurring" and warrants a permanent canary case when ANY of:

1. The same root cause has appeared in ≥2 different consumer repos
2. The bug-fix in dev-standards required a `v1` retag
3. The bug was invisible to existing gates (gate-green + runtime-broken)
4. The bug was in workflow plumbing itself, not consumer code (heredoc validator, fetch-tags divergence)
5. The fix involved adding/changing a workflow input (proves the input matters and needs coverage)

If any condition met → file a canary matrix variant in the same PR as the fix. No fix merges to dev-standards `main` without canary coverage if the trigger fired.

**Force-push authorization:** force-pushes (any branch) require explicit `CONFIRM: force-push of <ref> is authorized` from Ron in-session. Circuit-breaker enforced by cortex-hooks PreToolUse (`D:/Projects/cortex-hooks/dist/circuit-breaker.js`). No exceptions, including dev-standards itself.

**Circuit-breaker bypass:** the `bypassPermissions` mode auto-approves everything except the dangerous-ops list (CLAUDE.md). To temporarily bypass for a known-safe operation: Ron states `CONFIRM: <action> is authorized` for that single invocation. Bypass is per-action, never per-session.

**Decision-autonomy framework:**

| Tier | When supervisor uses | Example |
|------|---------------------|---------|
| **Decide-and-execute** | Reversible, low-blast-radius, well within established patterns | Bumping a patch version, fixing a typo, applying an established lint rule |
| **State-and-proceed** | Reversible, medium-blast-radius, novel but defensible | Adding a new gate to dev-standards, choosing between B and C in section 3, retagging a v1-rcN |
| **Pause-and-confirm** | Irreversible, high-blast-radius, or contradicts prior decision | Force push, repo delete, volume delete, dropping gen-2 of a credential, changing branch protection |

When in doubt → escalate one tier. Sub-agents always operate at tier 1 only; tiers 2 and 3 are supervisor-only.

---

## 12. Open Questions / Explicit Non-Decisions

These do NOT have a settled answer. Listed here so they don't get accidentally decided by drift.

1. **Auto-merge for Dependabot.** Deferred to a 4-week measure phase (per prior decision). Question: is the canary green-rate high enough that auto-merging patch bumps from Dependabot is safe? Need empirical data — manual-merge baseline first.

2. **Renovate vs Dependabot.** Renovate has richer grouping and Go support; Dependabot is GitHub-native and zero-cost. Not yet evaluated. Trigger: when section-4 blind-spot for non-npm ecosystems forces a richer tool.

3. **Branch protection policy.** Currently inconsistent across Ron-owned repos. Candidate: require PR for `main`, require all release gates green, require linear history, allow Ron to bypass (admin). Not standardized yet — pilot on dev-standards itself first, then propagate.

4. **Multi-repo vs monorepo.** Several Ron projects share substantial common scaffolding (cortex-hooks ↔ cortex-core, dev-standards templates). Question: do they belong in a single monorepo with workspace tooling, or stay multi-repo? Open. Cost: workspace tooling complexity. Benefit: atomic cross-cutting changes.

5. **Canary location: dev-standards subdir vs separate repo.** Section 5 lists trade-offs. Deferred until first canary implementation begins — implementer chooses based on which trade-off bites first.

6. **Image-layer vulnerability scanning.** Section 4 acknowledges base-image system-library CVEs are invisible to language-level auditors. Trivy and Grype are candidates. Not yet decided — pending evaluation of false-positive rate on Ron's typical base images.

7. **Healthcheck shape lint mechanism.** Section 4 proposes a `healthcheck-shape-lint` gate. Mechanism unclear — yamllint custom rule? AST parse of compose files? Implementation deferred until a second consumer repo trips the same nested-retry bug or until canary `healthcheck_*` variants ship.

8. **Reproducible builds.** Section 6 lists prerequisites. Aspirational, not enforced. Question: when does the pinning cost (dependabot-style auto-bumps for digest-pinned base images) become worth the reproducibility win?

9. **Retention of session-handoff memories beyond 90 days.** Section 1 says rolling 90 days. Question: should some session-handoffs auto-promote to `feedback` class if their lessons recurred? Open — needs the quarterly retrospective in section 9 to reveal patterns.

## 13. Application Independence Floor

**Ratified 2026-10-11 (Ron):** "application development, where applicable, is independent of AI and runs fully on its own infra as a complete deployable app."

**Motivating case (AIBrowser 2.36.9, 2026-10-11):** the installed browser runs, polls, verifies and installs updates with no AI anywhere on the path — the source makes no AI-vendor call, and the agent surfaces (control plane, MCP bridge) are idle loopback listeners when no agent is attached. But every release since 2.25.1 was cut by an AI session following a brain-stored runbook because hosted Actions on Ohio15 is billing-blocked. Had the AI sessions stopped, the shipped app would have kept working and the *next* version could not have been produced without a human reconstructing the runbook. The app passed; the delivery path did not. This section makes both a requirement.

**Rule:** every application or service Ron ships is a complete, deployable product that **runs, updates, and can be rebuilt and redeployed with no AI agent, AI vendor, or AI-mediated session in the loop.** AI may assist development. AI is never a runtime dependency, a release-path dependency, or the only holder of operational knowledge.

### 13.1 Requirements

| # | Requirement | Pass condition | Evidence lives in |
|---|-------------|----------------|-------------------|
| **AI-1 Runtime** | No AI-vendor API call on any startup, core-feature, update or recovery path. | App starts, performs its primary function, checks for and installs updates with every AI endpoint unreachable and no AI credential configured. | Harness/integration test with AI hosts blackholed, or a documented manual proof per release. |
| **AI-2 AI-purpose apps** | Where the app's purpose *is* AI mediation (OpenClaw, personal-ai-pod, AIBrowser's agent surfaces), the AI layer is provider-plural and owner-chosen, and the non-AI functions still work with no provider configured. | Provider absent ⇒ feature reports "no provider", everything else unaffected. No single vendor is hard-wired. | Provider abstraction in code; AI-1 proof covers the non-AI core. |
| **AI-3 Agent surfaces optional** | MCP servers, control planes, bridges and automation principals are add-ons. | App starts and functions with them disabled or unprovisioned. Their absence is never an error on the user's path. | Config flag or empty principal store exercised in the harness. |
| **AI-4 Build & release by a human** | A human can cut a release from a checked-in runbook alone. | `docs/RELEASE.md` (or `RELEASE.md`) in the repo lists every step with exact commands, inputs, and the verification at the boundary. A release that was produced from a brain memory, a chat transcript or an agent's context is **non-conforming until the runbook is committed**. | Repo file; §6 provenance. |
| **AI-5 Build & release by CI** | The same steps run unattended from a tag push. | A release workflow exists in the repo and the last tag either produced a release through it or the blocker is a tracked IMPL item with an owner and a closing condition. | `.github/workflows/`; §4 gates. |
| **AI-6 Own infra** | Deployed to Ron-owned infrastructure (NEXUS, Hetzner, workstation). | No AI vendor hosts, stores, tunnels or serves any part of the running app or its update channel. Substitutable third parties (GitHub, Cloudflare, a registrar) are allowed and named in the runbook with their replacement path. | §7 deploy contracts; `release-config.yml`. |
| **AI-7 Keys survive the machine** | Every secret or key the build, signing, deploy or update path needs is in 1Password (or a documented encrypted backup), not only on one workstation or in an agent's memory. | A fresh machine plus 1Password can reproduce a release. | 1Password item names in the runbook (never values). |
| **AI-8 Operate by a human** | Install, update, rollback, backup and restore each have a written procedure and have been proven once at the observable boundary. | Each procedure cites the date and the boundary it was proven at. | `docs/OPERATIONS.md` or the runbook; §11. |

### 13.2 Applicability

- **Applies in full** to every application and service repo (AIWebBrowser, Sentinel, APM, ToolVault, PDFManager, GameManager, OpenClaw, n3xus-identity, personal-ai-pod, shared-brain-mcp, truck-mcp, …).
- **Libraries, templates and tooling** (dev-standards, n3xus-notify, nexus-relay) inherit AI-4, AI-5 and AI-7.
- **The AI harness itself** (cortex, cortex-hooks, cortex-core) is exempt from AI-1/2/3 by definition and still owes AI-4, AI-5 and AI-7.
- **"Where applicable"** is decided per repo by Ron and recorded in `release-config.yml` as `independence: full | tooling | harness`. Absence of the key means `full`.

### 13.3 What this changes in practice

1. **Agent-run releases are debt, not a mode.** An AI session may cut a release *only* by executing the committed runbook verbatim. Each time it does, the session records the run in the release notes and in shared-brain as `manual-release` with the reason CI could not. Two consecutive agent-run releases on one repo open an IMPL item to restore CI.
2. **Runbooks are files, not memories.** Brain memories may *point to* the runbook; they may not *be* it. The AIBrowser runbook `d3b146a5` is the first migration (see §13.5).
3. **A new AI-vendor dependency is an ADR.** Adding any AI-vendor call to a runtime path requires an ADR that names the provider abstraction and the degraded behaviour, reviewed under the §4 gates.
4. **Release notes carry the independence line.** Every release's notes state `independence: AI-1..AI-8 pass` or list the failing items with their IMPL numbers.

### 13.4 Enforcement

| Mechanism | Scope | Status |
|-----------|-------|--------|
| `repo-hygiene-scan.py` check `independence` — advisory: missing `RELEASE.md`/`docs/RELEASE.md` (HIGH), no release workflow in a `full`/`tooling` repo (HIGH), release tag with no workflow run and no `manual-release` note (MEDIUM), AI-vendor host literal (`api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`, `localhost:11434`) in non-test runtime source of a `full` repo without an ADR reference (MEDIUM). | all Ron-owned repos, weekly | TO-BE — IMPL-34 |
| Release-gate job `independence-note` — fails a release whose notes lack the independence line. | enrolled consumers | TO-BE — IMPL-34 (warn-mode first, per §4 rollout pattern) |
| Session rule in global `CLAUDE.md` (Core Development Principle 5). | every AI session | ACTIVE 2026-10-11 |

Findings are advisory until the gate flips; Ron triages weekly with the rest of the hygiene scan.

### 13.5 State at ratification (2026-10-11)

| Repo | AI-1 | AI-2/3 | AI-4 | AI-5 | AI-6 | AI-7 | AI-8 |
|------|------|--------|------|------|------|------|------|
| AIWebBrowser | pass (source-verified) | pass (loopback listeners idle without an agent) | **fail** — runbook lives in brain `d3b146a5` + `docs/draft/manual-release.md`; must land as `docs/RELEASE.md` | **blocked** — `release.yml` exists; Ohio15 Actions billing-blocked (every release since 2.25.1 agent-run) | pass (NEXUS, Traefik, Cloudflare DNS) | **unverified** — signing key `~/.codesigning/aibrowser-codesign.pfx` backup in 1Password not confirmed | partial — install/update proven; rollback/restore undocumented |
| all other repos | not yet assessed | | | | | | |

First actions: AIWebBrowser `docs/RELEASE.md` from the runbook; confirm the signing key's 1Password item; restore Actions billing or move the release workflow to the self-hosted `nexus-ci` runner. Assess the remaining repos in the first weekly hygiene scan after IMPL-34 lands.

## 14. Discovered-Issue Triage

**Ratified 2026-10-16 (Ron):** "Make this flow standard across all sessions: discovered issues are assigned an agent to resolve and logged to shared-brain independently." Decision memory `7f366ca7`.

**Amended 2026-10-28 (Ron):** the work queue was ratified ("plan B is the plan", then "good to ship" after mockup v2), decision memory `52817d26`. A discovered issue now goes to the work-queue **Inbox** by default. Only three triggers still get it a dedicated agent. Agent-per-discovery made breadth the default: sessions grew past their objective one discovery at a time. The queue keeps the evidence and leaves the order to Ron.

**Motivating case (AIBrowser MCP, 2026-10-16):** during an Apple Business store task, AIBrowser's MCP could not read a cross-origin iframe. Fixing the browser inline would have derailed the purchase task. Noting the gap and moving on would have left a capability gap as a wall, against the build-option rule. The right move was to record the gap, put it where it gets fixed, and carry on.

**Rule:** a **discovered issue** is a defect, tooling or capability gap, or blocker found while working on something else, outside the primary task's own diff. In the same turn it is found, the discovering session:

1. logs it to shared-brain with its evidence;
2. files it to the work-queue Inbox with that evidence, its line of business, its kind and its severity (§14.5);
3. tells Ron one line: the issue, where it was filed, and its severity.

It then continues the primary task without fixing the issue inline or waiting for permission.

The issue gets its **own dedicated background agent ONLY if** one of these holds:

- it **blocks the current session objective** (§15);
- it is a **security finding rated HIGH or worse** (unrated security counts as HIGH, §14.5);
- it is a **live production break**.

Everything else waits in the Inbox until Ron ranks it.

### 14.1 The discovery (discovering session)

1. `brain_recall` the issue. If an open discovery, Inbox item or assigned agent already exists, `reinforce` it with the new evidence and stop there. One item and at most one agent per issue.
2. `brain_store` (remember): the issue, the evidence (error text, file:line, repro), where it was found, an explicit `domain`, the tag `discovered-issue` and the owning project.
3. File it: `brain_commitments add` with `kind: issue`, `lob` (`patriot`, `sentinel`, `nexus-infra`, `cortex-brain`, `truck`, `personal-apps` or `unsorted`), `severity` + `severity_reason` from §14.5, `security` (true/false), and `evidence` naming the discovery memory id. Session-filed items land on the board as `queued`; extractor-sourced items always land in `inbox`.
4. Only if an agent trigger above holds: launch a background agent with full context, scope, constraints, acceptance criteria, the discovery memory id and the Inbox item id. Implementation goes to `lead-engineer` (Opus); investigation, diagnosis or review goes to a Sonnet agent. Name the trigger in the one-line notice to Ron.

### 14.2 The resolution (resolving agent, when one is assigned)

- The agent `brain_store`s its own outcome (fixed, build proposal, or blocked on Ron) in the **same domain** as the discovery, cites the discovery id, and updates the Inbox item. That is the "independently" in the rule: two writes by two writers, at discovery time and at resolution time. Neither waits for the other or for the end of the session. The supervisor references the outcome and doesn't store a second copy. This is the one exception to the §1 rule that only the supervisor writes. A discovered-issue agent owns a distinct finding, linked by id and domain, so it can't produce competing memories about one finding.
- **Scope is the issue only.** The agent doesn't widen the primary task. It stops and surfaces anything outward-facing (email, posts, purchases, third-party changes), destructive, or needing Ron's decision. If the fix needs a new service, new infra or an architecture call, the deliverable is a Rigor-format build proposal stored to the brain, not the build.
- **Every other floor binds the agent:** §2 workspace layout (worktrees in `D:\Worktrees`), branch + version bump + commit/push (never to a default branch, never forced), the Ohio15 default and PatriotCompanies allow-list, the security review model (`/security-gate` for auth, credential and mutation surfaces; the audit before a flag flip), §11 rotation for a leaked secret, and UAC for elevation.

### 14.3 Interaction with other rules

| Rule | How §14 applies it |
|------|--------------------|
| Capability gap = build option | The build option is filed as a queue item. It runs now only on an agent trigger, otherwise when Ron ranks it. |
| Resolve unknowns as they arise | Unknowns about the **current objective** are still resolved now. A discovered issue is resolved by filing it with its evidence, so nothing is lost, and it is worked in Ron's order. |
| Don't over-extend scope | Filing instead of launching is the boundary. An agent, when there is one, fixes the issue, never the primary task's scope. |
| Session objective (§15) | "Blocks the current session objective" is the first agent trigger. A session declares no objective it could stretch to absorb discoveries. |
| Deferred follow-up (reminder + notification) | A queue item is the self-reminder for an issue. If an assigned agent can't finish in-session or its fix needs a later re-check: `brain_commitments` with a `due_at`, a scheduled trigger, and an n3xus-notify. An open discovery at session end goes into the handoff brief by memory id. |
| Fan-out is warn-only | No cap. The DR-010 notice asks whether each further agent serves the declared objective or a queue item Ron ranked, and points to the Inbox otherwise. |
| SPEND line | When an assigned agent's issue feeds a recommendation or plan, the agent's cost goes in its `SPEND:`. |
| Blocking issues | A blocker of the current objective gets its agent. The main session works the unblocked parts, then waits on the agent's result. |

### 14.4 Enforcement

| Mechanism | Scope | Status |
|-----------|-------|--------|
| Session rule in global `CLAUDE.md` + framework `feedback_discovered-issue-agents.md` | every AI session | ACTIVE 2026-10-16, amended 2026-10-28 |
| cortex-hooks decision register row DR-032, tier `norm`. Whether something counts as a discovered issue, and which trigger it meets, is a judgement of intent; no tool boundary carries it. Audit signals: a discovered-issue memory with no Inbox item citing it; an agent launched for a discovery that meets no trigger; an agent-launched discovery with no outcome memory. | journal + routine audit | ACTIVE 2026-10-16, amended 2026-10-28 (cortex-hooks v0.91.0) |
| cortex-hooks DR-010 fan-out notice asks the objective / ranked-queue question at each 12th launch, warn tier | every AI session | ACTIVE 2026-10-28 (cortex-hooks v0.91.0) |

### 14.5 Severity rubric and SLA

The filing session sets the severity from this rubric and cites the evidence in `severity_reason`. The first rule that matches wins:

| Condition | Severity |
|-----------|----------|
| Security item | The finding's own rating (security-gate / audit CRITICAL, HIGH, MEDIUM, LOW). **Unrated security → `high`** until rated. |
| Production break or data-loss risk | `high` |
| Blocks a merge, deploy, release or gate | `medium` |
| Otherwise | `low` |

**SLA** from the item's `created_at`: critical **7 days**, high **30 days**, medium **90 days**, low **none**. It is computed at read time (`sla_due_at`), never stored.

**Order on the board:** items Ron has ranked come first, in his order. Then severity, then overdue, then due date, then age. **Ron's rank always beats severity.** Ron may change a severity only with a recorded reason (`severity_source: ron`). **P0-P3 is not used.**

## 15. Session Objective

**Ratified 2026-10-28 (Ron):** "Every session declares an objective and its done criteria in the first response and stops once they are met." Decision memory `52817d26`, superseding proposal `77a3272c`.

**Why:** runaway sessions were rarely one bad step. They were a sequence of reasonable next steps with no declared finish line. A finish line written down in the first response gives the session, the fan-out notice and Ron something to measure against.

**Rule:**

1. **Declare.** Every session states its **objective** and its **"done when" criteria** in its first response.
2. **Done means:** green, committed, version bumped, deployed and verified at the observable boundary, and the work queue updated. Criteria that cannot apply say why (for example, a docs-only repo has no deploy).
3. **Record.** The session records both with the MCP action `brain_commitments objective_set` and records progress with `objective_update`.
4. **Stop.** The session stops when the criteria are met. More work comes from **Ron ranking the board** (`brain_commitments next` lists the top queued items), not from what the session found along the way. Those findings go to the Inbox under §14.
5. **Continuing sessions.** A resumed or compacted session restates its declared objective and its open criteria before further work. If it had none, it declares one then.

### 15.1 Enforcement

| Mechanism | Scope | Status |
|-----------|-------|--------|
| Session rule in global `CLAUDE.md` | every AI session | ACTIVE 2026-10-28 |
| cortex-hooks SessionStart nudge (`hooks/session-objective-core.ts`, a priority-0 bootstrap block on both bootstrap paths) | every AI session | ACTIVE 2026-10-28 (cortex-hooks v0.91.0) |
| cortex-hooks decision register row DR-036, tier `norm` (whether a response states an objective is prose; whether a launch serves it is intent). Audit signal: a session with no `session_objectives` row, or one that kept working after its row went `met`. | journal + routine audit | ACTIVE 2026-10-28 |

---

**End of v1.** Next retrospective: 2026-08-01 (quarterly). Living doc — all changes via PR with `docs(standards):` commit prefix. Companion: `STANDARDS-IMPLEMENTATION.md` for AS-IS → TO-BE work items.
