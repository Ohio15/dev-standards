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

**Sub-agent vs supervisor save responsibility.** Sub-agents return findings to the supervisor. Only the supervisor writes `[REMEMBER]:` markers, after synthesis. This prevents three agents writing three contradictory memories about the same finding.

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

**Pre-commit installation:** `bash <(curl -sL https://raw.githubusercontent.com/Ohio15/dev-standards/v1/install.sh)` from repo root, OR clone dev-standards and run `./install.sh /path/to/repo`. Idempotent. Currently installs: `.githooks/pre-commit` (dispatcher) + `pre-commit-secret-scan.sh` (gitleaks staged-diff) + `pre-commit-size-guard.sh` (10 MB ceiling). Sets `core.hooksPath=.githooks`. Conventional-commit-msg hook and version-bump-reminder hook are TO-BE additions (IMPL-2).

**Conventional commits:** `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`, `build:`, `ci:`. Currently advisory. Enforcement plan: PR titles via GitHub branch ruleset; commit messages via local hook (warn) + CI gate on protected branches (block).

**`repo-hygiene-scan.py` (weekly NEXUS cron, Sun 5am UTC):** scans every Ron-owned repo for:
1. Missing required files (table above)
2. Tracked binaries / large files / `.gitignore`-tracked files / `core.hooksPath` misconfig
3. Idle repos (>180 days since last release, candidate for archive review)
4. Workflow files referencing deprecated dev-standards versions
5. Phase 1C drift: `gh release list` + GHCR API + NEXUS `docker inspect` → writes `release/versions.yml`
6. ntfy alert to `nexus-alerts` when N≥2 releases behind
7. Output: JSON to `<output-dir>/hygiene-scan-<YYYY-MM-DD>.json`, optional `--brain-store` for shared-brain ingestion

Findings are advisory, not blocking — Ron triages weekly.

**Version control everything (no opt-out):** any directory containing infra config, deployment config, or source code is a git repo with a private GitHub remote. Including `~/infra/`, `~/AdGuardHome/config/`, `D:/Projects/*`. Bootstrap: `dev-standards/scripts/init-repo.sh <path>` (TO-BE — IMPL-3).

**Hooks single-source-of-truth:** dev-standards itself currently has `hooks/` and `.githooks/` as byte-identical duplicates. `install.sh` reads from `hooks/`; dev-standards' own pre-commit chain runs from `.githooks/`. This is a drift hazard. Tracked as IMPL-4: collapse to one path with a build step or symlink.

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

**Layer B — `dep-auto-apply.yml` (weekly cron, opt-in):** Sunday 06:00 UTC via repo-side `schedule:` trigger. Per-repo opt-in via `.github/auto-apply-enabled` file. Auto-applies safe (patch / minor for non-breaking) bumps across npm / go / python / docker / gh-actions. Notifies ntfy + shared-brain.

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

**Canary failure modes & SLA:** any canary red blocks v1 promotion. Ron is notified via ntfy `urgent` priority. Human review SLA: 24 hours to triage (fix forward, revert RC, or document as expected-fail). RCs older than 7 days without promotion auto-expire and get re-cut from latest main.

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

---

**End of v1.** Next retrospective: 2026-08-01 (quarterly). Living doc — all changes via PR with `docs(standards):` commit prefix. Companion: `STANDARDS-IMPLEMENTATION.md` for AS-IS → TO-BE work items.
