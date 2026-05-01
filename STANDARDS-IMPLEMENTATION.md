# Standards Implementation Ledger

Companion to `STANDARDS.md`. Each row is an AS-IS → TO-BE gap with a stable ID (`IMPL-N`). When work lands, mark the row `done:` with the commit SHA; do not delete (keeps the audit trail). New gaps append at the bottom.

**Effort tiers:** S = under a day, M = 1–3 days, L = >3 days or cross-cutting.

**Priority:** P0 = unblocks current consumers / prevents repeated bugs; P1 = closes documented blind-spots; P2 = polish.

**Status legend:** `open` / `in-progress` / `done <sha>` / `deferred <reason>`.

---

| ID | Gap | Target state | Tier | Priority | Status | Motivating scar / source |
|----|-----|--------------|------|----------|--------|--------------------------|
| IMPL-1 | `feedback_*.md` set on disk is incomplete — many rules referenced in MEMORY.md / CLAUDE.md exist only in shared-brain (proactive-brain-rules T1.x, root-cause-analysis-required, realtime-brain-sync, data-preservation, dont-over-extend, measure-before-building, fix-self-review, shared-brain-updates, credential-rotation-protocol, implementation-guardrails) | Each rule has a local `feedback_<name>.md` file at `~/.claude/projects/.../memory/`, generated from the brain canonical and kept in sync via a periodic sync job | M | P1 | open | Missing files would be invisible to a fresh local-only session |
| IMPL-2 | Pre-commit chain only runs `gitleaks` + `size-guard`. No conventional-commit-msg hook, no version-bump-reminder hook | Pre-commit chain installs `pre-commit-conventional-commit.sh` + `pre-commit-version-bump.sh`; `install.sh` updated; existing repos re-run install | S | P1 | open | Section 2 of STANDARDS describes the chain as if these existed |
| IMPL-3 | No `scripts/init-repo.sh` — version-control-everything rule has no bootstrap helper | Script that takes a path, runs `git init`, applies `install.sh`, creates `version.json` skeleton, opens GH repo, sets remote | S | P2 | open | feedback_version-control-everything.md prescribes the rule, lacks tooling |
| IMPL-4 | `hooks/` and `.githooks/` in dev-standards are byte-identical duplicates — install.sh reads `hooks/`, dev-standards' own pre-commit runs `.githooks/`. Single-source-of-truth violation | Collapse to one path. Either: (a) delete `.githooks/`, set `core.hooksPath=hooks` in dev-standards itself; or (b) delete `hooks/`, have install.sh read from `.githooks/` | S | P1 | open | Drift hazard — fix to one path won't propagate to the other |
| IMPL-5 | No `version-uniqueness` gate. APM had two `version.json` files diverge silently (root 0.9.2 vs server/ 0.9.1) | Gate fails if `find . -name version.json -not -path './node_modules/*'` returns >1 file with divergent `.version` values. Add to `release-gates.yml` | S | P0 | open | APM v0.9.2 cosmetic version drift; `/api/health` reported wrong version |
| IMPL-6 | No `tag-bump` enforcement. CLAUDE.md non-negotiable rule #1 says no commit without version bump; not enforced | Pre-commit hook (warn) + CI gate on protected branches (block) when files outside docs/ change but `version.json` doesn't | M | P2 | open | feedback_version-control-everything's "every change bumps" rule |
| IMPL-7 | `release-gates.yml` `npm_audit` gate is npm-only. Go / Python / Rust deps go unscanned at release time | Add `govulncheck`, `pip-audit`, `cargo-audit` ecosystem detection to release-gates. Run conditionally based on what's present in repo | M | P0 | open | APM: 1 critical Go-side (pgx memory-safety) + 7 high (jwt header DoS, chi host injection, etc.) — none visible to npm_audit. ToolVault: 16 high Dependabot alerts gate-passed for the same reason |
| IMPL-8 | No `secrets-in-binary` gate. gitleaks scans tracked files only; secrets baked into Docker images via build-args slip through | After build-and-push, extract image layers, run gitleaks against the unpacked filesystem | M | P2 | open | The `${{secrets.X}}` build-args mechanism warns "bakes secret in plaintext layers" but no automated check |
| IMPL-9 | No `healthcheck-shape-lint` gate. Nested retry loops in `health_check.command` were not caught by review | YAML lint rule (or AST check) that flags `health_check.command` containing `for` / `while` / `seq` patterns | S | P1 | open | ToolVault + APM both shipped with the nested-retry pattern |
| IMPL-10 | `npm-audit-weekly.sh` and `release-gates.yml`'s `npm_audit` step run at repo root only. pnpm/yarn workspaces and monorepos with multiple lockfiles are not enumerated | Walk the repo, find every lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`, `requirements.txt`, etc.), audit each, aggregate | M | P0 | open | n3xus-notify is a pnpm workspace; ToolVault has frontend+backend separate lockfiles — both currently unscanned at non-root |
| IMPL-11 | No `dev-standards-canary` repo. v1 retag churn (28 commits forced onto the same `v1` ref over Apr 30 + May 1, 2026) means consumers see different workflow content hour to hour with no pre-validation | Create canary repo with 4 surface mini-consumers (docker, electron, lib, mcp). RC tag flow: dev-standards push → tag v1-rcN → canary CI consumes @v1-rcN → if green for 3 consecutive runs, fast-forward v1 | L | P0 | open | 6 v1 retags in 2 days, each fix unmasked the next bug class |
| IMPL-12 | OCI labels not set on built images. `org.opencontainers.image.*` (source, revision, version, created, title, description, licenses) all missing | Add `--label` flags to `docker/build-push-action` step in `docker-release.yml`. Version/source/revision sourced from workflow context | S | P1 | open | Provenance traceability — without these, GHCR pages don't link back to source |
| IMPL-13 | Untagged GHCR manifests retained indefinitely. PR-preview images and rebuild-replaced manifests pile up | Scheduled workflow (weekly) that calls GHCR API to delete untagged manifests >7 d old, semver-tagged manifests retained forever | S | P2 | open | Storage hygiene; not yet a cost concern but compounds |
| IMPL-14 | Only `nexus-alerts` ntfy topic in active use. STANDARDS section 8 specifies three topics (`nexus-alerts`, `nexus-urgent`, `nexus-info`) for priority routing | Stand up `nexus-urgent` and `nexus-info` topics; route urgent traffic (canary-red, prod-down, security-incident) accordingly | S | P2 | open | Priority routing helps Ron triage when many notifications fire |
| IMPL-15 | No post-deploy version-match probe. Deploy succeeds even if running binary reports a different version than `version.json` claims | Workflow step after healthcheck-pass: `curl /api/health \| jq -r .version` must equal `jq -r .version version.json`. Fail and rollback if mismatch | S | P0 | open | APM v0.9.2 — `/api/health` returned 0.9.1 from a `:v0.9.2`-tagged image; bug invisible to existing checks |
| IMPL-16 | Dependabot critical alerts not aggregated. Each alert sits in its repo's tab; no central view | Nightly cron polls `gh api repos/Ohio15/<repo>/dependabot/alerts` for all repos, aggregates open critical/high counts, posts digest to `nexus-alerts` (or `nexus-urgent` if any new criticals) | S | P1 | open | APM had 1 critical + 7 high alerts at release time, none surfaced to ntfy |
| IMPL-17 | NEXUS Docker build cache: 45 GB / 100% reclaimable, never pruned (`docker system df` confirmed 2026-05-01) | Weekly cron: `docker buildx prune -f --filter unused-for=168h && docker system prune -f --filter until=168h`. Add to existing Sun cron stack | S | P1 | open | Live disk waste; will become a P0 when NVMe headroom shrinks |
| IMPL-18 | Windows Task Scheduler has zero hygiene tasks registered (`schtasks /query` with hygiene/audit/dev-standards filters returns nothing). `npm-audit-weekly.cmd` shim is staged but unwired | Either: (a) wire the cmd shim into Task Scheduler for desktop-side coverage; or (b) explicitly retire desktop-side hygiene and document NEXUS as the sole runner | S | P2 | deferred (NEXUS coverage is sufficient unless desktop-only repos appear) | Dual-side coverage avoids gaps when NEXUS is offline |
| IMPL-19 | `release/versions.yml` registry only covers 3 of 6 currently-enrolled repos (PDFManager, Sentinel, ToolVault). APM, MCP-Core, ms-account-router are absent despite having `release-config.yml` | `repo-hygiene-scan.py --check-drift` walks all repos with `release-config.yml`, not just a hardcoded list. Re-run weekly cron updates registry | S | P1 | open | Drift detection is silently incomplete — can miss N-behind alerts for unscanned repos |
| IMPL-20 | AIWebBrowser broken-enrollment: caller workflow `release.yml` exists, but no `release-config.yml`. Workflow will fail at `read-config` step with cryptic error | Either remove the caller workflow until enrollment completes, or finish enrollment by adding `release-config.yml` | S | P1 | open | Stale partial-enrollment will eventually trigger a confused user-facing failure |
| IMPL-21 | n3xus-notify partial-enrollment: NEXUS runner registered + has GH workflow activity, but no `release-config.yml`. pnpm workspace shape complicates lib-vs-docker surface decision | Decide surface (lib-release for the @n3xus/notify npm package?), add `release-config.yml`, OR de-register the runner if not actually used | S | P1 | open | Resource cost (idle runner) + enrollment confusion |
| IMPL-22 | `templates/.large-files-allowlist` is a comment-only stub. Consumers inherit empty allowlists; any legitimate large file requires manual edit per repo | Either: ship a sensible default (icons, fonts, common asset extensions), or document explicitly that the file is a starting placeholder. Either is fine — current state is a silent failure mode | S | P2 | open | Hygiene-scan won't surface this until a consumer tries to commit a large file |
| IMPL-23 | ntfy container Exited(2) on NEXUS at 14:22 UTC 2026-05-01 after 16 days uptime. Logs end at 10:21 UTC; root cause unknown. Restart-policy `unless-stopped` (won't auto-restart on graceful exit) | Restart-policy → `always`; add Loki log shipping for ntfy container; investigate why logs stop 4 hours before crash (rotation? buffering?) | S | P1 | open | If root-cause is unknown, recurrence is unpredictable; alerts go silent |
| IMPL-24 | Phase 1 mid-stabilization: 5/5 of last 5 workflow runs failed across most enrolled repos (dev-standards, Sentinel, ToolVault, PDFManager, n3xus-notify, Shared-Brain, MCP-Core). Confirmed via `gh run list --status=failure` | Drive failed-run rate to <20% via canary (IMPL-11) + dependent fixes. Track a "recent-failure-rate" metric in versions.yml | M | P0 | open | High failure rate masks new regressions; can't tell signal from noise |
| IMPL-25 | dev-standards itself has no `dependabot.yml`. Its own deps (action SHAs in workflows) drift unchecked | Add `.github/dependabot.yml` with `package-ecosystem: github-actions` weekly; let it propose action-pinning bumps | S | P2 | open | Eat your own dog food — section 2 of STANDARDS lists dependabot.yml as required for consumers |
| IMPL-26 | `healthcheck` runtime version assertion (IMPL-15) requires every consumer's `/health` endpoint to return JSON with `version` field. Currently inconsistent: APM returns `{"status":"ok","version":"..."}`, ToolVault returns `{"status":"ok","timestamp":"..."}` (no version), shared-brain returns plain `{ok:true}` | Standardize the `/health` response shape across all Ron-owned services. Document in section 7. Update SDK / boilerplate templates | M | P1 | open | Without standard shape, IMPL-15 can't be enforced uniformly |
| IMPL-27 | No "feature flag rollout" pattern documented. Several active flags exist (e.g. n3xus-identity Phase 1.A) but no removal cadence | Add a `flags.yml` per repo listing active flags with a `cleanup_after` date. Hygiene scan flags expired entries. Section 9 maintenance cadence covers it | M | P2 | deferred (only one repo has flags right now) | Will become P1 if flag count grows |

---

## Roll-up by priority

**P0 (5):** IMPL-5, IMPL-7, IMPL-10, IMPL-11, IMPL-15, IMPL-24

**P1 (11):** IMPL-1, IMPL-2, IMPL-4, IMPL-9, IMPL-12, IMPL-16, IMPL-17, IMPL-19, IMPL-20, IMPL-21, IMPL-23, IMPL-26

**P2 (8):** IMPL-3, IMPL-6, IMPL-8, IMPL-13, IMPL-14, IMPL-22, IMPL-25, IMPL-27

**Deferred (2):** IMPL-18, IMPL-27

## Roll-up by tier

**S (small, sub-day):** IMPL-2, IMPL-3, IMPL-4, IMPL-5, IMPL-9, IMPL-12, IMPL-13, IMPL-14, IMPL-15, IMPL-16, IMPL-17, IMPL-18, IMPL-19, IMPL-20, IMPL-21, IMPL-22, IMPL-23, IMPL-25 — 18 items

**M (1–3 days):** IMPL-1, IMPL-6, IMPL-7, IMPL-8, IMPL-10, IMPL-24, IMPL-26, IMPL-27 — 8 items

**L (cross-cutting):** IMPL-11 (canary repo) — 1 item

---

## Suggested first wave (top P0, lowest blast radius first)

1. **IMPL-5** (version-uniqueness gate) — half-day. Eliminates the APM bug class structurally. Pure additive — no consumer breaks.
2. **IMPL-15** (post-deploy version-match probe) — half-day. Catches the same bug at runtime as a defense-in-depth. Small workflow addition.
3. **IMPL-7** (govulncheck/pip-audit/cargo-audit gates) — 2 days. Closes the largest gate blind-spot. Need to handle the "gate fails on pre-existing CVEs" rollout: add as warning-only first, flip to blocking after 2 weeks of clean runs.
4. **IMPL-9** (healthcheck-shape-lint) — half-day. Cheap, catches a live recurring class.
5. **IMPL-11** (canary repo) — 3 days. Largest payoff but largest scope. Best done after 1–4 land so the canary itself exercises real working gates.

After first wave, pivot to P1 cleanup (IMPL-19/20/21/23/26 are all S-tier).
