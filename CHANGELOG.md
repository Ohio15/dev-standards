# Changelog

dev-standards had no root version until 1.1.0; earlier changes are recorded in the PR history
and the `v1` / `v1-rcN` workflow tags (which remain the consumer pin for reusable workflows).

## 1.2.5 - 2026-11-25

STANDARDS.md 1 gains "Process-memory corrections carry the artifact check" (Ron 2026-11-25, memory `1c12e9cf`): a correction to a
memory that describes a process is complete only when every artifact encoding that process (code, scripts, hooks, runbooks, STANDARDS.md,
decision register, scheduled tasks, agent briefs) has been checked in the same turn and the record names each as CHANGED (PR/commit) or
ALREADY CORRECT (evidence location). Steward enforces (work item `28d98ab6`). Origin: lesson `1524c3f7` corrected `7ac95d78` and the
follow-through found the handoff watcher already correct. Also fixes version drift: PR #109 recorded 1.2.4 in this file but left
`version.json` at 1.2.3; both now read 1.2.5 (defect filed to the work queue as a class: a docs-only PR can skip the bump unobserved).

## 1.2.4 - 2026-11-25

STANDARDS.md 14.7 gains rule 7: the "requested, never blocked" rule is IMMUTABLE (Ron 2026-11-25, decision `fe5ac5ad`). The approval-request
path is a server obligation with no flag, no per-class or per-principal disable, covering every refusal class; a bare refusal is a server
defect (shared-brain work item `52c87ce3`) and rule 3's decision-item fallback is the backstop for that defect, not the intended path.
The enforcement row for the shared-brain flag is marked non-compliant until the flag is removed. Trigger: 2026-11-25 `complete` on security
item `2a3d5d61` and decision item `f7c2f214` refused with no request stored. Mirrors the cortex-hooks DR-041 amendment (0.106.3, PR in flight at the time of this entry; 0.106.2 is the deployed release).

## 1.2.3 - 2026-11-24

The code-standards roster now lists the deployed OpenClaw fork `openclaw-1` (Steward item 0533106b follow-on; lesson fe7c2549).
The roster was built from `gh repo list Ohio15 --source`, which drops forks, so it listed only `OpenClaw` (Ohio15/OpenClaw), a non-fork
repo whose default branch is a 2025-11-25 snapshot with no lockfile, and never the gateway NEXUS actually runs (Ohio15/openclaw-1, a fork
with `pnpm-lock.yaml`). Steward's `pos-code-dependency-vulns/openclaw` read blind-scan (`no-lockfile`) and the deployed gateway's
dependencies were never audited. `openclaw-1` is the only fork pushed since 2026-08-10. Test `test_deployed_forks_are_listed`.
`OpenClaw` stays listed: whether that snapshot repo is archived or excluded is an owner decision, so its position stays honestly blind.

Expected after deploy, measured on NEXUS 2026-11-24 in a scratch mirror: `openclaw-1` reads UNEXAMINED, reason
`vendor/a2ui/renderers/angular:stage-refused:workspace-path-outside-repo`. That vendored package depends on `file:../lit`, an in-repo
sibling, and the 1.2.2 staging guard refuses every `../` lockfile key, including keys that resolve inside the repo. That is a scanner
gap filed as its own work item (a path guard on untrusted repo content, security-gated). Until it lands, the deployed gateway is
visibly unexamined, where before it was silently never scanned.

## 1.2.2 - 2026-11-23

This release closes a fail-open in the estate production-dependency signal (work item 0323e3cc, security HIGH; discovery a0eb44f4).
`npm-audit-weekly.sh` audited only each repo's ROOT lockfile, so a standalone package in a subdirectory with its own lockfile was never
audited and the repo read prod-clean. Measured case: nexus-realervnc `deploy/op-auth-proxy/pnpm-lock.yaml` (installed
`--ignore-workspace`, 26 production highs). On paxson 29 nested committed lockfiles across 13 repos had the same blind spot.

- `npm-audit-weekly.sh` audits a repo as every package directory it holds: the root (when it has a `package.json`) and every directory
  holding a lockfile of its own, `node_modules` and `.git` pruned, symlinked directories never followed. A workspace member has no lockfile
  of its own, so it is still covered once, through the root.
- A repo entry is `"ok"` only when every directory was examined; its counts are the sums over them. One directory not examined (audit
  error, timeout, yarn or bun lockfile, staging refused) makes the whole repo `"error"` with null counts, and its reason names the
  directory (`deploy/x:full:audit-error:...`). A lockfile path outside an ASCII allow-list (`A-Z a-z 0-9 . _ @ / + -` and space;
  a control character, a bidi override or a zero-width character would split or forge report and brain text, SC-54/SC-60), a failed
  walk, or more than `MAX_PACKAGE_DIRS`
  (default 50) directories also leaves the repo unexamined, never truncated.
- Repos are discovered by a root `package.json` OR a lockfile anywhere in the tree, so a repo whose only npm package is nested
  (`frontend/`, `server/`) is now audited instead of skipped.
- The JSON report adds `"lockfiles"` (every audited lockfile, repo-relative) and `"units"` (per-directory status, reason and counts).
  `"lockfile"` stays the root's lockfile.
- `code-standards-facts.py` gives `code_standards_deps_scanned` to a scanned repo with a root `package.json` or a lockfile in any
  subdirectory, so a missed nested package reads as not scanned rather than as having no npm dependencies. No series or label is
  added: the `code_standards.prom` contract Steward parses is unchanged. `code_deps.prom` (OSV, every ecosystem) remains the
  authoritative all-lockfile vulnerability feed.

## 1.2.1 - 2026-11-23

This release labels the upstream mirrors in the OSV feed, and corrects the inventory, which had called them Ron's own code.

- `estate/osv-mirrors.txt` lists the 16 roster repos that are unmodified mirrors of a third-party or frozen upstream:
  - 13 storytold craft repos (craft-microsoft README: mirrors never run CI and never diverge);
  - ceremony, juicebox-hsm-realm and juicebox-software-realm (Ron decision 02d97de7, item ecada2de).
- `osv-deps-facts.py --mirrors` exports `code_deps_repo_mirror{repo} 1` and adds `"mirror": true|false` to the JSON report. Mirrors
  are still scanned and their advisories still exported, so nothing is hidden. A name in the list that is not on the roster, a duplicate,
  or an invalid name refuses the run, and nothing is written.
- `docs/github-dependencies.md` row 3 is corrected: steward-sessionwatch is the only repo of Ron's own still on hosted runners. The
  mirrors must never be enrolled on nexus-ci, because they carry upstream's release workflows.

## 1.2.0 - 2026-11-23

This release adds a local scan meant to replace GitHub Dependabot alerts. It adds a local, all-ecosystem
dependency-vulnerability scan on NEXUS, and `docs/github-dependencies.md`, the inventory of what still runs
on or arrives from GitHub (Ron, brief e26f9441).

- `scripts/osv-deps-facts.py`: runs OSV-Scanner over the code-standards mirror for every ecosystem it reads
  (npm, pnpm, Go, crates.io, PyPI, NuGet and the rest) against the offline OSV database. It writes a
  separate textfile, `code_deps.prom`, with these series: `code_deps_repo_scanned`, `code_deps_packages`,
  `code_deps_vulns{ecosystem,severity}` and `code_deps_last_run_timestamp_seconds`. It also writes a JSON
  report. The file is separate because Steward refuses `code_standards.prom` whole if it contains any
  series outside its allow-list.
- Fail-closed: a repo reads as scanned only when its mirror refreshed this run and the pinned scanner
  completed with output that parses. A timeout, a crash, a wrong binary version, unparseable JSON, or an
  exit code that disagrees with the output each count as not scanned.
- Isolation, in the same class as the npm audit staging (SC-07/SC-12): the scanner runs with
  `--offline --download-offline-databases --no-resolve --no-call-analysis=all`. Its cwd is outside the
  repo, and its environment is scrubbed, with no Go toolchain on PATH. No repo code is built or run, and
  no package list leaves the host.
- `scripts/install-osv-scanner.sh` builds the version pinned in `estate/osv-scanner.version` with
  `go install` under `env -i` (no inherited GOINSECURE, GONOSUMDB or go.env), verified by the Go
  checksum database, and swaps `current` atomically.
- `scripts/code-standards-cron.sh` step 6 runs the scanner after the code-standards export. The step is
  degradable: a failure never blocks that export.
- No consumer exists yet. Steward ingestion (work item 8276fa8d) and APM Phase 4 (brain d04159db) are
  pending, and so is a staleness alert on `code_deps_last_run_timestamp_seconds`. Until those land, the feed
  is a report, not a control, and GitHub alerts stay on (security gate pass 1, SC-53 LOW).

## 1.1.21 - 2026-11-22

Register: graduate SC-69 and SC-70 and amend SC-54 again, from audit-shared-brain-2026-11-22.
Approved by Ron (decision 34df38b0). Both register copies are identical, with 67 rules.

- SC-69: a validator that throws at its first refusal is caught to classify a write, so a later and
  stronger check never runs for the real caller. Shared-Brain 7.96.0 assertNotBoardOnly masked the
  security-close verification (MEDIUM, 2 of 3 reviewers).
- SC-70: a throttle or cap whose key includes a component the caller can rotate for free. The
  Shared-Brain queue-full alert was keyed on principal plus MCP session (MEDIUM, 2 of 3 reviewers).
- SC-54 amended: the Check adds U+17B4, U+17B5 and U+180B-U+180D, U+180F, greps every Cf-based class
  in the repo, and prefers an allow-list class for trusted titles.

## 1.1.20 - 2026-11-22

`scripts/npm-audit-weekly.sh` audits pnpm repos. Steward's pos-code-dependency-vulns read blind-scan for
five repos because the script only knew npm lockfiles and labelled every other repo "missing-lockfile".
Three of them (n3xus-identity, n3xus-notify, nexus-realervnc) commit `pnpm-lock.yaml`; the other two
(notification-service, openclaw) commit no lockfile at all.

- pnpm-lock.yaml repos run `pnpm audit --json` and `pnpm audit --prod --json`; the entry fields are
  unchanged, so `code-standards-facts.py` needs no change. npm still wins when a repo has both.
- Same isolation model as npm (audit 2026-11-10.2 M3, SC-07/SC-12), fitted to what pnpm 12.21.0 was
  probed to read: the repo's pnpm-workspace.yaml is never staged (its `registry:` redirects the audit
  and beats npm_config_* env; the script writes `packages: []`), package.json is rebuilt by jq from its
  dependency fields (drops "pnpm" overrides/auditConfig, "packageManager", "devEngines"), pnpm_config_*
  pins alongside npm_config_*, XDG_CONFIG_HOME an empty dir, COREPACK_ENABLE_PROJECT_SPEC=0. Lockfile
  and manifest must be regular files with no symlink on the path. Workspace manifests are not staged:
  the audit reads importers from the lockfile, and staging them gives identical counts on all three repos.
- Reasons split: "no-lockfile" (nothing pins the tree, a repo defect), "unsupported-lockfile:yarn" /
  ":bun", "pnpm-missing", and pnpm's stderr-only failures as "audit-error:ERR_PNPM_*". All unexamined.
- Each entry carries `lockfile` (the file audited, or null).

Probed against the NEXUS mirrors 2026-11-22: the three pnpm repos go from error to ok, the two others
read no-lockfile, and the eleven npm repos are identical to that day's cron run.

## 1.1.19 - 2026-11-21

Seat ranks are proposals (docs): STANDARDS 14.5 no longer tells sessions to apply rubric ranks through the APM
board key. Under 14.7 rule 5 agents never use the board key, so until the proposed-rank write ships (018a4cf5)
a session records its ranks as a proposal memory and Ron or Steward applies them. Ron chose this 2026-11-21
(work item cf7b2b5b, option "Proposals only").

## 1.1.18 - 2026-11-21

Security register SC-63..SC-68 graduated from audit-n3xus-notify-2026-11-21.2, approved by Ron
2026-11-21 (decision 29e9eb74): tag-triggered release deploying without proving the tagged commit
passed the default-branch gates (SC-63); caller text forwarded to a downstream that parses an
inline directive grammar (SC-64); a network-facing service holding a credential wider than its one
action (SC-65); authorization by bare string prefix with no delimiter (SC-66); a globally capped
shared store whose eviction crosses tenants (SC-67); a rate limiter keyed only on authenticated
identity (SC-68). SC-54 amended: its enumerated invisible code points now include U+115F, U+1160,
U+3164, U+FFA0, U+2800, U+034F, U+FE00-U+FE0F and private use. Both register copies updated
identically (65 rules). Consumer copies installed by install.sh need re-sync.

Board approval rule (docs): new STANDARDS §14.7. No agent action on the work-queue board ends in
an outright block; what needs Ron becomes an approval request he approves in batches with a
passkey, and agents never use the board key. Ratified by Ron 2026-11-21 (decisions f5575b41,
5d4cddb1). Enforcement rows cite shared-brain 7.96.0 (flag off until its routine audit) and
cortex-hooks DR-041 (warn) and DR-042 (block), v0.104.0.

Pre-commit test bound: `.pre-commit-tests` TEST_TIMEOUT 900 -> 1800. The full scripts/tests suite
now measures 955 s on paxson (1422 passed, 33 skipped; slowest single test 14 s), so the 900 s
bound killed a green suite and refused every commit touching a tested path.

## 1.1.17 - 2026-11-20

Session handoff standard, enforcement status (docs): STANDARDS section 19.1 rows now cite what shipped. ACTIVE: watcher-only capped redelivery (Ohio15/cortex-hooks#169, v0.101.0), lineage labels and `claude -n` (Ohio15/cortex-hooks#171, v0.103.0), same-principal binding (Ohio15/brain-mcp-proxy#27, 0.3.0-alpha.34; `CREDENTIAL_RECOVERY` still off), Steward positions (Ohio15/steward-sessionwatch#7, v0.2.1). SHIPPED but not enforcing: the brain-direct PreToolUse guard (Ohio15/cortex-hooks#171); its `settings.json` registration is human-run and waits for the routine security audit (follow-up e0d4e152).

## 1.1.16 - 2026-11-20

Session handoff standard (docs): new STANDARDS §19 is the canonical handoff rule. It covers: one record in shared-brain; one path to it (no hand-written HTTP clients); delivered means a verified nonce ACK, with watcher-only capped redelivery; the parent stays open and says so; a credential rejection is never served from the replica or replayed under another principal; named lineages via `claude -n`; Steward's watchdog is the judge. The §1 `session-handoff` storage-class row now matches the real tags. §18 is left reserved for the proposed decision-binding standard. Ratified by Ron 2026-11-20 ("go with recommendations"); panel synthesis `107560b5`, circumvention finding `12d4fa26`.

## 1.1.15 - 2026-11-19

Workflow comments (no behaviour change): the citations of `scripts/tests/test_dep_auto_apply_workflow.py` in `templates/.github/workflows/dep-auto-apply.yml` (shared manifest detection block and the `publish` job note), `templates/.github/workflows/security-audit.yml`, and the own copies in `.github/workflows/` (`dep-auto-apply.yml`, `security-audit.yml`, `release-gates.yml`) now name the repo that holds the test (Ohio15/dev-standards). install.sh copies the templates byte-identical into consumer repos, where a bare repo-relative path pointed at a test that does not exist there and a consumer's security gate flagged it as SC-13 (claim without enforcement). The shared block stays byte-identical across all copies. Work item 9ed35b63.

## 1.1.14 - 2026-11-18

Decision binding, amendment (docs only): plan section 10 "Redesign for AI independence" answers Ron's two follow-ups. Seven principles (typed records; rules become code; the model proposes, deterministic code decides; Ron's decisions captured at the source by the APM answer form; recall is discovery only; model-agnostic harness with eval-gated autonomy; one verifier plus a scheduled blackhole drill), the stage sequence (stages 1-4 = P0-P7; stages 5-7 filed as work items f33dea53, 9e5391f8, bc458d2b), SPEND for stages 5-7 (~15-20 agent-days, ~2.5 h of Ron's time) and the residual risk (semantic contradictions outside the vocabulary are reported as "bound but unmatched", never clean; lesson `4c5ebec0`). Bound by `7e8c4616`, `111bfdb1`, `8bc6294e`.

## 1.1.13 - 2026-11-18

Decision binding: corrective plan and proposed STANDARDS §18 (docs only; no rule is in force until Ron ratifies).

- `docs/plans/2026-11-18-decision-binding.md`: Rigor-format survey, root cause, options (incremental / rewrite the decision layer / full rewrite), recommendation B, phases P0-P7, SPEND, and the six 2026-11-18 cases as replay acceptance tests.
- `docs/adr/0001-decision-binding-standard.md`: proposed §18 text (decisions are ledger records with scope and assertions; binding is computed, not recalled; artifacts are checked where written; Steward verifies independently and pages Ron; unknown is not clean).

## 1.1.12 - 2026-11-17

npm advisory exceptions: one declarative, expiring, loud exception list honoured by both npm
gates (incident ab044000: picomatch GHSA-fc5q-39xc-vjpf, HIGH ReDoS, `<= 4.0.7`, no patched
version, failed Keystone's `security-audit.yml` and release-gates `npm_audit` through vite/vitest
dev tooling with nothing the repo could change).

- `.github/npm-audit-exceptions.json` (schema and rules: `release/SPEC.md` "npm audit
  exceptions"): `{"exceptions":[{"ghsa","reason","expires","dirs"?}]}`. Peers: pnpm
  `auditConfig.ignoreGhsas`, cargo-audit `[advisories] ignore`, pip-audit `--ignore-vuln`,
  audit-ci `allowlist`.
- Both gates now run `npm audit --json` (release-gates keeps `--package-lock-only`) through the
  `# >>> shared npm audit exceptions` block, byte-identical in `release-gates.yml`,
  `security-audit.yml` and `templates/.github/workflows/security-audit.yml`. A package at or above
  the level is excused only when every advisory at or above the level that reaches it (`via`
  names followed to their root advisories) is listed; ids come from the report's `via[].url`,
  never from a `package.json` or `.npmrc`.
- Fail closed: an expired entry, one expiring more than 180 days out, malformed JSON, a
  duplicate key or id, an unknown key, a bad id, reason, date or dir, a symlinked file, a missing
  or error report, or a report that disagrees with npm's exit code fails the gate. A clean report
  still passes only on a valid file.
- Loud: every exception honoured is a `::warning::` and a step-summary row (id, reason, expiry,
  packages excused); one that excused nothing is a `::notice::` (stale).
- The level is never lowered and `gates.npm_audit: off` stays the only disable. pnpm and yarn
  audits in `security-audit.yml` do not read the file.
- A pull request never excuses its own findings (gate pass 1, SC-05 MEDIUM): the block takes the
  list's path, and the caller picks the copy. release-gates (pushed tag) and `security-audit.yml`
  on a trusted event read the checkout's copy; `security-audit.yml` on a `pull_request` reads the
  base branch's copy from the merge commit's first parent (checkout `fetch-depth: 2`, git objects,
  no fetch or credential), and a checkout that is not that merge commit is NOT EXAMINED; any
  other untrusted event honours none. So the PR that adds or changes an exception is red on its
  `pull_request` run and green on the `push` run after merge; merging it on red is an explicit,
  recorded reviewer decision.
- `scripts/tests/test_npm_audit_exceptions.py` proves the three copies identical and runs the
  shipped block (and both shipped steps) against fixture reports, including the real npm 11.7
  report for picomatch 4.0.7; `test_release_gates_workflow.py` shims now print a report.

independence: AI-1..AI-8 pass

Consumers: re-sync `security-audit.yml` from the template (keeping their own runs-on lines) and
re-pin reusable release workflows to pick up the release-gates change.

## 1.1.11 - 2026-11-17

release-gates `independence-note` recognises every common CHANGELOG heading (work item
36a8b0d6; n3xus-identity v0.14.8 release run 44152729472).

- The gate found a version's section only under `## [x.y.z]`, so repos writing `## 0.14.8 — title`
  (n3xus-identity, Keystone) failed with "CHANGELOG.md has no '## [VERSION]' section" although the
  section and its `independence:` line existed; it also ran a section on to the next `## [`
  heading, so in a bracket-free changelog an older release's independence line could count. One
  shared detector, `changelog_section` (block `# >>> shared changelog section`, byte-identical in
  `release-gates.yml` and `lib-release.yml`, which had its own different regex), now accepts
  `## [x.y.z]`, `## x.y.z`, `## vx.y.z` and `## [vx.y.z]` with any suffix that cannot continue a
  version (`## 0.14.80` and `## 0.14.8-rc.1` never name 0.14.8), bounds the section at the next
  `## ` heading, and ignores headings inside ``` / ~~~ fences. Documented in `release/SPEC.md`
  "CHANGELOG sections"; `scripts/tests/test_changelog_section.py` runs the block and both shipped
  steps on every style, near misses and fences, under default awk, POSIX-mode gawk and mawk when
  present. Still warn-mode soak.

## 1.1.10 - 2026-11-17

Reusable release workflows fail closed on runner selection and verify gitleaks (work items
ccfc277b and 67dbdbfb, GitHub-dependency audit 2026-11-17, brain ef2f6119).

- Every reusable release workflow (`docker-release.yml`, `release-gates.yml`, `lib-release.yml`,
  `mcp-release.yml`, `electron-release.yml`) picks its runner as
  `${{ inputs.runs_on || (github.event.repository.private && (vars.CI_RUNNER || 'nexus-ci')) || 'ubuntu-latest' }}`,
  and each now declares the `runs_on` input. Before, a private repository whose `CI_RUNNER`
  variable was missing released on GitHub-hosted compute with `packages: write`, `NPM_TOKEN` or
  the signing secrets and the job token. Now an unset variable cannot select a hosted label for a
  private repository (a missing variable queues on `nexus-ci` instead of releasing elsewhere); an
  explicit `runs_on` or `CI_RUNNER` names whatever single label it holds; a public repository
  keeps the hosted label. Deploy and notify keep `[self-hosted, nexus-deploy]`. The one hosted
  `runs-on` left is the `electron-release.yml` build matrix (win and mac need a Windows or macOS
  host for the platform build and code signing). `scripts/tests/test_release_runner_selection.py`
  derives the file list from every `workflow_call` workflow, parses the YAML (every `runs-on`
  spelling), names that matrix as the only permitted exception, proves the check goes red on a
  reverted expression, and locks the gitleaks step.
- `release-gates.yml` gitleaks: version 8.18.4 stays pinned and the archive's SHA-256 is now
  pinned beside it and checked with `sha256sum -c` before `tar` touches it (before: `curl | tar`
  straight into `/usr/local/bin`, unverified). When the runner image already carries gitleaks
  8.18.4 (the nexus-ci golden image does from infra ci-vm user-data 2026-11-17) nothing is
  downloaded; any other baked version refuses. cargo-audit already verified its archive the same
  way (unchanged).

## 1.1.9 - 2026-11-16

release-gates `npm_audit` examines every tracked npm manifest and fails closed (work item
6a5ac8ad, audit-keystone-2026-11-16 MEDIUM, brain ac517cd7). Before, the job ran
`[ ! -f package.json ] && exit 0` at the repo root, so a repo whose manifests live in
subdirectories (Keystone `frontend/`; ToolVault `backend/` + `frontend/`, brain cb5d82c9) released
with `npm_audit: high` having audited nothing. Detection is now the shared manifest-detection
block, byte-identical to `security-audit.yml` and `dep-auto-apply.yml`: tracked manifests only, never
`node_modules`, workspace members audited once through the root whose lockfile names them. Each
directory first proves its lockfile is the tree with `npm ci --dry-run --ignore-scripts` (refuses
when the manifest or any folded workspace member has drifted from the lockfile; installs nothing;
probed on npm 11.7), which is the frozen check the shared block's member folding relies on (gate
pass 1, SC-07), then runs `npm audit --package-lock-only --audit-level=<floor>`; an out-of-sync
lockfile is NOT EXAMINED and fails. A manifest that declares no
dependencies is examined and clean; dependencies without a `package-lock.json`, a pnpm or yarn
lockfile (pnpm support is work item b523b182) and an unreadable `package.json` fail as NOT
EXAMINED. An enabled gate with no tracked `package.json` anywhere fails, including when the key is
absent (the default is `high`): a repo with no npm dependencies says `gates.npm_audit: off`. An
unknown level is an error, and the level reaches the script through env, not `${{ }}`.

Same skip-means-pass shape fixed in `cargo_audit`: a `Cargo.toml` with no `Cargo.lock` alongside
or above it was a warning and `continue`; it is now NOT EXAMINED and fails the job (still
warn-mode, `continue-on-error`). Its manifest list moved from `/tmp` to `$RUNNER_TEMP`.
`scripts/tests/test_release_gates_workflow.py` runs the shipped step bodies against throwaway
repos with recording `npm` / `cargo-audit` shims. Supersedes PR #49 (2026-10-17, unmerged).

Consumers on `@v1` get this only when `v1` is next promoted through the canary.

## 1.1.8 - 2026-11-14

Security register SC-62 graduated from audit-shared-brain-2026-11-14, approved by Ron 2026-11-14
(decision 2a3eb88e): an attestation accepted as evidence for an action that is validated for
freshness and authorship but not bound to the target it attests to (shared-brain
`closeEvidenceRefProblem`, security-item verification memory accepted by tag+author+recency with
no item-id binding). Both register copies updated identically (59 rules).

## 1.1.7 - 2026-11-14

Security register SC-58..SC-61 graduated from audit-cortex-hooks-2026-11-14, approved by Ron
2026-11-14 (decision 19267a80): an authorization decision on a URL owner or path taken before
canonicalisation (SC-58), a per-call approval tier that can reach a control-plane or policy write
(SC-59), a multi-line operator prompt built from interpolated untrusted values (SC-60), and a
case-folded flag lookup against a case-sensitive flag table (SC-61). Both register copies updated
identically (58 rules).

## 1.1.6 - 2026-11-14

repo-hygiene-scan reads data, minified and vendored runtime-source files under a documented
16 MiB cap (`MAX_DATA_ARTEFACT_BYTES`; `artefact_kind()` classifies `.json`; `*.min.*`, `*-min.*`
and `*.bundle.*` with a js/mjs/cjs/css suffix; and any path under a `vendor`, `vendored`,
`third_party` or `third-party` segment, whatever its suffix) instead of the 1 MiB hand-written-code
cap. Before, one such file
(openobd `data/2010_silverado_best.cal.json`, 1.8 MB; pdfmanager
`src/renderer/public/pdf.worker.min.mjs`, 1.4 MB) produced a `*-unexamined` finding and the
code-standards exporter reported the whole repo as `repo_scanned 0`, so Steward saw blind-scan on
every code position of those repos (work item 9871f5ac). Those files are now read and examined by
the independence and stub-marker passes like any other source; an artefact past 16 MiB is still
reported unexamined, with its kind named (`data-artefact`, `minified-artefact`,
`vendored-artefact`). Hand-written source keeps the 1 MiB cap unchanged.

## 1.1.5 - 2026-11-14

Security register SC-56..SC-57 graduated from audit-shared-brain-2026-11-13, approved by Ron
2026-11-14 (decision 1f1bf2a9): an authorization tier assigned by action name where another action
reaches the same effect at a lower tier (SC-56), and a fix that revives a dormant data path
without re-auditing that path's sinks (SC-57). Both register copies updated identically.

## 1.1.4 - 2026-11-10

The code-standards exporter scanned no dependencies: `scripts/npm-audit-weekly.sh` was committed
mode 100644 (since before 1a18512) while `code-standards-cron.sh` runs it directly
(`timeout ... "$here/npm-audit-weekly.sh"`). On NEXUS every 6-hourly run got exit 126 and exported
every dependency position as not scanned (first exporter run 2026-11-10T18:26Z): a blind scan,
reported as not scanned rather than clean, but no dependency was examined.

- Index mode 100755 (`git update-index --chmod=+x`) for `scripts/npm-audit-weekly.sh` (run directly
  by the cron and by README's crontab and `./scripts/` examples), `scripts/register-nexus-runner.sh`
  (README and its own usage run `./scripts/register-nexus-runner.sh`) and
  `scripts/repo-hygiene-scan.py` (README's NEXUS crontab line runs it without an interpreter).
- `scripts/tests/test_exec_bits.py` (new): every tracked shell script or hook with a shebang, every
  `"$here/<name>"` a tracked script runs without an interpreter, and every `./scripts/<name>` /
  `.../dev-standards/scripts/<name>` a tracked doc or script runs without an interpreter must be
  100755 in the git index; a failure names the file and each place that runs it. Red on 9c90e0a
  (those three files), green after.

## 1.1.3 - 2026-11-10

Routine security audit 2026-11-10.2 (dev-standards): M3, M4 and L1, each found by all three
reviewers. Shared-brain 34910b22, 439c18f1, f48ee67e.

- M3 (34910b22) `scripts/npm-audit-weekly.sh`: a scanned repo's committed `.npmrc` configured the
  audit (proxy, strict-ssl, cafile, noproxy, scoped registries), so a forged all-zero answer
  read as clean. An env pin cannot fix that alone: npm ignores an empty `npm_config_*` value,
  so a repo `cafile=`/`noproxy=`/`@scope:registry=` survives (probed against npm 11.7). npm
  now never runs in the repo: package.json, the lockfile and each workspace manifest the
  lockfile names are staged (regular files only, no symlink on the path, nothing outside the
  repo) into an operator scratch tree with no `.npmrc`, with `npm_config_userconfig` /
  `npm_config_globalconfig` pinned to empty files the script creates, the public registry,
  `strict-ssl=true`, `proxy`/`https-proxy=false` and scripts off. A tree that cannot be staged
  is status `error`. `code-standards-cron.sh` header debt note replaced.
- M4 (439c18f1) `scripts/repo-hygiene-scan.py`: repo accesses followed symlinks (a `VERSION ->`
  secret reached the report and the shared-brain post as a "version"; `-> /dev/zero` passed a
  cap that trusted `st_size`). Every metadata probe of a path inside a scanned repo now goes
  through `lstat_repo_path` (no absolute or `..` path, lstat on every component, symlinks and
  Windows reparse points refused, only ENOENT/ENOTDIR read as absent) and every read through
  `read_repo_file` (that, plus `S_ISREG` re-checked on the descriptor, `O_NOFOLLOW|O_NONBLOCK`,
  bounded `read(cap + 1)`). The workflow walk (`walk_repo_files`, `followlinks=False`) replaces
  `rglob` and reports symlinked and unreadable entries as not examined.
- Security gate pass 1 on #87 (same version, unreleased):
  - SC-01: the first cut missed two accesses. `scan_security_register` compared
    `path.resolve()` with the canonical path, so a `SECURITY-CHECKS.md` committed as a symlink to
    the canonical was skipped as "the canonical file itself"; the self-skip is now an inode match
    on a real file reached with no link, and a linked copy reports `security-register-stale`.
    `.gitmodules` was probed with `is_file()` and handed to `git config -f` by repo path; it is
    now read with `read_repo_file` and git parses a private temp copy (new LOW
    `submodule-unexamined` when it cannot be read). `file_size`, the drift mtime, the hook-drift
    and hooksPath probes, the auto-apply marker and enrolment discovery use `lstat_repo_path`;
    git is run in a submodule path only when it is a real directory. The class test now
    inventories every filesystem access and every path argument to `run()` from the AST against
    an allow-list of operator paths (no dead rows allowed).
  - SC-04: `walk_repo_files` reported nothing on a permission or I/O error (`except OSError:
    return []`, `os.walk` without `onerror`); every error but absence is now listed as not
    examined. `discover_enrolled_repos` records each candidate it drops (symlinked, oversized,
    unreadable, not UTF-8, not a mapping) and the drift report lists them.
  - SC-13: this entry, the test docstring and STANDARDS.md now claim only what the boundary
    tests show.
  - `scripts/fleet-precommit-inventory.py` keeps its direct reads: it has no scheduled or mirror
    caller (manual run over the operator's own `D:/Projects` checkouts only).
- L1 (f48ee67e) `install.sh`: the lost-entries guard used a raw NUL as the `tr` argument, which
  bash strips, so it compared 0 with 0. Now `tr -cd '\000'`; no tracked file holds a NUL.
- Tests: `test_hygiene_symlinks.py` (new), npm `.npmrc`/staging cases checked against real npm
  config resolution, a lost-entries refusal and a no-control-byte check over tracked files;
  each is red against the pre-fix code.

## 1.1.2 - 2026-11-10

Security register SC-53..SC-55 graduated from audit-steward-sessionwatch-2026-11-10, approved by
Ron 2026-11-10 (shared-brain b37ab3ef): an enforcement point named with no consumer (SC-53), a
sanitizer that leaves Unicode format characters (SC-54), a finding resolved on absence rather
than a satisfied predicate (SC-55). Both register copies updated identically.
## 1.1.1 - 2026-11-10

Work item 2e17bd88 (security, high): `npm-audit-weekly.sh` failed open.

- `scripts/npm-audit-weekly.sh`: an errored `npm audit` (ENOLOCK, network, registry), a timeout,
  empty or unparseable output, a missing lockfile, or a missing `npm`/`jq` used to be written as
  zero counts, indistinguishable from a clean repo. Each repo entry now carries `status`
  (`ok` | `error`) and `reason`; `ok` only when both audits returned a numeric
  `.metadata.vulnerabilities` summary and no `.error`. On `error` every count is `null`, never 0.
  The roll-up has the same `status`, `repos_ok`, `repos_error`; totals cover examined repos only;
  zero repos discovered is an error. The report stays valid JSON without jq. New exit code 4
  (not examined; 3 stays "thresholds exceeded"). Per-audit timeout `AUDIT_TIMEOUT` (180s).
- `scripts/tests/test_npm_audit_weekly.py`: makes `npm audit` fail a dozen ways and asserts the
  output is never zeros.

## 1.1.0 - 2026-11-10

Code-standards facts for Steward (Ron, 2026-11-10, shared-brain 9d2d2d9e): Steward reviews new
and existing code on every estate repo, its own included, against these standards.

- `repo-hygiene-scan.py`: new checks `version-divergence` (§3), `tests-undeclared` (§2),
  `stub-marker` (no-stubs rule), `security-register-missing` and `security-register-stale`
  (with `--security-roster` / `--canonical-register`; without its argument a check is absent,
  never passed); `--no-layout`.
- `scripts/estate-mirror.sh`: shallow, read-only mirror of every repo on
  `estate/code-standards-roster.txt` (83 repos, Steward's five included; a test fails if any is
  dropped). Hooks off on every git call; nothing from a mirrored tree is executed.
- `scripts/code-standards-facts.py`: the hygiene and npm-audit reports as the Prometheus textfile
  `code_standards.prom` Steward parses (contract in the script header; fail-closed, atomic).
  Dependency facts read as not scanned until `npm-audit-weekly.sh` reports per-repo status.
- `scripts/code-standards-cron.sh`: the 6-hourly NEXUS entry point.
- Root `version.json` (§2/§3 floor, which this repo did not meet).
