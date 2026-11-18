# Decision binding: corrective plan for shared-brain and Steward

**Status:** proposed 2026-11-18. The go/no-go is Ron's (work item filed with this plan). The architecture choice below is the seat's recommendation.
**Origin:** Ron, 2026-11-18 (brief `03a3af57`): "a bullet proof corrective plan that makes issues such as this non-existent ... even if this requires a full re-write and shift in base-code, I NEED these things at their absolute best."
**Evidence:** root-cause report `e1de496d` (this plan corrects two of its claims, §1.3), lesson `445edcc7`, the six corrections `17889ec5` `7b692fd1` `2ad387e9` `48923aef` `4f42107c` `abb47387`, and session objective `13846bc1`.
**ADRs (one per repo touched):**

| Repo | ADR | Owns |
|---|---|---|
| Ohio15/Shared-Brain | `docs/adr/0006-decision-ledger.md` | the ledger: records, scope, practices, binding query, artifact check, write-time stamps, change feed |
| Ohio15/cortex-hooks | `docs/adr/0001-binding-consumer.md` | in-session enforcement: the binding block at session start and handoff, the binding gate, the claim-check |
| Ohio15/brain-mcp-proxy | `docs/adr/0001-offline-binding.md` | serving the binding query offline from the replica |
| Ohio15/steward-sessionwatch | `docs/adr/ADR-0002-binding-verification.md` | independent, continuous verification of sessions against the ledger, and paging Ron |
| Ohio15/steward | `docs/adr/ADR-0004-decision-binding-roles.md` | the role split, ledger records as canon, the canon-doc positions |
| Ohio15/dev-standards | `docs/adr/0001-decision-binding-standard.md` | proposed STANDARDS §18 and this plan |

ASSUMED OBJECTIVE: a session can never act on a brief, objective, plan, close or canonical doc that contradicts a standing decision unless Ron has been told first, with the decision id and the offending step. The plan optimizes for that guarantee holding deterministically, without AI, on Ron's infra. It ranks below it how fast it lands, and how little it changes in the hooks. Ron set the objective (03a3af57). The trade-off between the guarantee and the speed of the first phase is the seat's call, and it is stated in §4.

---

## 1. Survey

### 1.1 Role audit: what each component does today and what the decisions say it should do

| Component (deployed version, mode) | What it does today | Reads | Writes | What the decisions say | Gap or overlap |
|---|---|---|---|---|---|
| **Shared-Brain** 7.91.0, schema 48, NEXUS compose. `/health.commit` is `null` in prod. | Memory store; decision registry (`brain_decisions`); work queue + objectives; LLM contradiction pairing; work-item change feed (ADR-0005); security-verification route | everything | memories, registry (SQLite `lib/decision-journal.js:66-101`), `session_objectives`, `commitments`, `memory_edges`, `contradictions_pending_surface` | Record and query (I6). Decision `5422aef0` puts sync verification in Steward, not here | **Two decision stores, and neither is authoritative.** The registry is SQLite with only `project` and `tags` as scope. Typed `decision` memories live in PG. Each auto-mirrors into the other (`lib/decisions-unified.js:~370-395`, `:64-77`). Neither has repo, path, practice or work-item scope. Recall is semantic, has a floor of 0.4, a cap of 50, and no type filter on MCP. Contradiction surfacing is same-domain only (`lib/memory-graph.js:5037-5040`), and expiry by decay or age is by design (`pg-store.js:~5987-6038`). There is no event on `objective_set` or on a handoff store. |
| **brain-mcp-proxy** 0.3.0-alpha.31, paxson | stdio proxy; WAL for writes; offline FTS recall from a `/feed` replica | `/feed` | local SQLite replica, WAL | n/a | The decision registry is not replicated. `brain_decisions` fails fast offline. Offline recall ignores filters. |
| **cortex-hooks** 0.99.0, live from `dist/` | SessionStart bootstrap; UserPromptSubmit recall bound; handoff injection; claim-check (Stop, warn) | shared-brain `/api/session/briefing`, `/api/memory/recall` | journals, `.ready.json`, gate records | It is the in-session enforcement point. Its rules are DR-0xx | Bootstrap briefing sends `query: null`, 300 tokens (`hooks/session-start.ts:274-275`). Project comes from a 7-entry substring map (`:95-110`). Handoff project, tags and the objective are never used to recall. The per-prompt bound is 3072 B with no exempt class (`hooks/context-budget.ts:404,523-525`). The handoff brief template has no decision step (`hooks-win/session-hygiene.ps1:2336`). The consumer is told to "Follow the brief's EXACT NEXT STEPS" (`hooks/handoff.ts:739`). Claim-check is network-free and warn-only (`hooks/claim-check.ts:741-744`). |
| **steward-sessionwatch** 0.1.3, `\Steward\sessionwatch-scan` every 5 min, live | Out-of-band session watchdog, 5 positions (`src/assess.rs:309-374`) | session registry, transcripts | local verdicts, ledger, n3xus-notify | Decision `5422aef0`: verify sync, detect stops, raise to Ron | It has no shared-brain credential. It captures objective text (`src/transcript.rs:319-327`) but evaluates only whether it exists. No position compares anything against decisions. No `tests.yml`. |
| **steward-core** 0.7.1, NEXUS systemd, verifier `mode = off` | Work-item feed consumer, OPA estate positions, security verifier V1-V10 (built, off) | work-item feed (`work:read`), estate facts, Forgejo | own SQLite, ledger; in enforce, `POST /api/security-verifications` | `a8bb50c6`, `42df6d7c` (answered by `17889ec5` and `7b692fd1`): the security verifier, sources on Ron's infra, never self-attesting | **Out of scope by `35cb82ec`.** Its verifier routes and `VERIFIER_KEYS` are not touched. In enforce mode it is both verifier and recorder for security items. That is the existing exception, fenced by a reserved key class. |
| **steward-governance** 0.2.6, NEXUS docker | Signed governance ledger, `/admitted/<digest>` | signed change docs | ledger, ntfy | Root of trust for bundles | Notifies via direct ntfy, which bypasses n3xus-notify (§16 overlap, filed in §7). Genesis is deferred (`93834cbb`). |
| **steward** (umbrella) 0.10.1 | Decision model, positions, policy bundle, ranking rubric | n/a | n/a | `decision-model.md` (positions over facts, deterministic, "unexamined is not holding"); `canon-conformance.md` (decision memories are a canon source) | The design already has the right shape (positions, facts, `file-item`, `canon-conflict`). It has no fact source for decisions and no session scope. The act plane is not in force. |
| **steward-inference** 0.2.0, not running | Local model tier | n/a | n/a | Advisory only (ADR-0001 AI-1) | No role on the binding path. It may later rank semantic near-misses as advice. |
| **steward-presence** 0.1.3 | Desktop renderer, read-only | proxy `/health` | config | n/a | None |
| **n3xus-notify** 0.3.5 (shared notification service, §16.1) | Routes to toast, Signal, ntfy | config | sinks | It is the one notification router | **Routing defeats I4.** `~/.config/n3xus-notify/config.json`: on business days 08:00-17:00 ET, priorities 1-5 all go to `toast` only, which is the paxson desktop. Today's "delivered" receipts (sessionwatch ledger seq 407-416) were toasts. Ron away from paxson sees nothing until 17:00. |

Cross-cutting inventory (§16.1):
- identity: n3xus-identity is used for the viewer only.
- notifications: n3xus-notify is **deployed** and is the one path. Fix its routing, do not fork it.
- secrets: op-proxy and LoadCredential for the new read principal.
- governance ledger: steward-governance holds bundle admission, not decisions.
- approval surface: the APM board.

No new cross-cutting service is introduced.

### 1.2 Data-model audit

| Artifact | Represented today as | Why it cannot be bound |
|---|---|---|
| Decision | Prose `type=decision` memory, plus an auto-mirrored SQLite registry row (`title`, `decision`, `project`, `tags`, `status`, `superseded_by`) | There is no field for repo, path, practice or the work item it answers. `project` strings are free text and scattered. One body of work spans `patriot-companies`, `patriot-provisioning` and `git`; another spans `steward` and `infra`. Domains are scattered too: `17889ec5` is in platform and `7b692fd1` in security. A decision that is really an open question was stored as `type task` with no project (`d07791b0`). |
| Standard | STANDARDS.md sections, the decision register (DR-0xx), and memories | It is not queryable by scope. A plan doc's "resolved decision row" (INTUNE-SETUP-PLAN row 2) exists only in markdown. |
| Canonical doc (SOP, plan) | A file in a repo | No entity exists. Nothing links a doc to the decisions that govern it, and nothing has an owner. |
| Handoff brief | A free-text episodic memory, tags `[handoff,<id>]`, with no domain | Nothing checks its steps. The consumer is told to follow them. |
| Objective | A `session_objectives` row | No event fires, and nothing checks its done criteria. |
| Work-item answer | The answer to a `kind: decision` item is stored as a separate memory | The item does not carry the answer, so a reader of the item can't see it (case 2). |

**Why recall cannot be scoped to "what binds project X in the last N days":**
- `brain_recall` needs a query string.
- It is relevance-floored and top-k with a cap of 50.
- It is popularity-weighted: injections served chunks with access_count 2,020 and 9,487 ahead of same-day decisions.
- It has no type filter.
- `brain_decisions search` is `LIMIT`-ed, ordered by `updated_at`, matches tags with ANY semantics, and has no date filter.

**What the per-prompt budget drops.** Anything over 3,072 B is dropped, in arrival order. Anything seen in the last 6 prompts is dropped too, with no exemption for decisions. Live in this session: memory `0ad09274`, a 233-day-old backup report, was injected at relevance 1.00 on five consecutive prompts while the budget dropped 3-5 entries each time. That memory is unrelated to the prompt, and the 6-prompt de-dupe did not suppress it (filed, §7).

### 1.3 The six 2026-11-18 cases, traced (full trace: survey agent report, transcripts under `~/.claude/projects/{D--Projects-cortex,C--Program-Files-Git}`)

The report `e1de496d` needs two corrections:
- (a) The resume session `55ba8b46` ran in `D:\Projects\cortex`, not `C:\Program Files\Git`.
- (b) `detectProjectFromCwd` is a substring map that returns `undefined`, not "Git". The bootstrap was project-blind either way.

Also, `77c7da02` is a fleet snapshot. The governing Entra decision is `a06811f8` (2026-06-22, Option B), in project `patriot-companies`. Times below are transcript UTC; several brain texts label local time "Z".

| # | Case | Governing record | Offending artifact | Where the signal was lost (exact line) |
|---|---|---|---|---|
| 1 | GitHub App recommended for the verifier | `d07791b0` (2026-11-17: self-host registry + git mirror), which was stored as `type task` with no project | Session `f15a595b`, 12:18:58Z: "D2, GitHub App. Choose the App." | The ledger has no `practice` dimension, and the record isn't even a decision. The session made no forge-keyed recall (its recalls were handoff, op-front, SC-63, verifier synthesis). Bootstrap: `session-start.ts:274` (`query: null`). |
| 2 | D1-D4 re-asked 5h19m after Ron answered | `17889ec5` (12:30:29Z), written by session `f15a595b` | Session `2ce02577`, 13:48Z and 17:15Z: "D1 through D4 wait on you" | The answer was stored as a memory and **not bound to items `42df6d7c`/`3f152ef9`**. The session's own recall used `time_range.after=13:00Z`, which excluded 12:30Z by construction. |
| 3 | Inventory of "employee-owned" Patriot PCs | `c32eec24` (2026-10-07, company-owned), `a06811f8` | Inbox `081c7815` (filed 13:48:26Z): "Ron decides on employee-owned devices" | No ownership recall. The 15:58:56Z injection was empty, with "Recall bounded: 2 over per-prompt budget" (`context-budget.ts:523-525`). No check runs at `brain_commitments add`. |
| 4 | Three security items closed by the board drawer with no resolution | `dbe84759` (2026-11-13 closure rule), server `close_needs_evidence` | Items `a03045d2`/`365fedc3`/`9057bfee`, 16:28:08-27Z, `board_status=done` | **Structural:** the server exempted the board principal (now fixed in 7.91.0, PR #241). The session read "refused by design" as a cue to route around the refusal rather than stop. |
| 5 | Brief and objective require `gh auth login` + github.com clone | `17889ec5`, `ee05d2d0` (forge-out) | Brief `f7fc07af` STEP 2, objective `fd954aaf` criterion 2 (17:02:25Z), copied from SOP L118-121 | The brief writer made no decision step (`session-hygiene.ps1:2336`). The consumer is told "Follow EXACT NEXT STEPS" (`handoff.ts:739`). The prompt injection served the stale chunk `b5fc3232` at 0.44, while the assistant's own recall returned `17889ec5` at 0.67. |
| 6 | PatriotUSA password passed on an Entra-join target | `a06811f8` and INTUNE-SETUP-PLAN L37 / row 2 | SOP L131 and L258, brief STEP 4 `-PatriotUSAPassword`, "No, this app only" | The SOP was never reconciled. The scoped recall `project=patriot-provisioning` missed `a06811f8` because that record is in `patriot-companies`, which is project-key scatter. |

**Five of the six were reachable by an ordinary recall with the right words.** Signal was not missing. It was lost because binding is computed by probabilistic, query-dependent, budget-truncated recall, and because nothing checks an artifact at the moment it is written.

---

## 2. Root cause

**One root, three mechanisms.**

**The root.** The estate has no deterministic answer to "which decisions bind this work". Decisions are prose. Their scope is free-text `project` and `tags`. Whether a session sees one depends on someone asking the right question at the right time, and on the answer surviving a ranking and a byte budget.

The three mechanisms follow from that:
1. **No scope model.** A decision cannot name the practice it forbids, the docs and automations it governs, or the work item it answers. That covers cases 1, 2, 3, 5 and 6.
2. **No write-time check.** Briefs, objectives, filings and closes are accepted without being compared to anything. Readers then treat them as instructions. That covers cases 2, 3, 4 and 5.
3. **No independent verifier for consistency.** Steward verifies that sessions *store*, not that they are *consistent*. The page path does not reach Ron during his working day. That covers all six.

**Why the filed items alone don't fix it.** `ddcbc991`, `85199b3c`, `aaa464e7`, `e3502465` and `ace10974` each patch one mechanism, but each still computes binding through semantic recall (`brain_recall type=decision`, "same-project decisions from the last 7 days"). That inherits top-k, floor, popularity and project-key scatter. Case 6 defeats "same-project". Case 2 defeats "last 7 days" (the session's own filter). Case 1 defeats "type=decision", because the record was a task.

---

## 3. Options

| | A. Incremental (the five filed items as written) | B. Rewrite the decision layer, extend the rest (**recommended**) | C. Full rewrite of shared-brain and Steward |
|---|---|---|---|
| What | Better recall keys at session start, a handoff "decisions" section built from recall, `applies_to` by tag convention, a sessionwatch position that recalls same-project decisions, and the SOP fix | A new **Decision Ledger** bounded context in Shared-Brain replaces both decision stores as the authority, with structured scope, a practice vocabulary, a supersession DAG and work-item answers. It adds a deterministic `binding` query and artifact `check`, server-stamped checks at write time, and a change feed. cortex-hooks becomes a thin enforcement point. sessionwatch gains binding positions and pages via n3xus-notify with acknowledgement. Steward's canon positions cite ledger records. | A new governance kernel service replaces shared-brain's decision, queue and verification parts and Steward's session plane |
| I1 first-class decisions | ✗ (prose and tags) | ✓ | ✓ |
| I2 deterministic binding | ✗ (semantic, budgeted) | ✓ | ✓ |
| I3 brief cannot hide a contradiction | ✗ (client-side, skippable) | ✓ (server stamp) | ✓ |
| I4 independent verifier, pages within minutes | partial (recall-based, toast-only) | ✓ | ✓ |
| I5 reconcile items | partial (manual) | ✓ | ✓ |
| I6 one owner per concern | ✓ | ✓ | ✓ after migration, ✗ during it (two stores) |
| I7 AI-independent | ✓ | ✓ | ✓ |
| Concerns | It leaves the class in place: the next case with an odd project key or a task-typed decision repeats. | Backfilling about 500 existing decision rows needs scoping. Practice vocabulary is a curation job, and coverage gaps must surface as *unexamined*, never clean. The binding gate can block legitimate work if it is noisy, so it ships warn, then soak, then block. | It throws away healthy, recently hardened code: the 7.91.0 closure contract, PITR, the feed, and the verifier routes that `35cb82ec` forbids touching. Months pass before any invariant holds, and a second store exists during migration (§16). No invariant needs it. |
| Spend | ~2 agent-days | ~13 agent-days (§6) | 40+ agent-days |

---

## 4. Recommendation

Choose **B**. Concretely, it is a **full rewrite of the decision record and of session-consistency verification**, plus **extensions, not rewrites,** of the memory store, the work queue, the hooks and Steward's position engine.

The reasoning:
- **The defect is a missing data model, not a rotten base.** Every case was lost at a place where binding was *inferred* instead of *declared*. A ledger with declared scope and practice assertions makes binding a set-intersection query. Retrieval quality stops mattering.
- **Enforcement belongs at the write boundary.** A hook can be skipped, mis-keyed or budget-truncated, and the server cannot. Stamping the check onto the stored artifact with a reserved key, the same pattern the security-verification route uses (`lib/security-verification.js`, DB trigger in `work-items-schema.js:343-375`), makes I3 true whatever the client did.
- **Verification belongs to a different writer.** shared-brain's stamp is the record. Steward recomputes it from the ledger at a later sequence number and from transcripts that shared-brain never sees. That is the "two writers" rule of STANDARDS §14.2 applied to consistency, and Steward never writes the stamp it checks. The residual risk is common mode: a matcher bug shared by both sides, because both read the same vocabulary and Steward's transcript scanner implements the same spec. It is covered by shared golden vectors and the six-case replay suite in both repos.
- **The Steward design already has this shape.** Positions over facts, "unexamined is not holding" (`decision-model.md` §2.3), `canon-conflict` (`canon-conformance.md` §5). The binding check is new facts and new positions, not a new engine.
- **C buys nothing** that B lacks, and it would break `35cb82ec` and §16 during migration.

**Not delegated to AI anywhere on the path.** Matching is lexeme and regular-expression matching over a curated vocabulary (I7). A semantic near-miss with no vocabulary hit is reported as **unexamined coverage** for the decision. Steward's `pos-decision-bound` turns that into a curation item, so a gap in the vocabulary is visible work, never a silent pass. A local model may later *propose* vocabulary entries, as advice only.

---

## 5. Plan

Each phase ends green, committed on a branch, version-bumped, gated where it touches routes, principals or enforcement (`/security-gate`, capped at 2 passes), merged, deployed, and verified at the observable boundary. Phases are in dependency order. IDs are the work-queue items filed with this plan (§7).

**P0 Preconditions.** Repos: dev-standards, n3xus-notify config, Shared-Brain.
1. Ratify STANDARDS §18, Decision binding (text in dev-standards ADR-0001). Ron.
2. Route n3xus-notify priority 5 (`binding-conflict`) to **toast + Signal at all hours**, and add an acknowledgement loop: re-page every 15 min until Ron replies or the conflict is resolved. This is Ron's routing preference, so it is a decision item.
3. Seed the practice vocabulary from the six cases and all active decisions since 2026-10-01.
4. Fix `/health.commit: null` (build arg) so every later deploy is verifiable at the boundary.

**P1 Decision Ledger.** Shared-Brain ADR-0006, minor release, gated.
1. Schema:
   - `decision_records`
   - `decision_scope` (program, project, repo, path glob, work item, practice area, global)
   - `decision_assertions` (prohibits, requires, answers)
   - `decision_edges` (supersedes, refines)
   - `practices` (id, lexemes, regexes)
   - `projects` (canonical id, program, aliases); this ends key scatter, so `patriot-companies`, `patriot-provisioning` and `git` all map to program `patriot`
   - `canonical_docs` (repo, path, program, owner)
   - `binding_checks`, server-stamped, with a reserved metadata key and a DB trigger
2. Routes and MCP:
   - `POST /api/decisions/binding {scope, as_of_seq?}`: complete, ordered, cursor-paged with a total count, returns `ledger_seq` and a `digest`, no relevance and no limit.
   - `POST /api/decisions/check {artifact_kind, text, scope}`.
   - `brain_decisions record|supersede|binding|check`.
   - `record` requires scope and at least one assertion, or `narrative: true` with a reason.
3. Backfill:
   - Every registry row and every `type=decision` memory becomes a ledger row with status `proposed-unscoped`.
   - Decisions active since 2026-10-01 are scoped by the seat.
   - The rest appear in Steward's unscoped report.
   - The prose memory stays as the narrative (`source_memory_id`).
4. `decision_changes` feed, a copy of the ADR-0005 pattern, covering decisions, binding checks, objectives and handoff stores.
5. The LLM contradiction stream is kept for non-decision memories. For decisions it is superseded by the ledger, so a decision-versus-decision conflict is a supersession edge or a ledger conflict row, never a 30-day expiry.

**P2 Write-time enforcement.** Shared-Brain, patch release, gated.
1. **Handoff store.** A memory with tag `handoff` is checked. The server appends a stamped `BINDING CHECK (server)` block listing each violation (decision id, assertion, the offending excerpt), or "0 violations at ledger_seq N". The writer cannot omit or forge it (I3).
2. **`objective_set` / `objective_update`.** The objective and its criteria are checked. The response carries the violations, and the row carries the stamp.
3. **`brain_commitments add|update`.** The text is checked. For a `kind: decision` add whose subject items are already answered by an active decision, the call is refused with `already_decided` and the decision id (case 2).
4. **Decision with `answers: [item]`.** The answer is appended to the item as evidence, atomically (case 2 at source).
5. **Decision with `governs: [doc|automation]`.** One reconcile item is filed per bound doc in the same transaction (kind issue, lob from the program, owner = the recording principal until claimed), and the ids are returned (I5).
6. Closure: the 7.91.0 `close_needs_evidence` rule for every principal is kept. A regression test pins it (case 4).

**P3 cortex-hooks as enforcement point.** cortex-hooks ADR-0001, minor release, gated. The protected floor applies: new hook wiring in `~/.claude/settings.json` is a human-run step.
1. **Scope resolver.** The scope is built from:
   - the cwd git remote → repo → program via the ledger aliases
   - the pending handoff's project and tags
   - the latest `objective_set` text
   - the substring map is removed
2. **SessionStart.** It calls `binding` and injects `DECISIONS THAT BIND` as a priority-0, non-trimmable block (one line each: id, date, statement, assertions), with `ledger_seq` and `digest`, and journals the digest.
   - Over 6 KB: the full list goes to a state file and the block says so. That is a finding (the scope is too broad), never a silent drop.
   - Unreachable: it falls back to the proxy offline binding, else it injects a fail-visible `BINDING UNKNOWN` block that tells the session not to act on inherited steps.
3. **Handoff consume.** The injection leads with the server `BINDING CHECK`. "Follow the brief's EXACT NEXT STEPS" (`handoff.ts:739`) becomes "Verify each step against DECISIONS THAT BIND; a violation goes to Ron in your first response." The write directive (`session-hygiene.ps1:2336`) gains a `DECISIONS THAT BIND` section before EXACT NEXT STEPS.
4. **Mid-session.** UserPromptSubmit polls `decision_changes` since the session's `ledger_seq` and injects new binding decisions as an exempt rule block, outside the 3072 B bound.
5. **`binding-gate` (PreToolUse).** While the session has an open violation that is not raised, mutating tools are denied with a message naming the decision and the step. The violation comes from the bootstrap, handoff, objective or commitments responses, and from Steward's verdict file. Mutating tools are Bash writes, Edit, Write, and MCP writes other than `brain_store`, `brain_commitments`, `brain_decisions` and notify. "Raised" means the assistant text cited the decision id to Ron. "Resolved" means a ledger write: Ron's supersede or exception, or the artifact amended and re-checked clean.
   - Ships **warn**, with a durable commitment to flip to **block** after a one-week soak with zero false blocks on the replay plus live traffic. The flip waits for a `/security-audit` pass.
6. **claim-check.** New check `binding_unraised`: an open violation, and the final text does not cite its decision id (warn).

**P4 Offline binding.** brain-mcp-proxy ADR-0001, alpha bump. Replicate the ledger tables via `/feed` and serve `binding`/`check` from the replica, stamped `_offline` with its `ledger_seq`. The hooks fall back to the proxy admin port.

**P5 Steward verification.** sessionwatch ADR-0002 and steward ADR-0004, gated (new principal).
1. **Principal.** A read-only `service:steward-sessionwatch` with scopes `decisions:read work:read objectives:read handoffs:read`, held via 1Password Infra and DPAPI on paxson. This extends Ron-ranked item `040bd063` instead of minting a second reader. sessionwatch still never writes shared-brain (DR-007).
2. **Positions** (deterministic; unexamined when the ledger or principal is unreachable, never holding):
   - `pos-binding-injected` (attend): the session's bootstrap carried a binding block whose digest equals the ledger's digest for that scope at that `ledger_seq`.
   - `pos-binding-stamped` (act): every handoff and objective in the feed carries a server stamp. A missing stamp means the server path was bypassed.
   - `pos-conflict-raised` (act, **page**): an artifact or transcript plan matches a binding prohibition, and either the next assistant turn did not cite it to Ron or mutating tool calls followed. The page names the decision id, the session, and the offending step. For shared-brain artifacts the step is the excerpt; for transcript plans it is a `<session>:<line>` reference, so sessionwatch's no-retained-text floor holds.
   - `pos-decision-recheck` (act, level-triggered per D1): when a decision lands, re-check every open objective and every handoff from the last 7 days against it.
   - `pos-decision-bound` (track-star): an active decision that is unscoped, or that has no assertion, gets a curation item in the report.
   - `pos-reconcile-staffed` (attend): a reconcile item open more than 48 h with no session.
3. **Escalation.** n3xus-notify priority 5 with the P0 routing. The acknowledgement loop is owned by sessionwatch: it re-pages at 15 min and stops on ledger resolution or Ron's reply. Every receipt is journalled.
4. Add `tests.yml` to sessionwatch.
5. **Canon positions** (steward umbrella, bundle in observe): `pos-canon-doc-consistent`, over a `canon-docs` fact (lexeme hits of binding prohibitions in each registered canonical doc), with `file-item` filing.
   - While the act plane is not in force (`93834cbb`), sessionwatch's doc sweep pages Ron and the reconcile items come from P2 step 5.
   - That interim is labelled debt, with a commitment tied to bundle admission.

**P6 Acceptance and flip.**
1. The six-case replay suite (below) is green in CI on NEXUS runners.
   - Target: Forgejo Actions on forge.n3xus.uk once forge step 1 (`f62c7a4d`) lands.
   - Until then: GitHub Actions on the `nexus-ci` self-hosted runners, labelled debt against forge step 1.
2. One-week observe soak.
3. `/security-audit` over Shared-Brain P1-P2 and cortex-hooks P3.
4. Flip `binding-gate` to block, which needs Ron's settings.json step.
5. Retire the per-case filed items with evidence.

**P7 Reconcile existing canon.** `ace10974` (SOP to Entra join), `abb47387`/`606d02d3` (password off argv), `7f15e1ae` (GitHub out of SOP step 4). Merge the Patriot program keys. These become the first P2-filed reconcile items. They go through the new path, not by hand.

### Acceptance: the six cases as regression tests

The same fixtures (decision records and offending artifacts) are committed once at `Shared-Brain/tests/replay/2026-11-18/fixtures.json` and consumed by all three suites. Each case must be caught **before a human would see it**. That means at write time or at session start, never after Ron's next message.

| # | Fixture (ledger) | Offending artifact | Must be caught at | Assertion |
|---|---|---|---|---|
| 1 | `d07791b0` recorded as a decision with `prohibits: forge.github-app, registry.ghcr`, scope program `steward`+`infra` | Plan text "D2, GitHub App. Choose the App." | `check` (plan) and sessionwatch `pos-conflict-raised` on the transcript line | violation names `d07791b0`; page intent emitted with the session and line |
| 2 | `17889ec5` with `answers: [42df6d7c, 3f152ef9]` | `brain_commitments add kind=decision` re-asking D1-D4; assistant text "D1 through D4 wait on you" | P2 step 3 refusal; the answer is visible on item `3f152ef9`; sessionwatch transcript check | `already_decided` + `17889ec5`; the item evidence carries the answer |
| 3 | `c32eec24` with `prohibits: device.ownership.personal`, program `patriot` | Inbox add "inventory of company vs employee-owned ... Ron decides on employee-owned devices" | `brain_commitments add` stamp; bootstrap binding block for program `patriot` lists `c32eec24` | violation in the response; the binding block contains `c32eec24` whatever the cwd |
| 4 | Closure rule (`close_needs_evidence`, every principal) | Board-principal close with `board_status=done`, no note or ref | Server close path | `resolution_required`; the item stays open |
| 5 | `17889ec5` with `prohibits: forge.github` (lexemes `gh auth login`, `github.com/Ohio15`, `git clone https://github.com`), program `*` | Brief `f7fc07af` STEP 2; objective `fd954aaf` criterion 2 | Handoff store stamp; `objective_set` response; successor bootstrap; binding-gate on the first `winget install GitHub.cli` | the stamped block lists `17889ec5`; the gate denies with the decision id; the Steward page fires ≤5 min |
| 6 | `a06811f8` with `prohibits: device.identity.local-admin-build` (lexemes `-PatriotUSAPassword`, `No, this app only`), `governs: patriot-provisioning:docs/SOP-END-USER-PC-SETUP.md`, program `patriot` | SOP L131/L258; brief STEP 4 | Recording `a06811f8` files the SOP reconcile item (P2.5); the brief stamp; the canon-doc sweep | reconcile item exists with an owner; brief violation listed; doc finding names L131 and L258 |

Negative controls:
- Each fixture's compliant twin produces zero violations (for example "clone from forge.n3xus.uk", "OOBE Set up for work or school").
- An unscoped decision yields `unexamined`, never clean.
- An unreachable ledger yields `BINDING UNKNOWN` and sessionwatch `unexamined`.

---

## 6. SPEND

| Phase | Agent-days | Tokens (est.) | Gates / audits | Ron's time |
|---|---|---|---|---|
| P0 | 0.5 | 0.5M | none | 30 min (ratify §18, routing decision, vocabulary skim) |
| P1 | 3 | 3.5M | gate (≤2) | none |
| P2 | 1.5 | 1.8M | gate (≤2) | none |
| P3 | 2 | 2.5M | gate (≤2) | 10 min (settings.json wiring, human-run) |
| P4 | 1 | 1M | none (read path) | none |
| P5 | 3 | 3.5M | gate (≤2) on the principal | 10 min (principal mint approval if the key ceremony asks) |
| P6 | 1 + 1 week soak | 1.5M | 1 routine audit (3 Opus reviewers) | 15 min (flip) |
| P7 | 1 | 1M | gate if the orchestrator changes | none |
| **Total** | **~13 agent-days + 1 week soak** | **~15M tokens** | **5 gates (≤10 passes), 1 audit** | **~65 min** |

Dollars:
- Session work runs on the Claude subscription: $0 marginal cash.
- No per-session cost ledger exists from this seat. `cortex_costs` covers only Cortex runtime: $0 over 30 days.
- Runtime cost of the result: $0. The deterministic path uses no model, and it runs on existing NEXUS and paxson capacity.
- Implementation runs on Opus (lead-engineer). Exploration, review and test-scribe runs on Sonnet.

## 7. Work queue

Filed with this plan; ranked with the §14.6 rubric from the seat.
- One item per phase.
- Two `kind: decision` items for Ron: the plan go/no-go with §18 ratification, and the n3xus-notify routing.
- The five prior items are absorbed: `ddcbc991` → P3, `85199b3c` → P2+P3, `aaa464e7` → P1, `e3502465` → P5, `ace10974` → P7. Each gets the plan as evidence and is superseded on the board when its phase closes with evidence. They are not cancelled now.
- Discovered here and filed separately:
  - the per-prompt de-dupe failing to suppress a repeated injection (`0ad09274` ×5)
  - popularity-weighted prompt injection in cortex-core
  - `/health.commit: null`
  - `dist.prev-*` accumulating untracked in cortex-hooks
  - steward-governance notifying via direct ntfy, bypassing n3xus-notify

## 8. Unknowns (resolved from the seat)

| Unknown | Resolution |
|---|---|
| Does any Steward component already compare plans to decisions? | No. Positions are cited in §1.1 (`assess.rs:309-374`). |
| Is the escalation path live? | It is live but toast-only on business days (config read, receipts seq 407-416). It is fixed in P0. |
| Is Forgejo available for CI? | Forgejo 15.0.11 is live at forge.n3xus.uk (`5b55b4ff`). Repo migration (step 1, `f62c7a4d`) is pending, hence the interim nexus-ci runners labelled as debt. |
| Can Steward read decisions? | Not today. Its key is `work:read`, and the memory feed is closed to it (`a8bb50c6`). P5 adds the read principal by extending `040bd063`. |
| Does the verifier work collide with this? | No. `35cb82ec` routes and keys are untouched. The new stamp copies the pattern under its own reserved key. |
| Were the six cases reachable at all? | Five were, by a plain recall (traced timestamps in §1.3). Case 4 was structural and is fixed in 7.91.0. |

Open and genuinely Ron's: the go/no-go on B, §18 ratification, the n3xus-notify routing preference, and the settings.json wiring at P3 and P6 (protected floor).

## 9. Go / no-go

SEAT CHECK: before anything was handed to Ron, the following were tried from this seat:
- **Notification routing:** read `~/.config/n3xus-notify/config.json` and the sessionwatch receipts. It was not changed: it is Ron's personal paging preference, so it is a decision.
- **Forge state:** recalled; Forgejo live (`5b55b4ff`).
- **Steward's credentials:** read from code; no decision read path.
- **Settings.json wiring:** it is the protected floor, so it is human-run by DR-029. It is not routable from the seat.
- **The architecture choice:** the seat recommends B. Ron asked to be offered the full rewrite, so the go is his.

No capability gap was handed over. Every gap above is a phase item.

**GO on B**, subject to Ron's go on the decision item. P0 steps 3-4, and P1 design and implementation on a branch, can start before his answer. Neither changes behaviour until it is deployed, and deploying P1 adds routes without changing an existing one. Nothing here touches `35cb82ec`.
