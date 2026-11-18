---
status: proposed
date: 2026-11-18
deciders: Ron (ratification); proposed by session cortex-20261118-decision-binding-harmony (objective 13846bc1)
supersedes: null
---

# ADR-0001: Decision binding as an estate standard (proposed STANDARDS §18)

## Context

On 2026-11-18 Ron corrected six sessions himself. In five of the six, the governing decision already existed in shared-brain. It was lost for three reasons:
- binding was computed by semantic recall (query-dependent, top-k, popularity-weighted, 3072-byte budget);
- the decision had free-text scope (`project` keys scattered across `patriot-companies`, `patriot-provisioning` and `git`);
- no write-time check ran on briefs, objectives, filings or closes.

In the sixth case the rule was missing from the server's close path. The full survey, the traces and the plan are in `docs/plans/2026-11-18-decision-binding.md`.

The existing rules (new-topic recall, recall before a brief step: lesson `445edcc7`, standards-first) are norms that depend on the session remembering to apply them. Five of the six cases are failures of exactly those norms. **A norm with no tool boundary is not a control.**

## Decision

Adopt decision binding as STANDARDS §18. The mechanism lives in the services named below (§16: one owner per concern). This repo holds the rule text, and the six-case replay suite is the acceptance criterion.

### Proposed STANDARDS §18 text

> ## 18. Decision Binding
>
> **Ratified YYYY-MM-DD (Ron).** A session must not act on a brief, objective, plan, filing, close or canonical document that contradicts a standing decision unless Ron has been told first, with the decision id and the offending step.
>
> **Rule:**
>
> 1. **Decisions are records, not prose.** Every decision (Ron's or the seat's) is recorded in the Shared-Brain Decision Ledger (`brain_decisions record`). Each record carries:
>    - a **scope**: program/project, repos, path globs, work items, practice areas, or `global`;
>    - at least one **assertion**: `prohibits <practice>`, `requires <practice>`, or `answers <work item>`.
>
>    A decision that cannot be expressed this way is recorded `narrative: true` with the reason, and Steward reports it as unexamined coverage. The prose memory remains its narrative.
> 2. **Supersession is explicit.** A decision that changes an earlier one names it (`supersedes`). Two active decisions that disagree are a ledger conflict for Ron, never a silent expiry.
> 3. **Binding is computed, not recalled.** "What binds this work" is the deterministic ledger query over the session's resolved scope: git remote, handoff, objective. It is complete, ordered, never relevance-ranked and never budget-truncated. Every session start and every handoff consumption injects it.
> 4. **Artifacts are checked where they are written.** Shared-Brain checks handoff briefs, objectives, work-item filings and updates, and decision-kind questions against the ledger when they are stored, and stamps the result onto the artifact. A violation must be raised to Ron in the session's next response. The cortex-hooks binding gate refuses mutating tools until it is raised.
> 5. **Answers land on the question.** A decision that answers a `kind: decision` work item is appended to that item. Asking an answered question is refused.
> 6. **Canon follows decisions.** A decision that governs a canonical document or an automation files a reconcile work item with an owner in the same transaction. Steward's canon positions find documents that drift later.
> 7. **Steward verifies, independently.** steward-sessionwatch re-checks every session, handoff and objective against the ledger continuously. It pages Ron through n3xus-notify (Signal at all hours for binding conflicts) within minutes, with the decision id and the offending step, and re-pages until the conflict is acknowledged. Steward never writes the stamps it verifies.
> 8. **Unknown is not clean.** An unreachable ledger, an unscoped decision or a vocabulary gap is reported as *unexamined*, never as consistent.
>
> **Why:** the six corrections of 2026-11-18 (`e1de496d`, `445edcc7`). Five were reachable by a plain recall that no one ran at the right time.
>
> ### 18.1 Enforcement
>
> | Mechanism | Scope | Status |
> |---|---|---|
> | Shared-Brain Decision Ledger + write-time stamps (Shared-Brain ADR-0006) | every write | PENDING P1-P2 |
> | cortex-hooks binding block, handoff check, binding gate, `binding_unraised` claim-check (cortex-hooks ADR-0001) | every AI session | PENDING P3 (warn), P6 (block) |
> | brain-mcp-proxy offline binding (proxy ADR-0001) | outages | PENDING P4 |
> | steward-sessionwatch binding positions + paging (sessionwatch ADR-0002) | every session, every 5 min | PENDING P5 |
> | Steward canon-doc positions (steward ADR-0004) | registered canonical docs | PENDING P5 (observe) |
> | Six-case replay suite in CI on NEXUS runners | every change to the above | PENDING P6 |

## Consequences

- Recording a decision takes slightly longer: a scope and an assertion, chosen from the practice vocabulary or added to it. The seat does this, not Ron.
- The decision register rows (DR-0xx) stay where they are. They are the hook rules' governance and become ledger records with `scope: global` through the backfill.
- §14 and §15 are unchanged. A binding violation found mid-session is neither a discovered issue nor a new objective. It is raised to Ron at once.
- The norm "recall before executing a brief step" (`445edcc7`) becomes redundant once §18 is enforced. It stays until P6 closes.

## Verification

The rule is ratified when Ron accepts it. It holds when the replay suite (`Shared-Brain/tests/replay/2026-11-18/`) is green in CI and the one-week soak shows no unraised violation in sessionwatch's ledger.
