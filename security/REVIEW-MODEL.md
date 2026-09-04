# The two-tier security review model

Ratified by Ron on 2026-09-04 after the Max weekly budget was exhausted two
weeks running. Measured cause (shared-brain `e69cf6d8`): autonomous handoff
successor chains ran open-ended adversarial review rounds — 19 on one
shared-brain PR, 15 on one AIBrowser auth surface — and each round found
defects in the previous round's fixes without converging. The audit's job was
being done at gate cost, every session.

## The two questions

| Tier | Question it answers | When | Who | Cost profile |
|---|---|---|---|---|
| **Per-session gate** (`/security-gate`) | Does this change introduce a defect SHAPE we already know? | Before a session that touched a security surface ends | One reviewer on a small model (`security-gate` agent, Sonnet), given the register and the diff | Cheap; the shapes are enumerated; CAPPED |
| **Routine audit** (`/security-audit`) | What shapes do we NOT know yet? | Weekly, or per release, whichever first | Three independent reviewers on a large model, each given only the accumulated diff and a neutral description | Expensive; open-ended; SCHEDULED |

The register (`SECURITY-CHECKS.md`) is the contract between them: the gate
checks against it, the audit proposes additions to it. That feedback loop is
what makes the gate sharper over time instead of the rounds getting deeper.

## Per-session gate — mechanics

1. `node <cortex-hooks>/dist/security-gate.js check` decides whether another
   pass is permitted on this branch and builds the bundle (register first,
   then diff stat, untracked files IN FULL, then the diff).
2. The `security-gate` agent reads the bundle and reports, per register rule:
   CLEAR / FINDING / NOT EXAMINED. Unknown is never clean.
3. `security-gate.js record` appends the pass.
4. **The cap is mechanical.** After `security_gate_max_passes` (default 2) on a
   branch, `check` exits 3 and the command stops. A second pass covers only
   the fixes to the first. The session records the residual in its handoff
   brief and the change waits for the audit. The only ways past the cap: an
   operator token at `~/.cortex/security-gate/override/<key>` (the protected
   floor, written from the operator's own terminal), or an audit that clears
   the counter.
5. **Load-bearing gate.** Code touching auth, credentials, or mutation
   surfaces may MERGE behind a flag on a gate pass. The FLAG FLIP waits for an
   audit pass. Merged-and-inert is acceptable; deployed-and-load-bearing on a
   gate pass alone is not.

## Routine audit — mechanics

1. Weekly on the workstation that holds the checkouts
   (`Cortex-SecurityAudit-Weekly`, Sunday 03:00), over every repo in
   `cortex-hooks/config/security-repos.json`, diffing from the last audited
   commit (first audit: the last 30 days).
2. `security-audit.js plan` builds one bundle + orchestrator prompt per repo;
   a headless `claude -p` run spawns three reviewers in parallel with the
   file-first findings protocol (append each finding the moment it is formed —
   reviews have been lost to the turn limit twice).
3. Merge: deduplicate by (file, defect), keep the highest severity, note how
   many reviewers found each independently.
4. Graduate: each merged finding is either an instance of an existing rule
   (cite it) or a NEW SHAPE, written in the register format under "Proposed
   additions". Proposals need operator approval; the audit never edits the
   register.
5. `security-audit.js record` consumes the run's trailer, stores the audited
   commit, and clears that repo's gate counters.

## "Routine" decays into "never" — the dead-man

`Cortex-SecurityAudit-Deadman` runs daily (08:00): for every repo in the
roster, if the last audit is older than `security_audit_max_age_days`
(default 8) — or there has never been one — it pages `ntfy.nexus/cortex-alerts`.
It also reports yesterday's token burn by source and pages when yesterday
crossed the daily ceiling. A repo added to the roster is overdue from day one.

## Operator knobs (`~/.cortex/hooks.json`, outside every repo)

```json
{
  "chain_max_depth": 3,
  "chain_daily_token_ceiling": 1000000000,
  "chain_successor_model": "claude-fable-5-1",
  "security_gate_max_passes": 2,
  "security_audit_max_age_days": 8
}
```

Out-of-range values are REFUSED to the default and journalled, never clamped.
Nothing in the model reads an environment variable for a limit (SC-12).

## Why the register is versioned in each repo

A reviewer with no shared-brain access still sees it; the mechanical tests
that enforce a rule can cite it by id; a change to the register is a diff
someone reviews. The shared-brain copy is for recall; the repo copy is the
contract.
