# Handoff — turning lessons into enforced invariants

**Date:** 2026-08-06
**Origin:** truck-mcp Phase 3 control build. Ron's question, verbatim: *"are lessons from
discovered issues being tracked, resolved and then used to drive standardization practices?
like what are we doing with the info other than finding the same issues over and over
because we're not improving the delivery from the things that already bit us?"*
**Status:** diagnosis complete and evidence-backed. Implementation NOT started.

---

## The finding

We produce excellent diagnosis and then store it in the least durable format we have.
A lesson's output is currently a *memory*, not a *constraint*.

- A rule in prose (shared-brain, a session handoff, `~/.claude/CLAUDE.md`) is **advisory**.
  It only fires if some future agent reads it, recognises it applies, and chooses to act.
- A rule in a failing test is **enforced**. It fires whether or not anyone remembers it.

Roughly a fifth of what we've learned is enforced. The rest is re-derived, re-argued and
re-fixed on every pass. That is the whole answer to the question.

### Evidence gathered 2026-08-06 (truck-mcp @ `def10ff`)

Where the loop **works** — and this is the model to copy:

- `tests/mutation.py` breaks the code on purpose and fails if no test notices.
  **58 mutation-proven assertions**, 36 of them on the new safety-critical control code
  (19 in `test_session.py` alone).
- That harness is *itself* an artifact of the loop working. Its docstring records why:
  on 2026-08-05 three separate mutations **silently failed to apply** and the tests passed
  anyway. A mutation test that doesn't mutate manufactures false confidence. The lesson
  became executable machinery. **That is the pattern we want everywhere.**

Where it **fails**:

- `tests/test_static_integrity.py` — the natural home for "rules this project learned" —
  enforces exactly two things: no undefined names, and tool globals resolve.
- truck-mcp has **no `CLAUDE.md`**, no lessons file, no invariants file. Every hard-won
  rule lives only in prose.
- `D:/Projects/dev-standards` was found **nested** (`dev-standards/dev-standards`) with a
  dirty tree carrying uncommitted changes since June 2026 — the standards repo itself is
  not meeting the hygiene floor it documents.

### Recurrences observed in a single session

| Class | Prose rule exists | Enforced | What happened |
|---|---|---|---|
| "Unexamined reported as clean" | Yes, a global non-negotiable | No | Resurfaced as fresh work in Phase E: `chassis_dtcs` conflated *module not reached* with *reported nothing* |
| "Never assert a security control without checking the boundary" | Yes, from the v0.10.2 CSRF incident | No | Re-verified the refuse list **by hand with grep** — same manual check, different actor |
| Right logic, wrong place | No | No | The `$78` responsePending rule had one correct implementation buried in `parse_clear_capture`; an agent happened to notice |
| A docstring justifying behaviour for one caller class | No | No | `request_raw`'s replay was documented safe *because the frame is read-only* — true when written, a double-actuation bug the moment a control caller appeared |

### Second-order problem

516 tests were added in one wave by agents that also wrote the code under test, so they
largely encode the authors' assumptions. Mutation proofs are the mitigation and their
targeting is good — but 58 proofs against ~2,245 tests means **most of the suite mirrors
assumptions rather than adversarially probing them.**

---

## The work

### 1. `INVARIANTS.md` + `tests/test_invariants.py` (per repo)

Every hard-won rule becomes **one executable assertion citing the incident that produced
it**. The doc explains *why*; the test enforces *that*. Neither alone is sufficient — a
doc without a test is advisory, a test without the incident gets deleted by someone who
doesn't know what it cost.

Seed it from checks currently done by hand:

- Refuse-list conformance (truck-mcp: `$28`/`$A5` never appear as encoders; the control
  registry stays empty; no `$2F`/`$31` can target a `0x24x` module; no control frame
  reaches the bus outside a `ControlLease`).
- "Unexamined never renders or reports as clean" — as a real assertion, not a hope.
- "Every security control claimed in a docstring has a test that fails when it's removed."
- Structural rules belong in `test_static_integrity.py`, which is nearly empty today.

**Rule: every invariant test must be mutation-proven.** An invariant test that passes when
the invariant is broken is worse than none.

### 2. Per-repo `CLAUDE.md`

Carrying the project's non-negotiables so agents inherit them instead of re-deriving them.
The truck-mcp wave cost ~1.2M tokens *per wave* partly re-establishing context that should
have been three paragraphs at the top of the repo.

Should contain: what the project is, its hard constraints (truck-mcp: read-only by default,
empty control registry by design, simulator-only validation, dark mode, offline field kit),
the incidents that shaped it, and where the invariants live.

Promote a **template** into `dev-standards/templates/` so this is uniform across repos.

### 3. Global lessons file

A single index of cross-project lessons, each with: the incident, the rule, and
**the enforcement mechanism** (or an explicit "not yet enforced — advisory only").

Non-negotiable format rule: **a lesson entry is incomplete until it names its enforcement
mechanism or admits it has none.** That column is the entire point — it makes the
advisory/enforced gap visible instead of letting prose masquerade as protection.

Home: `dev-standards/STANDARDS.md` gains a "Lessons → Invariants" section, or a sibling
`LESSONS.md`. Shared-brain remains the searchable narrative layer; the repo holds the
enforceable list. They are different jobs and should stop being conflated.

### 4. Make verification cheap enough to actually run

Not cosmetic — it's *why* the loop is weak. truck-mcp's suite is ~3 minutes single-threaded
on a **32-core** machine. Agents batch changes and skip verification because it's expensive;
the pre-commit hook costs 3 minutes per commit.

`pytest-xdist` 3.8.0 was installed 2026-08-06 and is behaviorally inert until `-n` is used.

**MEASURED RESULT — do NOT enable `-n auto` as-is.** Verified in an isolated worktree at
`def10ff` (serial baseline: 2186 passed in 180s):

```
pytest tests/ -q -n auto   ->  23 failed, 2112 passed, 51 errors in 77s
```

Every failure is in `tests/test_webui.py` (browser-driver and port contention between
workers), not a real defect — the same tests pass serially. This is exactly the trap worth
naming: **it is 2.3x faster and completely wrong.** Enabling it would have sent agents
chasing phantom failures through safety-critical code, which is strictly worse than a slow
suite.

The prize is real (180s -> 77s), so the fix is isolation, not abandonment. Options in order
of preference:

1. ~~`--dist loadfile`~~ — **MEASURED, WORSE:** `33 failed, 2102 passed, 51 errors in 128s`.
   Keeping a file's tests on one worker does not help, which confirms the contention is
   *cross-file* (`test_app.py` and `test_webui.py` racing for the same ports/driver), not
   intra-file. Do not retry a different `--dist` mode expecting a different answer.
2. **An ephemeral-port fixture** so two workers can never claim the same port, and/or
   `@pytest.mark.xdist_group` on the server-binding tests. This is the actual fix — it
   addresses the cause rather than reshuffling the schedule.
3. Two-command split: parallel for the pure/unit majority, serial for `test_webui.py` +
   `test_app.py`. Least elegant, works today, and worth doing first to get the 60% win
   cheaply while the fixture is built.

Whichever lands, put it in `addopts` so agents *and* the pre-commit hook get it without any
prompt change. **Re-verify equivalence against the serial baseline every time this config
changes** — a parallel suite that silently drops tests looks identical to a fast one.

### 5. Fix the instruction template that caused this

Agent prompts said "run the full suite before you finish," reasonably read as "after every
change" — one agent ran pytest 23 times in 34 minutes. Correct guidance:
**iterate against your own test file (seconds); run the full suite once at the end.**
And: **mutation-prove every safety guard**, not just the ones an agent happens to choose.

---

## Sequencing

1. `pytest-xdist` verification + enable (unblocks everything else by making tests cheap)
2. `dev-standards`: de-nest the repo, commit the dirty June tree, add `LESSONS.md` + a
   `CLAUDE.md` template
3. truck-mcp as the pilot: `CLAUDE.md`, `INVARIANTS.md`, `tests/test_invariants.py` seeded
   from the refuse list and the manual checks of 2026-08-05/06
4. Backfill the four recurrences in the table above as invariant tests
5. Roll the pattern to Sentinel, shared-brain, GameManager

## Do not

- Do not write a lessons file that is only prose. That reproduces the exact failure being
  fixed.
- Do not delete an invariant test without reading the incident it cites.
- Do not enable parallel tests without verifying equivalence first.
