# Canary RC Promotion Flow

Productionizes [IMPL-11](../STANDARDS-IMPLEMENTATION.md). Implements the
promotion model described in [STANDARDS.md section 5](../STANDARDS.md).

## Goal

When `dev-standards/main` advances, exercise the new commit against
`Ohio15/dev-standards-canary` before letting consumers see it on `@v1`. Only
fast-forward `v1` after **3 consecutive canary runs** complete with
`conclusion=success` at the candidate ref. Block promotion (urgent ntfy) on
any red run.

## Components

| Path | Owner | Purpose |
|---|---|---|
| `.github/workflows/promote-canary.yml` | this repo | Tag `v1-rcN`, mirror tag to canary, monitor canary runs, promote `v1` or alert. |
| `release/canary-state.json` | this repo (rewritten by the workflow) | Single source of truth for "which RC is in flight, how many greens so far, what the last observed run was". |
| `Ohio15/dev-standards-canary/.github/workflows/release.yml` | sibling repo (C2) | Triggered by `push: tags: ['v1-rc*']`. Calls dev-standards reusable workflows at `@${{ github.ref_name }}` (i.e. the matching RC ref). |

## Event flow

```
   ┌───────────────────────┐
   │ push to               │
   │ dev-standards/main    │
   └──────────┬────────────┘
              │
              ▼
   ┌───────────────────────┐    cuts annotated tag, pushes to origin,
   │ tag-rc job            │    PATCHes refs/tags/v1-rcN into canary.
   │ - find max v1-rcN     │    Updates canary-state.json:
   │ - tag dev-standards   │      status: idle  -> pending
   │ - tag canary repo     │      consecutive_green_runs: 0
   │ - prime state file    │
   └──────────┬────────────┘
              │
              │  canary release.yml fires on tag push
              ▼
   ┌───────────────────────┐
   │ Ohio15/dev-standards- │
   │ canary CI runs        │   exercises ALL canary variants (single
   │ at @v1-rcN            │   variant today, multi-variant per IMPL-11)
   └──────────┬────────────┘
              │
              │  every 10 min the monitor job polls the canary's
              │  /actions/runs?branch=v1-rcN&event=push
              ▼
   ┌───────────────────────┐
   │ monitor job           │
   │ (schedule + dispatch) │
   │                       │
   │  total_count          │     • verdict = in_flight   -> wait
   │  any conclusion!=ok?  │     • verdict = red         -> ntfy URGENT
   │  most-recent N green? │     • verdict = green       -> promote v1
   │  age > 168h?          │     • verdict = expired     -> reset state
   └───────────────────────┘
```

## State machine

`release/canary-state.json:status`:

| State | Meaning | Transitions |
|---|---|---|
| `idle` | No RC in flight. | `tag-rc` -> `pending` |
| `pending` | Canary CI running or accumulating green runs. | `monitor` -> `pending` (still accumulating), `promoted` (3 green), `failed` (any red), or `idle` (RC expired). |
| `failed` | At least one canary run at this RC was non-success. v1 NOT advanced. Awaiting human triage. | `tag-rc` of next RC supersedes (current RC pushed onto `history` with status `superseded`). |
| `promoted` | v1 fast-forwarded to this RC. Terminal until next push:main. | `tag-rc` of next RC supersedes. |

Unknown transitions are no-ops; the monitor job exits with `::notice::` only.

## State file schema

```json
{
  "schema_version": 1,
  "current_rc": "v1-rc7",
  "current_rc_sha": "abcd1234...",
  "current_rc_created_at": "2026-05-01T19:42:11Z",
  "consecutive_green_runs": 2,
  "last_observed_run_id": 25223959710,
  "last_observed_run_conclusion": "success",
  "last_observed_run_at": "2026-05-01T19:50:33Z",
  "status": "pending",
  "promoted_at": null,
  "promoted_to_sha": null,
  "history": [
    {"rc":"v1-rc6","sha":"...","status":"promoted","green":3,"at":"2026-05-01T18:10:00Z"},
    {"rc":"v1-rc5","sha":"...","status":"superseded","green":1,"at":"2026-05-01T17:55:00Z"}
  ]
}
```

`history` is append-only and never truncated by the workflow. Manual prune
acceptable when the file gets large (>~200 entries); no current automation.

## Cross-repo prerequisites

### Secret: `CANARY_DISPATCH_TOKEN`

PAT or GitHub App installation token with `contents: write` on **both**
`Ohio15/dev-standards` and `Ohio15/dev-standards-canary`.

Required because:

1. `GITHUB_TOKEN` is scoped to a single repository; it cannot push to
   `dev-standards-canary` from a workflow running in `dev-standards`.
2. Tag pushes made with `GITHUB_TOKEN` do **not** trigger downstream
   workflows (GitHub's recursion guard). Without a separate token, the
   mirrored `v1-rcN` tag would land in canary but `release.yml` would not
   fire.
3. Fast-forwarding `v1` (force-update of an existing tag ref) needs
   `contents: write` and bypasses the recursion guard the same way.

Storage: `Settings -> Secrets and variables -> Actions -> Repository secrets`
in `Ohio15/dev-standards`. App tokens are preferred over PATs (revocable,
scoped, no human owner). PAT minimum scopes: `repo` (classic) or
`contents:write` + `metadata:read` (fine-grained, both repos selected).

### Canary contract (sibling C2 owns)

`Ohio15/dev-standards-canary/.github/workflows/release.yml` MUST:

- Trigger on `push: tags: ['v1-rc*']` (it already triggers on `v*`, which
  covers this).
- Call dev-standards reusable workflows at `@${{ github.ref_name }}` rather
  than `@main`. This is the change that makes the RC tag actually mean
  something — without it, every canary run would test whatever main happens
  to be at the moment of the run, defeating the RC isolation.

The current canary `release.yml` uses `@main`; this is documented in the
canary repo's own header as a known gap tracked under IMPL-11.

## Rate / cadence

| Event | Cadence | Justification |
|---|---|---|
| Tag-rc | Every push to `main`. | Direct trigger; one RC per main commit. State guard skips self-induced `[canary state]` commits. |
| Monitor | Every 10 minutes (cron) + on demand (`workflow_dispatch`). | Single-variant canary completes in 3-5 min; multi-variant in 8-12 min. 10 min cadence catches the run-completed transition with O(6) API calls/hour worst case. |
| RC max age | 168 hours (7 days). | Mirrors STANDARDS.md section 5: "RCs older than 7 days without promotion auto-expire and get re-cut from latest main." |
| Promotion threshold | 3 consecutive most-recent terminated runs at the RC ref, all `conclusion=success`, AND no red run anywhere in the RC's run history. | A transient red followed by 3 greens does NOT promote — STANDARDS section 5 requires "any canary red blocks v1 promotion". |

## Concurrency

`concurrency.group: promote-canary` with `cancel-in-progress: false`. Two
simultaneous monitor runs would race on the green counter; two simultaneous
tag-rc runs would race on N selection. Queueing rather than cancelling
ensures push-storms during rapid main commits all get tagged in order.

## Manual operations

`workflow_dispatch` exposes three actions:

| Input | Effect |
|---|---|
| `monitor` (default) | Force a poll without waiting for the next cron tick. Useful when canary just turned green and you don't want to wait 10 minutes. |
| `tag-rc` | Force-cut the next RC even outside a push:main event. Use after manually fixing main without a new commit (rare). |
| `reset` | Clear `current_rc*` and set status to `idle`. Use only when state is genuinely stuck (canary corrupted, force-deleted RC tag, etc). Pushes a state-file commit; safe to revert. |

## Failure handling

| Failure | Behaviour |
|---|---|
| `CANARY_DISPATCH_TOKEN` missing | tag-rc job fails fast with explicit error; monitor job same. |
| Canary tag mirror returns 422 (already exists) | Treated as success; assumes prior partial run created it. Idempotent. |
| `v1` ref does not yet exist on first promotion | Monitor falls through 422/404 path and CREATEs `v1` at the RC sha. |
| ntfy publish fails (host down, DNS, 5xx) | `::warning::` logged; workflow continues. The promotion outcome is owned by the git refs, not by alert delivery. |
| Cron tick lands while tag-rc is mid-flight | `concurrency: promote-canary` queues the monitor run; it observes the post-tag state when it eventually executes. |
| Monitor sees in-flight run (no terminated yet) | Verdict `in_flight`; no state change; recheck next cycle. |
| Stuck pending RC > 168h | Monitor marks RC `expired`, resets state to `idle`, ntfy default-priority. Next push:main re-cuts. |

## Open questions deferred to future iterations

1. **Multi-workflow canary.** Current monitor counts runs of the canary's
   single `Release` workflow. When C2 lands additional canary workflows
   (each variant of the matrix), the green-counter must be partitioned per
   workflow OR aggregated such that "3 greens" means "3 cycles where every
   workflow was green". The current code aggregates by run timestamp, which
   is incorrect for multi-workflow because three back-to-back greens of one
   workflow could promote even if a sibling workflow is still red. Track
   under a follow-up: add a `--workflow-mode {any|all}` knob to the monitor
   query and default to `all` once multi-variant ships.

2. **Self-promotion guard.** This workflow lives in `dev-standards`; if a
   commit to `dev-standards/main` regresses `promote-canary.yml` itself,
   the broken workflow could mis-promote v1. Mitigation today: branch
   protection on `main` + required review on `.github/workflows/`. Future:
   the canary should itself test changes to `promote-canary.yml` (a
   self-host pattern), tracked separately from IMPL-11.

3. **State-file race with parallel admin commits.** If a human pushes
   directly to main while a monitor run is mid-write, the monitor's
   `git push` will reject; the monitor exits without retry. Acceptable for
   now (next 10-min tick recovers); revisit if state contention shows up.
