# Canary RC Promotion Flow

Productionizes [IMPL-11](../STANDARDS-IMPLEMENTATION.md). Implements the
promotion model described in [STANDARDS.md section 5](../STANDARDS.md).

## Goal

When `dev-standards/main` advances, exercise the new commit against
`Ohio15/dev-standards-canary` before letting consumers see it on `@v1`. Only
fast-forward `v1` after **3 consecutive runs of the canary's `release.yml`**
complete with `conclusion=success` at the candidate tag AND at the canary
commit that pins the candidate. Block promotion (the monitor run fails, which
is the alert) on any red run.

## Components

| Path | Owner | Purpose |
|---|---|---|
| `.github/workflows/promote-canary.yml` | this repo | Pin the canary to the RC commit, tag `v1-rcN` in both repos, monitor canary runs, promote `v1` or fail. |
| `release/canary-state.json` | this repo (rewritten by the workflow) | Single source of truth for "which RC is in flight, which canary commit tests it, how many greens so far, what the last observed run was". |
| `Ohio15/dev-standards-canary/.github/workflows/release.yml` | sibling repo (C2); its `uses:` ref is rewritten by tag-rc | Triggered by `push: tags: ['v*']` and `workflow_dispatch`. Calls dev-standards reusable workflows at a static ref, which tag-rc rewrites to `@<rc_sha>` before tagging (see "Canary pin"). |

## Event flow

```
   ┌───────────────────────┐
   │ push to               │
   │ dev-standards/main    │
   └──────────┬────────────┘
              │
              ▼
   ┌───────────────────────┐    refuses unless ref is main and HEAD is
   │ tag-rc job            │    origin/main; commits the canary pin;
   │ - assert HEAD == main │    cuts annotated tag, pushes to origin,
   │ - find max v1-rcN     │    creates refs/tags/v1-rcN in canary AT
   │ - pin canary @rc_sha  │    the pin commit. Updates canary-state.json:
   │ - tag dev-standards   │      status: idle  -> pending
   │ - tag canary (pinned) │      current_rc_canary_sha: <pin commit>
   │ - prime state file    │      consecutive_green_runs: 0
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
              │  the monitor polls the canary's
              │  /actions/workflows/release.yml/runs?branch=v1-rcN
              │  keeping path == release.yml, head_sha == pin commit
              ▼
   ┌───────────────────────┐
   │ monitor job           │
   │ (schedule + dispatch) │
   │                       │
   │  total_count          │     • verdict = in_flight   -> wait
   │  any conclusion!=ok?  │     • verdict = red         -> run FAILS
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
  "schema_version": 2,
  "current_rc": "v1-rc7",
  "current_rc_sha": "abcd1234...",
  "current_rc_canary_sha": "ef567890...",
  "current_rc_canary_ref": "abcd1234...",
  "current_rc_created_at": "2026-05-01T19:42:11Z",
  "consecutive_green_runs": 2,
  "last_observed_run_id": 25223959710,
  "last_observed_run_conclusion": "success",
  "last_observed_run_at": "2026-05-01T19:50:33Z",
  "status": "pending",
  "promoted_at": null,
  "promoted_to_sha": null,
  "history": [
    {"rc":"v1-rc6","sha":"...","canary_sha":"...","status":"promoted","green":3,"at":"2026-05-01T18:10:00Z"},
    {"rc":"v1-rc5","sha":"...","canary_sha":"...","status":"superseded","green":1,"at":"2026-05-01T17:55:00Z"}
  ]
}
```

Schema version 2 (audit-dev-standards-2026-10-10) added these fields. tag-rc
writes `schema_version: 2` when it primes an RC; the file is never hand-edited
to migrate.

| Field | Meaning |
|---|---|
| `current_rc_canary_sha` | The canary commit `v1-rcN` was created at in the canary repo (the pin commit). Only canary `release.yml` runs whose `head_sha` equals it are scored; a `release.yml` run at the tag with any other `head_sha` means the tag moved and blocks promotion. |
| `current_rc_canary_ref` | The ref the canary's `release.yml` calls dev-standards at, at that commit: the RC sha when pinned, or `main` in the legacy `pin_canary: false` mode (which tests main at run time, not the RC). |
| `history[].canary_sha` | The same canary commit, recorded with each RC's outcome (`null` for an RC primed before version 2). |

The monitor refuses to score a `pending` state that has no
`current_rc_canary_sha` (primed by the version-1 workflow): it fails and asks
for `force_action=tag-rc` dispatched from `main` to re-cut.

`history` is append-only and never truncated by the workflow. Manual prune
acceptable when the file gets large (>~200 entries); no current automation.

## Cross-repo prerequisites

### GitHub App: release-promoter (`vars.RELEASE_PROMOTER_APP_ID` + `RELEASE_PROMOTER_PRIVATE_KEY`)

Installed on **both** `Ohio15/dev-standards` and
`Ohio15/dev-standards-canary` with `contents: write`, `actions: write`
(workflow dispatch) and `workflows: write` (the canary pin). Each job mints
short-lived installation tokens. The pin step mints a separate token limited
to `dev-standards-canary` with only `contents` and `workflows` write, so the
general token never requests `workflows: write`.

Required because:

1. `GITHUB_TOKEN` is scoped to a single repository; it cannot push to
   `dev-standards-canary` from a workflow running in `dev-standards`.
2. Tag pushes made with `GITHUB_TOKEN` do **not** trigger downstream
   workflows (GitHub's recursion guard). Without a separate token, the
   mirrored `v1-rcN` tag would land in canary but `release.yml` would not
   fire.
3. Fast-forwarding `v1` (force-update of an existing tag ref) needs
   `contents: write` and bypasses the recursion guard the same way.

### Storage and trust boundary

The token can move `refs/tags/v1`, which every `@v1` consumer executes. Both
jobs declare `environment: release-promoter`, run only when
`github.ref == 'refs/heads/main'`, and assert that again as their first step.
Those checks live in the workflow file, and a `workflow_dispatch` runs the
dispatched ref's own copy of the file, so they stop an unmodified copy
dispatched from a branch and nothing more. The boundary is repository
configuration the owner creates:

1. Environment `release-promoter` with a deployment-branch policy of `main`
   only. Move `RELEASE_PROMOTER_PRIVATE_KEY` into it as an environment
   secret, then delete the repository-level secret. A required reviewer is
   optional and costly here: it would gate every monitor cycle and every
   re-dispatch (about four approvals per RC), and a run waiting for approval
   holds the single-flight concurrency group.
2. A ruleset on `main` requiring a pull request, and a ruleset on
   `refs/tags/v*` restricting update and deletion to the release-promoter App.

GitHub creates an environment named in a workflow on its first use with no
protection rules, and repository-level secrets remain visible to environment
jobs, so this workflow keeps working on the repository secret until step 1 is
complete. Until it is, anyone who can push a branch can still dispatch an
edited copy of this workflow and use the key.

### Canary contract (sibling C2 owns)

`Ohio15/dev-standards-canary/.github/workflows/release.yml` MUST:

- Trigger on `push: tags: ['v1-rc*']` (it already triggers on `v*`, which
  covers this) and on `workflow_dispatch` (the monitor's re-runs).
- Call dev-standards reusable workflows with a static
  `uses: Ohio15/dev-standards/.github/workflows/<file>.yml@<ref>` line.

### Canary pin

GitHub does not evaluate expressions in a reusable workflow's `uses:`, so
`@${{ github.ref_name }}` is impossible and the RC cannot be passed at
dispatch time. A canary calling `@main` tests whatever main is when each run
starts, not the RC commit. So tag-rc, before any tag exists:

1. reads the canary's `release.yml` at canary `main`;
2. rewrites every `uses: Ohio15/dev-standards/.github/workflows/...@<ref>`
   line to `@<rc_sha> # v1-rcN`, refusing if there is no such line or if any
   other line would change;
3. commits it to canary `main` through the Contents API (token to curl on
   stdin, never in argv) and reads the file back at the returned commit;
4. tags dev-standards `v1-rcN` at `rc_sha` and creates canary `v1-rcN` at
   that canary commit, recording it as `current_rc_canary_sha`.

Runs at the tag, from the tag push or a re-dispatch at the tag ref, execute
the pinned file and so run the RC commit. `docker-release.yml` calls
`release-gates.yml` as `./`, which resolves within the same pinned commit.

`workflow_dispatch` input `pin_canary` (default `true`) skips steps 1-3 for a
forced `tag-rc`. It is accepted only when the canary already calls
`@<rc_sha>`, or calls `@main` (the legacy approximation: warned, and recorded
as `current_rc_canary_ref: "main"`).

Not pinned: the canary's `*-release.yml` variant workflows still call
`@main`. They fire on their own tag prefixes (`<variant>-v*`), never on
`v1-rcN`, so they are outside the scored population.

## Rate / cadence

| Event | Cadence | Justification |
|---|---|---|
| Tag-rc | Every push to `main`. | Direct trigger; one RC per main commit. State guard skips self-induced `[canary state]` commits. |
| Monitor | Every 10 minutes (cron) + on demand (`workflow_dispatch`). | Single-variant canary completes in 3-5 min; multi-variant in 8-12 min. 10 min cadence catches the run-completed transition with O(6) API calls/hour worst case. |
| RC max age | 168 hours (7 days). | Mirrors STANDARDS.md section 5: "RCs older than 7 days without promotion auto-expire and get re-cut from latest main." |
| Promotion threshold | 3 consecutive most-recent terminated runs of the canary's `release.yml` (runs API `path`) at head_branch == the RC tag AND head_sha == `current_rc_canary_sha` (the tag-push run plus the monitor's own `workflow_dispatch` re-runs at that ref, one per cycle after each green), all `conclusion=success`, AND no red run of it at that commit. Other canary workflows are never counted; a `release.yml` run at the tag with another head_sha blocks. | A transient red followed by 3 greens does NOT promote — STANDARDS section 5 requires "any canary red blocks v1 promotion". Counting only the pinned release run is what makes the count mean "the RC passed three times" (SC-08). |

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
| `tag-rc` | Force-cut the next RC for `main` HEAD even outside a push:main event. Use after manually fixing main without a new commit (rare). Refused from any ref other than `main`. `pin_canary: false` skips the canary pin (see "Canary pin"). |
| `reset` | Clear `current_rc*` and set status to `idle`. Use only when state is genuinely stuck (canary corrupted, force-deleted RC tag, etc). Pushes a state-file commit; safe to revert. |

## Failure handling

| Failure | Behaviour |
|---|---|
| Release-promoter token not minted | tag-rc job fails fast with explicit error; monitor job same. |
| Dispatched from a ref other than `main` | The job `if:` skips it; an edited copy that drops the `if:` fails at the first step. An edited copy that drops both is stopped only by the environment branch policy (see "Storage and trust boundary"). |
| HEAD is not `origin/main` HEAD | Behind main (push storm): tag-rc stands down and the newer push run tags. Not on main at all: tag-rc fails. |
| App lacks `workflows: write` | The pin-token mint fails and tag-rc fails before tagging anything, with an error naming the permission. |
| Canary `release.yml` has no `uses: Ohio15/dev-standards/...` line | tag-rc fails before tagging. |
| Canary tag already exists at a different commit | tag-rc fails: runs at it would not test this RC. |
| Canary tag mirror returns 422 (already exists) | Treated as success; assumes prior partial run created it. Idempotent. |
| `v1` ref does not yet exist on first promotion | Monitor falls through 422/404 path and CREATEs `v1` at the RC sha. |
| Red canary run | State set to `failed`, then the monitor run FAILS with an `::error::` naming the run. GitHub's failed-run notification is the alert; later monitor runs skip the `failed` state quietly. There is no ntfy post: the NEXUS ntfy is not reachable from hosted runners (SPEC.md), and the former post to the public, unauthenticated `ntfy.sh/nexus-alerts` was removed (audit-dev-standards-2026-10-10). |
| Cron tick lands while tag-rc is mid-flight | `concurrency: promote-canary` queues the monitor run; it observes the post-tag state when it eventually executes. |
| Monitor sees in-flight run (no terminated yet) | Verdict `in_flight`; no state change; recheck next cycle. |
| Stuck pending RC > 168h | Monitor marks RC `expired`, resets state to `idle`, `::warning::` annotation. Next push:main re-cuts. |
| Pending state without `current_rc_canary_sha` | Monitor fails and asks for a forced `tag-rc` from `main`. |

## Open questions deferred to future iterations

1. **Multi-workflow canary.** The monitor counts only the canary's
   `release.yml` at the pinned commit. The variant workflows
   (`*-release.yml`) fire on their own tag prefixes and still call `@main`;
   for them to gate promotion, tag-rc must pin them too and tag each variant
   prefix, and the green counter must mean "3 cycles where every scored
   workflow was green", not three greens of one workflow.

2. **Self-promotion guard.** This workflow lives in `dev-standards`; if a
   commit to `dev-standards/main` regresses `promote-canary.yml` itself,
   the broken workflow could mis-promote v1. There is NO mitigation today:
   as of 2026-10-10 `main` has no branch protection, no ruleset and no
   required review (audit-dev-standards-2026-10-10). The owner-created
   controls under "Storage and trust boundary" are the mitigation. Future:
   the canary should itself test changes to `promote-canary.yml` (a
   self-host pattern), tracked separately from IMPL-11.

3. **State-file race with parallel admin commits.** If a human pushes
   directly to main while a monitor run is mid-write, the monitor's
   `git push` will reject; the monitor exits without retry. Acceptable for
   now (next 10-min tick recovers); revisit if state contention shows up.
