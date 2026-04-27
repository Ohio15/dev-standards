# dev-standards

Shared enforcement artifacts for Ron-owned repos. Drop-in protection against the class of mistakes that caused the AIBrowser 100 MB wall and the 2026-04-26 `.env`-in-git incident.

## What's here

| Path | Purpose |
|---|---|
| `hooks/pre-commit` | Chained dispatcher. Runs every `pre-commit-*.sh` sub-hook in sorted order; first failure aborts the commit. |
| `hooks/pre-commit-size-guard.sh` | Rejects staged files >10 MB unless allowlisted. |
| `hooks/pre-commit-secret-scan.sh` | Runs `gitleaks protect --staged` to block commits introducing secrets. |
| `workflows/size-guard.yml` | GitHub Actions workflow that rejects tracked files >10 MB. Not skippable. |
| `templates/.github/workflows/security-audit.yml` | Layer A: always-on dependency-vulnerability gate. Fails PRs on high/critical findings across npm, Go, Python. |
| `templates/.github/workflows/dep-auto-apply.yml` | Layer B: weekly cron that auto-applies safe dep fixes, runs tests, opens a PR labeled `auto-apply`. Per-repo opt-in. |
| `templates/.large-files-allowlist` | Annotated template for per-repo large-file exemptions. |
| `templates/.gitleaks.toml` | Baseline gitleaks ruleset (default rules + Ron-specific patterns). |
| `install.sh` | One-shot installer that wires the guards into a target repo. |
| `scripts/repo-hygiene-scan.py` | Weekly hygiene scanner — drift, misconfig, noise, idle repos. |
| `scripts/npm-audit-weekly.sh` | Weekly `npm audit` roll-up + KEV cross-reference. |
| `credential-rotation/PROTOCOL.md` | Credential rotation protocol v1. |

## Hook distribution model

Hooks are distributed **per-repo via `.githooks/`** — each repo carries its own copy of the hook scripts, committed to the repo itself, with `core.hooksPath = .githooks` set as a local git config. There is no shared global hooks directory.

This replaces the earlier `core.hooksPath = D:/Projects/git-hooks` global model, which was retired on **2026-04-27**. The legacy directory is archived at `D:/Projects/.archive/git-hooks-2026-04-27/`. Reasons for the move:

- The global path was Windows-only and broke any repo cloned to a different machine.
- A directory outside any repo's git history left the hook policy un-versioned and silently divergent across machines.
- New machines / new clones got *no* hooks — nothing was wired up unless someone manually set the global.
- A per-repo `.githooks/` is auditable in the repo's diff, reviewable in PRs, and works on every clone the moment `core.hooksPath = .githooks` is set.

`install.sh` is the canonical onboarding command — it copies the hook scripts into the target repo and sets the local `core.hooksPath`. Each clone only needs that one local config (hooks live in the repo, but git doesn't auto-wire them on clone).

## Install into a new repo

```bash
./install.sh /path/to/target-repo
cd /path/to/target-repo
git add .githooks .github/workflows/size-guard.yml .large-files-allowlist .gitleaks.toml
git commit -m "ci: install dev-standards guards"
git push
```

CI workflows are the real enforcement; the local hooks are courtesies that catch mistakes before they leave the developer's machine.

## Size guard

Binaries don't go in git. Release artifacts ship via GitHub Releases. Build output, `node_modules`, venvs, vendored third-party binaries are `.gitignore`d. Test fixtures and source assets that are genuinely source can stay tracked if they're under 10 MB; larger legitimate cases go in `.large-files-allowlist` with a `# reason:` comment.

Threshold: 10 MB. Change `MAX_BYTES` in the hook and `MAX` in the workflow together if needed; the two must agree.

Full reasoning in shared-brain decision `badd9dd3-2220-4d5b-bf46-5ce7b9469831`.

### Allowlist

Uncomment or add entries in `.large-files-allowlist`. Each entry must be preceded by a `# reason:` comment that a reviewer can use to judge legitimacy. Directory prefixes end with `/`; exact file paths don't.

```
# reason: ML model checkpoint, required at runtime, no build step
models/embedding-base.onnx

# reason: test fixtures — real PDFs needed for regression suite
test-pdfs/
```

## Secret scan (gitleaks)

The pre-commit secret scanner blocks any commit that introduces values matching the gitleaks default ruleset (AWS, GCP, GitHub PATs, Slack, Stripe, npm, JWTs, generic high-entropy strings) plus Ron-specific patterns from `templates/.gitleaks.toml`:

- `MCP_API_KEY`, `BRAIN_PG_PASSWORD`, `WEBHOOK_SECRET`
- `AIBROWSER_*` and `GH_*TOKEN`/`PAT`/`SECRET`/`KEY`
- Catch-all `*_API_KEY=<20+ chars>`
- Anthropic (`sk-ant-*`) and OpenAI (`sk-*`) keys

The hook uses `gitleaks protect --staged` so it scans only the diff, not the whole tree or history. Sub-second on typical commits.

### Install gitleaks (per developer machine)

```bash
# macOS
brew install gitleaks
# Windows
choco install gitleaks
# Any platform with Go
go install github.com/zricethezav/gitleaks/v8@latest
```

If gitleaks is missing the hook exits with install instructions; commits are blocked until it's installed (use `--no-verify` in true emergencies, with written justification).

### Tuning false positives

- One-off line: append `# gitleaks:allow` to the line.
- Repo-wide pattern: add a `[[allowlist]]` entry or path/regex to `.gitleaks.toml`.
- New shaped secret: add a `[[rules]]` entry. Keep regexes anchored with both a keyword and a value-shape to avoid false positives.

### Why local-only (not CI)

GitHub Advanced Security secret-scanning is gated behind paid tiers for private repos and isn't available on the current plan. The local pre-commit hook is the durable prevention layer; once a secret reaches origin it has to be rotated regardless. For repos on a tier with secret-scanning + push-protection, enable both — defense in depth.

## Bypass

The pre-commit hook honors `git commit --no-verify`. The size-guard CI workflow does not — it's a hard stop on pushes to `main`/`master` and on every PR. `--no-verify` leaves an entry in `git reflog`, so it's audit-traceable.

## Adding new sub-hooks

Drop a `pre-commit-<name>.sh` into `hooks/`, make it executable, and update `install.sh` to copy it into `.githooks/`. The dispatcher discovers sub-hooks by name pattern and runs them in sorted order; no edits to `pre-commit` itself are required.

## Dependency hygiene (Layer A + Layer B)

Two-layer model for keeping dependencies patched without burning weekly attention. Pivoted to "auto-apply" architecture on **2026-04-27** after a self-critique of the original auto-merge scope (see shared-brain memory IDs at the end of this section).

### Layer A — `security-audit.yml` (always on)

Drop-in CI gate that runs on every pull request, every push to `main`/`master`, and on manual dispatch. Detect-and-dispatch: each ecosystem job is conditional on the presence of its lockfile or manifest, so the same workflow file works in pure-Node, pure-Go, polyglot, or empty repos.

| Ecosystem | Trigger | Tool | Gate |
|---|---|---|---|
| npm    | `package.json` present | `npm audit` (or `pnpm audit`) | fails on **high** or **critical** |
| Go     | `go.mod` present       | `govulncheck`                 | fails on any reachable vulnerability |
| Python | `requirements*.txt` or `pyproject.toml` | `pip-audit --strict` | fails on any vuln |

Moderate / low findings are logged to the workflow summary but don't fail the build. Layer A is **not** opt-in — it runs unconditionally on every repo `install.sh` touches.

### Layer B — `dep-auto-apply.yml` (opt-in, weekly)

Weekly cron (`Sundays 06:00 UTC`) that auto-**APPLIES** safe fixes itself, runs the project's test suite, and opens a PR labeled `auto-apply` for human review. Auto-merge is intentionally **not** part of this layer — it can be added later as a thin opt-in wrapper on top, once we have evidence from real auto-apply PRs.

| Ecosystem | Auto-apply behaviour |
|---|---|
| npm    | `npm audit fix` (never `--force`, never `--include-major`); `npm test` if a `test` script is defined. pnpm: `pnpm update <vuln-pkgs>` derived from audit JSON. yarn: skipped (no safe `audit fix`). |
| Go     | `govulncheck` enumerates affected modules; `go get -u=patch <mod>` for each; `go mod tidy`; `go build ./...`; `go test ./...`. **Aborted** if the resulting `go.sum` line-count delta exceeds 20 (heuristic for "this minor was actually breaking"). |
| Python | Only if every line of every `requirements*.txt` is pinned with `==` or `~=`. Runs `pip-audit --fix --strict --dry-run` first to preview, then for real. `pytest` if available. |
| Docker | **Read-only audit only.** Verifies every `FROM` line is digest-pinned (`@sha256:...`); auto-bumping digests is out of scope (needs a trusted digest oracle). Un-pinned Dockerfiles are flagged in the PR body. |
| GitHub Actions | **Read-only audit only.** Verifies every external `uses:` is SHA-pinned (40-char hex). Auto-bumping SHAs within-major is deferred to v2 (requires a Dependabot-style oracle). |

**Outcomes:**

- Anything bumped + tests pass -> branch `auto-apply/YYYY-MM-DD`, PR labeled `auto-apply`, ntfy notification fired, brain ingest posted (if `SHARED_BRAIN_TOKEN` secret is set).
- Anything bumped + tests fail -> **draft** PR labeled `auto-apply-broken` for human triage. Not auto-closed.
- Nothing bumped -> silent exit 0; no PR, no notification.

**Enrollment** (per-repo opt-in):

```bash
touch /path/to/repo/.github/auto-apply-enabled
git -C /path/to/repo add .github/auto-apply-enabled
git -C /path/to/repo commit -m "chore: enroll in dev-standards auto-apply Layer A + B"
git -C /path/to/repo push
```

`install.sh` deliberately does **not** create this file — Layer B is consequential enough that the admin must touch the file by hand.

**Kill switch:**

```bash
rm /path/to/repo/.github/auto-apply-enabled
git -C /path/to/repo commit -am "chore: disable dev-standards auto-apply"
git -C /path/to/repo push
```

The next scheduled run will exit silently with a notice.

**Required GitHub permissions / secrets:**

- `permissions: { contents: write, pull-requests: write }` (declared in the workflow itself; no repo-side change needed).
- `SHARED_BRAIN_TOKEN` (optional secret). If absent, the brain ingest step logs a notice and exits 0 — the workflow doesn't fail.

### Supply chain rule

Every `uses:` in both workflow templates is **SHA-pinned**, not tag-pinned. The pinned SHAs (and the human-readable version they map to) are:

| Action | SHA (40-char) | Version |
|---|---|---|
| `actions/checkout` | `692973e3d937129bcbf40652eb9f2f61becf3332` | v4.1.7 |
| `actions/setup-node` | `0a44ba7841725637a19e28fa30b79a866c81b0a6` | v4.0.4 |
| `actions/setup-go` | `0a12ed9d6a96ab950c8f026ed9f722fe0da7ef32` | v5.0.2 |
| `actions/setup-python` | `f677139bbe7f9c59b41e40162b753c062f5d49a3` | v5.2.0 |
| `peter-evans/create-pull-request` | `5e914681df9dc83aa4e4905692ca88beb2f9e91f` | v7.0.5 |

Per the lesson from the `tj-actions/changed-files` Mar-2025 supply-chain attack: never trust a moving tag. Bumps to these SHAs in dev-standards land via the same Layer B that the templates produce, once an oracle for action-SHA-within-major is built.

### References

- **Design:** shared-brain decision `81b962de-3e94-4d67-9093-7dbb5644094d`
- **Critique that forced the pivot:** shared-brain knowledge `7b258d5c-dcf4-49e9-973a-5e92b951a019`
- **Original (superseded) scope:** shared-brain knowledge `7af0b998-9cd8-4d45-b709-647aeaf3abac`

## Hygiene automation

Two scripts under `scripts/` keep repos honest. Both are stdlib-only (Python 3.8+ / bash + jq + curl), idempotent, and side-effect-free on the scanned repos.

### `scripts/repo-hygiene-scan.py`

Weekly scanner that walks one or more configured roots and flags:

| Severity | Code | What it catches |
|---|---|---|
| HIGH | `tracked-binary-or-oversized` | Tracked `.exe/.dll/.so/.dylib/.bin/.pyc/.class/.jar/.a` or any tracked file >5 MB |
| HIGH | `tracked-but-gitignored` | Tracked files that match the repo's own `.gitignore` (stale ignore rules / `add -f`) |
| MEDIUM | `stale-working-tree` | Modified or untracked files older than `--age-threshold` days (default 7) |
| MEDIUM | `hooks-path-legacy` | `core.hooksPath` still pointing at retired `D:/Projects/git-hooks` |
| MEDIUM | `hooks-path-misconfigured` | `.githooks/` exists but `core.hooksPath` doesn't point at it |
| LOW | `idle-repo` | No commits in 30+ days |
| LOW | `noise-files` | `.DS_Store`, `*.swp`, `Thumbs.db` tracked or untracked |

Output: structured JSON to `<output-dir>/hygiene-scan-<YYYY-MM-DD>.json` plus a human-readable markdown summary on stdout. Exit code reflects severity (HIGH=2, MEDIUM=1, else 0) so cron alerts naturally.

```bash
# Scan D:/Projects on Windows (default root)
python scripts/repo-hygiene-scan.py --dry-run

# Scan multiple roots, only HIGH findings, post summary to shared-brain
python scripts/repo-hygiene-scan.py \
    --root /home/ohio_ \
    --root /home/ohio_/Projects \
    --severity HIGH \
    --brain-store
```

### `scripts/npm-audit-weekly.sh`

Weekly `npm audit` roll-up across every Node.js repo under the configured roots. Per-repo it runs `npm audit --json` (full) and `npm audit --omit=dev --json` (prod-only), aggregates totals by severity, and best-effort cross-references the CISA KEV (Known Exploited Vulnerabilities) feed for each finding.

Exit codes: 3 if `THRESH_CRIT` (default 1) or `THRESH_HIGH` (default 3) thresholds are crossed — cron mail picks that up.

```bash
# Default scan
./scripts/npm-audit-weekly.sh

# With custom thresholds + brain-store
THRESH_CRIT=1 THRESH_HIGH=2 ./scripts/npm-audit-weekly.sh \
    --root /home/ohio_ \
    --brain-store
```

### Schedules

**NEXUS (Linux cron, ohio_'s crontab):**

```cron
# Weekly hygiene + npm-audit, Sundays 05:00 / 06:00 UTC
0 5 * * 0 /home/ohio_/dev-standards/scripts/repo-hygiene-scan.py --root /home/ohio_ --brain-store > ~/scans/hygiene-$(date -u +\%Y-\%m-\%d).log 2>&1
0 6 * * 0 /home/ohio_/dev-standards/scripts/npm-audit-weekly.sh --root /home/ohio_ --brain-store > ~/scans/npm-audit-$(date -u +\%Y-\%m-\%d).log 2>&1
```

**Windows (Task Scheduler):**

```powershell
# Hygiene scan — Sundays 05:00 local
schtasks /Create /TN "DevStandards-HygieneScan" /SC WEEKLY /D SUN /ST 05:00 /F `
  /RL LIMITED `
  /TR "python D:\Projects\dev-standards\scripts\repo-hygiene-scan.py --root D:/Projects --brain-store"

# npm audit — Sundays 06:00 local
# Uses the .cmd wrapper because schtasks /TR doesn't tolerate the quoted
# `C:\Program Files\Git\bin\bash.exe` path well.
schtasks /Create /TN "DevStandards-NpmAudit" /SC WEEKLY /D SUN /ST 06:00 /F `
  /RL LIMITED `
  /TR "D:\Projects\dev-standards\scripts\npm-audit-weekly.cmd"
```

`scripts/npm-audit-weekly.cmd` is a thin wrapper that invokes Git-Bash → `npm-audit-weekly.sh`. It exists purely to sidestep `schtasks` argument parsing of paths-with-spaces.

### Brain integration

`--brain-store` posts the markdown summary to `https://shared-brain.us/api/memory` as an `ingest`-action observation, tagged `hygiene-scan-<DATE>` or `npm-audit-<DATE>`. Requires the API key at `~/.config/shared-brain/api-key`. Failures are logged to stderr; the scan still writes its local JSON report regardless.
