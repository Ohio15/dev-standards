# dev-standards

Shared enforcement artifacts for Ron-owned repos. Drop-in protection against the class of mistakes that caused the AIBrowser 100 MB wall and the 2026-04-26 `.env`-in-git incident.

## What's here

| Path | Purpose |
|---|---|
| `hooks/pre-commit` | Chained dispatcher. Runs every `pre-commit-*.sh` sub-hook in sorted order; first failure aborts the commit. |
| `hooks/pre-commit-size-guard.sh` | Rejects staged files >10 MB unless allowlisted. |
| `hooks/pre-commit-secret-scan.sh` | Runs `gitleaks protect --staged` to block commits introducing secrets. |
| `workflows/size-guard.yml` | GitHub Actions workflow that rejects tracked files >10 MB. Not skippable. |
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
  /TR "python D:\Projects\dev-standards\scripts\repo-hygiene-scan.py --root D:/Projects --brain-store"

# npm audit — Sundays 06:00 local
schtasks /Create /TN "DevStandards-NpmAudit" /SC WEEKLY /D SUN /ST 06:00 /F `
  /TR "C:\Program Files\Git\bin\bash.exe D:/Projects/dev-standards/scripts/npm-audit-weekly.sh --root D:/Projects --brain-store"
```

### Brain integration

`--brain-store` posts the markdown summary to `https://shared-brain.us/api/memory` as an `ingest`-action observation, tagged `hygiene-scan-<DATE>` or `npm-audit-<DATE>`. Requires the API key at `~/.config/shared-brain/api-key`. Failures are logged to stderr; the scan still writes its local JSON report regardless.
