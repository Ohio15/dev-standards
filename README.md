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
| `credential-rotation/PROTOCOL.md` | Credential rotation protocol v1. |

## Install into a new repo

```bash
./install.sh /path/to/target-repo
cd /path/to/target-repo
git add .githooks .github/workflows/size-guard.yml .large-files-allowlist .gitleaks.toml
git commit -m "ci: install dev-standards guards"
git push
```

Each clone needs `git config core.hooksPath .githooks` once — the hook lives in the repo but git doesn't auto-wire it. CI workflows are the real enforcement; the local hooks are courtesies that catch mistakes before they leave the developer's machine.

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
