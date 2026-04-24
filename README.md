# dev-standards

Shared enforcement artifacts for Ron-owned repos. Drop-in protection against the class of mistakes that caused the AIBrowser 100 MB wall.

## What's here

| Path | Purpose |
|---|---|
| `hooks/pre-commit` | Rejects staged files >10 MB unless allowlisted. Skippable with `--no-verify` for emergencies. |
| `workflows/size-guard.yml` | GitHub Actions workflow that rejects tracked files >10 MB. Not skippable — enforces at PR/push. |
| `templates/.large-files-allowlist` | Annotated template for per-repo exemptions. |
| `install.sh` | One-shot installer that wires the guard into a target repo. |

## Install into a new repo

```bash
./install.sh /path/to/target-repo
cd /path/to/target-repo
git add .githooks .github/workflows/size-guard.yml .large-files-allowlist
git commit -m "ci: install size guard"
git push
```

Each clone needs `git config core.hooksPath .githooks` once — the hook lives in the repo but git doesn't auto-wire it. The CI workflow is the real enforcement; the hook is a courtesy that catches mistakes before they leave the local machine.

## The policy

Binaries don't go in git. Release artifacts ship via GitHub Releases. Build output, `node_modules`, venvs, vendored third-party binaries are `.gitignore`d. Test fixtures and source assets that are genuinely source can stay tracked if they're under 10 MB; larger legitimate cases go in `.large-files-allowlist` with a `# reason:` comment.

Full reasoning in shared-brain decision `badd9dd3-2220-4d5b-bf46-5ce7b9469831`.

## The allowlist

Uncomment or add entries in `.large-files-allowlist`. Each entry must be preceded by a `# reason:` comment that a reviewer can use to judge legitimacy. Directory prefixes end with `/`; exact file paths don't.

```
# reason: ML model checkpoint, required at runtime, no build step
models/embedding-base.onnx

# reason: test fixtures — real PDFs needed for regression suite
test-pdfs/
```

## Threshold

10 MB. Chosen to catch build output and most installers, low enough that every exemption gets a human review moment. Change `MAX_BYTES` in the hook and `MAX` in the workflow together if you need a different threshold; the two must agree.

## Bypass

The pre-commit hook honors `git commit --no-verify`. The CI workflow does not — it's a hard stop on pushes to `main`/`master` and on every PR. If you need to merge something >10 MB that isn't allowlistable (for example, a one-time migration), change the threshold or the allowlist via a PR rather than bypassing.
