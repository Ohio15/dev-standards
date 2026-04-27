# Credential Rotation Protocol v1

When a credential leaks (committed to git, exposed in a log, suspected compromise), follow this protocol exactly. Each phase is independently reversible.

## Phase 0 — Detection & Scope
- Identify leaked secret(s), value(s), file(s).
- `git log -p` to enumerate every historical value. Build redacted timeline.
- Search shared-brain access logs for usage of leaked-value prefixes (if logging exists).
- Classify each secret: bearer / HMAC / DB password / signing key. Each has its own rotation pattern.

## Phase 1 — Consumer Inventory (search by VALUE, not env-var-name)
Critical lesson: env-var-name search misses consumers using non-standard names. Always search by literal value across:
- Windows: `D:/Projects/**`, `~/.mcp.json`, `~/.claude/**`, `~/.claude.json` (Claude Code), `~/.config/`, IDE storage (`%APPDATA%/Code/User`, etc.), git hooks dir, HKCU env vars, shell profiles, browser-saved passwords (manual)
- NEXUS: `~/`, `/etc/`, every container's env via `docker inspect`, systemd units, cron, bash history, retired/dormant container dirs
- GitHub: `gh secret list -R Ohio15/<repo>` for every repo with workflows + grep `.github/workflows/*.yml` for `secrets.*` references

Output: every location with redacted value, mapped to which generation.

## Phase 2 — Pre-flight Cleanup (no rotation yet)
- Delete or env-ify all hardcoded fallbacks in source code (search by VALUE in working tree).
- Delete dead-code references (legacy unused secret slots).
- Scrub stale gen-N copies from inert paths (.claude.json.backup, retired-project .env files, container-volume snapshots).
- Add `.env` to `.gitignore`. `git rm --cached .env`. Local commit. Don't push yet.

## Phase 3 — Observability Pre-rotation (CRITICAL — was missed in v0)
Before rotating, the server must produce signal that lets you detect stranded consumers post-rotation:
- HTTP request logging with redacted bearer-prefix capture.
- `app.set('trust proxy', ...)` + read `CF-Connecting-IP` for real source IPs.
- Validate by tailing logs and confirming you can see your own traffic.

Without this, the post-rotation watch period is blind.

## Phase 4 — Server Patch for Overlap Support (skip only if accepting outage)
- ~10 LOC to replace single-key check with comma-list (`API_KEYS`) check.
- Pad candidates to fixed length, constant-iteration loop (avoid timing-attack edge cases).
- Deploy + verify both old and new keys validate concurrently before rotation.

## Phase 5 — Generate & Deploy New Secrets
- Cryptographic generation, same shape/length as old.
- Server first: write new `.env`, restart container.
- Then update each consumer in lockstep against the inventory list. Tick off each by hitting an authenticated endpoint and verifying 200.
- **Verification gate**: every consumer must confirm successful auth before proceeding. Failed consumer = stop, diagnose.

## Phase 6 — Watch Window (24–48h with new logging)
- Tail unauthorized-request log lines.
- Any 401s with old-key prefix = stranded consumer missed in inventory. Resolve.
- Any 401s from unknown IPs = either typo, attacker, or third-party probe. Investigate.
- After clean window, drop old key from `API_KEYS`. Server now accepts new only.

## Phase 7 — Eradication
- Build `replacements.txt`: every leaked literal across all secrets and all generations.
- `git filter-repo --invert-paths --path .env` (drops file from history).
- `git filter-repo --replace-text replacements.txt` (scrubs source-code literals).
- Force-push (requires explicit user confirmation).
- Verify with fresh-clone + grep for every leaked literal → zero hits.

## Phase 8 — Hardening
- Add `gitleaks` or `trufflehog` pre-commit hook to dev-standards. Roll out across active repos.
- Enable secret-scanning + push-protection on the affected repo.
- Add to lint rules: no hardcoded credential fallbacks in source.
- Update memory + shared-brain with rotation incident entry.

## Anti-patterns this protocol corrects (lessons from incident 2026-04-26)
1. Searching for consumers by env-var-name only → misses non-standard names. Always search by VALUE.
2. Scrubbing `.env` from history but leaving source-code fallbacks intact → key remains recoverable from old commits.
3. Rotating without HTTP request logging in place → post-rotation watch is blind.
4. Hardcoding credentials in shell-scripts and git hooks → silent failures across rotations, leaks survive.
5. Single-key `timingSafeEqual` without overlap support → forces outage on every rotation.
