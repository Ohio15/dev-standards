# Changelog

dev-standards had no root version until 1.1.0; earlier changes are recorded in the PR history
and the `v1` / `v1-rcN` workflow tags (which remain the consumer pin for reusable workflows).

## 1.1.3 - 2026-11-10

Routine security audit 2026-11-10.2 (dev-standards): M3, M4 and L1, each found by all three
reviewers. Shared-brain 34910b22, 439c18f1, f48ee67e.

- M3 (34910b22) `scripts/npm-audit-weekly.sh`: a scanned repo's committed `.npmrc` configured the
  audit (proxy, strict-ssl, cafile, noproxy, scoped registries), so a forged all-zero answer
  read as clean. An env pin cannot fix that alone: npm ignores an empty `npm_config_*` value,
  so a repo `cafile=`/`noproxy=`/`@scope:registry=` survives (probed against npm 11.7). npm
  now never runs in the repo: package.json, the lockfile and each workspace manifest the
  lockfile names are staged (regular files only, no symlink on the path, nothing outside the
  repo) into an operator scratch tree with no `.npmrc`, with `npm_config_userconfig` /
  `npm_config_globalconfig` pinned to empty files the script creates, the public registry,
  `strict-ssl=true`, `proxy`/`https-proxy=false` and scripts off. A tree that cannot be staged
  is status `error`. `code-standards-cron.sh` header debt note replaced.
- M4 (439c18f1) `scripts/repo-hygiene-scan.py`: reads followed symlinks (a `VERSION ->` secret
  reached the report and the shared-brain post as a "version"; `-> /dev/zero` passed a cap that
  trusted `st_size`). Every repo-relative read now goes through one helper, `read_repo_file`:
  no absolute or `..` path, lstat on every component (symlinks and Windows reparse points
  refused), `S_ISREG` (re-checked on the descriptor, `O_NOFOLLOW|O_NONBLOCK`), bounded
  `read(cap + 1)`. The workflow walk (`walk_repo_files`, `followlinks=False`) replaces `rglob`
  and reports symlinked entries as not examined; `file_size` and the drift mtime use `lstat`.
- L1 (f48ee67e) `install.sh`: the lost-entries guard used a raw NUL as the `tr` argument, which
  bash strips, so it compared 0 with 0. Now `tr -cd '\000'`; no tracked file holds a NUL.
- Tests: `test_hygiene_symlinks.py` (new), npm `.npmrc`/staging cases checked against real npm
  config resolution, a lost-entries refusal and a no-control-byte check over tracked files;
  each is red against the pre-fix code.

## 1.1.2 - 2026-11-10

Security register SC-53..SC-55 graduated from audit-steward-sessionwatch-2026-11-10, approved by
Ron 2026-11-10 (shared-brain b37ab3ef): an enforcement point named with no consumer (SC-53), a
sanitizer that leaves Unicode format characters (SC-54), a finding resolved on absence rather
than a satisfied predicate (SC-55). Both register copies updated identically.
## 1.1.1 - 2026-11-10

Work item 2e17bd88 (security, high): `npm-audit-weekly.sh` failed open.

- `scripts/npm-audit-weekly.sh`: an errored `npm audit` (ENOLOCK, network, registry), a timeout,
  empty or unparseable output, a missing lockfile, or a missing `npm`/`jq` used to be written as
  zero counts, indistinguishable from a clean repo. Each repo entry now carries `status`
  (`ok` | `error`) and `reason`; `ok` only when both audits returned a numeric
  `.metadata.vulnerabilities` summary and no `.error`. On `error` every count is `null`, never 0.
  The roll-up has the same `status`, `repos_ok`, `repos_error`; totals cover examined repos only;
  zero repos discovered is an error. The report stays valid JSON without jq. New exit code 4
  (not examined; 3 stays "thresholds exceeded"). Per-audit timeout `AUDIT_TIMEOUT` (180s).
- `scripts/tests/test_npm_audit_weekly.py`: makes `npm audit` fail a dozen ways and asserts the
  output is never zeros.

## 1.1.0 - 2026-11-10

Code-standards facts for Steward (Ron, 2026-11-10, shared-brain 9d2d2d9e): Steward reviews new
and existing code on every estate repo, its own included, against these standards.

- `repo-hygiene-scan.py`: new checks `version-divergence` (§3), `tests-undeclared` (§2),
  `stub-marker` (no-stubs rule), `security-register-missing` and `security-register-stale`
  (with `--security-roster` / `--canonical-register`; without its argument a check is absent,
  never passed); `--no-layout`.
- `scripts/estate-mirror.sh`: shallow, read-only mirror of every repo on
  `estate/code-standards-roster.txt` (83 repos, Steward's five included; a test fails if any is
  dropped). Hooks off on every git call; nothing from a mirrored tree is executed.
- `scripts/code-standards-facts.py`: the hygiene and npm-audit reports as the Prometheus textfile
  `code_standards.prom` Steward parses (contract in the script header; fail-closed, atomic).
  Dependency facts read as not scanned until `npm-audit-weekly.sh` reports per-repo status.
- `scripts/code-standards-cron.sh`: the 6-hourly NEXUS entry point.
- Root `version.json` (§2/§3 floor, which this repo did not meet).
