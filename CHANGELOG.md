# Changelog

dev-standards had no root version until 1.1.0; earlier changes are recorded in the PR history
and the `v1` / `v1-rcN` workflow tags (which remain the consumer pin for reusable workflows).

## 1.1.6 - 2026-11-14

repo-hygiene-scan reads data, minified and vendored runtime-source files under a documented
16 MiB cap (`MAX_DATA_ARTEFACT_BYTES`; `artefact_kind()` classifies `.json`, `*.min.*`/`*.bundle.*`
and `vendor`/`third_party` paths) instead of the 1 MiB hand-written-code cap. Before, one such file
(openobd `data/2010_silverado_best.cal.json`, 1.8 MB; pdfmanager
`src/renderer/public/pdf.worker.min.mjs`, 1.4 MB) produced a `*-unexamined` finding and the
code-standards exporter reported the whole repo as `repo_scanned 0`, so Steward saw blind-scan on
every code position of those repos (work item 9871f5ac). Those files are now read and examined by
the independence and stub-marker passes like any other source; an artefact past 16 MiB is still
reported unexamined, with its kind named (`data-artefact`, `minified-artefact`,
`vendored-artefact`). Hand-written source keeps the 1 MiB cap unchanged.

## 1.1.5 - 2026-11-14

Security register SC-56..SC-57 graduated from audit-shared-brain-2026-11-13, approved by Ron
2026-11-14 (decision 1f1bf2a9): an authorization tier assigned by action name where another action
reaches the same effect at a lower tier (SC-56), and a fix that revives a dormant data path
without re-auditing that path's sinks (SC-57). Both register copies updated identically.

## 1.1.4 - 2026-11-10

The code-standards exporter scanned no dependencies: `scripts/npm-audit-weekly.sh` was committed
mode 100644 (since before 1a18512) while `code-standards-cron.sh` runs it directly
(`timeout ... "$here/npm-audit-weekly.sh"`). On NEXUS every 6-hourly run got exit 126 and exported
every dependency position as not scanned (first exporter run 2026-11-10T18:26Z): a blind scan,
reported as not scanned rather than clean, but no dependency was examined.

- Index mode 100755 (`git update-index --chmod=+x`) for `scripts/npm-audit-weekly.sh` (run directly
  by the cron and by README's crontab and `./scripts/` examples), `scripts/register-nexus-runner.sh`
  (README and its own usage run `./scripts/register-nexus-runner.sh`) and
  `scripts/repo-hygiene-scan.py` (README's NEXUS crontab line runs it without an interpreter).
- `scripts/tests/test_exec_bits.py` (new): every tracked shell script or hook with a shebang, every
  `"$here/<name>"` a tracked script runs without an interpreter, and every `./scripts/<name>` /
  `.../dev-standards/scripts/<name>` a tracked doc or script runs without an interpreter must be
  100755 in the git index; a failure names the file and each place that runs it. Red on 9c90e0a
  (those three files), green after.

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
- M4 (439c18f1) `scripts/repo-hygiene-scan.py`: repo accesses followed symlinks (a `VERSION ->`
  secret reached the report and the shared-brain post as a "version"; `-> /dev/zero` passed a
  cap that trusted `st_size`). Every metadata probe of a path inside a scanned repo now goes
  through `lstat_repo_path` (no absolute or `..` path, lstat on every component, symlinks and
  Windows reparse points refused, only ENOENT/ENOTDIR read as absent) and every read through
  `read_repo_file` (that, plus `S_ISREG` re-checked on the descriptor, `O_NOFOLLOW|O_NONBLOCK`,
  bounded `read(cap + 1)`). The workflow walk (`walk_repo_files`, `followlinks=False`) replaces
  `rglob` and reports symlinked and unreadable entries as not examined.
- Security gate pass 1 on #87 (same version, unreleased):
  - SC-01: the first cut missed two accesses. `scan_security_register` compared
    `path.resolve()` with the canonical path, so a `SECURITY-CHECKS.md` committed as a symlink to
    the canonical was skipped as "the canonical file itself"; the self-skip is now an inode match
    on a real file reached with no link, and a linked copy reports `security-register-stale`.
    `.gitmodules` was probed with `is_file()` and handed to `git config -f` by repo path; it is
    now read with `read_repo_file` and git parses a private temp copy (new LOW
    `submodule-unexamined` when it cannot be read). `file_size`, the drift mtime, the hook-drift
    and hooksPath probes, the auto-apply marker and enrolment discovery use `lstat_repo_path`;
    git is run in a submodule path only when it is a real directory. The class test now
    inventories every filesystem access and every path argument to `run()` from the AST against
    an allow-list of operator paths (no dead rows allowed).
  - SC-04: `walk_repo_files` reported nothing on a permission or I/O error (`except OSError:
    return []`, `os.walk` without `onerror`); every error but absence is now listed as not
    examined. `discover_enrolled_repos` records each candidate it drops (symlinked, oversized,
    unreadable, not UTF-8, not a mapping) and the drift report lists them.
  - SC-13: this entry, the test docstring and STANDARDS.md now claim only what the boundary
    tests show.
  - `scripts/fleet-precommit-inventory.py` keeps its direct reads: it has no scheduled or mirror
    caller (manual run over the operator's own `D:/Projects` checkouts only).
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
