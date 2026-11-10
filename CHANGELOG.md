# Changelog

dev-standards had no root version until 1.1.0; earlier changes are recorded in the PR history
and the `v1` / `v1-rcN` workflow tags (which remain the consumer pin for reusable workflows).

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
