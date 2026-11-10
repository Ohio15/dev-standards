# Changelog

dev-standards had no root version until 1.1.0; earlier changes are recorded in the PR history
and the `v1` / `v1-rcN` workflow tags (which remain the consumer pin for reusable workflows).

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
