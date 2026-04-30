# Release Standard v1

Canonical release pipeline for Ron-owned repos. One contract, four reusable
workflows, opt-in per repo via a `release-config.yml` file at the repo root.

## Goals

- One way to release any Ron-owned project — same trigger (push tag `v*`),
  same gates, same artifact pattern, same notification path.
- Per-repo behavior is data, not bespoke YAML. The reusable workflows in
  this repo do the work; consumers add a thin caller workflow + a config.
- Drift is observable. The hygiene cron records "what's running where" vs
  "what's the latest tag" and alerts on lag.

## Non-goals (v1)

- Code signing for Electron desktop apps. The workflow has a `signing` block
  that is a no-op when omitted; flip it on per-app once you commit to a cert.
- Multi-arch Docker images. v1 ships `linux/amd64` only — NEXUS is x86_64.
- Public registries other than GHCR.
- ntfy publish from cloud runners. ntfy is LAN/Tailscale only. The
  `docker-release` deploy job runs on the self-hosted NEXUS runner and
  posts there; cloud-only flows (`electron-release`, `lib-release`) defer
  to GitHub email + `gh release list`. A future Phase 1A.5 may add a
  Cloudflare-tunnel ntfy bridge with publisher auth.

## Surfaces

| Surface | Reusable workflow | Artifact | Consumer example |
|---|---|---|---|
| Electron desktop | `electron-release.yml` | NSIS installer + `latest.yml` published to GitHub Release | PDFManager |
| Container service | `docker-release.yml` | Image at `ghcr.io/ohio15/<repo>:<tag>` + rolling deploy on NEXUS | Sentinel, OpenClaw, ToolVault, APM |
| MCP server | `mcp-release.yml` | Same as docker-release + post-deploy `~/.mcp.json` version pin update | shared-brain MCP, n3xus-notify |
| Library / shared module | `lib-release.yml` | Tagged GitHub Release; consumers fetch by tag | dev-standards itself |

## The contract: `release-config.yml`

Every enrolled repo has a `release-config.yml` at root. The reusable workflow
reads it; the caller workflow is a 5-line shim.

```yaml
# release-config.yml — schema v1
surface: electron | docker | mcp | lib   # which reusable workflow this repo consumes
project: pdf-manager                      # used in artifact names + ntfy title

# Pre-release gates. All required unless explicitly disabled.
gates:
  tests: true                  # run `npm test` (or test_command override)
  test_command: npm test       # optional override
  gitleaks: true               # secret scan on the tagged commit
  size_guard: true             # reject files >10 MB not in .large-files-allowlist
  npm_audit: high              # min severity that fails: low | moderate | high | critical | off

# Surface-specific blocks below. Only the matching block is read.

electron:
  targets: [win, mac, linux]   # which builds to produce. omit for win-only.
  installer_name_template: PDF-Manager-Setup-${version}.${ext}
  signing:                     # optional — omit for unsigned
    win:
      cert_secret: WIN_CSC_LINK
      cert_password_secret: WIN_CSC_KEY_PASSWORD
    mac:
      identity_secret: MAC_DEVELOPER_ID
      notarize: true

docker:
  # One or more images per release. Each is built in parallel on a cloud
  # runner, tagged `:vX.Y.Z` + `:latest` + `:<sha>`, and pushed to GHCR.
  images:
    - name: ghcr.io/ohio15/sentinel-backend
      dockerfile: server/Dockerfile
      context: ./server
      # build_args is optional — omit entirely if no bake-time config needed.
    - name: ghcr.io/ohio15/sentinel-frontend
      dockerfile: frontend/Dockerfile
      context: ./frontend
      # build_args: passed as --build-arg to docker build. Values support two
      # placeholder forms expanded at runtime, before the image is built:
      #
      #   ${vars.NAME}     resolved from GitHub Actions repo/org Variables.
      #                    Missing variables fail the build with a clear error.
      #   ${secrets.NAME}  resolved from a secrets JSON the CALLER must opt
      #                    into by passing `build_secrets_json: ${{ toJson(secrets) }}`
      #                    to the reusable workflow. Each substitution emits a
      #                    ::warning:: in the build log because the resulting
      #                    image bakes the secret in plaintext layers — anyone
      #                    who can pull it can extract the secret. Use sparingly
      #                    (private package registry tokens are the typical
      #                    legitimate case; prefer BuildKit `--mount=type=secret`
      #                    when possible).
      #
      # NAME must match [A-Z_][A-Z0-9_]*. Plain literals (no placeholder) pass
      # straight through. Dollar-brace expressions without a dot — e.g.
      # `${HOME}` for Dockerfile-time shell expansion — are NOT interpreted by
      # the substitution layer and pass through as-is.
      #
      # Note: the syntax is `${name.X}`, NOT `${{ name.X }}`, so the YAML
      # expression engine ignores it at workflow-eval time and substitution
      # happens after release-config.yml is parsed at build time.
      build_args:
        VITE_API_URL: https://${vars.DOMAIN}/api
        VITE_WS_URL: wss://${vars.DOMAIN}/ws
        BUILD_REVISION: ${vars.GIT_SHA_SHORT}
        STATIC_VAL: literal-value
        # Rare: bake a secret into the image. Emits a ::warning:: per build.
        # NPM_TOKEN: ${secrets.NPM_READ_TOKEN}
  deploy:
    nexus_path: ~/Sentinel      # cwd on NEXUS for `docker compose up -d`
    compose_file: docker-compose.yml
    services: [backend, frontend]   # which services to roll. Compose entries
                                # for these must use
                                # `image: ghcr.io/<owner>/<repo>-<svc>:${IMAGE_TAG:-latest}`
                                # so the deploy can swap tags atomically.
    health_check:
      command: curl -fsS http://localhost:3001/health
      timeout_seconds: 60
      interval_seconds: 5
    rollback_on_health_fail: true

mcp:
  # Inherits all `docker:` keys.
  image: ghcr.io/ohio15/n3xus-notify
  # plus:
  client_pin_paths:            # files updated post-deploy with new version
    - ~/.mcp.json
    - ~/.claude/.mcp.json
  pin_key: "@n3xus/notify"     # key to bump in those files

lib:
  changelog: CHANGELOG.md      # required for lib releases — release notes pulled from here
  npm_publish: false           # if true, publishes to npm registry; else tag-only
```

## Versioning rules

- **Source of truth**: the version in `package.json` (or `pyproject.toml` /
  `Cargo.toml` / `release-config.yml:version` for non-npm repos). The CI
  asserts that the pushed tag matches this value: `v${pkg.version}`.
- **Bump policy**: Conventional Commits since the previous tag drive the
  bump. `fix:` → patch, `feat:` → minor, `BREAKING CHANGE:` footer or `!`
  in the type → major. The Dependabot tier matrix already in shared-brain
  governs auto-merge; this is the same matrix surfaced for human releases.
- **Tag format**: `v<major>.<minor>.<patch>` (no `v` for the package.json
  field; only on the git tag).
- **Pre-releases**: `v1.2.3-rc.1`, `v1.2.3-beta.2`. The reusable workflow
  marks the GitHub Release as prerelease=true automatically when the tag
  has a `-` segment.

## Pre-release gates (`release-gates.yml`)

A composite reusable workflow that the four surface workflows all depend on.
Runs in parallel jobs; any failure aborts the release.

| Gate | What it does | Bypassable? |
|---|---|---|
| `tests` | Runs `npm test` (or `test_command` override). Coverage threshold not enforced at this layer. | Per-repo by setting `gates.tests: false` (rare; usually done only for documentation-only repos). |
| `gitleaks` | Re-runs the gitleaks scan on the full tagged commit (not just diff). The pre-commit hook scans staged diffs only; this is the belt-and-suspenders catch. | No. |
| `size_guard` | Same logic as `workflows/size-guard.yml` but enforced at release time. | Per-file via `.large-files-allowlist`. |
| `npm_audit` | Runs `npm audit --json` against `gates.npm_audit` severity floor. | Per-repo by setting `npm_audit: off` (discouraged). |
| `tag_matches_version` | Asserts pushed tag matches `package.json:version`. Catches the "I forgot to bump" case. | No. |
| `conventional_commits_lint` | Lints commit messages since previous tag. | Per-repo via `gates.conventional_commits: false`. |

## Caller workflow shape

A consumer's `.github/workflows/release.yml` is a 5-line shim:

```yaml
name: Release
on:
  push:
    tags: ['v*']
jobs:
  release:
    uses: Ohio15/dev-standards/.github/workflows/electron-release.yml@v1
    secrets: inherit
```

`@v1` is a moving major-version tag in dev-standards. Patch updates to the
reusable workflow are picked up automatically; breaking changes ship as
`@v2` and consumers migrate when they choose.

### Build-arg secrets (docker / mcp surfaces)

If the docker `build_args` block uses any `${secrets.X}` placeholders, the
caller must opt in by forwarding the secrets context as a JSON input.
Reusable workflows cannot enumerate `secrets: inherit` programmatically, so
the caller has to make it explicit:

```yaml
jobs:
  release:
    uses: Ohio15/dev-standards/.github/workflows/docker-release.yml@v1
    secrets: inherit
    with:
      # Required only if any build_args value references ${secrets.X}.
      # Pass the whole secrets context, or curate a subset by hand.
      build_secrets_json: ${{ toJson(secrets) }}
```

Without this input, any `${secrets.X}` reference in `build_args` fails the
build with an explicit error pointing the user at this section. `${vars.X}`
references work without any caller change because `vars` is always
enumerable from inside the reusable workflow.

## Drift detection

`scripts/repo-hygiene-scan.py` is extended (Phase 1C) to:

1. For each enrolled repo (those with a `release-config.yml`), record:
   - `latest_release` from `gh release list -L 1 --json tagName,publishedAt`
   - `latest_image_tag` from GHCR API for docker/mcp surfaces
2. SSH NEXUS, `docker inspect` each running container in scope, capture the
   `Image` digest.
3. Resolve `Image` digest → tag via the GHCR manifest API.
4. Write `versions.yml` to dev-standards, committed each scan run.
5. ntfy alert (priority=high) when running tag is N≥2 releases behind latest.

## Migration policy

No big-bang. Each repo migrates the next time it's touched in normal work:
add `release-config.yml`, replace bespoke `dist:*` scripts with the caller
workflow. PDFManager and Sentinel are the Phase 1 pilots — every other
repo waits its turn.

## Phasing

| Phase | Deliverables | Status |
|---|---|---|
| 1A | SPEC, `release-gates.yml`, `electron-release.yml`, PDFManager pilot | in progress |
| 1B | Self-hosted runner on NEXUS, `docker-release.yml`, Sentinel pilot, ntfy publish from deploy job | pending Phase 1A approval |
| 1C | `mcp-release.yml`, `lib-release.yml`, drift detection, dev-standards self-migration | pending |
| 2 | Opportunistic migration of remaining repos | rolling |

## Open questions (resolve before Phase 1B)

- GHCR retention: keep last N tags, or unbounded? GitHub auto-prunes if
  storage budget is hit; default is unbounded for private packages.
- Rollback target: previous tag from `gh release list`, or last known
  healthy from `versions.yml` registry? The latter is more reliable
  (records actual deployed-and-healthy state) but requires the registry
  to be in place first — Phase 1C dependency.
- Self-hosted runner security: Docker-socket access lets a compromised
  workflow take over NEXUS. Mitigate with branch protection (only `main`
  + tags can dispatch deploy jobs) and required reviews on workflow file
  changes in this repo.
