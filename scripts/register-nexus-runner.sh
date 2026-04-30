#!/usr/bin/env bash
# Register a self-hosted GitHub Actions runner on NEXUS for a Ron-owned repo.
#
# Personal-account repos can't share runners across repositories, so each new
# consumer of `docker-release.yml` needs its own dedicated runner. This script
# encodes the ~6-step toil of provisioning one and is idempotent: if a runner
# with the same name already exists for the repo, it's force-replaced via
# `config.sh --replace` rather than failing.
#
# Steps performed:
#   1. Verify gh auth + repo access (caller-side).
#   2. Mint a fresh runner registration token via the GitHub API.
#   3. SSH to NEXUS (Tailscale IP 100.98.48.63 for reachability).
#   4. Bootstrap ~/actions-runner-<repo-lower>/ from the existing
#      ~/actions-runner/actions-runner.tar.gz template + svc.sh shim
#      (the tarball ships without svc.sh; cp from the canonical install).
#   5. config.sh --unattended --replace --work _work --name <runner-name>
#      --labels self-hosted,Linux,X64,<repo-lower>,nexus-deploy[,extras]
#   6. Install + start the systemd service via svc.sh.
#   7. Verify the runner shows online via the GitHub API.
#
# Usage:
#   ./register-nexus-runner.sh <repo> <runner-name> [extra-labels]
#
# Examples:
#   ./register-nexus-runner.sh APM nexus-apm
#   ./register-nexus-runner.sh OpenClaw nexus-openclaw gpu,cuda
#
# Requirements: gh (authenticated), ssh access to ohio_@100.98.48.63 with
# passwordless sudo on the remote side.

set -euo pipefail

# ------------------------------- args ------------------------------------
if [[ $# -lt 2 || $# -gt 3 ]]; then
    cat >&2 <<EOF
usage: $(basename "$0") <repo> <runner-name> [extra-labels]

  repo          GitHub repo name under Ohio15 (e.g. APM)
  runner-name   Runner display name + systemd suffix (e.g. nexus-apm)
  extra-labels  Optional comma-separated labels to add to the standard set
                self-hosted,Linux,X64,<repo-lower>,nexus-deploy

examples:
  $(basename "$0") APM nexus-apm
  $(basename "$0") OpenClaw nexus-openclaw gpu,cuda
EOF
    exit 2
fi

REPO="$1"
RUNNER_NAME="$2"
EXTRA_LABELS="${3:-}"

OWNER="Ohio15"
NEXUS_USER="ohio_"
NEXUS_HOST="100.98.48.63"
NEXUS_TARGET="${NEXUS_USER}@${NEXUS_HOST}"
REPO_LOWER="$(echo "$REPO" | tr '[:upper:]' '[:lower:]')"

LABELS="self-hosted,Linux,X64,${REPO_LOWER},nexus-deploy"
if [[ -n "$EXTRA_LABELS" ]]; then
    LABELS="${LABELS},${EXTRA_LABELS}"
fi

SUMMARY_LINE=""
fail() {
    SUMMARY_LINE="${RUNNER_NAME}: ERROR: $*"
    echo "$SUMMARY_LINE" >&2
    exit 1
}

# ------------------------------- step 1: gh auth + repo access -----------
echo ">> verifying gh auth"
if ! gh auth status >/dev/null 2>&1; then
    fail "gh not authenticated (run: gh auth login)"
fi

echo ">> verifying access to ${OWNER}/${REPO}"
if ! gh api "repos/${OWNER}/${REPO}" --jq '.full_name' >/dev/null 2>&1; then
    fail "no access to ${OWNER}/${REPO} (typo? token scope?)"
fi

# ------------------------------- step 2: mint registration + remove tokens
echo ">> minting registration token"
REG_TOKEN="$(gh api -X POST "repos/${OWNER}/${REPO}/actions/runners/registration-token" --jq '.token' 2>/dev/null || true)"
if [[ -z "$REG_TOKEN" || "$REG_TOKEN" == "null" ]]; then
    fail "registration token mint failed"
fi

# Remove token is only used by the remote re-registration path (when an
# existing config is present). Mint pre-emptively because we won't have
# another chance once we're inside the SSH session.
echo ">> minting remove token (for idempotent re-registration)"
REMOVE_TOKEN="$(gh api -X POST "repos/${OWNER}/${REPO}/actions/runners/remove-token" --jq '.token' 2>/dev/null || true)"
if [[ -z "$REMOVE_TOKEN" || "$REMOVE_TOKEN" == "null" ]]; then
    fail "remove token mint failed"
fi

# ------------------------------- step 3+4+5+6: remote provisioning -------
# Everything from here runs on NEXUS in a single SSH session so failures
# bubble up cleanly. The remote script is parameterized via env so the token
# never appears in argv (visible in `ps`).
echo ">> provisioning on ${NEXUS_HOST} (dir: actions-runner-${REPO_LOWER})"

# Build the remote script with values substituted on this side. The token
# travels over the encrypted ssh stdin only and never appears in argv.
# The heredoc is unquoted so local "$VAR" expand; remote-only vars (HOME,
# bash internals) are escaped with \$.
REMOTE_SCRIPT="$(cat <<REMOTE_EOF
set -euo pipefail
cd "\$HOME"

OWNER='${OWNER}'
REPO='${REPO}'
RUNNER_NAME='${RUNNER_NAME}'
RUNNER_DIR="\$HOME/actions-runner-${REPO_LOWER}"
LABELS='${LABELS}'
NEXUS_USER='${NEXUS_USER}'
REG_TOKEN='${REG_TOKEN}'
REMOVE_TOKEN='${REMOVE_TOKEN}'

# Bootstrap a fresh runner directory if it doesn't already exist. If it does,
# we re-use it and let \`config.sh --replace\` handle the registration swap.
if [[ ! -d "\$RUNNER_DIR" ]]; then
    if [[ ! -f "\$HOME/actions-runner/actions-runner.tar.gz" ]]; then
        echo "ERROR: template tarball missing at ~/actions-runner/actions-runner.tar.gz" >&2
        exit 1
    fi
    if [[ ! -f "\$HOME/actions-runner/svc.sh" ]]; then
        echo "ERROR: template svc.sh missing at ~/actions-runner/svc.sh" >&2
        exit 1
    fi
    mkdir -p "\$RUNNER_DIR"
    tar -xzf "\$HOME/actions-runner/actions-runner.tar.gz" -C "\$RUNNER_DIR"
    cp "\$HOME/actions-runner/svc.sh" "\$RUNNER_DIR/svc.sh"
    chmod +x "\$RUNNER_DIR/svc.sh"
fi

cd "\$RUNNER_DIR"

# If a service is already installed in this directory, stop+uninstall it so
# the fresh config can re-template svc.sh and reinstall cleanly.
if [[ -f .service ]]; then
    SVC_FILE="\$(cat .service 2>/dev/null || true)"
    if [[ -n "\$SVC_FILE" ]] && systemctl list-unit-files "\$SVC_FILE" >/dev/null 2>&1; then
        sudo ./svc.sh stop      >/dev/null 2>&1 || true
        sudo ./svc.sh uninstall >/dev/null 2>&1 || true
    fi
fi

# If the runner is already configured (.runner exists), unregister it before
# re-registering. config.sh refuses to run twice in the same directory even
# with --replace — that flag only resolves *server-side* name collisions
# during a fresh local config pass. The remove path uses a separate "remove
# token" minted by the caller.
if [[ -f .runner ]]; then
    ./config.sh remove --token "\$REMOVE_TOKEN" >/dev/null 2>&1 || true
fi

./config.sh \\
    --unattended \\
    --replace \\
    --url "https://github.com/\${OWNER}/\${REPO}" \\
    --token "\$REG_TOKEN" \\
    --name "\$RUNNER_NAME" \\
    --work _work \\
    --labels "\$LABELS"

sudo ./svc.sh install "\$NEXUS_USER"
sudo ./svc.sh start
REMOTE_EOF
)"

if ! ssh -o StrictHostKeyChecking=accept-new "$NEXUS_TARGET" bash -s <<<"$REMOTE_SCRIPT"; then
    fail "remote provisioning failed (see ssh output above)"
fi

# ------------------------------- step 7: verify ---------------------------
echo ">> verifying runner online via GitHub API"
# Allow a few seconds for the runner to phone home and register as online.
ONLINE="false"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    STATUS="$(gh api "repos/${OWNER}/${REPO}/actions/runners" \
        --jq ".runners[] | select(.name == \"${RUNNER_NAME}\") | .status" 2>/dev/null || true)"
    if [[ "$STATUS" == "online" ]]; then
        ONLINE="true"
        break
    fi
    sleep 2
done

if [[ "$ONLINE" != "true" ]]; then
    LAST="$(gh api "repos/${OWNER}/${REPO}/actions/runners" \
        --jq ".runners[] | select(.name == \"${RUNNER_NAME}\") | {status, busy}" 2>/dev/null || echo '{}')"
    fail "runner did not reach online state within 20s (last: ${LAST:-unknown})"
fi

# ------------------------------- summary ---------------------------------
SUMMARY_LINE="${RUNNER_NAME}: online"
echo "$SUMMARY_LINE"
exit 0
