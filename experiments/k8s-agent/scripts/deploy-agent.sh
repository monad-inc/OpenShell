#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0

# Deploy the repo-watcher agent onto an OpenShell gateway.
#
# This is the step that a Kubernetes Job runs (see manifests/launcher-job.yaml).
# It is deliberately free of host state: every credential is read from the
# environment, which the Job supplies from Secrets.
#
# It differs from scripts/agents/run.sh in one structural way. run.sh creates a
# sandbox and then `sandbox exec`s the supervisor, keeping the launching shell
# attached for the life of the agent. That suits an operator's terminal but not
# a Job, which must exit while the agent keeps running. Here the supervisor is
# the sandbox's own main process, started detached, so the launcher's exit has
# no bearing on the agent.
#
# Required environment:
#   GITHUB_TOKEN        token scoped to the watched repository
#   SLACK_BOT_TOKEN     xoxb- token with read-only history scopes
#   and exactly one of:
#   ANTHROPIC_API_KEY | CLAUDE_CODE_OAUTH_TOKEN

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_DIR="$EXPERIMENT_DIR/agent"

GATEWAY="${OPENSHELL_GATEWAY:-kind-experiments}"
IMAGE_REF="${IMAGE_REF:-openshell-agents/repo-watcher:dev}"
SANDBOX_NAME="${SANDBOX_NAME:-repo-watcher}"
OPENSHELL_BIN="${OPENSHELL_BIN:-openshell}"
RUN_MODE="${RUN_MODE:-watch}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-900}"
MAX_TRANSIENT_FAILURES="${MAX_TRANSIENT_FAILURES:-5}"
CLAUDE_MODEL="${CLAUDE_MODEL:-claude-opus-5}"
PAYLOAD_IMAGE_DIR="/etc/openshell/agent-payload"
RECREATE="${RECREATE:-0}"

fail() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*" >&2; }

osh() { "$OPENSHELL_BIN" --gateway "$GATEWAY" "$@"; }

[[ -n "${GITHUB_TOKEN:-}" ]] || fail "GITHUB_TOKEN is required"
[[ -n "${SLACK_BOT_TOKEN:-}" ]] || fail "SLACK_BOT_TOKEN is required"

# Pick the Claude credential shape. The harness adapter enforces this too, but
# failing here gives a far better error than a sandbox that starts and dies.
if [[ -n "${ANTHROPIC_API_KEY:-}" && -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]]; then
    fail "set exactly one of ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN, not both"
elif [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
    CLAUDE_PROFILE="claude-code-apikey"
    CLAUDE_CREDENTIAL="ANTHROPIC_API_KEY"
elif [[ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]]; then
    CLAUDE_PROFILE="claude-code-oauth"
    CLAUDE_CREDENTIAL="CLAUDE_CODE_OAUTH_TOKEN"
else
    fail "set one of ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN"
fi
log "Claude credential shape: $CLAUDE_PROFILE"

import_profile() {
    local profile_id="$1" file="$2"
    # Delete-then-import, matching scripts/agents/run.sh. Importing over an
    # existing profile is refused, and the update path needs the current
    # resource_version echoed back in a re-serialized file that the CLI has
    # been observed to reject ("unsupported provider profile file format"), so
    # the delete is the reliable path. It is best-effort: a profile in use by a
    # live provider will refuse deletion, and the update fallback runs instead.
    osh provider profile delete "$profile_id" >/dev/null 2>&1 || true
    if osh provider profile import --file "$file" >/dev/null 2>&1; then
        log "Imported provider profile: $profile_id"
        return 0
    fi
    # Already present: re-import needs the current resource_version echoed back.
    local current resource_version tmp tmpdir
    current="$(osh provider profile export --output json "$profile_id")" \
        || fail "cannot import or export provider profile: $profile_id"
    resource_version="$(printf '%s' "$current" | jq -r '.resource_version // 0')"
    [[ "$resource_version" =~ ^[1-9][0-9]*$ ]] || fail "no resource version for profile: $profile_id"
    # The filename must keep a .yaml extension: the CLI picks its parser from
    # the extension and rejects an extensionless mktemp file with
    # "unsupported provider profile file format".
    local tmpdir
    tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/openshell-profile-XXXXXX")"
    tmp="$tmpdir/profile.yaml"
    ruby -ryaml -e '
        profile = YAML.load_file(ARGV[0]) || {}
        profile["resource_version"] = Integer(ARGV[1], 10)
        File.write(ARGV[2], YAML.dump(profile))
    ' "$file" "$resource_version" "$tmp"
    osh provider profile update "$profile_id" --file "$tmp" >/dev/null \
        || { rm -rf "$tmpdir"; fail "failed to update provider profile: $profile_id"; }
    rm -rf "$tmpdir"
    log "Updated provider profile: $profile_id"
}

upsert_provider() {
    local name="$1" type="$2" credential="$3"
    # `--credential KEY` (no =VALUE) makes the CLI read KEY from the
    # environment, so the secret never appears in a command line or in ps.
    if osh provider get "$name" >/dev/null 2>&1; then
        osh provider update "$name" --credential "$credential" >/dev/null
        log "Updated provider: $name"
    else
        osh provider create --name "$name" --type "$type" --credential "$credential" >/dev/null
        log "Created provider: $name"
    fi
}

log "Gateway: $GATEWAY"
osh status >/dev/null || fail "gateway $GATEWAY is not reachable"

# Apply manifest-declared gateway settings before anything else, exactly as
# run.sh does. This is not optional: with providers_v2_enabled unset, the
# gateway ignores provider profile endpoint metadata entirely and the sandbox
# gets no egress at all — every host, including the ones the profiles allow,
# fails to connect with "network connections not allowed by policy". The
# symptom looks like a broken policy rather than a missing setting.
log "Applying gateway settings."
osh settings set --global --key providers_v2_enabled --value true --yes >/dev/null

import_profile github-watcher "$AGENT_DIR/providers/github-watcher.yaml"
import_profile slack-reader "$AGENT_DIR/providers/slack-reader.yaml"
import_profile "$CLAUDE_PROFILE" "$AGENT_DIR/providers/${CLAUDE_PROFILE}.yaml"

upsert_provider github-watcher github-watcher GITHUB_TOKEN
upsert_provider slack-reader slack-reader SLACK_BOT_TOKEN
upsert_provider "$CLAUDE_PROFILE" "$CLAUDE_PROFILE" "$CLAUDE_CREDENTIAL"

if osh sandbox list 2>/dev/null | grep -qE "^${SANDBOX_NAME}[[:space:]]"; then
    if [[ "$RECREATE" == "1" ]]; then
        log "Deleting existing sandbox: $SANDBOX_NAME"
        osh sandbox delete "$SANDBOX_NAME" >/dev/null
    else
        log "Sandbox '$SANDBOX_NAME' already exists; set RECREATE=1 to replace it."
        exit 0
    fi
fi

log "Creating sandbox '$SANDBOX_NAME' from $IMAGE_REF"

# The supervisor runs as the sandbox's main process, with its configuration
# passed through an `env` command prefix rather than `--env`: the CLI reserves
# the OPENSHELL_ prefix on --env, so run.sh uses the same `env ...` trick.
#
# In watch mode the supervisor loops
# forever: bounded harness cycle, sentinel, sleep, repeat. Nothing outside the
# sandbox needs to stay attached for that to continue.
env -u OPENSHELL_SANDBOX_POLICY "$OPENSHELL_BIN" --gateway "$GATEWAY" sandbox create \
    --name "$SANDBOX_NAME" \
    --from "$IMAGE_REF" \
    --policy "$AGENT_DIR/policy.yaml" \
    --provider github-watcher \
    --provider slack-reader \
    --provider "$CLAUDE_PROFILE" \
    --no-auto-providers \
    --no-tty \
    --detach \
    -- env \
    "OPENSHELL_AGENT_ID=repo-watcher" \
    "OPENSHELL_AGENT_HARNESS=claude" \
    "OPENSHELL_AGENT_RUN_MODE=$RUN_MODE" \
    "OPENSHELL_AGENT_POLL_INTERVAL_SECONDS=$POLL_INTERVAL_SECONDS" \
    "OPENSHELL_AGENT_MAX_TRANSIENT_FAILURES=$MAX_TRANSIENT_FAILURES" \
    "CLAUDE_MODEL=$CLAUDE_MODEL" \
    bash "$PAYLOAD_IMAGE_DIR/runtime/entrypoint.sh"

log "Deployed. Follow the agent with:"
log "  openshell --gateway $GATEWAY sandbox logs $SANDBOX_NAME --follow"
