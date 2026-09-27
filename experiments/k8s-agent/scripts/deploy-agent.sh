#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0

# Deploy an agent from experiments/k8s-agent/agents/<name> onto an OpenShell
# gateway. Agent-agnostic: providers, credentials, and scope all come from the
# agent's own manifest.
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
AGENT_NAME="${AGENT_NAME:-repo-watcher}"
# In the launcher image the definition is baked at /work/agent; from a checkout
# it resolves from the agent name.
AGENT_DIR="${AGENT_DIR:-$EXPERIMENT_DIR/agents/$AGENT_NAME}"

# Two ways to address the gateway:
#   OPENSHELL_GATEWAY_ENDPOINT -- a URL, used directly with no local
#     registration. This is the in-cluster path: a Job has no ~/.config/openshell
#     and cannot run `gateway add`.
#   OPENSHELL_GATEWAY -- a registered gateway name, for workstation use.
GATEWAY="${OPENSHELL_GATEWAY:-kind-experiments}"
GATEWAY_ENDPOINT="${OPENSHELL_GATEWAY_ENDPOINT:-}"
IMAGE_REF="${IMAGE_REF:-openshell-agents/$AGENT_NAME:dev}"
SANDBOX_NAME="${SANDBOX_NAME:-$AGENT_NAME}"
OPENSHELL_BIN="${OPENSHELL_BIN:-openshell}"
RUN_MODE="${RUN_MODE:-watch}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-900}"
MAX_TRANSIENT_FAILURES="${MAX_TRANSIENT_FAILURES:-5}"
CLAUDE_MODEL="${CLAUDE_MODEL:-claude-opus-5}"
PAYLOAD_IMAGE_DIR="/etc/openshell/agent-payload"
RECREATE="${RECREATE:-0}"

# One workspace per agent. Provider profiles, providers, and sandboxes are all
# workspace-scoped, and profile names carry enforced scope: a github profile
# pins one repository. Deploying a second agent into the shared `default`
# workspace would upsert over the first agent's profile and silently re-pin what
# it is allowed to reach, with nothing visible in git or in `helm diff`.
# Isolating per agent makes that structurally impossible.
WORKSPACE="${WORKSPACE:-$SANDBOX_NAME}"

# Provenance stamped onto the sandbox so `openshell sandbox list` shows what is
# actually running, rather than requiring trust that it matches git.
GIT_SHA="${GIT_SHA:-unknown}"
CHART_VERSION="${CHART_VERSION:-unknown}"
SKILLS_VERSION="${SKILLS_VERSION:-unknown}"

fail() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*" >&2; }

if [[ -n "$GATEWAY_ENDPOINT" ]]; then
    GATEWAY_ARGS=(--gateway-endpoint "$GATEWAY_ENDPOINT")
    GATEWAY_LABEL="$GATEWAY_ENDPOINT"
else
    GATEWAY_ARGS=(--gateway "$GATEWAY")
    GATEWAY_LABEL="$GATEWAY"
fi

# Workspace names are DNS-1123 labels capped at 19 characters by the gateway.
# Fail here with a clear message rather than at the first API call.
if [[ ! "$WORKSPACE" =~ ^[a-z0-9]([a-z0-9-]{0,17}[a-z0-9])?$ ]]; then
    fail "workspace '$WORKSPACE' is not a valid DNS-1123 label of at most 19 characters; set WORKSPACE (or agent.workspace) explicitly"
fi

# Two arg sets. Workspace-scoped calls carry --workspace; the call that creates
# the workspace must not, because the flag names a workspace that does not exist
# yet.
GATEWAY_BASE_ARGS=("${GATEWAY_ARGS[@]}")
GATEWAY_ARGS+=(--workspace "$WORKSPACE")

osh() { "$OPENSHELL_BIN" "${GATEWAY_ARGS[@]}" "$@"; }
osh_global() { "$OPENSHELL_BIN" "${GATEWAY_BASE_ARGS[@]}" "$@"; }

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
    local import_output
    if import_output="$(osh provider profile import --file "$file" 2>&1)"; then
        log "Imported provider profile: $profile_id"
        return 0
    fi
    # An existing profile is the expected steady-state path, not a problem.
    # Anything else is a real rejection — a bad category, a malformed rule — and
    # must be shown. Swallowing it means a schema error surfaces later as the
    # export fallback's far less useful "provider profile not found".
    if [[ "$import_output" != *"already exists"* ]]; then
        log "Import of '$profile_id' was rejected:"
        printf '%s\n' "$import_output" >&2
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

# Multi-credential form: some providers declare more than one credential.
upsert_provider_multi() {
    local name="$1" type="$2"
    shift 2
    if osh provider get "$name" >/dev/null 2>&1; then
        osh provider update "$name" "$@" >/dev/null
        log "Updated provider: $name"
    else
        osh provider create --name "$name" --type "$type" "$@" >/dev/null
        log "Created provider: $name"
    fi
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

log "Gateway: $GATEWAY_LABEL"
log "Workspace: $WORKSPACE"
osh status >/dev/null || fail "gateway $GATEWAY_LABEL is not reachable"

# Apply manifest-declared gateway settings before anything else, exactly as
# run.sh does. This is not optional: with providers_v2_enabled unset, the
# gateway ignores provider profile endpoint metadata entirely and the sandbox
# gets no egress at all — every host, including the ones the profiles allow,
# fails to connect with "network connections not allowed by policy". The
# symptom looks like a broken policy rather than a missing setting.
PROVIDER_ARGS=()

# Gateway settings come from the agent manifest. Settings are global, not
# workspace-scoped; --workspace is harmless here.
#
# A key the gateway does not recognise is a warning, not a failure. Toggles get
# removed once the behavior they gated becomes the default — `providers_v2_enabled`
# did exactly that — and a manifest pinned to an older gateway should not block
# a deploy against a newer one. A genuine rejection still fails.
log "Applying gateway settings."
SETTINGS_SPEC="$(ruby -ryaml -e '
  manifest = YAML.load_file(ARGV[0]) || {}
  (manifest["settings"] || []).each { |setting| puts "#{setting.fetch("key")} #{setting.fetch("value")}" }
' "$AGENT_DIR/agent.yaml")" || fail "cannot read settings from $AGENT_DIR/agent.yaml"

while read -r setting_key setting_value; do
    [[ -n "$setting_key" ]] || continue
    if settings_output="$(osh settings set --global --key "$setting_key" --value "$setting_value" --yes 2>&1)"; then
        log "Setting applied: $setting_key=$setting_value"
    elif [[ "$settings_output" == *"unknown setting key"* ]]; then
        log "Setting '$setting_key' is not recognised by this gateway; skipping (likely graduated to default)."
    else
        printf '%s\n' "$settings_output" >&2
        fail "failed to apply gateway setting '$setting_key'"
    fi
done <<< "$SETTINGS_SPEC"

# Create-then-tolerate rather than get-then-create: `workspace get` has been
# observed to report success for a workspace that does not exist, which then
# fails confusingly at the first workspace-scoped call.
if workspace_output="$(osh_global workspace create --name "$WORKSPACE" \
    --label "managed-by=openshell-agent-chart" 2>&1)"; then
    log "Workspace: $WORKSPACE (created)"
elif [[ "$workspace_output" == *"already exists"* || "$workspace_output" == *"AlreadyExists"* ]]; then
    log "Workspace: $WORKSPACE (exists)"
else
    printf '%s\n' "$workspace_output" >&2
    log "Known workspaces:"
    osh_global workspace list >&2 || true
    fail "cannot create or find workspace '$WORKSPACE'"
fi

# Scope assertion. The Helm chart passes what its values *claim* the agent's
# scope is; the profile below is what actually gets enforced. If someone changes
# the chart value without rebuilding the images, this turns a silent mismatch —
# an agent quietly pinned to the wrong repository — into a failed release.
if [[ -n "${DEPLOY_DEBUG:-}" ]]; then
    log "DEBUG workspace bytes:"; printf '%s' "$WORKSPACE" | od -c | head -2 >&2
    log "DEBUG gateway args: ${GATEWAY_ARGS[*]}"
    log "DEBUG workspace list:"; osh_global workspace list >&2 || true
fi

# EXPECTED_GITHUB_SCOPE is an owner, or an owner/repo. It is checked against
# whichever GitHub profile this agent ships, so it works for a single-repo
# agent and an org-scoped one alike.
EXPECTED_GITHUB_SCOPE="${EXPECTED_GITHUB_SCOPE:-${EXPECTED_GITHUB_REPO:-}}"
if [[ -n "$EXPECTED_GITHUB_SCOPE" ]]; then
    if grep -qr "/repos/${EXPECTED_GITHUB_SCOPE}" "$AGENT_DIR/providers/"; then
        log "Scope verified: a provider profile pins $EXPECTED_GITHUB_SCOPE"
    else
        fail "scope mismatch: expected '$EXPECTED_GITHUB_SCOPE', but no baked provider profile pins it. Rebuild the launcher and sandbox images after changing the GitHub scope."
    fi
fi

# Providers come from the agent's own manifest rather than being hardcoded
# here, so this script works unchanged for any agent. Each line is
# "<profile-id> <credential-env> [<credential-env>...]".
PROVIDER_SPEC="$(ruby -ryaml -e '
  manifest = YAML.load_file(ARGV[0]) || {}
  (manifest["providers"] || []).each do |provider|
    envs = (provider["credentials"] || []).map { |c| c["env"] }.compact
    puts ([provider.fetch("profile")] + envs).join(" ")
  end
' "$AGENT_DIR/agent.yaml")" || fail "cannot read providers from $AGENT_DIR/agent.yaml"

[[ -n "$PROVIDER_SPEC" ]] || fail "agent manifest declares no providers"

while read -r profile_id credential_envs; do
    [[ -n "$profile_id" ]] || continue

    # The Claude provider is the one variant point: the manifest names the
    # API-key profile, and supplying CLAUDE_CODE_OAUTH_TOKEN instead selects the
    # OAuth one. Everything else is taken from the manifest verbatim.
    if [[ "$profile_id" == "claude-code-apikey" || "$profile_id" == "claude-code-oauth" ]]; then
        profile_id="$CLAUDE_PROFILE"
        credential_envs="$CLAUDE_CREDENTIAL"
    fi

    profile_file="$AGENT_DIR/providers/${profile_id}.yaml"
    [[ -f "$profile_file" ]] || fail "missing provider profile: $profile_file"

    for credential_env in $credential_envs; do
        [[ -n "${!credential_env:-}" ]] || fail "$credential_env is required by provider '$profile_id' but is not set"
    done

    import_profile "$profile_id" "$profile_file"

    credential_args=()
    for credential_env in $credential_envs; do
        credential_args+=(--credential "$credential_env")
    done
    upsert_provider_multi "$profile_id" "$profile_id" "${credential_args[@]}"
    PROVIDER_ARGS+=(--provider "$profile_id")
done <<< "$PROVIDER_SPEC"

if osh sandbox list 2>/dev/null | grep -qE "^${SANDBOX_NAME}[[:space:]]"; then
    if [[ "$RECREATE" == "1" ]]; then
        log "Deleting existing sandbox: $SANDBOX_NAME"
        osh sandbox delete "$SANDBOX_NAME" >/dev/null
    else
        log "Sandbox '$SANDBOX_NAME' already exists; set RECREATE=1 to replace it."
        # Not an early exit: probes should still run so a re-deploy re-asserts
        # that the live policy still matches what the profiles declare.
        SKIP_CREATE=1
    fi
fi

# Sandbox label values accept only alphanumerics, '-', '_', and '.', so an
# image reference has to be flattened before it can be recorded as one.
IMAGE_REF_LABEL="$(printf '%s' "$IMAGE_REF" | tr '/:' '__')"

if [[ "${SKIP_CREATE:-0}" != "1" ]]; then
log "Creating sandbox '$SANDBOX_NAME' from $IMAGE_REF"

# The supervisor runs as the sandbox's main process, with its configuration
# passed through an `env` command prefix rather than `--env`: the CLI reserves
# the OPENSHELL_ prefix on --env, so run.sh uses the same `env ...` trick.
#
# In watch mode the supervisor loops
# forever: bounded harness cycle, sentinel, sleep, repeat. Nothing outside the
# sandbox needs to stay attached for that to continue.
env -u OPENSHELL_SANDBOX_POLICY "$OPENSHELL_BIN" "${GATEWAY_ARGS[@]}" sandbox create \
    --name "$SANDBOX_NAME" \
    --from "$IMAGE_REF" \
    --policy "$AGENT_DIR/policy.yaml" \
    "${PROVIDER_ARGS[@]}" \
    --no-auto-providers \
    --no-tty \
    --detach \
    --label "git-sha=$GIT_SHA" \
    --label "chart-version=$CHART_VERSION" \
    --label "agent-image=$IMAGE_REF_LABEL" \
    --label "skills-version=$SKILLS_VERSION" \
    -- env \
    "OPENSHELL_AGENT_ID=$AGENT_NAME" \
    "OPENSHELL_AGENT_HARNESS=claude" \
    "OPENSHELL_AGENT_RUN_MODE=$RUN_MODE" \
    "OPENSHELL_AGENT_POLL_INTERVAL_SECONDS=$POLL_INTERVAL_SECONDS" \
    "OPENSHELL_AGENT_MAX_TRANSIENT_FAILURES=$MAX_TRANSIENT_FAILURES" \
    "CLAUDE_MODEL=$CLAUDE_MODEL" \
    bash "$PAYLOAD_IMAGE_DIR/runtime/entrypoint.sh"
fi

# Optional policy probe. Asserts that the deployed policy actually behaves the
# way the provider profiles claim, instead of trusting that it does. The proxy
# answers 403 when no rule permits a request, so 403 means denied-by-policy and
# anything else means permitted-by-policy (the result then coming from upstream,
# which with placeholder credentials is a 401).
if [[ "${POLICY_PROBE:-0}" == "1" && -f "$AGENT_DIR/probes.txt" ]]; then
    log "Running policy probes against '$SANDBOX_NAME'."
    probe_failures=0
    # Read probes on FD 3: `sandbox exec` reads stdin and would otherwise
    # consume the rest of the file after the first iteration.
    while IFS='|' read -r probe_label probe_expect probe_cmd <&3; do
        [[ -n "$probe_label" && "$probe_label" != \#* && "$probe_label" != *=* ]] || continue

        if [[ "$probe_cmd" == curl\ * ]]; then
            # Classify by HTTP status. 403 is an L7 refusal; 000 means the
            # connection never opened, which for a resolvable host is an L4
            # refusal.
            probe_out="$(osh sandbox exec -n "$SANDBOX_NAME" --no-tty -- \
                bash -lc "${probe_cmd/curl /curl -s -o /dev/null -w '%{http_code}' --max-time 15 }" \
                </dev/null 2>/dev/null | tr -dc '0-9' || true)"
            probe_out="${probe_out:-000}"
            if [[ "$probe_out" == "403" ]]; then
                probe_result="deny"; probe_detail="denied by L7 (403)"
            elif [[ "$probe_out" == "000" ]]; then
                probe_result="deny"; probe_detail="denied by L4 (no connection)"
            else
                probe_result="allow"; probe_detail="permitted; upstream said $probe_out"
            fi
        else
            # Classify by exit status.
            if osh sandbox exec -n "$SANDBOX_NAME" --no-tty -- \
                bash -lc "$probe_cmd" </dev/null >/dev/null 2>&1; then
                probe_result="allow"; probe_detail="command succeeded"
            else
                probe_result="deny"; probe_detail="command failed"
            fi
        fi

        if [[ "$probe_result" == "$probe_expect" ]]; then
            log "  PASS  $probe_label: $probe_detail"
        else
            log "  FAIL  $probe_label: expected $probe_expect, got $probe_result ($probe_detail)"
            probe_failures=$((probe_failures + 1))
        fi
    done 3< "$AGENT_DIR/probes.txt"
    [[ "$probe_failures" -eq 0 ]] || fail "$probe_failures policy probe(s) did not match the declared intent"
    log "All policy probes matched the declared intent."
fi

log "Deployed. Follow the agent with:"
log "  openshell ${GATEWAY_ARGS[*]} logs $SANDBOX_NAME --tail"
