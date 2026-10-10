#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: exec.sh <prompt-file>" >&2
    exit 2
fi

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || { echo "missing required env: $name" >&2; exit 1; }
}

require_env CODEX_AUTH_ACCESS_TOKEN
require_env CODEX_AUTH_ACCOUNT_ID
require_env GITHUB_TOKEN

PROMPT_FILE="$1"
export GH_TOKEN="$GITHUB_TOKEN"
export GH_PROMPT_DISABLED=1
export GH_NO_UPDATE_NOTIFIER=1
export GH_NO_EXTENSION_UPDATE_NOTIFIER=1
export GH_TELEMETRY=false
export DO_NOT_TRACK=1
export HOME="${OPENSHELL_AGENT_HOME:-/sandbox/home}"

echo "openshell-agent: preparing Codex harness auth and workspace" >&2
mkdir -p "$HOME/.codex"
node - <<'NODE'
const fs = require("fs");
const path = `${process.env.HOME}/.codex/auth.json`;
const b64u = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
// Preserve gateway-issued revision and stable-handle placeholders verbatim.
// Endpoint-bound credentials reject identityless aliases by design.
const providerValue = (envName) => process.env[envName];
const now = Math.floor(Date.now() / 1000);
const fallbackIdToken = [
  b64u({ alg: "none", typ: "JWT" }),
  b64u({
    iss: "https://auth.openai.com",
    aud: "codex",
    sub: "openshell-agent",
    email: "agent@openshell.local",
    iat: now,
    exp: now + 3600,
  }),
  "placeholder",
].join(".");

fs.writeFileSync(path, JSON.stringify({
  auth_mode: "chatgpt",
  OPENAI_API_KEY: null,
  tokens: {
    id_token: providerValue("CODEX_AUTH_ID_TOKEN") || fallbackIdToken,
    access_token: providerValue("CODEX_AUTH_ACCESS_TOKEN"),
    refresh_token: providerValue("CODEX_AUTH_REFRESH_TOKEN") || "gateway-managed-refresh-token",
    account_id: providerValue("CODEX_AUTH_ACCOUNT_ID"),
  },
  last_refresh: new Date().toISOString(),
}, null, 2));
NODE
chmod 600 "$HOME/.codex/auth.json"

WORK="$(mktemp -d)"
# The final message lives outside the harness's working dir, so the agent
# cannot read or rewrite it mid-cycle.
RESULT_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK" "$RESULT_DIR"' EXIT
cd "$WORK"

CODEX_BIN="${CODEX_BIN:-codex}"
ADAPTER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$(cd "$ADAPTER_DIR/../../.." && pwd)"
if [[ -x "$PAYLOAD_DIR/runtime/harnesses/codex/codex" ]]; then
    CODEX_BIN="$PAYLOAD_DIR/runtime/harnesses/codex/codex"
fi
CODEX_MODEL="${CODEX_MODEL:-gpt-5.5}"
CODEX_REASONING="${CODEX_REASONING:-high}"

echo "openshell-agent: invoking Codex bounded cycle (model=$CODEX_MODEL, reasoning=$CODEX_REASONING)" >&2

LAST_MESSAGE_FILE="$RESULT_DIR/last-message.txt"

CODEX_EXEC_ARGS=(
    exec
    --skip-git-repo-check
    --sandbox danger-full-access
    --ephemeral
    # One JSON event per line on stdout, written as each happens: every agent
    # message, command and its output, MCP call and result, and turn usage.
    # With the sandbox's agent_output_export_enabled setting on, the
    # supervisor exports the stream unchanged.
    --json
    --output-last-message "$LAST_MESSAGE_FILE"
)

if "$CODEX_BIN" exec --help 2>/dev/null | grep -q -- "--ignore-user-config"; then
    CODEX_EXEC_ARGS+=(--ignore-user-config)
fi
if "$CODEX_BIN" exec --help 2>/dev/null | grep -q -- "--ignore-rules"; then
    CODEX_EXEC_ARGS+=(--ignore-rules)
fi

"$CODEX_BIN" "${CODEX_EXEC_ARGS[@]}" \
    -c "model=\"${CODEX_MODEL}\"" \
    -c "model_reasoning_effort=\"${CODEX_REASONING}\"" \
    - \
    < "$PROMPT_FILE" &
harness_pid=$!

# The harness is not exec'd, so pass termination on to it and wait for it to
# finish: it must never outlive the adapter, or lose its directories to the
# EXIT trap while still running.
trap 'kill -TERM "$harness_pid" 2>/dev/null || true' TERM INT HUP
status=0
wait "$harness_pid" || status=$?
# A trapped signal interrupts `wait` while the harness is still shutting down.
while kill -0 "$harness_pid" 2>/dev/null; do
    status=0
    wait "$harness_pid" || status=$?
done

# The JSON stream carries the final answer inside an event, so hand the
# supervisor the answer's sentinel lines directly.
if [[ -f "$LAST_MESSAGE_FILE" ]]; then
    grep -E '^OPENSHELL_AGENT_RESULT[[:space:]]+' "$LAST_MESSAGE_FILE" || true
fi

exit "$status"
