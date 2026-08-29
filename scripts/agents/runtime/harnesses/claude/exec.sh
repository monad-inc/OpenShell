#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Claude Code harness adapter.
#
# Contract (shared with runtime/harnesses/codex/exec.sh):
#   argv[1]  path to the rendered agent prompt
#   stdout   streamed harness output; the supervisor scans it for the final
#            `OPENSHELL_AGENT_RESULT {...}` sentinel line
#   exit     harness exit status
#
# Auth: exactly one of the two credential shapes must be present. Both arrive as
# gateway-issued provider placeholders that the sandbox egress proxy swaps for
# the real secret on the wire, so neither is written to disk here.
#   ANTHROPIC_API_KEY        -> claude-code provider (API key billing)
#   CLAUDE_CODE_OAUTH_TOKEN  -> claude-code-oauth provider (subscription billing)

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: exec.sh <prompt-file>" >&2
    exit 2
fi

PROMPT_FILE="$1"
[[ -f "$PROMPT_FILE" ]] || { echo "missing prompt file: $PROMPT_FILE" >&2; exit 2; }

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || { echo "missing required env: $name" >&2; exit 1; }
}

has_env() {
    [[ -n "${!1:-}" ]]
}

# Exactly one auth mode. Refusing both-set keeps billing attribution
# unambiguous rather than silently deferring to the CLI's precedence.
if has_env ANTHROPIC_API_KEY && has_env CLAUDE_CODE_OAUTH_TOKEN; then
    echo "both ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN are set; attach exactly one Claude provider" >&2
    exit 1
fi
if ! has_env ANTHROPIC_API_KEY && ! has_env CLAUDE_CODE_OAUTH_TOKEN; then
    echo "missing Claude credentials: attach either the claude-code or claude-code-oauth provider" >&2
    exit 1
fi

if has_env ANTHROPIC_API_KEY; then
    CLAUDE_AUTH_MODE="api-key"
else
    CLAUDE_AUTH_MODE="oauth-token"
fi

require_env GITHUB_TOKEN

export GH_TOKEN="$GITHUB_TOKEN"
export GH_PROMPT_DISABLED=1
export GH_NO_UPDATE_NOTIFIER=1
export GH_NO_EXTENSION_UPDATE_NOTIFIER=1
export GH_TELEMETRY=false
export DO_NOT_TRACK=1
export HOME="${OPENSHELL_AGENT_HOME:-/sandbox/home}"

# Keep the harness off every network path the sandbox policy does not
# explicitly allow, and off any operator config baked into the image.
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export DISABLE_AUTOUPDATER=1
export DISABLE_TELEMETRY=1
export DISABLE_ERROR_REPORTING=1
export DISABLE_BUG_COMMAND=1

CLAUDE_MODEL="${CLAUDE_MODEL:-claude-opus-5}"

echo "openshell-agent: preparing Claude Code harness (auth=$CLAUDE_AUTH_MODE, model=$CLAUDE_MODEL)" >&2

# A fresh config dir per cycle. The supervisor runs each cycle as a new bounded
# child, so no harness state is allowed to leak between reconciliations —
# durable state belongs in GitHub, per the shared runtime's state contract.
CLAUDE_CONFIG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/claude-config.XXXXXX")"
export CLAUDE_CONFIG_DIR
trap 'rm -rf "$CLAUDE_CONFIG_DIR"' EXIT

mkdir -p "$HOME"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/claude-cycle.XXXXXX")"
cd "$WORK"

CLAUDE_BIN="${CLAUDE_BIN:-claude}"
ADAPTER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$(cd "$ADAPTER_DIR/../../.." && pwd)"
if [[ -x "$PAYLOAD_DIR/runtime/harnesses/claude/claude" ]]; then
    CLAUDE_BIN="$PAYLOAD_DIR/runtime/harnesses/claude/claude"
fi

command -v "$CLAUDE_BIN" >/dev/null 2>&1 || [[ -x "$CLAUDE_BIN" ]] || {
    echo "claude binary not found: $CLAUDE_BIN" >&2
    exit 1
}

CLAUDE_ARGS=(
    --print
    --output-format text
    --model "$CLAUDE_MODEL"
    # The OpenShell sandbox is the security boundary here: filesystem reach,
    # egress, and binaries are already policy-enforced around this process.
    # A second in-harness prompt layer would only deadlock a headless cycle.
    --dangerously-skip-permissions
)

echo "openshell-agent: invoking Claude Code bounded cycle" >&2

exec "$CLAUDE_BIN" "${CLAUDE_ARGS[@]}" < "$PROMPT_FILE"
