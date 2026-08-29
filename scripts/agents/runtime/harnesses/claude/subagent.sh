#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Claude Code subagent dispatcher. Runs one bounded, separate `claude --print`
# invocation for a manifest-declared subagent definition.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: subagent.sh <subagent-id> < task.md" >&2
    exit 2
fi

SUBAGENT_ID="$1"
ADAPTER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$(cd "$ADAPTER_DIR/../../.." && pwd)"
SUBAGENT_PROMPT="$PAYLOAD_DIR/subagents/$SUBAGENT_ID.md"
[[ -f "$SUBAGENT_PROMPT" ]] || {
    echo "missing subagent prompt: $SUBAGENT_PROMPT" >&2
    exit 1
}

CLAUDE_BIN="${CLAUDE_BIN:-claude}"
if [[ -x "$PAYLOAD_DIR/runtime/harnesses/claude/claude" ]]; then
    CLAUDE_BIN="$PAYLOAD_DIR/runtime/harnesses/claude/claude"
fi
CLAUDE_MODEL="${CLAUDE_MODEL:-claude-opus-5}"

TASK_FILE="$(mktemp)"
PROMPT_FILE="$(mktemp)"
trap 'rm -f "$TASK_FILE" "$PROMPT_FILE"' EXIT

cat >"$TASK_FILE"

{
    printf '%s\n\n' "You are running as the $SUBAGENT_ID sub-agent inside an OpenShell sandbox."
    cat "$SUBAGENT_PROMPT"
    printf '\n\n## Task\n\n'
    cat "$TASK_FILE"
} >"$PROMPT_FILE"

exec "$CLAUDE_BIN" \
    --print \
    --output-format text \
    --model "$CLAUDE_MODEL" \
    --dangerously-skip-permissions \
    < "$PROMPT_FILE"
