#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# A mock Claude Code that checks for stream-json and writes a short stream
# whose final `result` carries the sentinel inside a JSON string.
cat > "$TMP_DIR/claude" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

args=" $* "
[[ "$args" == *" --output-format stream-json "* ]] \
    || { echo "not ok - claude runs without stream-json" >&2; exit 1; }
[[ "$args" == *" --verbose "* ]] \
    || { echo "not ok - stream-json requires --verbose" >&2; exit 1; }
cat > /dev/null
if [[ -n "${MOCK_SLEEP_MARKER:-}" ]]; then
    trap 'echo terminated > "$MOCK_SLEEP_MARKER.term"; exit 143' TERM
    echo "$$" > "$MOCK_SLEEP_MARKER"
    # The transcript copy must not sit in the harness's working dir.
    ls -A > "$MOCK_SLEEP_MARKER.cwd"
    sleep 30 &
    wait
fi
printf '%s\n' '{"type":"system","subtype":"init","session_id":"s-1"}'
printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"echo hi"}}]},"session_id":"s-1"}'
printf '%s\n' '{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"hi"}]},"session_id":"s-1"}'
# Key order as Claude Code actually emits it: `type` is not first, and a
# nested object carries a "type" of its own.
printf '%s\n' '{"is_error":false,"num_turns":3,"usage":{"type":"usage"},"result":"All quiet.\nOPENSHELL_AGENT_RESULT {\"status\":\"complete\",\"reason\":\"no alerts\"}","total_cost_usd":0.01,"session_id":"s-1","subtype":"success","type":"result"}'
exit "${MOCK_EXIT:-0}"
MOCK
chmod +x "$TMP_DIR/claude"
printf '%s\n' 'test prompt' > "$TMP_DIR/prompt.md"

run_adapter() {
    OPENSHELL_AGENT_HOME="$TMP_DIR/home" \
    CLAUDE_BIN="$TMP_DIR/claude" \
    ANTHROPIC_API_KEY="openshell:resolve:env:v42_ANTHROPIC_API_KEY" \
    GITHUB_TOKEN="openshell:resolve:env:v42_GITHUB_TOKEN" \
        bash "$SCRIPT_DIR/exec.sh" "$TMP_DIR/prompt.md" > "$TMP_DIR/stdout" 2> "$TMP_DIR/stderr"
}

run_adapter || { cat "$TMP_DIR/stderr" >&2; echo "not ok - adapter failed" >&2; exit 1; }

[[ "$(grep -c '^{' "$TMP_DIR/stdout")" -eq 4 ]] \
    || { echo "not ok - stream-json events missing from stdout" >&2; exit 1; }
sentinel="$(grep '^OPENSHELL_AGENT_RESULT ' "$TMP_DIR/stdout")"
[[ "$sentinel" == 'OPENSHELL_AGENT_RESULT {"status":"complete","reason":"no alerts"}' ]] \
    || { echo "not ok - sentinel not re-emitted plainly: $sentinel" >&2; exit 1; }
printf '%s\n' 'ok - Claude streams JSON events and re-emits the result sentinel'

MOCK_EXIT=7 run_adapter && status=0 || status=$?
[[ "$status" -eq 7 ]] || { echo "not ok - adapter exit $status, want the harness's 7" >&2; exit 1; }
printf '%s\n' 'ok - Claude adapter propagates the harness exit status'

marker="$TMP_DIR/harness.pid"
MOCK_SLEEP_MARKER="$marker" \
OPENSHELL_AGENT_HOME="$TMP_DIR/home" \
CLAUDE_BIN="$TMP_DIR/claude" \
ANTHROPIC_API_KEY="openshell:resolve:env:v42_ANTHROPIC_API_KEY" \
GITHUB_TOKEN="openshell:resolve:env:v42_GITHUB_TOKEN" \
    bash "$SCRIPT_DIR/exec.sh" "$TMP_DIR/prompt.md" > "$TMP_DIR/stdout" 2> "$TMP_DIR/stderr" &
adapter_pid=$!
for _ in $(seq 1 100); do [[ -s "$marker" ]] && break; sleep 0.05; done
[[ -s "$marker" ]] || { echo "not ok - mock harness never started" >&2; exit 1; }
[[ ! -s "$marker.cwd" ]] || { echo "not ok - harness cwd not empty: $(cat "$marker.cwd")" >&2; exit 1; }
kill -TERM "$adapter_pid"
wait "$adapter_pid" && status=0 || status=$?
[[ -f "$marker.term" ]] || { echo "not ok - SIGTERM never reached the harness" >&2; exit 1; }
if kill -0 "$(cat "$marker")" 2>/dev/null; then
    echo "not ok - harness outlived the adapter" >&2
    exit 1
fi
[[ "$status" -eq 143 ]] || { echo "not ok - adapter exit $status after SIGTERM, want 143" >&2; exit 1; }
printf '%s\n' 'ok - Claude adapter forwards SIGTERM to the harness and waits for it'
