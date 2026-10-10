#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || { echo "missing required env: $name" >&2; exit 1; }
}

require_env OPENSHELL_AGENT_HARNESS

RUNTIME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$(cd "$RUNTIME_DIR/.." && pwd)"
SUPERVISOR="$PAYLOAD_DIR/runtime/supervisor.sh"

# The harness is baked into the image, so the version the deployment pins
# (OPENSHELL_AGENT_HARNESS_VERSION) cannot be installed here. What this can do
# is refuse to run an image that carries a different version, rather than
# quietly running whatever the image happened to be built with. The pin decides
# the event format the supervisor exports, so a mismatch is a deploy error, not
# something to retry. `latest` is a deliberate opt-out of the check.
HARNESS_VERSION_SCRIPT="$RUNTIME_DIR/harnesses/$OPENSHELL_AGENT_HARNESS/version.sh"
HARNESS_VERSION_TIMEOUT="${OPENSHELL_AGENT_HARNESS_VERSION_TIMEOUT:-30}"
pinned_version="${OPENSHELL_AGENT_HARNESS_VERSION:-}"
installed_version=""
echo "openshell-agent: checking harness $OPENSHELL_AGENT_HARNESS version (pinned: ${pinned_version:-unpinned})" >&2
if [[ -f "$HARNESS_VERSION_SCRIPT" ]]; then
    # Bounded, so a CLI that hangs fails the check rather than the sandbox
    # sitting silent forever. The CLI's own stderr is kept: it is the cause.
    installed_version="$(timeout "$HARNESS_VERSION_TIMEOUT" bash "$HARNESS_VERSION_SCRIPT" || true)"
fi
echo "openshell-agent: harness $OPENSHELL_AGENT_HARNESS ${installed_version:-unknown} (pinned: ${pinned_version:-unpinned})" >&2
if [[ -n "$pinned_version" && "$pinned_version" != "latest" && "$installed_version" != "$pinned_version" ]]; then
    echo "openshell-agent: refusing to start: the image carries $OPENSHELL_AGENT_HARNESS ${installed_version:-unknown}, but the deployment pins $pinned_version; rebuild the image for $pinned_version or change the pin" >&2
    exit 78
fi

# A main process other than the supervisor (a listener, say) is given as
# arguments and runs after the same check, so no way of running the agent
# skips it.
if [[ $# -gt 0 ]]; then
    exec "$@"
fi

[[ -x "$SUPERVISOR" ]] || { echo "missing agent supervisor: $SUPERVISOR" >&2; exit 1; }

exec bash "$SUPERVISOR"
