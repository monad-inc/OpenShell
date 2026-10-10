#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Prints the installed Claude Code version, bare (`2.1.251`), for the
# entrypoint's pin check. `claude --version` prints `2.1.251 (Claude Code)`.
#
# Resolves the binary exactly as exec.sh does ($CLAUDE_BIN, then a payload-local
# binary such as the one run.sh --claude-bin uploads), so the check is on the
# binary that will actually run, not merely the one on PATH. Takes the first
# x.y.z[-pre] token rather than a fixed field, so a warning line or a changed
# output layout cannot pass off another word as the version.

set -euo pipefail

CLAUDE_BIN="${CLAUDE_BIN:-claude}"
ADAPTER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$(cd "$ADAPTER_DIR/../../.." && pwd)"
if [[ -x "$PAYLOAD_DIR/runtime/harnesses/claude/claude" ]]; then
    CLAUDE_BIN="$PAYLOAD_DIR/runtime/harnesses/claude/claude"
fi

"$CLAUDE_BIN" --version \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?' \
    | head -n 1
