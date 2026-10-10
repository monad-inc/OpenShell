#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Prints the installed Codex version, bare (`0.162.1`), for the
# entrypoint's pin check. `codex --version` prints `codex-cli 0.162.1`.
#
# Resolves the binary exactly as exec.sh does ($CODEX_BIN, then a payload-local
# binary such as the one run.sh --codex-bin uploads), so the check is on the
# binary that will actually run, not merely the one on PATH. Takes the first
# x.y.z[-pre] token rather than a fixed field, so a warning line or a changed
# output layout cannot pass off another word as the version.

set -euo pipefail

CODEX_BIN="${CODEX_BIN:-codex}"
ADAPTER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$(cd "$ADAPTER_DIR/../../.." && pwd)"
if [[ -x "$PAYLOAD_DIR/runtime/harnesses/codex/codex" ]]; then
    CODEX_BIN="$PAYLOAD_DIR/runtime/harnesses/codex/codex"
fi

"$CODEX_BIN" --version \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?' \
    | head -n 1
