#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Prints the installed Codex version, bare (`0.162.1`), for the entrypoint's
# pin check. `codex --version` prints `codex-cli 0.162.1`.

set -euo pipefail

codex --version | awk 'NR == 1 { print $NF }'
