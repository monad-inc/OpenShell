#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Prints the installed Claude Code version, bare (`2.1.251`), for the
# entrypoint's pin check. `claude --version` prints `2.1.251 (Claude Code)`.

set -euo pipefail

claude --version | awk 'NR == 1 { print $1 }'
