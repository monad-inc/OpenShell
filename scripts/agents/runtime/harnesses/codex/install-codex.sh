#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# No default. The harness version decides the event format the supervisor
# exports and parses, so it is pinned by whoever builds the image, and `latest`
# is accepted only when someone passes it on purpose.
version="${1:-${CODEX_VERSION:-}}"
if [[ -z "$version" ]]; then
    echo "no Codex version given: pass one (or set CODEX_VERSION); use latest only deliberately" >&2
    exit 2
fi

if [[ "$version" != "latest" && ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
    echo "unsupported Codex version: $version" >&2
    exit 2
fi

npm install -g "@openai/codex@${version}"
npm cache clean --force >/dev/null 2>&1 || true
codex --version
