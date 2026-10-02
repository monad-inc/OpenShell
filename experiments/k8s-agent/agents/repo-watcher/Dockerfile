# syntax=docker/dockerfile:1

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


# SPDX-License-Identifier: Apache-2.0

# repo-watcher sandbox image: a thin payload layer over the shared base.
# The build script appends the immutable-payload COPY instructions.

ARG BASE_IMAGE=openshell-agents/base:dev
FROM ${BASE_IMAGE} AS final

USER root
RUN mkdir -p /etc/openshell
COPY policy.yaml /etc/openshell/policy.yaml
USER sandbox
