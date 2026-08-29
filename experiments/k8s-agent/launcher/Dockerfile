# syntax=docker/dockerfile:1

# SPDX-License-Identifier: Apache-2.0

# Launcher image for the repo-watcher deployment Job.
#
# The published gateway image is distroless and carries no shell, CLI, or
# interpreter, so the Job that talks to the gateway needs its own image. This
# one holds exactly what scripts/deploy-agent.sh calls: the OpenShell CLI, ruby
# (provider-profile resource_version rewriting), jq, and bash.

FROM debian:bookworm-slim

ARG OPENSHELL_VERSION=latest

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        jq \
        ruby \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh \
        | env OPENSHELL_VERSION="${OPENSHELL_VERSION}" sh \
    && openshell --version

WORKDIR /work
ENTRYPOINT ["/bin/bash"]
