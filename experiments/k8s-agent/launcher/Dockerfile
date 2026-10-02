# syntax=docker/dockerfile:1

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


# SPDX-License-Identifier: Apache-2.0

# Launcher image for an agent's deployment Job.
#
# One image per agent: it bakes that agent's manifest, policy, and provider
# profiles, so the enforceable scope of a deployment is pinned by an image tag.
# Select the agent with --build-arg AGENT_NAME=<name>.
#
# The published gateway image is distroless and carries no shell, CLI, or
# interpreter, so the Job that talks to the gateway needs its own image. This
# one holds exactly what deploy-agent.sh calls: the OpenShell CLI, ruby
# (provider-profile resource_version rewriting), jq, and bash.
#
# The agent definition — sandbox policy and provider profiles — is baked in
# rather than mounted from a ConfigMap. That keeps one property worth having:
# an agent's enforceable scope is pinned by an image tag, so it is versioned,
# auditable, and cannot drift because someone edited a ConfigMap in place. It
# also means the Helm chart needs no file plumbing at all.
#
# Build context is experiments/k8s-agent/.

# The OpenShell CLI comes from the Monad build's `cli` image, the same build as
# the gateway. Its tag MUST equal `global.image.tag` in
# manifests/values-kind-experiments.yaml: a CLI built against a different
# protocol revision than the gateway fails in ways that do not look like a
# version problem. The image is private; `docker login ghcr.io` before building.
ARG OPENSHELL_CLI_IMAGE=ghcr.io/monad-inc/openshell/cli:sha-a67777d0c7be

FROM ${OPENSHELL_CLI_IMAGE} AS openshell-cli

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        jq \
        ruby \
    && rm -rf /var/lib/apt/lists/*

COPY --from=openshell-cli /usr/local/bin/openshell /usr/local/bin/openshell
RUN openshell --version

WORKDIR /work

ARG AGENT_NAME=repo-watcher
COPY scripts/deploy-agent.sh /work/scripts/deploy-agent.sh
COPY agents/${AGENT_NAME}/agent.yaml /work/agent/agent.yaml
COPY agents/${AGENT_NAME}/policy.yaml /work/agent/policy.yaml
COPY agents/${AGENT_NAME}/providers/ /work/agent/providers/
# Optional; agents without probes simply skip the check.
COPY agents/${AGENT_NAME}/ /work/agent-src/
RUN if [ -f /work/agent-src/probes.txt ]; then cp /work/agent-src/probes.txt /work/agent/probes.txt; fi && rm -rf /work/agent-src
# watch-config.yaml is deliberately absent: it belongs to the sandbox image, so
# a running agent's scope cannot be changed by redeploying the launcher.

RUN chmod 0755 /work/scripts/deploy-agent.sh && \
    chmod -R a+rX /work && \
    useradd -r -u 65532 -g nogroup launcher

USER 65532:65534

ENTRYPOINT ["/bin/bash"]
