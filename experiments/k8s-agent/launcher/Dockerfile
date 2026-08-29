# syntax=docker/dockerfile:1

# SPDX-License-Identifier: Apache-2.0

# Launcher image for the repo-watcher deployment Job.
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

FROM debian:bookworm-slim

# Empty installs the latest tagged release. OPENSHELL_VERSION is a literal
# release tag, so "latest" is NOT a valid value — install.sh would try to fetch
# releases/download/latest/... and 404. Pin a real tag for reproducible builds;
# match the gateway version where practical.
ARG OPENSHELL_VERSION=""

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        jq \
        ruby \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    if [ -n "${OPENSHELL_VERSION}" ]; then \
        curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh \
            | env OPENSHELL_VERSION="${OPENSHELL_VERSION}" sh; \
    else \
        curl -fsSL https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh; \
    fi; \
    openshell --version

WORKDIR /work

COPY scripts/deploy-agent.sh /work/scripts/deploy-agent.sh
COPY agent/policy.yaml /work/agent/policy.yaml
COPY agent/providers/ /work/agent/providers/
# watch-config.yaml is deliberately absent: it belongs to the sandbox image, so
# a running agent's scope cannot be changed by redeploying the launcher.

RUN chmod 0755 /work/scripts/deploy-agent.sh && \
    chmod -R a+rX /work && \
    useradd -r -u 65532 -g nogroup launcher

USER 65532:65534

ENTRYPOINT ["/bin/bash"]
