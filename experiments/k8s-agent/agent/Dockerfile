# syntax=docker/dockerfile:1

# SPDX-License-Identifier: Apache-2.0

# repo-watcher sandbox image.
#
# Mirrors scripts/agents/gator/Dockerfile, with the Claude Code CLI in place of
# Codex and curl/jq present for the Slack Web API calls.

FROM nvcr.io/nvidia/base/ubuntu:noble-20251013 AS system

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /sandbox

# Matches the community base image's network tooling. The supervisor needs
# iproute2/nftables for namespace setup and bypass detection.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        iproute2 \
        iptables \
        nftables \
        iputils-ping \
        net-tools \
        netcat-openbsd \
        openssh-sftp-server \
        procps \
        traceroute \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r supervisor && useradd -r -g supervisor -s /usr/sbin/nologin supervisor && \
    groupadd -r sandbox && useradd -r -g sandbox -d /sandbox -s /bin/bash sandbox

FROM system AS devtools

RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends \
        build-essential \
        git \
        jq \
        less \
        nodejs=22.22.1-1nodesource1 \
        ripgrep \
        vim-tiny \
        nano \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g npm@11.11.0

# GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /usr/share/keyrings/githubcli-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list && \
    apt-get update && apt-get install -y --no-install-recommends gh && \
    rm -rf /var/lib/apt/lists/*

ARG CLAUDE_CODE_VERSION=latest
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" && \
    (npm cache clean --force >/dev/null 2>&1 || true) && \
    claude --version

# Provider profiles pin binaries by absolute path and list both /usr/bin and
# /usr/local/bin variants. Create the aliases so policy reloads resolve cleanly.
RUN ln -sf /usr/bin/gh /usr/local/bin/gh && \
    ln -sf /usr/bin/git /usr/local/bin/git && \
    ln -sf /usr/bin/curl /usr/local/bin/curl && \
    ln -sf /usr/bin/claude /usr/local/bin/claude

FROM devtools AS final

ENV PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

RUN mkdir -p /etc/openshell
COPY policy.yaml /etc/openshell/policy.yaml

RUN printf 'export PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"\nexport PS1="\\u@\\h:\\w\\$ "\n' \
        > /sandbox/.bashrc && \
    printf '[ -f ~/.bashrc ] && . ~/.bashrc\n' > /sandbox/.profile && \
    mkdir -p /sandbox/home && \
    chown -R sandbox:sandbox /sandbox

USER sandbox

ENTRYPOINT ["/bin/bash"]
