#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0

# Build the launcher image used by the repo-watcher deploy Job.
#
# Usage: build-launcher-image.sh [--tag <tag>] [--push] [--kind-cluster <name>]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

AGENT_NAME="${AGENT_NAME:-repo-watcher}"
IMAGE_REPO="${IMAGE_REPO:-}"
IMAGE_TAG="dev"
PUSH=0
KIND_CLUSTER="${KIND_CLUSTER:-kind}"

fail() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --agent) [[ $# -ge 2 ]] || fail "--agent requires a value"; AGENT_NAME="$2"; shift 2 ;;
        --tag) [[ $# -ge 2 ]] || fail "--tag requires a value"; IMAGE_TAG="$2"; shift 2 ;;
        --push) PUSH=1; shift ;;
        --kind-cluster) [[ $# -ge 2 ]] || fail "--kind-cluster requires a value"; KIND_CLUSTER="$2"; shift 2 ;;
        -h|--help) sed -n '3,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done

[[ -d "$EXPERIMENT_DIR/agents/$AGENT_NAME" ]] || fail "unknown agent '$AGENT_NAME'"
IMAGE_REPO="${IMAGE_REPO:-openshell-agents/${AGENT_NAME}-launcher}"
IMAGE_REF="${IMAGE_REPO}:${IMAGE_TAG}"

log "Building $IMAGE_REF (agent=$AGENT_NAME)"
docker build -f "$EXPERIMENT_DIR/launcher/Dockerfile" \
    --build-arg "AGENT_NAME=$AGENT_NAME" \
    -t "$IMAGE_REF" "$EXPERIMENT_DIR"

if [[ "$PUSH" == "1" ]]; then
    log "Pushing $IMAGE_REF"
    docker push "$IMAGE_REF"
else
    log "Side-loading $IMAGE_REF into kind cluster '$KIND_CLUSTER'"
    command -v kind >/dev/null || fail "kind is required without --push"
    kind load docker-image "$IMAGE_REF" --name "$KIND_CLUSTER"
fi

log "Done: $IMAGE_REF"
