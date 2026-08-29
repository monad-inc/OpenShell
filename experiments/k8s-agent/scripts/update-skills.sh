#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0

# Roll a skill change out to one or more agents.
#
# Skills are the fastest-moving part of an agent: they get refined as its
# judgment is corrected in review. They are still baked into the sandbox image
# rather than mounted from a ConfigMap, for two reasons worth restating because
# they are the whole argument for this script existing:
#
#   1. A running agent must not have its instructions rewritten underneath it.
#      A mutable mount means a half-applied edit can land mid-cycle, and it means
#      the agent's behavior can change with no deploy, no diff, and no review.
#   2. Every revision should be a reviewable diff with a version you can point
#      at. Baking gives each skill set a content digest that is stamped onto the
#      running sandbox, so "which skills is this agent running?" has a truthful
#      answer that can be compared against git.
#
# The cost is that updating skills means a new image and a sandbox restart. This
# script makes that cheap: the base tooling layers are cached, so a skills-only
# rebuild is seconds, and the restart costs one in-flight cycle.
#
# Usage:
#   update-skills.sh --agent repo-watcher                 # roll one agent
#   update-skills.sh --all                                # roll every release
#   update-skills.sh --agent repo-watcher --dry-run       # build, do not roll

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$EXPERIMENT_DIR/../.." && pwd)"

NAMESPACE="${NAMESPACE:-openshell-experiments}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-kind}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-$HOME/.kube/config}"
IMAGE_REPO="${IMAGE_REPO:-openshell-agents/repo-watcher}"
CHART_DIR="$EXPERIMENT_DIR/chart"
AGENTS=()
ALL=0
DRY_RUN=0
PUSH_ARGS=()

fail() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*" >&2; }

helm_() { helm --kubeconfig "$KUBECONFIG_PATH" --kube-context "$KUBE_CONTEXT" "$@"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --agent) [[ $# -ge 2 ]] || fail "--agent requires a value"; AGENTS+=("$2"); shift 2 ;;
        --all) ALL=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --push) PUSH_ARGS=(--push); shift ;;
        -h|--help) sed -n '3,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done

[[ ${#AGENTS[@]} -gt 0 || "$ALL" == "1" ]] || fail "pass --agent <name> or --all"

# Tag by skills digest so the image reference itself names what changed. A
# rebuild with unchanged skills produces the same tag and is a no-op roll.
SKILLS_VERSION_FILE="$(mktemp)"
trap 'rm -f "$SKILLS_VERSION_FILE"' EXIT

log "Building agent image with current skills."
SKILLS_VERSION_FILE="$SKILLS_VERSION_FILE" \
    "$SCRIPT_DIR/build-agent-image.sh" --tag "skills-pending" "${PUSH_ARGS[@]}" >&2

SKILLS_VERSION="$(cat "$SKILLS_VERSION_FILE")"
[[ -n "$SKILLS_VERSION" ]] || fail "could not determine skills version"
IMAGE_TAG="skills-${SKILLS_VERSION}"

log "Retagging as $IMAGE_REPO:$IMAGE_TAG"
docker tag "$IMAGE_REPO:skills-pending" "$IMAGE_REPO:$IMAGE_TAG"
if [[ ${#PUSH_ARGS[@]} -gt 0 ]]; then
    docker push "$IMAGE_REPO:$IMAGE_TAG"
else
    kind load docker-image "$IMAGE_REPO:$IMAGE_TAG" --name "${KIND_CLUSTER:-kind}" >&2
fi

if [[ "$DRY_RUN" == "1" ]]; then
    log "Dry run: built $IMAGE_REPO:$IMAGE_TAG, not rolling any agent."
    exit 0
fi

if [[ "$ALL" == "1" ]]; then
    mapfile -t AGENTS < <(helm_ list -n "$NAMESPACE" -o json \
        | ruby -rjson -e 'JSON.parse(STDIN.read).each { |r| puts r["name"] if r["chart"].to_s.start_with?("repo-watcher-") }')
    [[ ${#AGENTS[@]} -gt 0 ]] || fail "no repo-watcher releases found in namespace $NAMESPACE"
    log "Rolling ${#AGENTS[@]} agent(s): ${AGENTS[*]}"
fi

GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

failed=()
for agent in "${AGENTS[@]}"; do
    log "Rolling $agent -> $IMAGE_TAG"
    # recreate=true is required: the payload is baked, so a new skills revision
    # only takes effect on a new sandbox.
    if helm_ upgrade "$agent" "$CHART_DIR" -n "$NAMESPACE" --reuse-values \
        --set "agent.image=${IMAGE_REPO}:${IMAGE_TAG}" \
        --set "agent.recreate=true" \
        --set "provenance.gitSha=${GIT_SHA}" \
        --set "provenance.skillsVersion=${SKILLS_VERSION}" \
        --wait --timeout 6m >&2; then
        log "Rolled $agent"
    else
        # Keep going: one bad agent should not block a fleet-wide skill fix.
        log "FAILED to roll $agent"
        failed+=("$agent")
    fi
done

if [[ ${#failed[@]} -gt 0 ]]; then
    fail "failed to roll: ${failed[*]}"
fi

log "Done. skills-version=$SKILLS_VERSION image=$IMAGE_REPO:$IMAGE_TAG"
log "Verify with: openshell sandbox list  (skills-version label)"
