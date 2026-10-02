#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0


# SPDX-License-Identifier: Apache-2.0

# Build the repo-watcher agent image with its payload baked in.
#
# Why this exists: scripts/agents/run.sh bakes the payload by handing a local
# Dockerfile to `openshell sandbox create`, which only works against a gateway
# backed by the local Docker daemon. A Kubernetes gateway cannot see the
# operator's Docker daemon, so the image has to exist in a registry the cluster
# can pull from before the sandbox is created. This script performs the same
# payload rendering and staging as run.sh, then produces a pushable image.
#
# Usage:
#   build-agent-image.sh [--tag <tag>] [--push] [--kind-cluster <name>]
#
# With --push, IMAGE_REPO must name a registry the cluster can pull from.
# Without it, the image is side-loaded into the named kind cluster instead.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$EXPERIMENT_DIR/../.." && pwd)"
AGENT_NAME="${AGENT_NAME:-repo-watcher}"
BASE_IMAGE="${BASE_IMAGE:-openshell-agents/base:dev}"
RUNTIME_DIR="$REPO_ROOT/scripts/agents/runtime"

IMAGE_REPO="${IMAGE_REPO:-}"
IMAGE_TAG="dev"
PUSH=0
KIND_CLUSTER="${KIND_CLUSTER:-kind}"
PAYLOAD_IMAGE_DIR="/etc/openshell/agent-payload"

fail() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*" >&2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --agent) [[ $# -ge 2 ]] || fail "--agent requires a value"; AGENT_NAME="$2"; shift 2 ;;
        --base-image) [[ $# -ge 2 ]] || fail "--base-image requires a value"; BASE_IMAGE="$2"; shift 2 ;;
        --tag) [[ $# -ge 2 ]] || fail "--tag requires a value"; IMAGE_TAG="$2"; shift 2 ;;
        --push) PUSH=1; shift ;;
        --kind-cluster) [[ $# -ge 2 ]] || fail "--kind-cluster requires a value"; KIND_CLUSTER="$2"; shift 2 ;;
        -h|--help) sed -n '3,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done

AGENT_DIR="$EXPERIMENT_DIR/agents/$AGENT_NAME"
[[ -d "$AGENT_DIR" ]] || fail "unknown agent '$AGENT_NAME'; expected $AGENT_DIR"
IMAGE_REPO="${IMAGE_REPO:-openshell-agents/$AGENT_NAME}"
IMAGE_REF="${IMAGE_REPO}:${IMAGE_TAG}"

command -v docker >/dev/null || fail "docker is required"
command -v ruby >/dev/null || fail "ruby is required (matches run.sh's renderer)"
[[ -f "$AGENT_DIR/agent.yaml" ]] || fail "missing agent manifest: $AGENT_DIR/agent.yaml"
[[ -d "$RUNTIME_DIR" ]] || fail "missing shared runtime: $RUNTIME_DIR"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/repo-watcher-build.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
PAYLOAD="$STAGE/openshell-agent-payload"
mkdir -p "$PAYLOAD"

log "Staging shared runtime."
cp -R "$RUNTIME_DIR" "$PAYLOAD/runtime"

log "Rendering prompt template and manifest-declared resources."
# Mirrors the variable set run.sh supports. Keep these in sync: the renderer
# hard-fails on an unknown {{VAR}} rather than leaving it unsubstituted.
ruby -ryaml - "$AGENT_DIR" "$PAYLOAD" <<'RUBY'
agent_dir, payload_dir = ARGV
manifest = YAML.load_file(File.join(agent_dir, "agent.yaml")) || {}

harness = manifest.dig("harness", "default").to_s
run_mode = manifest.dig("runtime", "mode").to_s
poll_interval = manifest.dig("runtime", "poll_interval_seconds").to_s
payload_version = manifest.fetch("payload_version", 1).to_s

values = {
  "HARNESS" => harness,
  "RUN_MODE" => run_mode,
  "POLL_INTERVAL_SECONDS" => poll_interval,
  "PAYLOAD_VERSION" => payload_version,
  # Baked images carry no per-launch prompt; scope comes from watch-config.yaml.
  "USER_PROMPT" => "Reconcile according to your baked watch-config.yaml.",
}

resolve = lambda do |ref|
  case ref
  when %r{\Aagent://(.*)\z} then File.join(agent_dir, Regexp.last_match(1))
  when %r{\Arepo://(.*)\z} then File.join(agent_dir, "..", "..", "..", Regexp.last_match(1))
  when %r{\A/} then ref
  else File.join(agent_dir, ref)
  end
end

template_path = resolve.call(manifest.fetch("prompt_template"))
rendered = File.read(template_path).gsub(/\{\{([A-Z0-9_]+)\}\}/) { values.fetch(Regexp.last_match(1)) }
File.write(File.join(payload_dir, "agent-prompt.md"), rendered)

# Same three manifest sections run.sh copies into the payload. Skills were
# previously ignored here, which meant a manifest could declare a skill that
# silently never reached the image.
require "fileutils"
%w[skills subagents resources].each do |section|
  (manifest[section] || []).each do |entry|
    src = resolve.call(entry.fetch("source"))
    dst = File.join(payload_dir, entry.fetch("destination"))
    abort "missing #{section} source: #{src}" unless File.exist?(src)
    FileUtils.mkdir_p(File.dirname(dst))
    FileUtils.cp(src, dst)
  end
end

# MCP client config, generated from the manifest rather than hand-maintained,
# so the servers an agent can reach and the binaries installed for it cannot
# drift apart.
mcp_servers = manifest["mcp_servers"] || []
unless mcp_servers.empty?
  require "json"
  config = { "mcpServers" => {} }
  mcp_servers.each do |server|
    entry = { "command" => server.fetch("command") }
    entry["args"] = server["args"] if server["args"]
    entry["env"] = server["env"] if server["env"]
    config["mcpServers"][server.fetch("id")] = entry
  end
  File.write(File.join(payload_dir, "mcp.json"), JSON.pretty_generate(config) + "\n")
end

skill_ids = (manifest["skills"] || []).map { |e| e.fetch("id") }
puts "harness=#{harness} run_mode=#{run_mode} poll=#{poll_interval}s payload_version=#{payload_version}"
puts "skills=#{skill_ids.empty? ? '(none)' : skill_ids.join(',')}"
puts "mcp_servers=#{mcp_servers.empty? ? '(none)' : mcp_servers.map { |m| m.fetch('id') }.join(',')}"
RUBY

# Content digest over the staged skills. This is the version identity for the
# part of the agent that changes most often: it moves when a skill's bytes move
# and not otherwise, so it is a truthful answer to "which skills is this agent
# running?" and it is comparable against git.
if [[ -d "$PAYLOAD/skills" ]]; then
    SKILLS_VERSION="$(find "$PAYLOAD/skills" -type f -exec sha256sum {} + \
        | sort -k2 | sha256sum | cut -c1-12)"
else
    SKILLS_VERSION="none"
fi
log "Skills version: $SKILLS_VERSION"
printf '%s\n' "$SKILLS_VERSION" > "$PAYLOAD/skills-version"

log "Staging build context."
tar -C "$AGENT_DIR" --exclude './logs' -cf - . | tar -C "$STAGE" -xf -

# Same payload-immutability treatment run.sh applies: root-owned, world
# readable, and stripped of write bits so the agent cannot edit its own guts.
# Install declared MCP server binaries into the image. `oci_binary` copies a
# binary straight out of a published image with a multi-stage COPY --from, so
# no download step and no package manager is involved, and pinning the source
# image by digest makes the build reproducible.
ruby -ryaml - "$AGENT_DIR/agent.yaml" "$STAGE/Dockerfile" <<'RUBY'
manifest_path, dockerfile_path = ARGV
manifest = YAML.load_file(manifest_path) || {}
servers = manifest["mcp_servers"] || []
exit 0 if servers.empty?

lines = File.readlines(dockerfile_path)
final_from = lines.rindex { |line| line.strip.start_with?("FROM ") } or abort "no FROM in Dockerfile"
final_user = lines[final_from..].reverse.find { |line| line.strip.start_with?("USER ") }&.strip

stages = []
copies = []
servers.each_with_index do |server, index|
  install = server["install"] or next
  case install.fetch("kind")
  when "oci_binary"
    stage = "mcpsrc#{index}"
    stages << "FROM #{install.fetch("image")} AS #{stage}"
    copies << "COPY --from=#{stage} #{install.fetch("source_path")} #{install.fetch("dest_path")}"
    copies << "RUN chmod 0755 #{install.fetch("dest_path")}"
  when "npm"
    copies << "RUN npm install -g #{install.fetch("package")} && (npm cache clean --force >/dev/null 2>&1 || true)"
  else
    abort "unsupported mcp_servers install kind: #{install.fetch("kind")}"
  end
end

# Source stages must precede the final FROM that copies from them.
unless stages.empty?
  lines.insert(final_from, *stages.map { |stage| stage + "\n" })
end

trailer = []
trailer << "\n"
trailer << "# MCP server binaries declared in agent.yaml\n"
trailer << "USER root\n"
copies.each { |copy| trailer << copy + "\n" }
trailer << final_user + "\n" if final_user

# Write the whole file: the inserted FROM stages live in `lines`, so appending
# alone would silently drop them and leave COPY --from pointing at a stage that
# does not exist — which BuildKit then tries to pull as an image name.
File.write(dockerfile_path, (lines + trailer).join)
RUBY

ruby - "$STAGE/Dockerfile" "$PAYLOAD_IMAGE_DIR" <<'RUBY'
dockerfile_path, payload_image_dir = ARGV
lines = File.readlines(dockerfile_path)
final_stage_start = lines.rindex { |line| line.strip.start_with?("FROM ") } || 0
final_user = lines[final_stage_start..].reverse.find { |line| line.strip.start_with?("USER ") }&.strip
File.open(dockerfile_path, "a") do |file|
  file.puts
  file.puts "# OpenShell staged immutable agent payload"
  file.puts "USER root"
  file.puts "COPY openshell-agent-payload/ #{payload_image_dir}/"
  file.puts "RUN chmod -R a+rX #{payload_image_dir}"
  file.puts "RUN chmod -R a-w #{payload_image_dir}"
  file.puts "ARG SKILLS_VERSION=unknown"
  file.puts "LABEL com.monad.openshell.skills-version=$SKILLS_VERSION"
  file.puts final_user if final_user
end
RUBY

log "Building $IMAGE_REF (agent=$AGENT_NAME, base=$BASE_IMAGE)"
docker build \
    --build-arg "SKILLS_VERSION=$SKILLS_VERSION" \
    --build-arg "BASE_IMAGE=$BASE_IMAGE" \
    -t "$IMAGE_REF" "$STAGE"

if [[ "$PUSH" == "1" ]]; then
    log "Pushing $IMAGE_REF"
    docker push "$IMAGE_REF"
else
    log "Side-loading $IMAGE_REF into kind cluster '$KIND_CLUSTER'"
    command -v kind >/dev/null || fail "kind is required without --push"
    kind load docker-image "$IMAGE_REF" --name "$KIND_CLUSTER"
fi

log "Done: $IMAGE_REF (skills-version=$SKILLS_VERSION)"
printf '%s\n' "$SKILLS_VERSION" > "${SKILLS_VERSION_FILE:-/dev/null}"
