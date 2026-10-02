# Deploying an OpenShell Agent to Kubernetes

Working notes and runnable artifacts for standing up a policy-constrained agent
on Kubernetes: it watches Slack channels for requests, may touch exactly one
GitHub repository, and opens pull requests.

Everything here targets the local **`kind-kind`** cluster, namespace
**`openshell-experiments`**. Every command pins that context explicitly. The
same kubeconfig holds production EKS and AKS contexts, so no command in this
document may rely on the ambient current-context.

## What Already Works, and What Had to Be Built

OpenShell gives you most of this out of the box:

| Layer | Status |
|---|---|
| Gateway on Kubernetes | Shipped. Helm chart in `deploy/helm/openshell`. |
| Sandbox pods | Shipped. Delegated to the Agent Sandbox controller (`sandboxes.agents.x-k8s.io`). |
| Declarative agent definition | Shipped. `scripts/agents/<agent>/agent.yaml` + `policy.yaml` + provider profiles. |
| Self-polling watch loop | Shipped. `scripts/agents/runtime/supervisor.sh`, `runtime.mode: watch`. |
| Codex harness | Shipped. |
| **Claude Code harness** | **Added here** — `scripts/agents/runtime/harnesses/claude/`. |
| **Deploying an agent to a K8s gateway** | **Added here** — see the gap below. |
| Helm chart for the agent itself | Does not exist upstream. `experiments/k8s-agent/chart` is ours. |

### The gap: `run.sh` cannot deploy to a Kubernetes gateway

`scripts/agents/run.sh` bakes the agent payload by handing a **local Dockerfile**
to `openshell sandbox create`. The CLI builds that through the operator's local
Docker daemon, which is why the docs say local directories and Dockerfiles
require a local gateway. A Kubernetes gateway cannot see that daemon.

`run.sh` also `sandbox exec`s the supervisor and stays attached for the life of
the agent. That is right for an operator's terminal and wrong for a Job, which
has to exit while the agent keeps running.

So the K8s path splits into two phases, which is also exactly the split CI wants:

```
BUILD (CI, has Docker)              DEPLOY (Job, has cluster + secrets)
  render payload                      import provider profiles
  docker build                        upsert providers from Secret env
  push to registry  ────────────────> sandbox create --from <registry ref>
                                        --policy policy.yaml
                                        -- supervisor as main process, detached
```

Phase 1 is `scripts/build-agent-image.sh`, phase 2 is `scripts/deploy-agent.sh`.
Making the supervisor the sandbox's **main process** rather than an exec target
is what decouples the agent's lifetime from the launcher's.

## There Is No Declarative Sandbox

Worth stating plainly, because it shapes everything above: **the gateway API is
the only way to create a sandbox.** There is no manifest, CRD, or idempotent
apply for an agent.

- The OpenShell chart is gateway-only — 21 templates, all gateway resources, no
  `crds/` directory. The `server.sandbox*` values are *defaults* the gateway
  applies to sandboxes created at runtime; setting them creates nothing.
- Provider profiles cannot be seeded by Helm. The gateway's `user` profile
  source reads `StoredProviderProfile` rows from its own store, populated
  through `provider profile import`. A ConfigMap cannot supply them.
- Hand-writing an Agent Sandbox `Sandbox` CR does not produce an OpenShell
  agent. The Kubernetes driver only lists and watches CRs matching
  `openshell_sandbox_label_selector()` plus its own gateway-id labels, which it
  stamps on create. A chart-authored CR is invisible to the gateway and would
  have no providers, no policy, and no credential proxy.
- The verbs are `create`, `get`, `list`, `delete`, `stop`, `start`. There is no
  `apply` and no upsert: creating an existing name fails with
  `hint: delete it first with: openshell sandbox delete <name>`.

So anything "declarative" here is necessarily a thin convergent wrapper that
calls the API. That is exactly what the chart's Job is, and why it is modelled
as a hook rather than as a resource that pretends to own the agent.

## Where Enforcement Actually Lives

This trips people up, so it is worth stating plainly:

- **`agent/policy.yaml` governs filesystem and process**, not the network. Its
  `network_policies: {}` is not "allow everything".
- **Egress is default-deny, and provider profiles open it.** Each profile
  declares the hosts, methods, and paths it needs; the sandbox proxy enforces
  them. A sandbox with no providers attached has no network at all — verified
  below.
- **The agent payload is mounted read-only** at `/etc/openshell/agent-payload`,
  so the agent cannot rewrite its own prompt or widen its declared scope.

Single-repo access is therefore enforced twice: scope the GitHub token, *and*
pin the paths in `agent/providers/github-watcher.yaml`. A token that could reach
other repositories still cannot, through this profile. Measured from inside the
running agent, same binary and same host:

```text
git clone https://github.com/monad-inc/OpenShell   -> cloned
git clone https://github.com/torvalds/linux        -> fatal: ... error: 403
```

Three properties of this enforcement are easy to get wrong, and each cost real
debugging time here:

**Egress needs `providers_v2_enabled`.** Until that global gateway setting is
`true`, the gateway ignores provider profile endpoint metadata completely and
the sandbox gets *no* egress — every host fails with `network connections not
allowed by policy`, including the ones the profiles explicitly allow. The
symptom reads as a broken policy rather than a missing setting. `run.sh` applies
manifest `settings:` before launch; `scripts/deploy-agent.sh` now does the same.

**Policy is binary-aware.** Rules apply to the binaries a profile lists, so the
*same request from a different program* is denied. `github-watcher` lists `gh`
and `git`, so `curl https://api.github.com/...` is denied from that same
sandbox while `gh api ...` succeeds. Enforcement is on the *resolved* executable:
the supervisor logs `Resolved policy binary symlink: original=/usr/bin/claude
resolved=/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe`.

That resolution is why the builtin `claude-code` profile does not work with an
npm-installed Claude Code: it pins `/usr/bin/claude` and `/usr/local/bin/claude`,
and the image must actually contain those symlinks for resolution to reach
`claude.exe`. `agent/providers/claude-code-apikey.yaml` lists the real path
outright, and the image creates both aliases.

**`/**` does not match the bare path.** `path: "/repos/OWNER/REPO/**"` requires
at least one further segment: it matches `/repos/OWNER/REPO/pulls` but not
`/repos/OWNER/REPO`, which returns 403. Both forms are needed. This one is
invisible until an agent tries to read repository metadata.

The builtin `github` profile cannot be used as-is here: it is read-only on
`api.github.com` and denies `git-receive-pack`, so it cannot push a branch or
open a PR. `github-watcher` is the narrowest profile that can.

## Layout

```
experiments/k8s-agent/
  base/Dockerfile            # shared sandbox tooling (Claude Code, gh, git, curl, jq)
  agents/
    repo-watcher/            # watches Slack, opens PRs on one repo
    oncall-triage/           # watches alert channels, investigates in Grafana
      agent.yaml             # manifest: harness, watch mode, providers, skills
      watch-config.yaml      # WHAT it watches — channels, Grafana, repos, limits
      policy.yaml            # filesystem + process policy
      Dockerfile             # thin payload layer over base
      prompts/oncall.md      # prompt template
      skills/                # alert-triage, grafana-investigation, root-cause-analysis
      providers/             # grafana-reader, github-triage, slack-oncall-reader, claude-*
      probes.txt             # policy assertions checked at deploy time
  launcher/Dockerfile        # deploy-Job image; bakes one agent's definition
  chart/                     # Helm chart for an agent, agent-agnostic
  registry-auth/             # Helm chart: ghcr pull secret for Monad's images
  deploy/
    oncall-triage.values.yaml
    oncall-triage.credentials.DUMMY.yaml
    repo-watcher.values.yaml
    CREDENTIALS.md           # procedure for real credentials
  scripts/
    build-agent-image.sh --agent <name>
    build-launcher-image.sh --agent <name>
    deploy-agent.sh          # manifest-driven; no agent hardcoded
    update-skills.sh
```

Adding an agent means adding a directory under `agents/` and a values file under
`deploy/`. Nothing in the chart, the scripts, or the launcher is agent-specific:
providers, credentials, settings, and scope all come from the agent's own
`agent.yaml`.

## Runbook

### 0. Pin the context

Every command below carries the context explicitly. Confirm the target first:

```shell
kubectl --kubeconfig ~/.kube/config --context kind-kind get nodes
```

Expect a single `kind-control-plane` node on v1.35.0. If you see EKS nodes, stop.

**`--kubeconfig ~/.kube/config` is not optional here, and omitting it looks like
a missing cluster.** `mise.toml` sets `KUBECONFIG` to `{{config_root}}/kubeconfig`
for any shell inside this repo. That file does not exist unless you created a
k3d cluster with the `helm:k3s` task, so a bare `kubectl` sees an empty
kubeconfig: `config get-contexts` lists nothing and `--context kind-kind` fails
with "context does not exist" even though the context is fine.

Either pass `--kubeconfig ~/.kube/config` on every command, as this runbook
does, or override it for the shell:

```shell
export KUBECONFIG=~/.kube/config
```

Running from a directory outside the repo also avoids it, since the override is
scoped to this project.

### 1. Install the Agent Sandbox controller

OpenShell provisions sandbox pods through the Kubernetes SIG
[Agent Sandbox](https://agent-sandbox.sigs.k8s.io) project, so its CRD and
controller must exist before the gateway.

```shell
gh release download v1.0.0 --repo kubernetes-sigs/agent-sandbox \
  --pattern sandbox.yaml --dir /tmp
kubectl --kubeconfig ~/.kube/config --context kind-kind apply --server-side -f /tmp/sandbox.yaml
kubectl --kubeconfig ~/.kube/config --context kind-kind \
  -n agent-sandbox-system rollout status deploy/agent-sandbox-controller
```

> The published docs point at
> `.../releases/latest/download/manifest.yaml`, which does not exist for v1.0.0 —
> that release ships `sandbox.yaml`, `extensions.yaml`, and
> `sandbox-with-extensions.yaml`. Downloading the documented URL yields an empty
> file and a confusing preflight failure later. Worth an upstream docs fix.

Confirm the served API version, because the chart's preflight checks for it:

```shell
kubectl --kubeconfig ~/.kube/config --context kind-kind get crd sandboxes.agents.x-k8s.io \
  -o jsonpath='{.spec.versions[*].name}'
```

v1.0.0 serves `v1beta1`, which the chart accepts.

### 2. Install the gateway

The gateway, supervisor, sandbox runtime, and launcher CLI all come from Monad's
private OpenShell build (`ghcr.io/monad-inc/openshell/*`, see `MONAD.md`), so the
namespace needs a pull secret before any pod pulls.

That secret is its own Helm release rather than something applied by hand: a
chart cannot create a prerequisite for a release installed earlier than it, so
it installs first and uninstalls last, and `--create-namespace` makes the
namespace Helm's too. Nothing in this runbook is applied imperatively.

Use a GitHub token with `read:packages`. On a SAML-enforced org it must also be
SSO-authorized for that org — scopes alone are not enough, and `docker login`
succeeds either way, so an unauthorized token surfaces later as a `403` on the
manifest pull, which reads like a missing image.

```shell
helm --kubeconfig ~/.kube/config --kube-context kind-kind \
  upgrade --install registry-auth experiments/k8s-agent/registry-auth \
  -n openshell-experiments --create-namespace \
  --set registry.username=<github-user> \
  --set registry.password="$GITHUB_TOKEN"

helm --kubeconfig ~/.kube/config --kube-context kind-kind \
  upgrade --install openshell deploy/helm/openshell \
  -n openshell-experiments \
  -f experiments/k8s-agent/manifests/values-kind-experiments.yaml \
  --wait --timeout 7m
```

Notes on the values, both learned the hard way:

- **`global.image.tag` must be set, to a `sha-` tag of a `monad/main` build.**
  The chart's `appVersion` is the `0.0.0` dev placeholder, so the default tag
  resolves to an image that does not exist. Before v0.1.3 this was `image.tag`;
  Helm ignores the old key silently, so a stale values file falls back to `0.0.0`
  without an error. Keep it equal to the tag in the launcher's
  `OPENSHELL_CLI_IMAGE`, and run `docker login ghcr.io` before building the
  launcher image.
- **`pkiInitJob.enabled` must stay `true` even with `server.disableTls: true`.**
  The certgen pre-install hook is gated on
  `pkiInitJob.enabled || certManager.enabled`, and it creates the sandbox JWT
  signing secret (`openshell-jwt-keys`) as well as the PKI material. The
  StatefulSet mounts that secret unconditionally, so turning the job off wedges
  the pod in `ContainerCreating` with `FailedMount` on `sandbox-jwt`. The chart's
  own `ci/values-tls-disabled.yaml` sets exactly this broken combination, but it
  is only ever used as a `helm template` lint target, so nothing catches it.
  Also worth an upstream fix.

`helm template` fails the Agent Sandbox preflight because it renders offline and
cannot see the CRD. Pass the capability explicitly when rendering:

```shell
helm template openshell deploy/helm/openshell -n openshell-experiments \
  -f experiments/k8s-agent/manifests/values-kind-experiments.yaml \
  --api-versions agents.x-k8s.io/v1beta1 --kube-version 1.35.0
```

#### Orphaned Sandbox resources after a gateway version jump

An incompatible gateway upgrade means a fresh database (the `server.dbUrl`
suffix above), and that strands the `Sandbox` custom resources the previous
gateway created. The new gateway discovers them but refuses to manage them:

```text
Sandbox resource admission revalidation failed sandbox_id=896f45ef…
  reason=sandbox driver config is disabled or lacks admission provenance; recreate it
```

`openshell sandbox delete` then reports success — it removes its own record —
while the resource itself persists, so the next create fails with `sandbox
already exists`. It is not a race; the resource stays indefinitely.

Nothing in Helm can clean this up, because a sandbox is gateway state rather
than a release resource. That is the same split described in [There Is No
Declarative Sandbox](#there-is-no-declarative-sandbox), and orphaned resources
are its cost at upgrade time. Clear them as part of the version jump:

```shell
kubectl --kubeconfig ~/.kube/config --context kind-kind \
  -n openshell-experiments delete sandboxes.agents.x-k8s.io --all
```

Do it after uninstalling the gateway and before installing the new one. Note the
explicit `--kubeconfig`, for the reason in [step 0](#0-pin-the-context).

### 3. Register the CLI

```shell
kubectl --kubeconfig ~/.kube/config --context kind-kind \
  -n openshell-experiments port-forward svc/openshell 18080:8080 &

./scripts/bin/openshell gateway add http://127.0.0.1:18080 --local --name kind-experiments
./scripts/bin/openshell --gateway kind-experiments status
```

Because this deployment runs with `disableTls: true` and
`allowUnauthenticatedUsers: true`, an `http://` endpoint registers as plaintext
with no mTLS bundle or OIDC flow. That is acceptable only because access is a
port-forward from one workstation. Anything shared needs
[Access Control](../../docs/kubernetes/access-control.mdx).

### 4. Enable providers v2

```shell
./scripts/bin/openshell --gateway kind-experiments \
  settings set --global --key providers_v2_enabled --value true --yes
```

`scripts/deploy-agent.sh` applies this too, so this step is only needed when
driving the CLI by hand. See the note above for what happens without it.

### 5. Build the agent image

```shell
./experiments/k8s-agent/scripts/build-agent-image.sh --tag dev
```

This renders the payload the same way `run.sh` does — shared runtime, prompt
template with `{{HARNESS}}`/`{{RUN_MODE}}`/`{{POLL_INTERVAL_SECONDS}}`/
`{{PAYLOAD_VERSION}}`/`{{USER_PROMPT}}` substituted, plus manifest `resources:` —
then bakes it read-only into the image at `/etc/openshell/agent-payload` and
side-loads it into kind.

For a real cluster, push to a registry instead:

```shell
IMAGE_REPO=ghcr.io/monad-inc/repo-watcher \
  ./experiments/k8s-agent/scripts/build-agent-image.sh --tag "$GIT_SHA" --push
```

> `kind load docker-image` fails with `content digest ... not found` on images
> **pulled** as multi-platform manifests. Locally built single-arch images load
> fine. If you hit it on a pulled image, run a local registry instead.

### 6. Provide credentials

Agent credentials are chart-rendered, never applied by hand. For local bring-up
the DUMMY values file carries deliberately non-functional placeholders:

```shell
-f experiments/k8s-agent/deploy/oncall-triage.credentials.DUMMY.yaml
```

For anything real, have External Secrets or the 1Password operator own a Secret
and point the release at it with `credentials.existingSecret`, which keeps
credential material out of both git and the shell. Per-token scopes and the
rotation caveat are in [deploy/CREDENTIALS.md](deploy/CREDENTIALS.md).

Supply `CLAUDE_CODE_OAUTH_TOKEN` instead of `ANTHROPIC_API_KEY` for the
subscription-billing variant. Setting both is rejected by the launcher and again
by the harness adapter, so billing attribution is never ambiguous.

Slack scopes are read-only: `channels:history`, `groups:history`,
`channels:read`, `users:read`. The `slack-reader` profile allows no
`chat.postMessage` path, so the agent cannot post even if given a token that
could.


### 7. Deploy the agent

Two images first — the sandbox image (step 5) and the launcher image, which
bakes the agent definition and the deploy script:

```shell
./experiments/k8s-agent/scripts/build-launcher-image.sh --tag dev
```

Then install the chart:

```shell
helm --kubeconfig ~/.kube/config --kube-context kind-kind \
  upgrade --install repo-watcher experiments/k8s-agent/chart \
  -n openshell-experiments \
  --set credentials.existingSecret=repo-watcher-credentials \
  --wait
```

Set `--set agent.recreate=true` to replace a running agent, which is required
whenever `agent.image` changes, since the payload is baked into that image.

To drive it from a workstation instead, without Helm:

```shell
export GITHUB_TOKEN="$(gh auth token)" SLACK_BOT_TOKEN=... ANTHROPIC_API_KEY=...
OPENSHELL_BIN=./scripts/bin/openshell \
  ./experiments/k8s-agent/scripts/deploy-agent.sh
```

#### What the chart does and does not own

The chart owns a ServiceAccount, optionally a Secret, and a Job. **It does not
own the agent.** There is no Kubernetes object representing a sandbox, so the
Job makes imperative gateway API calls and the resulting agent outlives the
release. Consequences worth knowing:

- `helm uninstall` does **not** delete the agent. Delete it explicitly with
  `openshell sandbox delete`.
- The Job is a `post-install,post-upgrade` hook, so every `helm upgrade`
  reconverges: profiles are re-imported, providers upserted, and an existing
  sandbox left alone unless `agent.recreate=true`. Re-running is safe.
- `helm rollback` restores the chart's own objects, not the agent.

#### The scope assertion

`scope.github.repo` is not what the agent reads. `watch-config.yaml` is baked
into the sandbox image on purpose, so a running agent's scope cannot be widened
by editing Helm values. The chart passes the value to the Job, which checks it
against the baked `github-watcher` profile and fails the release on a mismatch:

```text
==> Scope verified: github-watcher pins monad-inc/OpenShell
```

```text
error: scope mismatch: expected 'someone-else/private-repo', but the baked
github-watcher profile does not pin it. Rebuild the launcher and sandbox images
after changing the watched repository.
Error: UPGRADE FAILED: post-upgrade hooks failed
```

Changing the watched repository is therefore a rebuild, not a value edit. Set
`scope.verify=false` only if you deliberately want that check off.

### 8. Observe

```shell
./scripts/bin/openshell --gateway kind-experiments sandbox list
./scripts/bin/openshell --gateway kind-experiments sandbox logs repo-watcher --follow

kubectl --kubeconfig ~/.kube/config --context kind-kind \
  -n openshell-experiments get sandboxes.agents.x-k8s.io,pods
```

A healthy watch loop reports one bounded cycle, a sentinel, then a sleep:

```text
openshell-agent: starting watch cycle 1 with harness claude
openshell-agent: waiting (no_new_requests); sleeping 900s outside harness
openshell-agent: still waiting (no_new_requests); next cycle in 840s
```

## How the Loop Works

`runtime.mode: watch` means the sandbox stays up and
`runtime/supervisor.sh` runs **bounded** agent cycles. The agent itself never
sleeps or polls. It performs one reconciliation pass, prints a final-line
sentinel, and exits:

```text
OPENSHELL_AGENT_RESULT {"status":"waiting","next_poll_seconds":900,"reason":"no_new_requests"}
```

The supervisor sleeps *outside* the harness, then starts a fresh cycle. Only
`complete` and `terminal_failure` stop it; `waiting`, `blocked`, malformed
sentinels, and transport failures all retry with bounded backoff. That is what
makes a long-lived agent resilient to upstream model errors.

Because every cycle is a fresh process, **durable state must live outside the
sandbox**. Gator uses GitHub labels, comments, and checks. This agent uses a
fenced ```json openshell-watcher-state block in a tracking issue named by
`watch-config.yaml`, holding the per-channel Slack cursor and what it has
already acted on. Set `github.state_issue`, or the agent correctly reports
`blocked`.

## The On-Call Triage Agent

Watches production alert channels in Slack, investigates alerts against Grafana,
traces causes in the org's code, and opens a PR when — and only when — it can
name a mechanism. Read-only everywhere except pull-request creation.

Deploy it with two YAML files and one command:

```shell
helm upgrade --install oncall-triage experiments/k8s-agent/chart \
  -n openshell-experiments \
  -f experiments/k8s-agent/deploy/oncall-triage.values.yaml \
  -f experiments/k8s-agent/deploy/oncall-triage.credentials.DUMMY.yaml \
  --set policyProbe.enabled=true
```

Build its two images first:

```shell
docker build -f experiments/k8s-agent/base/Dockerfile -t openshell-agents/base:dev experiments/k8s-agent/base
./experiments/k8s-agent/scripts/build-agent-image.sh    --agent oncall-triage --tag dev
./experiments/k8s-agent/scripts/build-launcher-image.sh --agent oncall-triage --tag dev
```

For real credentials, see [deploy/CREDENTIALS.md](deploy/CREDENTIALS.md).

### MCP servers run inside the sandbox

Grafana is reached through the Grafana MCP server, which runs as a **stdio
subprocess inside the agent's sandbox** — not as a separate service.

That placement is what keeps Grafana an ordinary OpenShell provider. MCP frames
never cross the sandbox boundary, so what OpenShell sees and enforces is plain
HTTPS to Grafana: a provider profile with a credential and a path allowlist,
exactly like GitHub and Slack.

`mcp-grafana` reads `GRAFANA_SERVICE_ACCOUNT_TOKEN` from its environment and
sends it as `Authorization: Bearer <value>`. In the sandbox that value is an
OpenShell placeholder and the proxy substitutes the real token on the wire —
verified by capturing the header the binary emits:

```text
HEADER Authorization: Bearer openshell:resolve:env:GRAFANA_SERVICE_ACCOUNT_TOKEN
```

Confirmed running, with the binary itself as the identified process:

```text
ALLOWED /usr/local/bin/mcp-grafana(0) -> kube-prometheus-stack-grafana...:80
        [policy:_provider_grafana engine:opa]
```

#### Declaring an MCP server

An agent declares what it needs in `agent.yaml`. One block drives both the image
build and the client config, so the binaries installed and the servers the agent
can reach cannot drift apart:

```yaml
mcp_servers:
  - id: grafana
    install:
      kind: oci_binary
      image: mcp/grafana:latest
      source_path: /app/mcp-grafana
      dest_path: /usr/local/bin/mcp-grafana
    command: /usr/local/bin/mcp-grafana
    args: [-disable-write, -enabled-tools, "search,datasource,prometheus,loki,..."]
    env:
      GRAFANA_URL: http://kube-prometheus-stack-grafana.grafana.svc.cluster.local
      GRAFANA_SERVICE_ACCOUNT_TOKEN: ${GRAFANA_SERVICE_ACCOUNT_TOKEN}
```

At build time `build-agent-image.sh` turns each entry into a multi-stage
`COPY --from`, so the binary comes straight out of a published image with no
download step or package manager:

```dockerfile
FROM mcp/grafana:latest AS mcpsrc0
...
COPY --from=mcpsrc0 /app/mcp-grafana /usr/local/bin/mcp-grafana
```

and generates `mcp.json` into the read-only payload. The harness loads it with
`--mcp-config` plus `--strict-mcp-config`, so the servers an agent can run are
fixed at build time. Install kinds are `oci_binary` and `npm`; adding an MCP
server to an agent is this block and nothing else — no chart change, no service.

`install.image` is pinned by digest, which required mirroring the upstream image
first: a by-digest pull of `docker.io/mcp/grafana` fails under BuildKit with
`insufficient_scope: authorization failed` on an anonymous pull, so only a
moving tag worked there. The mirror lives at
`ghcr.io/monad-inc/openshell/mirror/mcp-grafana` — `mirror/` marks it as a copy
of a third-party image rather than something Monad builds.

It is a server-side manifest copy, so the mirrored index carries the identical
digest to the source with both `linux/amd64` and `linux/arm64` intact, and the
digest is therefore verifiable against upstream rather than being a new identity:

```shell
docker buildx imagetools create \
  --tag ghcr.io/monad-inc/openshell/mirror/mcp-grafana:<date> \
  mcp/grafana@sha256:<upstream-digest>
```

Refreshing the MCP server means re-copying upstream and bumping the digest in
`agent.yaml`. The cluster never pulls this image — the binary is baked into the
agent image at build time — so it needs no pull secret; only the build host
needs `docker login ghcr.io`.

#### Why not run the MCP server as a service

The first version did, giving it its own Grafana credential. That was wrong, in
a way worth recording.

It made the token ambient authority for anything that could reach the Service.
Nothing guarded it — mcp-grafana has no caller authentication, and the tool
allowlist only constrained traffic arriving through the OpenShell proxy, so it
bounded the agent and nothing else. Credentials stopped being tied to a caller,
and two agents would have been indistinguishable in Grafana's audit log.

Moving to per-request credentials fixed the ambient part but exposed something
sharper: **mcp-grafana honours an `X-Grafana-URL` request header over its
configured URL, and the header wins.** Verified — a server pinned to
`pinned-by-env.invalid` dialed `attacker-supplied.invalid` when asked. So an
agent able to craft a request could have the proxy inject the *real* token into
a request forwarded to a host it chose. Credential injection is only as safe as
a fixed destination, and that generalizes to any provider whose upstream lets
the caller pick a forwarding target.

Closing that needed an egress NetworkPolicy on the server pod — which **kind's
kindnetd does not enforce**. It accepts the object and ignores it, as it does
OpenShell's own `openshell-sandbox-*` policies in this namespace.

Running the server in-sandbox removes the whole problem. There is no second
service, no exposed endpoint, no credential in transit to another pod, and no
redirect primitive: the destination is the provider endpoint, enforced by
OpenShell rather than by a CNI feature this cluster lacks.

| | in-sandbox stdio | separate service |
|---|---|---|
| Credential | placeholder in env; real value only at the proxy | transmitted to another pod |
| Destination control | OpenShell egress policy, always enforced | NetworkPolicy, CNI-dependent |
| Added attack surface | none | a Service any pod can reach |
| Granularity | HTTP method + path | MCP method + tool name |
| Extra infra | none | Deployment + Service + NetworkPolicy |

The one thing given up is tool-name granularity. It becomes `-disable-write` and
`-enabled-tools` on the server invocation, baked into the read-only payload —
immutable config rather than enforced policy, since a compromised agent could
re-invoke the binary with other flags. The real boundary reverts to the path
allowlist, which is directly probeable:

```text
PASS  grafana-read-search:      permitted; upstream said 401
PASS  grafana-read-query:       permitted; upstream said 401   (POST /api/ds/query)
PASS  grafana-write-dashboard:  denied by L7 (403)
PASS  grafana-write-annotation: denied by L7 (403)
PASS  grafana-admin-users:      denied by L7 (403)
```

Read-only is a path allowlist, not a method rule: Grafana's main read endpoint
is `POST /api/ds/query`, because the query travels in the body.

`curl` is an allowed binary on this provider alongside `mcp-grafana`, and that
is safe here — both are confined to the same paths with the same injected
credential, so curl grants no capability the MCP server lacks. It was excluded
under the service model only because the redirect primitive made binary pinning
load bearing.

### Pin the versions — all three of them

The gateway image, the Helm chart, and the CLI inside the launcher must be the
same release. This cost most of a session to learn:

`image.tag: latest` on the gateway meant a pod restart silently re-pulled a
newer build. That removed the `providers_v2_enabled` setting, and left the
gateway on a different protocol revision from the CLI baked into the launcher.
The symptom was not a version error. It was:

```text
workspace '\n\roncall-triage' not found
```

— a workspace that demonstrably existed, with a name whose bytes were clean.
That is a protobuf field read at the wrong offset. The gateway said so plainly
only once it was restarted against the older store:

```text
provider policy composition startup preflight failed:
NetworkEndpoint.enforcement: invalid wire type: LengthDelimited (expected Varint)
```

Persisted provider profiles are serialized protobuf, and that field changed
shape across 0.0.x → 0.1.x, so profiles written by one build stop the other from
starting. `helm uninstall` does not clear it — the StatefulSet's PVC survives —
so `server.dbUrl` carries a version suffix to give a new gateway a clean store
without deleting the volume.

Note the two spellings: the container tag is `0.1.1`, the git tag the CLI
installer wants is `v0.1.1`.

### Policy probes: assert, do not assume

`probes.txt` states what the policy should do; `policyProbe.enabled=true` checks
it at deploy time and fails the release on a mismatch. Every line below is
measured output, not intent:

```text
PASS  grafana-read-search:      permitted; upstream said 401
PASS  grafana-read-query:       permitted; upstream said 401
PASS  grafana-write-dashboard:  denied by L7 (403)
PASS  grafana-write-annotation: denied by L7 (403)
PASS  grafana-admin-users:      denied by L4 (no connection)
PASS  slack-read-history:       permitted; upstream said 200
PASS  slack-write-post:         denied by L7 (403)
PASS  github-wrong-binary:      denied by L4 (no connection)
PASS  github-org-clone:         command succeeded
PASS  github-outside-org:       command failed
PASS  unrelated-host:           denied by L4 (no connection)
```

Three things in there are worth reading twice.

**Read-only is a path allowlist, not a method rule.** Grafana's main read
endpoint is `POST /api/ds/query` — the query travels in the body. Blocking POST
would break reading. The profile permits that one POST and no mutating path, so
`POST /api/dashboards/db` is refused while `POST /api/ds/query` is not.

**`curl` to `api.github.com` is denied.** Not because of the path — because
`github-triage` pins its binaries to `gh` and `git`. The same request from `git`
succeeds. Policy is binary-aware, so a probe using the wrong program proves
nothing about the path rules, which is why the GitHub probes use `git`.

**Denials arrive at two layers.** 403 means the host was reachable and the
request was refused on method or path. No connection at all means it was refused
before any request. Both are correct denials and they are not interchangeable —
a probe that treats "no connection" as success will pass against a host that
merely fails to resolve, which is exactly the bug the first draft of these
probes had.

### Known limit, stated plainly

Opening a PR requires pushing a branch, which requires `git-receive-pack`. The
proxy enforces at HTTP level and cannot inspect a git pack, so it cannot
distinguish a push to `oncall/*` from a force-push to `main`. Branch protection
and a fine-grained token are required companion controls, not optional hardening.
See `providers/github-triage.yaml` and `deploy/CREDENTIALS.md`.

## Running More Than One Agent

Two properties matter once there is a second bot.

### One workspace per agent — not optional

Provider profiles, providers, and sandboxes are **workspace-scoped**, and a
profile name carries enforced scope: `github-watcher` pins one repository.

Deploying two agents into the shared `default` workspace means the second one's
`provider profile import` + `provider create` upsert **over the first one's**.
The first agent keeps running, its sandbox untouched, but the scope it is
granted has been silently re-pinned to the second agent's repository. Nothing
appears in git. Neither Helm release looks wrong. `helm diff` shows nothing,
because the change happened in gateway state rather than in a manifest.

`agent.workspace` defaults to `agent.name`, so each release is isolated by
default. Verified directly — the same profile id in two workspaces:

```text
bot-two workspace pins:        /repos/monad-inc/other-repo
repo-watcher workspace pins:   /repos/monad-inc/OpenShell
```

Workspace names are DNS-1123 labels capped at **19 characters**. Both the chart
and the deploy script reject an invalid name up front rather than failing at the
first API call.

### Provenance: what is actually running

Every sandbox is stamped at creation, so the cluster reports its own version
instead of being assumed to match git:

```text
Labels:
  agent-image:    openshell-agents_repo-watcher_skills-6205cc23d675
  chart-version:  0.1.0
  git-sha:        9e664e72
  skills-version: 6205cc23d675
```

`openshell sandbox get <name>` answers "which revision is this bot on?" without
inspecting the image. Label values accept only alphanumerics, `-`, `_`, and `.`,
so image references are flattened before being recorded.

### Fleet layout

```shell
helm upgrade --install slack-triage experiments/k8s-agent/chart \
  -f values/base.yaml -f values/slack-triage.yaml
```

A shared `base.yaml` carries fleet-wide settings — model, poll interval,
gateway — and each bot's file carries only what differs. Both are diffable in
git, `helm diff` previews a change before it lands, and each bot keeps its own
release history and rollback.

## Updating Skills

Skills are the fastest-moving part of an agent: they get refined as its judgment
is corrected. `agent.yaml` declares them, and they are baked into the immutable
payload alongside the prompt.

### Why baked rather than mounted

A ConfigMap mount would make updates instant, and it is the wrong trade:

- A running agent could have its instructions rewritten underneath it, and a
  half-applied edit can land mid-cycle.
- Behavior could change with no deploy, no diff, and no review — the same
  invisible-change problem as the workspace collision above.
- There would be no version to point at when asking what a given agent was
  actually running when it did something surprising.

Baking costs a rebuild and a sandbox restart. The base tooling layers are
cached, so a skills-only rebuild takes seconds, and the restart costs one
in-flight cycle.

Note the division of responsibility that makes fast skill iteration safe: skills
change what the agent *does*, while policy and provider profiles govern what it
*can* do. A bad skill revision still cannot exceed the enforced boundary, so
skills can iterate quickly without widening blast radius.

### The loop

```shell
# edit experiments/k8s-agent/agent/skills/<skill>/SKILL.md
./experiments/k8s-agent/scripts/update-skills.sh --agent repo-watcher
./experiments/k8s-agent/scripts/update-skills.sh --all        # every release
./experiments/k8s-agent/scripts/update-skills.sh --agent x --dry-run
```

The image tag *is* the skills digest — a sha256 over the staged skill files —
so the reference names what changed, an unchanged rebuild is a no-op, and the
digest is comparable against git. `--all` keeps going when one agent fails, so a
single broken bot cannot block a fleet-wide skill fix.

Verified end to end: appending a refinement moved the digest from `3dfe6dcfc2ce`
to `6205cc23d675`, and the running agent picked up the new text under the new
label.

## Changing What the Agent Watches

`watch-config.yaml` is baked into the image, so changing scope means rebuild and
redeploy. That is deliberate: a running agent cannot widen its own scope, and
the deployed artifact fully determines what it can see.

When changing the repository, edit **both**:

1. `agent/watch-config.yaml` — `github.repo` (what the agent aims at)
2. `agent/providers/github-watcher.yaml` — every pinned path (what it can reach)

Only the second is enforced. Changing the first alone gets an agent that tries
and is denied at the proxy.

## Verified So Far

On `kind-kind` / `openshell-experiments`, observed directly:

- Gateway 0.1.1 healthy on the Kubernetes compute driver, chart and image matched.
- The on-call triage agent deploys from two YAML files, runs as a `Sandbox` CR
  and pod, and cycles on its watch interval.
- Four providers registered from the agent manifest with no agent-specific code
  in the deploy script.
- **All 11 policy probes pass**, covering Grafana read/write paths, Slack
  read/write, GitHub org scoping, binary pinning, and an unrelated host.
- The Grafana MCP server runs in-sandbox and its traffic is authorized as an
  ordinary provider, with the binary named as the acting process.
- The credential reaches Grafana as a proxy-substituted placeholder; the
  binary never holds it.
- Credentials reach the sandbox as placeholders; the proxy substitutes them on
  the wire.
- Agents are isolated per gateway workspace, so profile names carrying enforced
  scope cannot collide.
- Both agents build from the shared base image; adding one is a directory plus
  a values file.

## Still Open

- **No cycle has completed with real credentials.** Everything runs on
  placeholders, which proves wiring, policy, and the loop — not a real
  investigation or a real PR. The agent currently fails each model call and
  retries, which is the supervisor behaving correctly.
- `github.state_issue` is unset, so the agent reports `blocked` by design until
  a tracking issue exists.
- `slack.channels` is empty — needs real alert channel IDs.
- Grafana points at the in-cluster kube-prometheus-stack instance, which makes
  probes meaningful locally but is not the production Grafana.
- `-enabled-tools` is set from the Grafana MCP catalogue, not from watching a
  real investigation. Expect to narrow it, and the path allowlist, once real
  cycles show what is actually used.
- The repo-watcher agent builds after the restructure but has not been
  redeployed; its values file is ready.
- Skills are unproven in practice. They encode judgment that only survives
  contact with real alerts.

## Upstream Issues Worth Filing

Found while doing this, all reproducible:

1. **Stale Agent Sandbox manifest URL.** `docs/kubernetes/setup.mdx` points at
   `.../releases/latest/download/manifest.yaml`, which does not exist for
   v1.0.0. `curl` silently writes an empty file, and the failure only surfaces
   later as a confusing chart preflight error.
2. **`pkiInitJob.enabled: false` with `disableTls: true` wedges the gateway.**
   The certgen hook also creates the sandbox JWT signing secret, and the
   StatefulSet mounts it unconditionally. The chart's own
   `ci/values-tls-disabled.yaml` encodes this broken combination but is only
   used as a `helm template` lint target, so CI never catches it.
3. **The builtin `claude-code` profile's `binaries:` do not match an npm
   install.** The real executable is
   `/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe`; the profile
   works only if the image happens to provide both listed symlinks.
4. **`provider profile update --file` rejects an extensionless filename** with
   "unsupported provider profile file format" — it dispatches on file
   extension. A `mktemp` file fails; `mktemp -d` plus `profile.yaml` works.
5. **`provider profile import` rejects `category: observability`.** The
   accepted set includes agent, data, inference, messaging, other, and
   source_control. An observability tool is a natural profile to write and the
   category list is not discoverable from the CLI.
6. **`install.sh` rejects `OPENSHELL_VERSION=latest`.** The variable is a
   literal release tag, so the plausible-looking `latest` resolves to
   `releases/download/latest/...` and 404s. Leaving it unset is what selects the
   latest release. Worth either accepting `latest` or naming it in the error.
7. **No agent launcher path for a Kubernetes gateway.** `run.sh` requires a
   local Docker daemon to bake the payload and stays attached to the agent.
   Both assumptions break in-cluster; the build/deploy split here is one answer
   and could reasonably be upstreamed.
