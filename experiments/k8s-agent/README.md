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
  agent/
    agent.yaml               # manifest: harness, watch mode, providers, resources
    watch-config.yaml        # WHAT it watches — repo, channels, limits
    policy.yaml              # filesystem + process policy
    Dockerfile               # sandbox image (Claude Code CLI, gh, git, curl, jq)
    prompts/watcher.md       # prompt template; renders to agent-prompt.md
    providers/
      github-watcher.yaml    # one repo, read + push + PR
      slack-reader.yaml      # read-only Slack Web API
      claude-code-oauth.yaml # OAuth billing variant (API-key variant is builtin)
  launcher/Dockerfile        # deploy-Job image: CLI + ruby + jq + baked agent def
  chart/                     # Helm chart that deploys the agent
    Chart.yaml
    values.yaml
    templates/               # ServiceAccount, optional Secret, deploy Job hook
  manifests/
    values-kind-experiments.yaml   # values for the OpenShell gateway chart
    namespace.yaml
    secrets.example.yaml     # template; never holds real values
  scripts/
    build-agent-image.sh     # sandbox image (payload baked in)
    build-launcher-image.sh  # launcher image (agent def + deploy script baked in)
    deploy-agent.sh
```

## Runbook

### 0. Pin the context

Every command below carries the context explicitly. Confirm the target first:

```shell
kubectl --kubeconfig ~/.kube/config --context kind-kind get nodes
```

Expect a single `kind-control-plane` node on v1.35.0. If you see EKS nodes, stop.

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

```shell
kubectl --kubeconfig ~/.kube/config --context kind-kind create namespace openshell-experiments

helm --kubeconfig ~/.kube/config --kube-context kind-kind \
  upgrade --install openshell deploy/helm/openshell \
  -n openshell-experiments \
  -f experiments/k8s-agent/manifests/values-kind-experiments.yaml \
  --wait --timeout 7m
```

Notes on the values, both learned the hard way:

- **`image.tag` must be set.** The chart's `appVersion` is the `0.0.0` dev
  placeholder, so the default tag resolves to an image that does not exist.
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

```shell
kubectl --kubeconfig ~/.kube/config --context kind-kind \
  -n openshell-experiments create secret generic repo-watcher-credentials \
  --from-literal=GITHUB_TOKEN="$GITHUB_TOKEN" \
  --from-literal=SLACK_BOT_TOKEN="$SLACK_BOT_TOKEN" \
  --from-literal=ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY"
```

Supply `CLAUDE_CODE_OAUTH_TOKEN` instead of `ANTHROPIC_API_KEY` for the
subscription-billing variant. Setting both is rejected by the launcher and again
by the harness adapter, so billing attribution is never ambiguous.

Slack scopes are read-only: `channels:history`, `groups:history`,
`channels:read`, `users:read`. The `slack-reader` profile allows no
`chat.postMessage` path, so the agent cannot post even if given a token that
could.

This cluster already runs External Secrets and the 1Password operator; a real
deployment should source the Secret from one of those rather than an operator's
shell.

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

On `kind-kind` / `openshell-experiments`, all observed directly:

- Agent Sandbox v1.0.0 controller and CRD installed; serves `v1beta1`.
- Gateway healthy on the Kubernetes compute driver.
- CLI registered over the port-forward; `status` reports Connected.
- Sandboxes materialise as real `Sandbox` CRs and pods; `exec` works.
- **Default-deny egress**: a sandbox with no providers reaches nothing —
  `api.github.com`, `slack.com`, and `example.com` all fail to connect.
- **Single-repo enforcement**: `git clone` of the watched repo succeeds while
  `git clone` of `torvalds/linux` is refused with 403, same binary, same host.
- **Read-only Slack**: `GET /api/auth.test` returns 200; `POST
  /api/chat.postMessage`, which no rule allows, returns 403.
- **Binary-aware policy**: `curl` to `api.github.com` is denied where `gh`
  succeeds, because `github-watcher` pins `gh` and `git`.
- **L7 path enforcement on the model API**: with the corrected profile,
  `POST /v1/messages` and `GET /api/claude_code/settings` are allowed under
  `policy:_provider_claude_code_apikey`.
- Agent image builds with the payload baked read-only at
  `/etc/openshell/agent-payload`.
- **Helm-driven deploy works in-cluster**: `helm upgrade --install` runs the
  launcher Job, which reaches the gateway over the cluster Service, imports
  profiles, upserts providers, and creates the agent. Job completed in 10s.
- **`helm upgrade` is safely re-runnable**: a second run reconverges providers
  and leaves the running agent untouched.
- **The scope assertion fails the release** on a mismatch between
  `scope.github.repo` and the baked profile.
- The deployed agent runs `supervisor.sh` as the sandbox's **main process**,
  which invokes `claude --print --output-format text --model claude-opus-5
  --dangerously-skip-permissions` per cycle and retries on failure — the
  launcher's exit does not disturb it.

## Still Open

- **No cycle has completed with real credentials.** Slack and Anthropic were
  exercised with placeholder tokens, which proves the network and policy path
  but not a successful model call or a real PR. The retry loop observed is the
  supervisor correctly handling an invalid key.
- `github.state_issue` is unset in `watch-config.yaml`, so the agent will report
  `blocked` by design until a tracking issue exists.
- `slack.channels` is empty — needs real channel IDs.
- The OAuth variant (`claude-code-oauth`) is defined and lints, but only the
  API-key variant has been deployed.

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
5. **`install.sh` rejects `OPENSHELL_VERSION=latest`.** The variable is a
   literal release tag, so the plausible-looking `latest` resolves to
   `releases/download/latest/...` and 404s. Leaving it unset is what selects the
   latest release. Worth either accepting `latest` or naming it in the error.
6. **No agent launcher path for a Kubernetes gateway.** `run.sh` requires a
   local Docker daemon to bake the payload and stays attached to the agent.
   Both assumptions break in-cluster; the build/deploy split here is one answer
   and could reasonably be upstreamed.
