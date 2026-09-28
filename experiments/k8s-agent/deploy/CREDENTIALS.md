# Supplying Real Credentials

The cluster deployment runs on deliberately non-functional placeholders from
`oncall-triage.credentials.DUMMY.yaml`. With them the agent deploys, starts,
enforces policy, and cycles; every outbound call is refused by the upstream API
rather than by the sandbox. That is enough to verify wiring, policy, and the
watch loop, and not enough to triage a real alert.

This document is the procedure for replacing them.

## What each credential is, and how to scope it

Scope every token at the source. The sandbox policy is a second boundary, not a
substitute for a narrow token — two independent constraints, either of which
alone should be enough.

### `GITHUB_TOKEN`

A **fine-grained** personal access token, or a GitHub App installation token.

- Repository access: only the repositories in `github.repos` in
  `agents/oncall-triage/watch-config.yaml`.
- Permissions: **Contents: Read and write** (clone, and push the PR branch),
  **Pull requests: Read and write** (open a PR), **Metadata: Read**.
- Nothing else. No Administration, no Actions, no Secrets, no org permissions.

**Required companion control.** Opening a PR requires pushing a branch, which
requires `git-receive-pack`. The proxy enforces at HTTP level and cannot inspect
the contents of a git pack, so it cannot tell "push to `oncall/*`" from
"force-push to `main`". Before using a real token, turn on branch protection for
the default branch of every repository in scope, including *block force pushes*
and a required review. Treat this as part of the deployment, not a nicety.

### `SLACK_BOT_TOKEN`

A bot token (`xoxb-`) from a Slack app installed in your workspace.

- Scopes: `channels:history`, `groups:history`, `channels:read`, `users:read`.
- Do **not** grant `chat:write`. The agent never posts, and
  `providers/slack-oncall-reader.yaml` has no rule permitting it — verified:
  `POST /api/chat.postMessage` is refused with 403.
- Invite the bot to each alert channel; a token alone does not grant access to
  a channel it is not in.
- Put the channel IDs (not names) in `slack.channels` in `watch-config.yaml`.

### `GRAFANA_SERVICE_ACCOUNT_TOKEN`

A **service account token** with the **Viewer** role. Grafana's legacy API keys
are deprecated; use a service account.

This is the agent's own credential and behaves like every other one here. The
Grafana MCP server runs as a stdio subprocess *inside* the sandbox, so it reads
this token from the sandbox environment — where it is an OpenShell placeholder —
and sends it as `Authorization: Bearer <value>` to Grafana. The proxy
substitutes the real token on the wire. The binary never holds it, and neither
does the agent.

Give each agent its own token. They are scoped and attributable independently in
Grafana's audit log.

Viewer is sufficient because every allowed path reads. `providers/grafana.yaml`
is a second, independent constraint — a path allowlist with nothing mutating in
it — and the MCP server additionally runs with `-disable-write` and a narrowed
`-enabled-tools`.

Which Grafana it talks to is `GRAFANA_URL` in the `mcp_servers` block of
`agents/oncall-triage/agent.yaml`; what it may reach there is the endpoint in
`providers/grafana.yaml`. Change both together — the first states intent, the
second is enforced.

### `ANTHROPIC_API_KEY`

An Anthropic API key for the Claude Code harness. Supply
`CLAUDE_CODE_OAUTH_TOKEN` instead to bill against a subscription. Setting both
is refused by the launcher and again by the harness adapter, so billing
attribution is never ambiguous.

## Where to put them

### Recommended: a Secret this chart does not own

This cluster already runs External Secrets and the 1Password operator. Have one
of them produce a Secret in `openshell-experiments`, then point the release at
it and drop the DUMMY values file:

```yaml
# oncall-triage.values.yaml
credentials:
  existingSecret: oncall-triage-credentials
```

```shell
helm upgrade --install oncall-triage experiments/k8s-agent/chart \
  -n openshell-experiments \
  -f experiments/k8s-agent/deploy/oncall-triage.values.yaml
```

The Secret must carry these keys, which are the environment variable names the
agent manifest declares:

| Key | Required |
|---|---|
| `GITHUB_TOKEN` | yes |
| `SLACK_BOT_TOKEN` | yes |
| `GRAFANA_SERVICE_ACCOUNT_TOKEN` | yes — the agent's own, injected per request |
| `ANTHROPIC_API_KEY` *or* `CLAUDE_CODE_OAUTH_TOKEN` | exactly one |

### Local testing: a values file kept out of git

Copy the DUMMY file, fill it in, and keep it untracked:

```shell
cp experiments/k8s-agent/deploy/oncall-triage.credentials.DUMMY.yaml \
   /path/outside/the/repo/oncall-triage.credentials.yaml
```

Never edit real values into the DUMMY file — it is committed. Prefer a path
outside the working tree so a stray `git add -A` cannot pick it up.

## How the credentials actually reach the agent

Worth understanding, because it is why the agent never holds a real secret:

1. The Job reads them from its environment, sourced from the Secret.
2. It registers each as a **provider credential** on the gateway
   (`--credential KEY`, an environment lookup — the value never appears in a
   command line or in `ps`).
3. The sandbox receives **placeholders**, not values. The egress proxy
   substitutes the real credential onto the wire per request.

So a compromised agent process cannot read the tokens out of its own
environment, and a prompt-injected instruction to print a credential yields a
placeholder. That is the design intent; the policy probes verify the egress half
of it.

## After swapping them in

```shell
helm upgrade --install oncall-triage experiments/k8s-agent/chart \
  -n openshell-experiments \
  -f experiments/k8s-agent/deploy/oncall-triage.values.yaml \
  --set policyProbe.enabled=true \
  --set agent.recreate=true
```

`agent.recreate=true` is required for the new credentials to reach a running
agent. `policyProbe.enabled=true` re-asserts that the live policy still matches
what the profiles declare, and fails the release if it does not.

Then set `github.state_issue` in `watch-config.yaml` to a tracking issue and
rebuild — until it is set the agent correctly reports `blocked`, because it has
nowhere durable to record what it has already investigated.

## Rotation

Rotating means updating the Secret and re-running the deploy with
`agent.recreate=true`. The gateway holds provider credentials, so a rotation
that updates only the Secret without re-running the Job leaves the gateway on
the old value.
