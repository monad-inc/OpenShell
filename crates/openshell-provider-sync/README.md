# openshell-provider-sync

Keeps provider credentials current with Kubernetes Secrets that something else
manages, such as External Secrets Operator syncing from Vault or 1Password.

The controller watches Secrets labelled `openshell.nvidia.com/provider-sync=true`.
Each Secret names the providers it feeds and the credential keys it backs for
each one:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pm
  labels:
    openshell.nvidia.com/provider-sync: "true"
  annotations:
    openshell.nvidia.com/provider-workspace: pm   # optional
    openshell.nvidia.com/provider-credentials: >-
      slack-pm:SLACK_BOT_TOKEN, slack-pm:SLACK_APP_TOKEN,
      linear:LINEAR_API_KEY,
      claude-code-apikey:ANTHROPIC_API_KEY,
      claude-code-oauth:CLAUDE_CODE_OAUTH_TOKEN
```

An entry is `[provider:]CREDENTIAL_KEY[=secret-key]`, separated by commas or
newlines:

- `slack-pm:SLACK_BOT_TOKEN` reads the Secret key `SLACK_BOT_TOKEN` into the
  credential `SLACK_BOT_TOKEN` of provider `slack-pm`.
- `linear:LINEAR_API_KEY=linear-key` reads the Secret key `linear-key` instead.
- An entry without a `provider:` prefix goes to the provider named by the
  `openshell.nvidia.com/provider` annotation, which is otherwise optional.

All providers of one Secret are in one workspace, from
`openshell.nvidia.com/provider-workspace` or the controller's default. Only listed
keys are read, so a key added to the Secret later never becomes a credential by
accident, and one Secret key may be listed only once.

## Behavior

- **What it sends.** When a mapped value changes, the controller sends only the
  changed keys of that provider as a value-only `UpdateProvider`. The gateway
  merges them into the provider, and attached sandboxes refetch on their next
  provider poll, every 10s by default.
- **Restarting affected agents.** After a successful rotation the controller
  restarts every sandbox the gateway reports attached to that provider, with
  `StopSandbox` then `StartSandbox`, so the agent starts fresh and no open
  connection keeps using the old value. Sandboxes of other providers are not
  touched, and a sandbox restarts once even when several of its providers
  rotate together. A rotation that lands while a sandbox is already restarting
  restarts it once more afterwards. Agents must therefore tolerate a restart at
  any time: keep state outside the sandbox or resume from it. `--no-restart`
  turns this off.
- **Never leaving an agent stopped.** Each restart is a saved state machine:
  requested, then stopping, then awaiting running. The request is saved in the
  same write as the rotation's fingerprints, and the controller saves that it
  owns the stop before it stops anything, so after a controller restart it
  resumes every restart where it was. Every gateway failure and every failed
  save is retried, backing off from 10 seconds to 5 minutes. A restart is done
  only when the sandbox is ready again. This holds with `--state-secret`;
  without it a restart in progress is lost when the controller restarts, which
  can leave an agent stopped, and the controller warns about it at startup.
  At startup a state Secret that cannot be read is retried with backoff, never
  replaced. One that does not parse is copied to
  `<state-secret>-corrupt-<unix-time>` and reported with a `StateSecretCorrupt`
  Warning; every restart entry that still parses is kept and the rest starts
  over as a baseline. An agent whose restart entry was lost stays stopped,
  because a stop by this controller cannot be told from one by a person.
- **What a restart leaves to others.** A sandbox that is stopped, stopping,
  completed, in Error or being deleted when the restart begins is left alone,
  and so is one someone else stops after the restart started it. A sandbox that
  ends in Error is left to the gateway's own recovery, with an
  `AgentRestartFailed` event. One race remains: if someone stops a sandbox in
  the moment between the controller reading its phase and stopping it, the
  controller starts it again afterwards. The gateway has no conditional stop
  to close that window.
- **What it leaves alone.** It never creates or deletes providers, never clears
  a credential when its Secret is deleted or unlabelled, and never touches
  credential keys that no Secret lists. Providers are still created by whatever
  creates them today.
- **Each provider on its own.** A provider that fails does not hold back the
  other providers of the same Secret.
- **Empty means absent.** A Secret key that is missing and one whose value is
  empty are treated the same, so a Secret that writes every known key and leaves
  unused ones empty works. An empty value is never sent.
- **All or nothing per provider.** If some but not all of a provider's keys are
  set, or any is not UTF-8, nothing is sent to that provider, so a half-written
  Secret cannot produce a partial rotation.
- **Absent providers.** A provider with none of its keys set in the Secret is
  skipped. This lets a Secret list alternative credentials, such as an API key
  and an OAuth token, and feed whichever one it holds. When it switches, the
  newly present provider is sent in full.
- **One Secret per credential.** A second live Secret that maps the same
  workspace, provider and credential key is refused with a
  `ProviderSyncConflict` event.
- **Rotations, not baselines.** Only a value that replaces one this controller
  applied before restarts agents. The first values it sees for a provider are a
  baseline: they are sent, and nothing restarts.
- **Startup and restarts.** The watch starts with a full list, so every labelled
  Secret is synced at startup. The controller keeps a salted fingerprint of each
  value sent, never the value. With `--state-secret`, the salt and fingerprints
  are kept in that Secret, so after a restart unchanged values are recognized:
  nothing is re-sent and no agent restarts. Without it, every Secret is sent
  once more after a restart as a baseline that restarts nothing; a rotation
  that happened while the controller was down then reaches the providers but
  restarts no agents.
- **Retries.**
  - A missing provider is retried every 30s.
  - Transient gateway failures are retried every 10s.
  - Invalid annotations, conflicts, partly set keys and rejected updates
    are retried every 5m, or as soon as the Secret changes.
  - An absent provider is not retried; the next change to the Secret is seen.
- **Audit.** Each outcome is published as a Kubernetes Event on the Secret
  (`ProviderSynced`, `ProviderSyncSkipped`, `ProviderNotFound`,
  `ProviderSyncConflict`, `InvalidProviderSync`, `ProviderSyncFailed`,
  `AgentRestarted`, `AgentRestartSkipped`, `AgentRestartPending`,
  `AgentRestartFailed`). `AgentRestartPending` is a Warning at each retry after
  a failure, and when a sandbox takes over 2 minutes to stop or start; repeats
  of the same failure aggregate into one Event with a count. The
  gateway separately audits each `UpdateProvider` with the controller's
  principal. Neither carries values.

## Running

The Monad fork publishes the controller as `ghcr.io/monad-inc/openshell/provider-sync`,
with the same tags as the gateway. Run it as its own Deployment.

```shell
openshell-provider-sync \
  --gateway http://openshell.openshell.svc:8080 \
  --namespace agents \
  --default-workspace default
```

| Flag | Environment | Purpose |
|---|---|---|
| `--gateway` | `OPENSHELL_GATEWAY_ENDPOINT` | Gateway URL |
| `--gateway-ca-file` | `OPENSHELL_GATEWAY_CA_FILE` | CA for a private-CA gateway |
| `--gateway-token-file` | `OPENSHELL_GATEWAY_TOKEN_FILE` | Bearer token, re-read when the gateway rejects it. Omit for a gateway that allows unauthenticated users |
| `--namespace` | `OPENSHELL_PROVIDER_SYNC_NAMESPACE` | Namespace to watch; all namespaces when omitted |
| `--default-workspace` | `OPENSHELL_PROVIDER_SYNC_DEFAULT_WORKSPACE` | Workspace when a Secret has no workspace annotation |
| `--reporter`, `--reporter-instance` | `OPENSHELL_PROVIDER_SYNC_REPORTER`, `POD_NAME` | Event reporter |
| `--no-events` | | Disable Kubernetes Events |
| `--no-restart` | `OPENSHELL_PROVIDER_SYNC_NO_RESTART` | Do not restart agents after a rotation |
| `--state-secret` | `OPENSHELL_PROVIDER_SYNC_STATE_SECRET` | Secret that keeps applied-value fingerprints across restarts |
| `--state-namespace` | `POD_NAMESPACE` | Namespace of the state Secret, usually the controller's own |
| `--log-json` | `OPENSHELL_LOG_JSON` | Log as JSON lines |

On a gateway that requires authentication, the principal needs `provider:write`
with the workspace `admin` role in every workspace it updates, plus
`sandbox:read` and `sandbox:write` there to restart agents. The token file
suits a projected ServiceAccount token or a Secret-mounted token that something
else rotates on disk.

The ServiceAccount needs `get`, `list` and `watch` on Secrets in the watched
namespace, and `create` and `patch` on `events.k8s.io` Events. With
`--state-secret` it also needs `get`, `create` and `patch` on Secrets in its own
namespace, which a `resourceNames` rule can limit to the state Secret for `get`
and `patch`.

The gateway client is the Rust SDK, which speaks bearer-token auth only. A
gateway that requires mTLS client certificates is not supported yet.

## Limits

- **One replica.** There is no leader election. Two replicas would send the same
  idempotent updates twice; that is wasteful but not wrong.
- **No activation wait.** The controller does not wait for supervisors to report
  that they activated the update before restarting. A restarted sandbox fetches
  the provider's current values when it starts. The gateway's mutation id is
  logged for correlation.
- **Attachment at update time.** The restart set is the gateway's target set for
  the update. A sandbox attached to the provider afterwards already starts with
  the new values.
