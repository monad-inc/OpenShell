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
- **Running processes.** A process that is already running gets the new value
  only when the credential's profile sets `stable_placeholder: true`. Without it,
  only processes started after the update see the new value.
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
- **Startup and restarts.** The watch starts with a full list, so every labelled
  Secret is synced at startup. State is in memory: a salted fingerprint of each
  value sent, never the value. After a restart every Secret is sent once more.
  That is a value-only update and does not disturb running sandboxes.
- **Retries.**
  - A missing provider is retried every 30s.
  - Transient gateway failures are retried every 10s.
  - Invalid annotations, conflicts, partly set keys and rejected updates
    are retried every 5m, or as soon as the Secret changes.
  - An absent provider is not retried; the next change to the Secret is seen.
- **Audit.** Each outcome is published as a Kubernetes Event on the Secret
  (`ProviderSynced`, `ProviderSyncSkipped`, `ProviderNotFound`,
  `ProviderSyncConflict`, `InvalidProviderSync`, `ProviderSyncFailed`). The
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
| `--log-json` | `OPENSHELL_LOG_JSON` | Log as JSON lines |

On a gateway that requires authentication, the principal needs `provider:write`
with the workspace `admin` role in every workspace it updates. The token file
suits a projected ServiceAccount token or a Secret-mounted token that something
else rotates on disk.

The ServiceAccount needs `get`, `list` and `watch` on Secrets in the watched
namespace, and `create` and `patch` on `events.k8s.io` Events.

The gateway client is the Rust SDK, which speaks bearer-token auth only. A
gateway that requires mTLS client certificates is not supported yet.

## Limits

- **One replica.** There is no leader election. Two replicas would send the same
  idempotent updates twice; that is wasteful but not wrong.
- **No activation wait.** The controller does not wait for supervisors to report
  that they activated the update. The gateway's mutation id is logged for
  correlation.
