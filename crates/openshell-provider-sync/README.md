# openshell-provider-sync

Keeps provider credentials current with Kubernetes Secrets that something else
manages, such as External Secrets Operator syncing from Vault or 1Password.

The controller watches Secrets labelled `openshell.nvidia.com/provider-sync=true`.
Each Secret names one provider and the credential keys it backs:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: github-triage-credentials
  labels:
    openshell.nvidia.com/provider-sync: "true"
  annotations:
    openshell.nvidia.com/provider: github-triage
    openshell.nvidia.com/provider-workspace: oncall   # optional
    openshell.nvidia.com/provider-credentials: GITHUB_TOKEN, LINEAR_API_KEY=linear-key
```

An entry is `CREDENTIAL_KEY`, read from the Secret key of the same name, or
`CREDENTIAL_KEY=secret-key`. Only listed keys are read, so a key added to the
Secret later never becomes a credential by accident.

## Behavior

- **What it sends.** When a mapped value changes, the controller sends only the
  changed keys as a value-only `UpdateProvider`. The gateway merges them into the
  provider, and attached sandboxes refetch on their next provider poll, every 10s
  by default.
- **Running processes.** A process that is already running gets the new value
  only when the credential's profile sets `stable_placeholder: true`. Without it,
  only processes started after the update see the new value.
- **What it leaves alone.** It never creates or deletes providers, and never
  clears a credential when its Secret is deleted or unlabelled. Providers are
  still created by whatever creates them today.
- **All or nothing per Secret.** If any mapped key is missing, empty or not
  UTF-8, nothing from that Secret is sent, so a half-written Secret cannot
  produce a partial rotation.
- **One Secret per credential.** A second live Secret that maps the same
  workspace, provider and credential key is refused with a
  `ProviderSyncConflict` event.
- **Restarts.** State is in memory: a salted fingerprint of each value sent,
  never the value. After a restart every Secret is sent once more. That is a
  value-only update and does not disturb running sandboxes.
- **Retries.**
  - A missing provider is retried every 30s.
  - Transient gateway failures are retried every 10s.
  - Invalid annotations, conflicts and rejected updates are retried every 5m, or
    as soon as the Secret changes.
- **Audit.** Each outcome is published as a Kubernetes Event on the Secret
  (`ProviderSynced`, `ProviderNotFound`, `ProviderSyncConflict`,
  `InvalidProviderSync`, `ProviderSyncFailed`). The gateway separately audits
  each `UpdateProvider` with the controller's principal. Neither carries values.

## Running

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
| `--gateway-token-file` | `OPENSHELL_GATEWAY_TOKEN_FILE` | Bearer token, re-read when the gateway rejects it |
| `--namespace` | `OPENSHELL_PROVIDER_SYNC_NAMESPACE` | Namespace to watch; all namespaces when omitted |
| `--default-workspace` | `OPENSHELL_PROVIDER_SYNC_DEFAULT_WORKSPACE` | Workspace when a Secret has no workspace annotation |
| `--reporter`, `--reporter-instance` | `OPENSHELL_PROVIDER_SYNC_REPORTER`, `POD_NAME` | Event reporter |
| `--no-events` | | Disable Kubernetes Events |

The principal needs `provider:write` with the workspace `admin` role. The
ServiceAccount needs `get`, `list` and `watch` on Secrets in the watched
namespace, and `create` and `patch` on `events.k8s.io` Events.

The gateway client is the Rust SDK, which speaks bearer-token auth only. A
gateway that requires mTLS client certificates is not supported yet.

## Limits

- **One replica.** There is no leader election. Two replicas would send the same
  idempotent updates twice; that is wasteful but not wrong.
- **No activation wait.** The controller does not wait for supervisors to report
  that they activated the update. The gateway's mutation id is logged for
  correlation.
