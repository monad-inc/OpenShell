// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Watches labelled Secrets and pushes changed values to their providers.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::runtime::controller::{Action, Controller};
use kube::runtime::events::{Event, EventType, Recorder, Reporter};
use kube::runtime::reflector::{ObjectRef, Store};
use kube::runtime::watcher;
use kube::{Api, Client, Resource, ResourceExt};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::gateway::{ProviderUpdater, UpdateError};
use crate::mapping::{self, MappingError};
use crate::state::{Conflict, SecretRef, SyncState};

/// How long to wait before retrying a provider that does not exist yet.
const PROVIDER_MISSING_RETRY: Duration = Duration::from_secs(30);
/// How long to wait before retrying a transient gateway failure.
const TRANSIENT_RETRY: Duration = Duration::from_secs(10);
/// How long to wait before retrying a Secret that can only succeed once it,
/// the provider or the gateway's configuration changes.
const INVALID_RETRY: Duration = Duration::from_mins(5);

/// The result of one sync, for logging and events.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Values pushed; `keys` lists the credential keys that changed.
    Updated {
        workspace: String,
        provider: String,
        keys: Vec<String>,
        mutation_id: String,
    },
    /// Nothing changed since the last push.
    Unchanged,
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Mapping(#[from] MappingError),
    #[error(transparent)]
    Conflict(#[from] Conflict),
    #[error(transparent)]
    Update(#[from] UpdateError),
}

impl SyncError {
    fn retry_after(&self) -> Duration {
        match self {
            Self::Update(UpdateError::ProviderNotFound { .. }) => PROVIDER_MISSING_RETRY,
            Self::Update(UpdateError::Transient(_)) => TRANSIENT_RETRY,
            Self::Mapping(_) | Self::Conflict(_) | Self::Update(UpdateError::Rejected(_)) => {
                INVALID_RETRY
            }
        }
    }

    fn reason(&self) -> &'static str {
        match self {
            Self::Mapping(_) => "InvalidProviderSync",
            Self::Conflict(_) => "ProviderSyncConflict",
            Self::Update(UpdateError::ProviderNotFound { .. }) => "ProviderNotFound",
            Self::Update(_) => "ProviderSyncFailed",
        }
    }
}

/// Shared by every reconcile.
pub struct Context {
    updater: Arc<dyn ProviderUpdater>,
    state: Mutex<SyncState>,
    default_workspace: String,
}

impl Context {
    pub fn new(updater: Arc<dyn ProviderUpdater>, default_workspace: impl Into<String>) -> Self {
        Self {
            updater,
            state: Mutex::new(SyncState::new()),
            default_workspace: default_workspace.into(),
        }
    }

    /// Sync one Secret: parse its annotations, read the mapped keys, and push
    /// the ones that changed.
    ///
    /// `owner_exists` reports whether another Secret holding a claim still
    /// exists; see [`SyncState::plan`].
    pub async fn sync(
        &self,
        secret_ref: &SecretRef,
        secret: &Secret,
        owner_exists: impl Fn(&SecretRef) -> bool,
    ) -> Result<Outcome, SyncError> {
        let target = match mapping::parse_target(secret.annotations(), &self.default_workspace) {
            Ok(target) => target,
            Err(err) => {
                // An invalid Secret holds no claims, so fixing a sibling is
                // not blocked by it.
                self.state.lock().await.forget(secret_ref);
                return Err(err.into());
            }
        };
        let values = mapping::extract_values(&target, secret.data.as_ref())?;

        // The lock is held across the gateway call. Updates are rare and
        // small, and holding it keeps two Secrets from racing on a claim.
        let mut state = self.state.lock().await;
        let plan = state.plan(secret_ref, &target, &values, owner_exists)?;
        if plan.changed.is_empty() {
            return Ok(Outcome::Unchanged);
        }
        let mutation_id = self
            .updater
            .update_credentials(&target.workspace, &target.provider, &plan.changed)
            .await?;
        state.commit(secret_ref, &target, &values);
        Ok(Outcome::Updated {
            workspace: target.workspace,
            provider: target.provider,
            keys: plan.changed.keys().cloned().collect(),
            mutation_id,
        })
    }

    async fn forget(&self, secret_ref: &SecretRef) {
        self.state.lock().await.forget(secret_ref);
    }
}

struct Runtime {
    ctx: Context,
    store: Store<Secret>,
    recorder: Option<Recorder>,
}

fn secret_ref(secret: &Secret) -> SecretRef {
    SecretRef {
        namespace: secret.namespace().unwrap_or_default(),
        name: secret.name_any(),
    }
}

fn is_live(store: &Store<Secret>, secret: &SecretRef) -> bool {
    store
        .get(&ObjectRef::new(&secret.name).within(&secret.namespace))
        .is_some_and(|secret| secret.meta().deletion_timestamp.is_none())
}

async fn reconcile(secret: Arc<Secret>, runtime: Arc<Runtime>) -> Result<Action, SyncError> {
    let secret_ref = secret_ref(&secret);
    if secret.meta().deletion_timestamp.is_some() {
        runtime.ctx.forget(&secret_ref).await;
        return Ok(Action::await_change());
    }
    let result = runtime
        .ctx
        .sync(&secret_ref, &secret, |owner| is_live(&runtime.store, owner))
        .await;
    match &result {
        Ok(Outcome::Updated {
            workspace,
            provider,
            keys,
            mutation_id,
        }) => {
            info!(
                secret = %secret_ref,
                workspace,
                provider,
                keys = ?keys,
                mutation_id,
                "provider credentials updated from Secret"
            );
            let note = format!(
                "Updated {} on provider {workspace}/{provider}",
                keys.join(", ")
            );
            publish(&runtime, &secret, EventType::Normal, "ProviderSynced", note).await;
        }
        Ok(Outcome::Unchanged) => debug!(secret = %secret_ref, "provider credentials unchanged"),
        Err(err) => {
            warn!(secret = %secret_ref, error = %err, "provider sync failed");
            publish(
                &runtime,
                &secret,
                EventType::Warning,
                err.reason(),
                err.to_string(),
            )
            .await;
        }
    }
    result.map(|_| Action::await_change())
}

fn error_policy(_secret: Arc<Secret>, err: &SyncError, _runtime: Arc<Runtime>) -> Action {
    Action::requeue(err.retry_after())
}

async fn publish(runtime: &Runtime, secret: &Secret, type_: EventType, reason: &str, note: String) {
    let Some(recorder) = &runtime.recorder else {
        return;
    };
    let event = Event {
        type_,
        reason: reason.to_string(),
        note: Some(note),
        action: "UpdateProviderCredentials".to_string(),
        secondary: None,
    };
    if let Err(err) = recorder.publish(&event, &secret.object_ref(&())).await {
        debug!(error = %err, "failed to publish Kubernetes event");
    }
}

/// Options for [`run`].
pub struct Options {
    /// Watch one namespace, or every namespace when `None`.
    pub namespace: Option<String>,
    /// Reporter for Kubernetes Events on the Secret; `None` disables them.
    pub reporter: Option<Reporter>,
}

/// Run until the watch stream ends or the process receives a shutdown signal.
pub async fn run(client: Client, ctx: Context, options: Options) {
    let api: Api<Secret> = options.namespace.as_ref().map_or_else(
        || Api::all(client.clone()),
        |namespace| Api::namespaced(client.clone(), namespace),
    );
    let controller = Controller::new(
        api,
        watcher::Config::default().labels(&mapping::label_selector()),
    );
    let runtime = Arc::new(Runtime {
        ctx,
        store: controller.store(),
        recorder: options
            .reporter
            .map(|reporter| Recorder::new(client, reporter)),
    });
    controller
        .shutdown_on_signal()
        .run(reconcile, error_policy, runtime)
        .for_each(|result| async move {
            if let Err(err) = result {
                debug!(error = %err, "reconcile did not complete");
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::{
        CREDENTIALS_ANNOTATION, CredentialValues, PROVIDER_ANNOTATION, WORKSPACE_ANNOTATION,
    };
    use k8s_openapi::ByteString;
    use kube::api::ObjectMeta;
    use std::collections::BTreeMap;
    use std::sync::Mutex as StdMutex;

    /// Workspace, provider and values of one update.
    type UpdateCall = (String, String, BTreeMap<String, String>);

    #[derive(Default)]
    struct FakeUpdater {
        calls: StdMutex<Vec<UpdateCall>>,
        fail_with: StdMutex<Option<fn() -> UpdateError>>,
    }

    #[async_trait::async_trait]
    impl ProviderUpdater for FakeUpdater {
        async fn update_credentials(
            &self,
            workspace: &str,
            provider: &str,
            values: &CredentialValues,
        ) -> Result<String, UpdateError> {
            let fail_with = *self.fail_with.lock().unwrap();
            if let Some(fail) = fail_with {
                return Err(fail());
            }
            self.calls.lock().unwrap().push((
                workspace.to_string(),
                provider.to_string(),
                values.0.clone(),
            ));
            Ok("mutation-1".to_string())
        }
    }

    fn secret(
        name: &str,
        annotations: &[(&str, &str)],
        data: &[(&str, &str)],
    ) -> (SecretRef, Secret) {
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("agents".to_string()),
                annotations: Some(
                    annotations
                        .iter()
                        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                        .collect(),
                ),
                ..Default::default()
            },
            data: Some(
                data.iter()
                    .map(|(k, v)| ((*k).to_string(), ByteString(v.as_bytes().to_vec())))
                    .collect(),
            ),
            ..Default::default()
        };
        (secret_ref(&secret), secret)
    }

    fn github(token: &str) -> (SecretRef, Secret) {
        secret(
            "github-creds",
            &[
                (PROVIDER_ANNOTATION, "github"),
                (WORKSPACE_ANNOTATION, "oncall"),
                (CREDENTIALS_ANNOTATION, "GITHUB_TOKEN=token"),
            ],
            &[("token", token), ("unrelated", "x")],
        )
    }

    #[tokio::test]
    async fn pushes_on_first_sight_and_on_change_only() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");

        let (r, s) = github("v1");
        let outcome = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert!(matches!(outcome, Outcome::Updated { ref keys, .. } if keys == &["GITHUB_TOKEN"]));
        assert_eq!(
            ctx.sync(&r, &s, |_| true).await.unwrap(),
            Outcome::Unchanged
        );

        let (r, s) = github("v2");
        ctx.sync(&r, &s, |_| true).await.unwrap();

        let calls = updater.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, "oncall");
        assert_eq!(calls[1].1, "github");
        assert_eq!(
            calls[1].2,
            BTreeMap::from([("GITHUB_TOKEN".to_string(), "v2".to_string())])
        );
    }

    #[tokio::test]
    async fn failed_update_is_retried_with_the_same_values() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");
        let (r, s) = github("v1");

        *updater.fail_with.lock().unwrap() =
            Some(|| UpdateError::Transient("unavailable".to_string()));
        let err = ctx.sync(&r, &s, |_| true).await.unwrap_err();
        assert_eq!(err.retry_after(), TRANSIENT_RETRY);

        *updater.fail_with.lock().unwrap() = None;
        assert!(matches!(
            ctx.sync(&r, &s, |_| true).await.unwrap(),
            Outcome::Updated { .. }
        ));
    }

    #[tokio::test]
    async fn missing_provider_retries_sooner_than_invalid_secret() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");
        *updater.fail_with.lock().unwrap() = Some(|| UpdateError::ProviderNotFound {
            workspace: "w".to_string(),
            provider: "p".to_string(),
        });
        let (r, s) = github("v1");
        let err = ctx.sync(&r, &s, |_| true).await.unwrap_err();
        assert_eq!(err.retry_after(), PROVIDER_MISSING_RETRY);
        assert_eq!(err.reason(), "ProviderNotFound");

        let (r, s) = secret("bad", &[(PROVIDER_ANNOTATION, "p")], &[]);
        let err = ctx.sync(&r, &s, |_| true).await.unwrap_err();
        assert_eq!(err.retry_after(), INVALID_RETRY);
        assert_eq!(err.reason(), "InvalidProviderSync");
    }

    #[tokio::test]
    async fn half_written_secret_pushes_nothing() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");
        let (r, s) = secret(
            "two-keys",
            &[
                (PROVIDER_ANNOTATION, "p"),
                (CREDENTIALS_ANNOTATION, "A=a,B=b"),
            ],
            &[("a", "1")],
        );
        assert!(matches!(
            ctx.sync(&r, &s, |_| true).await,
            Err(SyncError::Mapping(MappingError::MissingSecretKey { .. }))
        ));
        assert!(updater.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn second_secret_for_the_same_credential_is_refused() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");
        let (r1, s1) = github("v1");
        ctx.sync(&r1, &s1, |_| true).await.unwrap();

        let (r2, mut s2) = github("v2");
        s2.metadata.name = Some("github-creds-copy".to_string());
        let r2 = SecretRef {
            name: "github-creds-copy".to_string(),
            ..r2
        };
        assert!(matches!(
            ctx.sync(&r2, &s2, |_| true).await,
            Err(SyncError::Conflict(_))
        ));
        assert_eq!(updater.calls.lock().unwrap().len(), 1);
    }
}
