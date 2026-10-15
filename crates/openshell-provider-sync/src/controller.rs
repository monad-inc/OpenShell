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
use crate::mapping::{self, Extracted, MappingError};
use crate::state::{Conflict, SecretRef, SyncState};

/// How long to wait before retrying a provider that does not exist yet.
const PROVIDER_MISSING_RETRY: Duration = Duration::from_secs(30);
/// How long to wait before retrying a transient gateway failure.
const TRANSIENT_RETRY: Duration = Duration::from_secs(10);
/// How long to wait before retrying a Secret that can only succeed once it,
/// the provider or the gateway's configuration changes.
const INVALID_RETRY: Duration = Duration::from_mins(5);

/// The result of syncing one provider.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Values pushed; `keys` lists the credential keys that changed.
    Updated {
        keys: Vec<String>,
        mutation_id: String,
    },
    /// Nothing changed since the last push.
    Unchanged,
    /// The Secret holds none of this provider's keys, so nothing was sent.
    Absent { keys: Vec<String> },
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

/// What happened to each provider a Secret feeds.
#[derive(Debug)]
pub struct SyncReport {
    pub workspace: String,
    /// In provider-name order. Each provider succeeds or fails on its own.
    pub providers: Vec<(String, Result<Outcome, SyncError>)>,
}

impl SyncReport {
    /// When to look at the Secret again: the soonest retry of any failed
    /// provider, or `None` when every provider succeeded.
    fn retry_after(&self) -> Option<Duration> {
        self.providers
            .iter()
            .filter_map(|(_, result)| result.as_ref().err().map(SyncError::retry_after))
            .min()
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

    /// Sync one Secret: parse its annotations, then for each provider read
    /// the mapped keys and push the ones that changed.
    ///
    /// Fails only when the annotations are invalid. A provider that fails is
    /// reported in the [`SyncReport`] and does not hold back the others.
    ///
    /// `owner_exists` reports whether another Secret holding a claim still
    /// exists; see [`SyncState::claim`].
    pub async fn sync(
        &self,
        secret_ref: &SecretRef,
        secret: &Secret,
        owner_exists: impl Fn(&SecretRef) -> bool + Sync,
    ) -> Result<SyncReport, MappingError> {
        let target = match mapping::parse_target(secret.annotations(), &self.default_workspace) {
            Ok(target) => target,
            Err(err) => {
                // An invalid Secret holds no claims, so fixing a sibling is
                // not blocked by it.
                self.state.lock().await.forget(secret_ref);
                return Err(err);
            }
        };

        // The lock is held across the gateway calls. Updates are rare and
        // small, and holding it keeps two Secrets from racing on a claim.
        let mut state = self.state.lock().await;
        state.retain(secret_ref, &target);
        let mut providers = Vec::with_capacity(target.providers.len());
        for (provider, keys) in &target.providers {
            let result: Result<Outcome, SyncError> = async {
                state.claim(secret_ref, &target.workspace, provider, keys, &owner_exists)?;
                let values = match mapping::extract_values(keys, secret.data.as_ref())? {
                    Extracted::Present(values) => values,
                    Extracted::Absent => {
                        state.clear_applied(secret_ref, provider);
                        return Ok(Outcome::Absent {
                            keys: keys.keys().cloned().collect(),
                        });
                    }
                };
                let changed = state.changed(secret_ref, &target.workspace, provider, &values);
                if changed.is_empty() {
                    return Ok(Outcome::Unchanged);
                }
                let mutation_id = self
                    .updater
                    .update_credentials(&target.workspace, provider, &changed)
                    .await?;
                state.commit(secret_ref, &target.workspace, provider, &values);
                Ok(Outcome::Updated {
                    keys: changed.keys().cloned().collect(),
                    mutation_id,
                })
            }
            .await;
            providers.push((provider.clone(), result));
        }
        Ok(SyncReport {
            workspace: target.workspace,
            providers,
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
    let report = match runtime
        .ctx
        .sync(&secret_ref, &secret, |owner| is_live(&runtime.store, owner))
        .await
    {
        Ok(report) => report,
        Err(err) => {
            let err = SyncError::from(err);
            warn!(secret = %secret_ref, error = %err, "provider sync failed");
            publish(
                &runtime,
                &secret,
                EventType::Warning,
                err.reason(),
                err.to_string(),
            )
            .await;
            return Err(err);
        }
    };
    let workspace = &report.workspace;
    for (provider, result) in &report.providers {
        match result {
            Ok(Outcome::Updated { keys, mutation_id }) => {
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
            Ok(Outcome::Unchanged) => {
                debug!(secret = %secret_ref, workspace, provider, "provider credentials unchanged");
            }
            Ok(Outcome::Absent { keys }) => {
                debug!(
                    secret = %secret_ref,
                    workspace,
                    provider,
                    keys = ?keys,
                    "Secret holds none of the provider's keys"
                );
                let note = format!(
                    "Skipped provider {workspace}/{provider}: Secret has no value for {}",
                    keys.join(", ")
                );
                publish(
                    &runtime,
                    &secret,
                    EventType::Normal,
                    "ProviderSyncSkipped",
                    note,
                )
                .await;
            }
            Err(err) => {
                warn!(
                    secret = %secret_ref,
                    workspace,
                    provider,
                    error = %err,
                    "provider sync failed"
                );
                let note = format!("Provider {workspace}/{provider}: {err}");
                publish(&runtime, &secret, EventType::Warning, err.reason(), note).await;
            }
        }
    }
    Ok(report
        .retry_after()
        .map_or_else(Action::await_change, Action::requeue))
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
///
/// The watch starts with a full list, so every labelled Secret is synced once
/// at startup, not only when it next changes.
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

    /// Fails updates for the named provider, or for every provider when the
    /// name is `None`.
    type FailRule = (Option<&'static str>, fn() -> UpdateError);

    #[derive(Default)]
    struct FakeUpdater {
        calls: StdMutex<Vec<UpdateCall>>,
        fail_with: StdMutex<Option<FailRule>>,
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
            if let Some((only, fail)) = fail_with
                && only.is_none_or(|only| only == provider)
            {
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

    /// An agent Secret feeding three providers, with two alternative Claude
    /// credentials of which only one is set.
    fn agent(data: &[(&str, &str)]) -> (SecretRef, Secret) {
        secret(
            "pm",
            &[
                (WORKSPACE_ANNOTATION, "pm"),
                (
                    CREDENTIALS_ANNOTATION,
                    "slack-pm:SLACK_BOT_TOKEN, slack-pm:SLACK_APP_TOKEN, linear:LINEAR_API_KEY,\
                     claude-code-apikey:ANTHROPIC_API_KEY, claude-code-oauth:CLAUDE_CODE_OAUTH_TOKEN",
                ),
            ],
            data,
        )
    }

    fn outcome<'a>(report: &'a SyncReport, provider: &str) -> &'a Result<Outcome, SyncError> {
        &report
            .providers
            .iter()
            .find(|(name, _)| name == provider)
            .unwrap()
            .1
    }

    #[tokio::test]
    async fn pushes_on_first_sight_and_on_change_only() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");

        let (r, s) = github("v1");
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert!(
            matches!(outcome(&report, "github"), Ok(Outcome::Updated { keys, .. }) if keys == &["GITHUB_TOKEN"])
        );
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert!(matches!(outcome(&report, "github"), Ok(Outcome::Unchanged)));
        assert_eq!(report.retry_after(), None);

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
    async fn one_secret_updates_each_provider_with_its_own_keys() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");
        let (r, s) = agent(&[
            ("SLACK_BOT_TOKEN", "bot"),
            ("SLACK_APP_TOKEN", "app"),
            ("LINEAR_API_KEY", "lin"),
            ("ANTHROPIC_API_KEY", "ant"),
            // Unused keys are written empty, which counts as absent.
            ("CLAUDE_CODE_OAUTH_TOKEN", ""),
        ]);
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert_eq!(report.workspace, "pm");
        assert!(matches!(
            outcome(&report, "claude-code-oauth"),
            Ok(Outcome::Absent { .. })
        ));
        assert_eq!(report.retry_after(), None);

        let mut calls = updater.calls.lock().unwrap().clone();
        calls.sort();
        let providers: Vec<(&str, Vec<&str>)> = calls
            .iter()
            .map(|(_, provider, values)| {
                (
                    provider.as_str(),
                    values.keys().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            providers,
            [
                ("claude-code-apikey", vec!["ANTHROPIC_API_KEY"]),
                ("linear", vec!["LINEAR_API_KEY"]),
                ("slack-pm", vec!["SLACK_APP_TOKEN", "SLACK_BOT_TOKEN"]),
            ]
        );
        assert!(calls.iter().all(|(workspace, _, _)| workspace == "pm"));
    }

    #[tokio::test]
    async fn rotating_one_key_touches_only_its_provider() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");
        let base = [
            ("SLACK_BOT_TOKEN", "bot"),
            ("SLACK_APP_TOKEN", "app"),
            ("LINEAR_API_KEY", "lin"),
            ("ANTHROPIC_API_KEY", "ant"),
        ];
        let (r, s) = agent(&base);
        ctx.sync(&r, &s, |_| true).await.unwrap();
        updater.calls.lock().unwrap().clear();

        let mut rotated = base;
        rotated[0] = ("SLACK_BOT_TOKEN", "bot-2");
        let (r, s) = agent(&rotated);
        ctx.sync(&r, &s, |_| true).await.unwrap();
        let calls = updater.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, "slack-pm");
        assert_eq!(
            calls[0].2,
            BTreeMap::from([("SLACK_BOT_TOKEN".to_string(), "bot-2".to_string())])
        );
    }

    #[tokio::test]
    async fn a_failing_provider_does_not_hold_back_the_others() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");
        *updater.fail_with.lock().unwrap() =
            Some((Some("linear"), || UpdateError::ProviderNotFound {
                workspace: "pm".to_string(),
                provider: "linear".to_string(),
            }));
        // Slack is half-written; Linear does not exist yet; Claude is fine.
        let (r, s) = agent(&[
            ("SLACK_BOT_TOKEN", "bot"),
            ("LINEAR_API_KEY", "lin"),
            ("ANTHROPIC_API_KEY", "ant"),
        ]);
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert!(matches!(
            outcome(&report, "slack-pm"),
            Err(SyncError::Mapping(MappingError::MissingSecretKey { .. }))
        ));
        assert!(matches!(
            outcome(&report, "linear"),
            Err(SyncError::Update(UpdateError::ProviderNotFound { .. }))
        ));
        assert!(matches!(
            outcome(&report, "claude-code-apikey"),
            Ok(Outcome::Updated { .. })
        ));
        assert_eq!(report.retry_after(), Some(PROVIDER_MISSING_RETRY));

        let calls = updater.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, "claude-code-apikey");
    }

    #[tokio::test]
    async fn switching_alternative_credentials_pushes_the_new_one() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");
        let (r, s) = agent(&[("ANTHROPIC_API_KEY", "ant")]);
        ctx.sync(&r, &s, |_| true).await.unwrap();
        let (r, s) = agent(&[("CLAUDE_CODE_OAUTH_TOKEN", "oauth")]);
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert!(matches!(
            outcome(&report, "claude-code-apikey"),
            Ok(Outcome::Absent { .. })
        ));
        assert!(matches!(
            outcome(&report, "claude-code-oauth"),
            Ok(Outcome::Updated { .. })
        ));
        // Switching back resends the API key, even with the same value.
        let (r, s) = agent(&[("ANTHROPIC_API_KEY", "ant")]);
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert!(matches!(
            outcome(&report, "claude-code-apikey"),
            Ok(Outcome::Updated { .. })
        ));
    }

    #[tokio::test]
    async fn failed_update_is_retried_with_the_same_values() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");
        let (r, s) = github("v1");

        *updater.fail_with.lock().unwrap() =
            Some((None, || UpdateError::Transient("unavailable".to_string())));
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert_eq!(report.retry_after(), Some(TRANSIENT_RETRY));

        *updater.fail_with.lock().unwrap() = None;
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert!(matches!(
            outcome(&report, "github"),
            Ok(Outcome::Updated { .. })
        ));
    }

    #[tokio::test]
    async fn missing_provider_retries_sooner_than_invalid_secret() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");
        *updater.fail_with.lock().unwrap() = Some((None, || UpdateError::ProviderNotFound {
            workspace: "w".to_string(),
            provider: "p".to_string(),
        }));
        let (r, s) = github("v1");
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        let err = outcome(&report, "github").as_ref().unwrap_err();
        assert_eq!(err.retry_after(), PROVIDER_MISSING_RETRY);
        assert_eq!(err.reason(), "ProviderNotFound");

        let (r, s) = secret("bad", &[(PROVIDER_ANNOTATION, "p")], &[]);
        let err = SyncError::from(ctx.sync(&r, &s, |_| true).await.unwrap_err());
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
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert!(matches!(
            outcome(&report, "p"),
            Err(SyncError::Mapping(MappingError::MissingSecretKey { .. }))
        ));
        assert_eq!(report.retry_after(), Some(INVALID_RETRY));
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
        let report = ctx.sync(&r2, &s2, |_| true).await.unwrap();
        assert!(matches!(
            outcome(&report, "github"),
            Err(SyncError::Conflict(_))
        ));
        assert_eq!(updater.calls.lock().unwrap().len(), 1);
    }
}
