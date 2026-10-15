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

use crate::gateway::{ProviderUpdater, Restart, SandboxRestarter, UpdateError};
use crate::mapping::{self, Extracted, MappingError};
use crate::state::{Conflict, SecretRef, SyncState};
use crate::state_store::StateStore;

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
        /// Sandboxes attached to the provider whose agents must restart to
        /// pick up the new values. Empty for a baseline: values this
        /// controller had not applied before, such as at first sight.
        restart: Vec<String>,
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

impl SyncReport {
    /// Every sandbox to restart, once each even when several of its
    /// providers rotated.
    pub fn sandboxes_to_restart(&self) -> Vec<String> {
        let mut sandboxes: Vec<String> = self
            .providers
            .iter()
            .filter_map(|(_, result)| match result {
                Ok(Outcome::Updated { restart, .. }) => Some(restart.iter().cloned()),
                _ => None,
            })
            .flatten()
            .collect();
        sandboxes.sort();
        sandboxes.dedup();
        sandboxes
    }
}

/// Shared by every reconcile.
pub struct Context {
    updater: Arc<dyn ProviderUpdater>,
    restarter: Option<Arc<dyn SandboxRestarter>>,
    state: Mutex<SyncState>,
    store: Option<Arc<dyn StateStore>>,
    default_workspace: String,
}

impl Context {
    pub fn new(updater: Arc<dyn ProviderUpdater>, default_workspace: impl Into<String>) -> Self {
        Self {
            updater,
            restarter: None,
            state: Mutex::new(SyncState::new()),
            store: None,
            default_workspace: default_workspace.into(),
        }
    }

    /// Restart the agents attached to a provider whose values rotated.
    #[must_use]
    pub fn with_restarter(mut self, restarter: Arc<dyn SandboxRestarter>) -> Self {
        self.restarter = Some(restarter);
        self
    }

    /// Resume from persisted state and keep it current, so a restart of this
    /// controller does not mistake values it already applied for rotations.
    #[must_use]
    pub fn with_state(mut self, state: SyncState, store: Arc<dyn StateStore>) -> Self {
        self.state = Mutex::new(state);
        self.store = Some(store);
        self
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
                let rotation = state.has_applied(secret_ref, &target.workspace, provider);
                let updated = self
                    .updater
                    .update_credentials(&target.workspace, provider, &changed)
                    .await?;
                state.commit(secret_ref, &target.workspace, provider, &values);
                Ok(Outcome::Updated {
                    keys: changed.keys().cloned().collect(),
                    mutation_id: updated.mutation_id,
                    restart: if rotation {
                        updated.sandboxes
                    } else {
                        Vec::new()
                    },
                })
            }
            .await;
            providers.push((provider.clone(), result));
        }
        if let Some(store) = &self.store
            && providers
                .iter()
                .any(|(_, result)| matches!(result, Ok(Outcome::Updated { .. })))
            && let Err(err) = store.save(&state.to_persisted()).await
        {
            // In-memory state is still right. The cost of a lost save is one
            // extra restart of these agents after this controller restarts.
            warn!(error = %err, "failed to persist provider sync state");
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
            Ok(Outcome::Updated {
                keys,
                mutation_id,
                restart,
            }) => {
                info!(
                    secret = %secret_ref,
                    workspace,
                    provider,
                    keys = ?keys,
                    mutation_id,
                    restart = ?restart,
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
    if let Some(restarter) = &runtime.ctx.restarter {
        for sandbox in report.sandboxes_to_restart() {
            tokio::spawn(restart_sandbox(
                Arc::clone(restarter),
                Arc::clone(&runtime),
                Arc::clone(&secret),
                report.workspace.clone(),
                sandbox,
            ));
        }
    }
    Ok(report
        .retry_after()
        .map_or_else(Action::await_change, Action::requeue))
}

/// Restart one agent so it starts fresh with the rotated values. Runs apart
/// from the reconcile: a restart waits for the sandbox to stop and start.
async fn restart_sandbox(
    restarter: Arc<dyn SandboxRestarter>,
    runtime: Arc<Runtime>,
    secret: Arc<Secret>,
    workspace: String,
    sandbox: String,
) {
    let secret_ref = secret_ref(&secret);
    match restarter.restart(&workspace, &sandbox).await {
        Ok(Restart::Restarted) => {
            info!(secret = %secret_ref, workspace, sandbox, "restarted agent after credential rotation");
            let note =
                format!("Restarted sandbox {workspace}/{sandbox} after its credentials rotated");
            publish(&runtime, &secret, EventType::Normal, "AgentRestarted", note).await;
        }
        Ok(Restart::Skipped { phase }) => {
            info!(secret = %secret_ref, workspace, sandbox, phase, "agent not running; left alone");
            let note = format!("Did not restart sandbox {workspace}/{sandbox}: it is {phase}");
            publish(
                &runtime,
                &secret,
                EventType::Normal,
                "AgentRestartSkipped",
                note,
            )
            .await;
        }
        Err(err) => {
            warn!(secret = %secret_ref, workspace, sandbox, error = %err, "agent restart failed");
            let note = format!("Restarting sandbox {workspace}/{sandbox} failed: {err}");
            publish(
                &runtime,
                &secret,
                EventType::Warning,
                "AgentRestartFailed",
                note,
            )
            .await;
        }
    }
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
        /// Sandboxes every provider reports attached; `<provider>-agent`
        /// when unset.
        attached: StdMutex<Option<Vec<String>>>,
    }

    #[derive(Default)]
    struct MemoryStore(StdMutex<Option<crate::state::PersistedState>>);

    #[async_trait::async_trait]
    impl StateStore for MemoryStore {
        async fn load(&self) -> Result<Option<crate::state::PersistedState>, String> {
            Ok(self.0.lock().unwrap().clone())
        }
        async fn save(&self, state: &crate::state::PersistedState) -> Result<(), String> {
            *self.0.lock().unwrap() = Some(state.clone());
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl ProviderUpdater for FakeUpdater {
        async fn update_credentials(
            &self,
            workspace: &str,
            provider: &str,
            values: &CredentialValues,
        ) -> Result<crate::gateway::Updated, UpdateError> {
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
            let sandboxes = self
                .attached
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| vec![format!("{provider}-agent")]);
            Ok(crate::gateway::Updated {
                mutation_id: "mutation-1".to_string(),
                sandboxes,
            })
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

    const PM_CREDENTIALS: [(&str, &str); 4] = [
        ("SLACK_BOT_TOKEN", "bot"),
        ("SLACK_APP_TOKEN", "app"),
        ("LINEAR_API_KEY", "lin"),
        ("ANTHROPIC_API_KEY", "ant"),
    ];

    fn with(
        base: [(&'static str, &'static str); 4],
        key: &str,
        value: &'static str,
    ) -> [(&'static str, &'static str); 4] {
        base.map(|(name, current)| {
            if name == key {
                (name, value)
            } else {
                (name, current)
            }
        })
    }

    #[tokio::test]
    async fn a_rotation_restarts_only_the_agents_attached_to_its_provider() {
        let updater = Arc::new(FakeUpdater::default());
        let ctx = Context::new(updater.clone(), "default");
        let (r, s) = agent(&PM_CREDENTIALS);
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert!(
            report.sandboxes_to_restart().is_empty(),
            "first sight is a baseline, not a rotation"
        );

        let (r, s) = agent(&with(PM_CREDENTIALS, "SLACK_BOT_TOKEN", "bot-2"));
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert_eq!(report.sandboxes_to_restart(), ["slack-pm-agent"]);
        assert!(matches!(
            outcome(&report, "slack-pm"),
            Ok(Outcome::Updated { restart, .. }) if restart == &["slack-pm-agent"]
        ));
        assert!(matches!(outcome(&report, "linear"), Ok(Outcome::Unchanged)));

        // Unchanged values restart nothing.
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert!(report.sandboxes_to_restart().is_empty());
    }

    #[tokio::test]
    async fn an_agent_restarts_once_when_several_of_its_providers_rotate() {
        let updater = Arc::new(FakeUpdater::default());
        *updater.attached.lock().unwrap() = Some(vec!["pm".to_string()]);
        let ctx = Context::new(updater.clone(), "default");
        let (r, s) = agent(&PM_CREDENTIALS);
        ctx.sync(&r, &s, |_| true).await.unwrap();

        let rotated = with(
            with(PM_CREDENTIALS, "SLACK_BOT_TOKEN", "bot-2"),
            "LINEAR_API_KEY",
            "lin-2",
        );
        let (r, s) = agent(&rotated);
        let report = ctx.sync(&r, &s, |_| true).await.unwrap();
        assert_eq!(report.sandboxes_to_restart(), ["pm"]);
    }

    #[tokio::test]
    async fn persisted_state_keeps_a_controller_restart_from_restarting_agents() {
        let store = Arc::new(MemoryStore::default());
        let updater = Arc::new(FakeUpdater::default());
        let first =
            Context::new(updater.clone(), "default").with_state(SyncState::new(), store.clone());
        let (r, s) = agent(&PM_CREDENTIALS);
        first.sync(&r, &s, |_| true).await.unwrap();
        updater.calls.lock().unwrap().clear();

        // A new controller process resumes from the saved fingerprints.
        let persisted = store.load().await.unwrap().expect("state saved");
        let second = Context::new(updater.clone(), "default")
            .with_state(SyncState::from_persisted(persisted), store.clone());
        let report = second.sync(&r, &s, |_| true).await.unwrap();
        assert!(report.sandboxes_to_restart().is_empty());
        assert!(
            updater.calls.lock().unwrap().is_empty(),
            "nothing re-pushed"
        );

        let (r, s) = agent(&with(PM_CREDENTIALS, "LINEAR_API_KEY", "lin-2"));
        let report = second.sync(&r, &s, |_| true).await.unwrap();
        assert_eq!(report.sandboxes_to_restart(), ["linear-agent"]);
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
