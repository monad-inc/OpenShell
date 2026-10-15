// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell-provider-sync`: sync provider credentials from Kubernetes Secrets.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use kube::runtime::events::{Event, EventType, Recorder, Reporter};
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_provider_sync::controller::{self, Context, Options};
use openshell_provider_sync::gateway::{GatewayRestarter, GatewayUpdater, TokenFile};
use openshell_provider_sync::state::{PersistedState, SyncState};
use openshell_provider_sync::state_store::{LoadError, SecretStateStore};
use openshell_sdk::{AuthConfig, ClientConfig, OpenShellClient};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "openshell-provider-sync",
    about = "Sync OpenShell provider credentials from labelled Kubernetes Secrets",
    version
)]
struct Cli {
    /// Gateway URL, e.g. `http://openshell.openshell.svc:8080`.
    #[arg(long, env = "OPENSHELL_GATEWAY_ENDPOINT")]
    gateway: String,

    /// PEM CA certificate for a gateway with a private CA.
    #[arg(long, env = "OPENSHELL_GATEWAY_CA_FILE")]
    gateway_ca_file: Option<PathBuf>,

    /// File holding a bearer token for the gateway. Re-read when the gateway
    /// rejects the current token. Omit for a gateway that allows
    /// unauthenticated users.
    #[arg(long, env = "OPENSHELL_GATEWAY_TOKEN_FILE")]
    gateway_token_file: Option<PathBuf>,

    /// Namespace to watch. Watches every namespace when omitted.
    #[arg(long, env = "OPENSHELL_PROVIDER_SYNC_NAMESPACE")]
    namespace: Option<String>,

    /// Workspace for Secrets without a provider-workspace annotation.
    #[arg(
        long,
        env = "OPENSHELL_PROVIDER_SYNC_DEFAULT_WORKSPACE",
        default_value = "default"
    )]
    default_workspace: String,

    /// Name reported on Kubernetes Events; usually the Deployment name.
    #[arg(
        long,
        env = "OPENSHELL_PROVIDER_SYNC_REPORTER",
        default_value = "openshell-provider-sync"
    )]
    reporter: String,

    /// Instance reported on Kubernetes Events; usually the pod name.
    #[arg(long, env = "POD_NAME")]
    reporter_instance: Option<String>,

    /// Do not publish Kubernetes Events on synced Secrets.
    #[arg(long)]
    no_events: bool,

    /// Do not restart the agents attached to a provider whose values rotated.
    /// They then keep running with connections opened on the old values.
    #[arg(long, env = "OPENSHELL_PROVIDER_SYNC_NO_RESTART")]
    no_restart: bool,

    /// Secret, in this controller's own namespace, that keeps fingerprints of
    /// applied values across restarts. Without it, the first sync after a
    /// restart is a baseline that restarts no agents.
    #[arg(long, env = "OPENSHELL_PROVIDER_SYNC_STATE_SECRET")]
    state_secret: Option<String>,

    /// Namespace of the state Secret; usually this pod's namespace.
    #[arg(long, env = "POD_NAMESPACE", requires = "state_secret")]
    state_namespace: Option<String>,

    /// Log as JSON lines.
    #[arg(long, env = "OPENSHELL_LOG_JSON")]
    log_json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.log_json);

    let mut config = ClientConfig::new(cli.gateway.clone());
    if let Some(path) = &cli.gateway_ca_file {
        config.ca_cert = Some(
            std::fs::read(path)
                .into_diagnostic()
                .wrap_err_with(|| format!("read gateway CA {}", path.display()))?,
        );
    }
    if let Some(path) = cli.gateway_token_file {
        let token_file = TokenFile::new(path);
        let token = token_file.read().map_err(|err| miette::miette!("{err}"))?;
        config.auth = Some(AuthConfig::Oidc {
            token,
            expires_at: None,
            refresh: Some(Arc::new(token_file)),
        });
    }
    let gateway = OpenShellClient::connect(config)
        .await
        .map_err(|err| miette::miette!("connect to gateway {}: {err}", cli.gateway))?;

    let kube_client = kube::Client::try_default()
        .await
        .into_diagnostic()
        .wrap_err("build Kubernetes client")?;

    let reporter = (!cli.no_events).then_some(Reporter {
        controller: cli.reporter.clone(),
        instance: cli.reporter_instance.clone(),
    });
    let mut context = Context::new(
        Arc::new(GatewayUpdater::new(gateway.clone())),
        cli.default_workspace.clone(),
    );
    if !cli.no_restart {
        context = context.with_restarter(Arc::new(GatewayRestarter::new(gateway)));
        if cli.state_secret.is_none() {
            tracing::warn!(
                "agent restarts are on without --state-secret: a restart in progress is \
                 forgotten if this controller restarts, which can leave an agent stopped"
            );
        }
    }
    if let Some(name) = &cli.state_secret {
        let namespace = cli.state_namespace.clone().ok_or_else(|| {
            miette::miette!("--state-secret needs --state-namespace or POD_NAMESPACE")
        })?;
        let store = SecretStateStore::new(kube_client.clone(), &namespace, name.clone());
        let state = load_state(&store, &kube_client, &namespace, reporter.as_ref()).await;
        context = context.with_state(state, Arc::new(store));
    }

    tracing::info!(
        gateway = %cli.gateway,
        namespace = cli.namespace.as_deref().unwrap_or("<all>"),
        default_workspace = %cli.default_workspace,
        restart_agents = !cli.no_restart,
        state_secret = cli.state_secret.as_deref().unwrap_or("<none>"),
        "starting provider sync"
    );
    controller::run(
        kube_client,
        context,
        Options {
            namespace: cli.namespace,
            reporter,
        },
    )
    .await;
    Ok(())
}

/// Load saved state, never starting over state that is only unreadable for
/// now, and never stopping all syncing over state that is corrupt.
async fn load_state(
    store: &SecretStateStore,
    client: &kube::Client,
    namespace: &str,
    reporter: Option<&Reporter>,
) -> SyncState {
    let mut backoff = std::time::Duration::from_secs(5);
    loop {
        match store.load_checked().await {
            Ok(Some(persisted)) => return SyncState::from_persisted(persisted),
            Ok(None) => return SyncState::new(),
            Err(LoadError::Unavailable(err)) => {
                // Starting fresh now would overwrite the saved state, and
                // with it any restart in progress.
                tracing::warn!(error = %err, retry_in_secs = backoff.as_secs(), "provider sync state unavailable; retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_mins(5));
            }
            Err(LoadError::Corrupt { raw, error }) => {
                let (salvaged, recovered) = PersistedState::salvage(&raw);
                let copy = store.quarantine(&raw).await;
                let kept = match &copy {
                    Ok(name) => format!("kept in Secret {name}"),
                    Err(err) => format!("not kept ({err})"),
                };
                let note = format!(
                    "State in Secret {} does not parse ({error}); {kept}. Starting over: the next values are a \
                     baseline that restarts no agents. Recovered {recovered} restart(s) in progress; any \
                     other agent this controller had stopped stays stopped, because a stop by this \
                     controller cannot be told from one by a person",
                    store.name()
                );
                tracing::warn!(note, "provider sync state is corrupt");
                if let Some(reporter) = reporter {
                    let recorder = Recorder::new(client.clone(), reporter.clone());
                    let reference = k8s_openapi::api::core::v1::ObjectReference {
                        api_version: Some("v1".to_string()),
                        kind: Some("Secret".to_string()),
                        namespace: Some(namespace.to_string()),
                        name: Some(store.name().to_string()),
                        ..Default::default()
                    };
                    let event = Event {
                        type_: EventType::Warning,
                        reason: "StateSecretCorrupt".to_string(),
                        note: Some(note),
                        action: "LoadState".to_string(),
                        secondary: None,
                    };
                    if let Err(err) = recorder.publish(&event, &reference).await {
                        tracing::debug!(error = %err, "failed to publish Kubernetes event");
                    }
                }
                return SyncState::from_persisted(salvaged);
            }
        }
    }
}

fn init_tracing(json: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}
