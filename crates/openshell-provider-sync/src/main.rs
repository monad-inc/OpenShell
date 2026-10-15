// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell-provider-sync`: sync provider credentials from Kubernetes Secrets.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use kube::runtime::events::Reporter;
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_provider_sync::controller::{self, Context, Options};
use openshell_provider_sync::gateway::{GatewayRestarter, GatewayUpdater, TokenFile};
use openshell_provider_sync::state::SyncState;
use openshell_provider_sync::state_store::{SecretStateStore, StateStore};
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

    let mut context = Context::new(
        Arc::new(GatewayUpdater::new(gateway.clone())),
        cli.default_workspace.clone(),
    );
    if !cli.no_restart {
        context = context.with_restarter(Arc::new(GatewayRestarter::new(gateway)));
    }
    if let Some(name) = &cli.state_secret {
        let namespace = cli.state_namespace.clone().ok_or_else(|| {
            miette::miette!("--state-secret needs --state-namespace or POD_NAMESPACE")
        })?;
        let store = SecretStateStore::new(kube_client.clone(), &namespace, name.clone());
        let state = match store.load().await {
            Ok(Some(persisted)) => SyncState::from_persisted(persisted),
            Ok(None) => SyncState::new(),
            Err(err) => {
                // Starting fresh only costs a baseline sync that restarts
                // nothing; refusing to start would stop all syncing.
                tracing::warn!(error = %err, "could not load provider sync state; starting fresh");
                SyncState::new()
            }
        };
        context = context.with_state(state, Arc::new(store));
    }

    let reporter = (!cli.no_events).then_some(Reporter {
        controller: cli.reporter,
        instance: cli.reporter_instance,
    });
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

fn init_tracing(json: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}
