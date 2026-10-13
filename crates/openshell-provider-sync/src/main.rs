// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell-provider-sync`: sync provider credentials from Kubernetes Secrets.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use kube::runtime::events::Reporter;
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_provider_sync::controller::{self, Context, Options};
use openshell_provider_sync::gateway::{GatewayUpdater, TokenFile};
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
        controller: cli.reporter,
        instance: cli.reporter_instance,
    });
    tracing::info!(
        gateway = %cli.gateway,
        namespace = cli.namespace.as_deref().unwrap_or("<all>"),
        default_workspace = %cli.default_workspace,
        "starting provider sync"
    );
    controller::run(
        kube_client,
        Context::new(
            Arc::new(GatewayUpdater::new(gateway)),
            cli.default_workspace,
        ),
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
