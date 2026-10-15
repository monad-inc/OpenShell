// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Writing credential values to the gateway.

use std::collections::HashMap;
use std::path::PathBuf;

use openshell_core::proto::datamodel::v1::{ObjectMeta, Provider};
use openshell_core::proto::{
    GetSandboxRequest, ProviderResponse, SandboxPhase, StartSandboxRequest, StopSandboxRequest,
    UpdateProviderRequest, workspace_selector,
};
use openshell_sdk::{OpenShellClient, Refresh, RefreshError, RefreshedToken};
use tonic::Code;

use crate::mapping::CredentialValues;

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// The provider does not exist yet. Whatever creates providers (a deploy
    /// job, a human) has not run; retry later.
    #[error("provider {workspace}/{provider} does not exist")]
    ProviderNotFound { workspace: String, provider: String },
    /// The gateway refused the values. Retrying the same values will fail
    /// again; the Secret has to change.
    #[error("gateway rejected the update: {0}")]
    Rejected(String),
    /// A transport, auth or server failure that may clear on retry.
    #[error("gateway update failed: {0}")]
    Transient(String),
}

impl UpdateError {
    fn from_status(status: &tonic::Status, workspace: &str, provider: &str) -> Self {
        match status.code() {
            Code::NotFound => Self::ProviderNotFound {
                workspace: workspace.to_string(),
                provider: provider.to_string(),
            },
            Code::InvalidArgument | Code::FailedPrecondition | Code::PermissionDenied => {
                Self::Rejected(format!("{:?}: {}", status.code(), status.message()))
            }
            _ => Self::Transient(format!("{:?}: {}", status.code(), status.message())),
        }
    }
}

/// What one provider update reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Updated {
    pub mutation_id: String,
    /// Sandboxes the gateway found attached to the provider when it applied
    /// the update, by name.
    pub sandboxes: Vec<String>,
}

impl Updated {
    fn from_response(response: ProviderResponse) -> Self {
        let mut sandboxes: Vec<String> = response
            .target_receipts
            .iter()
            .filter_map(|receipt| receipt.desired.as_ref())
            .map(|desired| desired.sandbox.clone())
            .filter(|sandbox| !sandbox.is_empty())
            .collect();
        sandboxes.sort();
        sandboxes.dedup();
        Self {
            mutation_id: response.mutation_id,
            sandboxes,
        }
    }
}

/// Writes credential values to a provider.
#[async_trait::async_trait]
pub trait ProviderUpdater: Send + Sync + 'static {
    /// Merge `values` into the provider's credentials. Keys not in `values`
    /// are left unchanged.
    async fn update_credentials(
        &self,
        workspace: &str,
        provider: &str,
        values: &CredentialValues,
    ) -> Result<Updated, UpdateError>;
}

/// [`ProviderUpdater`] over the gateway's `UpdateProvider` RPC.
pub struct GatewayUpdater {
    client: OpenShellClient,
}

impl GatewayUpdater {
    pub fn new(client: OpenShellClient) -> Self {
        Self { client }
    }
}

fn update_request(
    workspace: &str,
    provider: &str,
    values: &CredentialValues,
) -> UpdateProviderRequest {
    UpdateProviderRequest {
        workspace_scope: Some(workspace_selector(workspace)),
        provider: Some(Provider {
            metadata: Some(ObjectMeta {
                name: provider.to_string(),
                workspace: workspace.to_string(),
                // Zero: last write wins. The Secret is the source of truth
                // for these keys, so there is no concurrent edit to protect.
                resource_version: 0,
                ..Default::default()
            }),
            credentials: values
                .0
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<HashMap<_, _>>(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[async_trait::async_trait]
impl ProviderUpdater for GatewayUpdater {
    async fn update_credentials(
        &self,
        workspace: &str,
        provider: &str,
        values: &CredentialValues,
    ) -> Result<Updated, UpdateError> {
        let mut retried_auth = false;
        loop {
            let mut grpc = self
                .client
                .raw_grpc_fresh()
                .await
                .map_err(|err| UpdateError::Transient(err.to_string()))?;
            match grpc
                .update_provider(update_request(workspace, provider, values))
                .await
            {
                Ok(response) => return Ok(Updated::from_response(response.into_inner())),
                Err(status) if status.code() == Code::Unauthenticated && !retried_auth => {
                    retried_auth = true;
                    let refreshed = self
                        .client
                        .force_refresh()
                        .await
                        .map_err(|err| UpdateError::Transient(err.to_string()))?;
                    if !refreshed {
                        return Err(UpdateError::from_status(&status, workspace, provider));
                    }
                }
                Err(status) => return Err(UpdateError::from_status(&status, workspace, provider)),
            }
        }
    }
}

/// What stopping a sandbox for a restart did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    Stopped,
    /// Stopped, stopping, completed, being deleted or gone: someone or
    /// something else decided it should not run, so it is left alone.
    Skipped {
        phase: String,
    },
}

/// Stops and starts sandboxes so their agents start fresh with current
/// credentials. Retrying is the caller's job.
#[async_trait::async_trait]
pub trait SandboxRestarter: Send + Sync + 'static {
    /// Stop the sandbox unless it is already meant to stay down.
    async fn stop(&self, workspace: &str, sandbox: &str) -> Result<Stop, UpdateError>;
    /// The sandbox's phase, or `None` when it no longer exists.
    async fn phase(
        &self,
        workspace: &str,
        sandbox: &str,
    ) -> Result<Option<SandboxPhase>, UpdateError>;
    /// One start attempt.
    async fn start(&self, workspace: &str, sandbox: &str) -> Result<(), UpdateError>;
}

/// Call one gateway RPC, refreshing the bearer token once if it is rejected.
macro_rules! call_refreshing {
    ($client:expr, $method:ident, $request:expr) => {{
        let client = $client;
        let first = client
            .raw_grpc_fresh()
            .await
            .map_err(|err| UpdateError::Transient(err.to_string()))?
            .$method($request.clone())
            .await;
        match first {
            Err(status) if status.code() == Code::Unauthenticated => {
                client
                    .force_refresh()
                    .await
                    .map_err(|err| UpdateError::Transient(err.to_string()))?;
                client
                    .raw_grpc_fresh()
                    .await
                    .map_err(|err| UpdateError::Transient(err.to_string()))?
                    .$method($request)
                    .await
            }
            other => other,
        }
    }};
}

/// [`SandboxRestarter`] over the gateway's `GetSandbox`, `StopSandbox` and
/// `StartSandbox`.
pub struct GatewayRestarter {
    client: OpenShellClient,
}

impl GatewayRestarter {
    pub fn new(client: OpenShellClient) -> Self {
        Self { client }
    }
}

/// A sandbox in one of these phases is meant to stay down.
pub(crate) fn left_alone(phase: SandboxPhase) -> bool {
    matches!(
        phase,
        SandboxPhase::Stopping
            | SandboxPhase::Stopped
            | SandboxPhase::Completed
            | SandboxPhase::Deleting
    )
}

#[async_trait::async_trait]
impl SandboxRestarter for GatewayRestarter {
    async fn stop(&self, workspace: &str, sandbox: &str) -> Result<Stop, UpdateError> {
        let Some(phase) = self.phase(workspace, sandbox).await? else {
            return Ok(Stop::Skipped {
                phase: "deleted".to_string(),
            });
        };
        if left_alone(phase) {
            return Ok(Stop::Skipped {
                phase: phase.as_str_name().to_string(),
            });
        }
        // A request id makes a retried stop a replay, not a repeat.
        let stop = StopSandboxRequest {
            workspace_scope: Some(workspace_selector(workspace)),
            name: sandbox.to_string(),
            request_id: uuid::Uuid::new_v4().to_string(),
        };
        call_refreshing!(&self.client, stop_sandbox, stop)
            .map_err(|status| UpdateError::from_status(&status, workspace, sandbox))?;
        Ok(Stop::Stopped)
    }

    async fn phase(
        &self,
        workspace: &str,
        sandbox: &str,
    ) -> Result<Option<SandboxPhase>, UpdateError> {
        let request = GetSandboxRequest {
            workspace_scope: Some(workspace_selector(workspace)),
            name: sandbox.to_string(),
        };
        match call_refreshing!(&self.client, get_sandbox, request) {
            Ok(response) => Ok(Some(
                response
                    .into_inner()
                    .sandbox
                    .and_then(|sandbox| sandbox.status)
                    .map_or(SandboxPhase::Unspecified, |status| status.phase()),
            )),
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(status) => Err(UpdateError::from_status(&status, workspace, sandbox)),
        }
    }

    async fn start(&self, workspace: &str, sandbox: &str) -> Result<(), UpdateError> {
        let start = StartSandboxRequest {
            workspace_scope: Some(workspace_selector(workspace)),
            name: sandbox.to_string(),
            request_id: uuid::Uuid::new_v4().to_string(),
        };
        call_refreshing!(&self.client, start_sandbox, start)
            .map(|_| ())
            .map_err(|status| UpdateError::from_status(&status, workspace, sandbox))
    }
}

/// Bearer token read from a file, re-read whenever the client refreshes.
///
/// Suits a projected `ServiceAccount` token or a Secret-mounted token that
/// something else rotates on disk.
pub struct TokenFile {
    path: PathBuf,
}

impl TokenFile {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn read(&self) -> Result<String, RefreshError> {
        let token = std::fs::read_to_string(&self.path).map_err(|err| {
            RefreshError::Transient(format!("read {}: {err}", self.path.display()))
        })?;
        let token = token.trim();
        if token.is_empty() {
            return Err(RefreshError::Transient(format!(
                "{} is empty",
                self.path.display()
            )));
        }
        Ok(token.to_string())
    }
}

#[async_trait::async_trait]
impl Refresh for TokenFile {
    async fn refresh(&self) -> Result<RefreshedToken, RefreshError> {
        self.read().map(RefreshedToken::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn request_carries_only_the_given_keys() {
        let values = CredentialValues(BTreeMap::from([("A".to_string(), "1".to_string())]));
        let request = update_request("oncall", "github", &values);
        let provider = request.provider.unwrap();
        let metadata = provider.metadata.unwrap();
        assert_eq!(metadata.name, "github");
        assert_eq!(metadata.workspace, "oncall");
        assert_eq!(metadata.resource_version, 0);
        assert_eq!(provider.r#type, "");
        assert_eq!(provider.profile_workspace, "");
        assert!(provider.credential_handles.is_empty());
        assert!(provider.config.is_empty());
        assert_eq!(provider.credentials.len(), 1);
        assert_eq!(provider.credentials["A"], "1");
        assert_eq!(request.workspace_scope, Some(workspace_selector("oncall")));
    }

    #[test]
    fn update_reports_the_attached_sandboxes_once_each() {
        use openshell_core::proto::{ProviderDesiredIdentity, ProviderMutationReceipt};
        let receipt = |sandbox: &str| ProviderMutationReceipt {
            desired: Some(ProviderDesiredIdentity {
                sandbox: sandbox.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let updated = Updated::from_response(ProviderResponse {
            mutation_id: "m".to_string(),
            target_receipts: vec![
                receipt("pm"),
                receipt("gtm-bot"),
                receipt("pm"),
                receipt(""),
            ],
            ..Default::default()
        });
        assert_eq!(updated.mutation_id, "m");
        assert_eq!(updated.sandboxes, ["gtm-bot", "pm"]);
    }

    #[test]
    fn stopped_sandboxes_are_left_alone() {
        for phase in [
            SandboxPhase::Stopping,
            SandboxPhase::Stopped,
            SandboxPhase::Completed,
            SandboxPhase::Deleting,
        ] {
            assert!(left_alone(phase), "{phase:?}");
        }
        for phase in [
            SandboxPhase::Ready,
            SandboxPhase::Error,
            SandboxPhase::Provisioning,
            SandboxPhase::Starting,
            SandboxPhase::Unknown,
            SandboxPhase::Unspecified,
        ] {
            assert!(!left_alone(phase), "{phase:?}");
        }
    }

    #[test]
    fn classifies_gateway_errors() {
        let not_found = UpdateError::from_status(&tonic::Status::not_found("x"), "w", "p");
        assert!(matches!(not_found, UpdateError::ProviderNotFound { .. }));
        let rejected = UpdateError::from_status(&tonic::Status::invalid_argument("x"), "w", "p");
        assert!(matches!(rejected, UpdateError::Rejected(_)));
        let transient = UpdateError::from_status(&tonic::Status::unavailable("x"), "w", "p");
        assert!(matches!(transient, UpdateError::Transient(_)));
    }
}
