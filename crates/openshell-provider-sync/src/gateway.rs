// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Writing credential values to the gateway.

use std::collections::HashMap;
use std::path::PathBuf;

use openshell_core::proto::datamodel::v1::{ObjectMeta, Provider};
use openshell_core::proto::{UpdateProviderRequest, workspace_selector};
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

/// Writes credential values to a provider.
#[async_trait::async_trait]
pub trait ProviderUpdater: Send + Sync + 'static {
    /// Merge `values` into the provider's credentials. Keys not in `values`
    /// are left unchanged. Returns the gateway's mutation receipt id.
    async fn update_credentials(
        &self,
        workspace: &str,
        provider: &str,
        values: &CredentialValues,
    ) -> Result<String, UpdateError>;
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
    ) -> Result<String, UpdateError> {
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
                Ok(response) => return Ok(response.into_inner().mutation_id),
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
    fn classifies_gateway_errors() {
        let not_found = UpdateError::from_status(&tonic::Status::not_found("x"), "w", "p");
        assert!(matches!(not_found, UpdateError::ProviderNotFound { .. }));
        let rejected = UpdateError::from_status(&tonic::Status::invalid_argument("x"), "w", "p");
        assert!(matches!(rejected, UpdateError::Rejected(_)));
        let transient = UpdateError::from_status(&tonic::Status::unavailable("x"), "w", "p");
        assert!(matches!(transient, UpdateError::Transient(_)));
    }
}
