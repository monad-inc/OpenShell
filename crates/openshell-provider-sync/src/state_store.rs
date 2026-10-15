// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keeping applied-value fingerprints across controller restarts.
//!
//! Without them every Secret looks new after a restart, and a rotation could
//! not be told from a baseline. Restarting every agent whenever this
//! controller restarts would be wrong, so the fingerprints live in a Secret
//! this controller owns.

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::Api;
use kube::api::{ObjectMeta, Patch, PatchParams};

use crate::state::PersistedState;

const STATE_KEY: &str = "state.json";
const FIELD_MANAGER: &str = "openshell-provider-sync";

/// Why saved state could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// It could not be read, as when the API server is unavailable. Retry:
    /// starting without it would overwrite it.
    #[error("read state: {0}")]
    Unavailable(String),
    /// It was read but does not parse. Retrying cannot help.
    #[error("state does not parse: {error}")]
    Corrupt { raw: Vec<u8>, error: String },
}

/// Where persisted state is kept.
#[async_trait::async_trait]
pub trait StateStore: Send + Sync + 'static {
    /// The saved state, or `None` when nothing has been saved yet.
    async fn load(&self) -> Result<Option<PersistedState>, String>;
    async fn save(&self, state: &PersistedState) -> Result<(), String>;
}

/// [`StateStore`] in one Kubernetes Secret.
pub struct SecretStateStore {
    api: Api<Secret>,
    name: String,
}

impl SecretStateStore {
    pub fn new(client: kube::Client, namespace: &str, name: impl Into<String>) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
            name: name.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Load, telling a read failure from state that does not parse.
    pub async fn load_checked(&self) -> Result<Option<PersistedState>, LoadError> {
        let Some(secret) = self
            .api
            .get_opt(&self.name)
            .await
            .map_err(|err| LoadError::Unavailable(format!("Secret {}: {err}", self.name)))?
        else {
            return Ok(None);
        };
        let Some(raw) = secret.data.as_ref().and_then(|data| data.get(STATE_KEY)) else {
            return Ok(None);
        };
        serde_json::from_slice(&raw.0)
            .map(Some)
            .map_err(|err| LoadError::Corrupt {
                raw: raw.0.clone(),
                error: err.to_string(),
            })
    }

    /// Keep unparseable state for diagnosis in a new Secret beside this one,
    /// before it is overwritten. Returns the copy's name.
    pub async fn quarantine(&self, raw: &[u8]) -> Result<String, String> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let name = format!("{}-corrupt-{stamp}", self.name);
        let copy = Secret {
            metadata: ObjectMeta {
                name: Some(name.clone()),
                ..Default::default()
            },
            data: Some([(STATE_KEY.to_string(), ByteString(raw.to_vec()))].into()),
            ..Default::default()
        };
        match self
            .api
            .create(&kube::api::PostParams::default(), &copy)
            .await
        {
            Ok(_) => Ok(name),
            Err(err) => Err(format!("create Secret {name}: {err}")),
        }
    }
}

#[async_trait::async_trait]
impl StateStore for SecretStateStore {
    async fn load(&self) -> Result<Option<PersistedState>, String> {
        self.load_checked().await.map_err(|err| err.to_string())
    }

    async fn save(&self, state: &PersistedState) -> Result<(), String> {
        let raw = serde_json::to_vec(state).map_err(|err| err.to_string())?;
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(self.name.clone()),
                ..Default::default()
            },
            data: Some([(STATE_KEY.to_string(), ByteString(raw))].into()),
            ..Default::default()
        };
        self.api
            .patch(
                &self.name,
                &PatchParams::apply(FIELD_MANAGER).force(),
                &Patch::Apply(&secret),
            )
            .await
            .map(|_| ())
            .map_err(|err| format!("write Secret {}: {err}", self.name))
    }
}
