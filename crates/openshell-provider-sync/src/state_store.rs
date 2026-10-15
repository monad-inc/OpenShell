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
}

#[async_trait::async_trait]
impl StateStore for SecretStateStore {
    async fn load(&self) -> Result<Option<PersistedState>, String> {
        let Some(secret) = self
            .api
            .get_opt(&self.name)
            .await
            .map_err(|err| format!("read Secret {}: {err}", self.name))?
        else {
            return Ok(None);
        };
        let Some(raw) = secret.data.as_ref().and_then(|data| data.get(STATE_KEY)) else {
            return Ok(None);
        };
        serde_json::from_slice(&raw.0)
            .map(Some)
            .map_err(|err| format!("parse Secret {}: {err}", self.name))
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
