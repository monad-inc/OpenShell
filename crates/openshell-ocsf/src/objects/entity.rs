// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Managed Entity object.

use serde::{Deserialize, Serialize};

/// OCSF Managed Entity object — the platform resource an Entity Management
/// event acts on (workspace, provider, sandbox, credential, …).
///
/// `entity_type` carries `OpenShell`'s resource type name; OCSF leaves the
/// vocabulary to the producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedEntity {
    /// Resource type (`workspace`, `provider`, `sandbox`, …).
    #[serde(rename = "type")]
    pub entity_type: String,

    /// Stable identifier of the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Human-readable name of the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl ManagedEntity {
    #[must_use]
    pub fn new(entity_type: impl Into<String>, uid: impl Into<String>) -> Self {
        let uid = uid.into();
        Self {
            entity_type: entity_type.into(),
            uid: Some(uid),
            name: None,
        }
    }

    /// Attach a display name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The most readable identifier available: name, else uid, else the type.
    #[must_use]
    pub fn display(&self) -> &str {
        self.name
            .as_deref()
            .or(self.uid.as_deref())
            .unwrap_or(&self.entity_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_round_trips_with_type_key() {
        let entity = ManagedEntity::new("workspace", "ws-1").with_name("team-a");
        let json = serde_json::to_value(&entity).unwrap();
        assert_eq!(json["type"], "workspace");
        assert_eq!(json["uid"], "ws-1");
        assert_eq!(json["name"], "team-a");
        let back: ManagedEntity = serde_json::from_value(json).unwrap();
        assert_eq!(back, entity);
    }

    #[test]
    fn display_prefers_name_then_uid() {
        assert_eq!(
            ManagedEntity::new("workspace", "ws-1")
                .with_name("team-a")
                .display(),
            "team-a"
        );
        assert_eq!(ManagedEntity::new("workspace", "ws-1").display(), "ws-1");
    }
}
