// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Managed Entity object.

use serde::{Deserialize, Serialize};

use crate::enums::ManagedEntityTypeId;

/// OCSF Managed Entity object — the platform resource an Entity Management
/// event acts on (workspace, provider, sandbox, credential, …).
///
/// `type_id` is the OCSF classification; the sibling `type` carries
/// `OpenShell`'s resource name (`workspace`, `provider`, …), which is the
/// schema's caption slot for `Other`. The schema requires at least one of
/// `name`, `uid`, …; [`ManagedEntity::new`] always sets `uid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedEntity {
    /// OCSF entity type id. Absent from OCSF 1.1.0; the schema downgrade
    /// strips it for 1.1 targets.
    #[serde(default = "default_type_id")]
    pub type_id: ManagedEntityTypeId,

    /// Resource type name (`workspace`, `provider`, `sandbox`, …).
    #[serde(rename = "type")]
    pub entity_type: String,

    /// Stable identifier of the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Human-readable name of the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

fn default_type_id() -> ManagedEntityTypeId {
    ManagedEntityTypeId::Other
}

impl ManagedEntity {
    /// A platform resource classified as `Other`, named by its resource type.
    #[must_use]
    pub fn new(entity_type: impl Into<String>, uid: impl Into<String>) -> Self {
        Self {
            type_id: ManagedEntityTypeId::Other,
            entity_type: entity_type.into(),
            uid: Some(uid.into()),
            name: None,
        }
    }

    /// Override the OCSF classification (e.g. `User` for workspace members,
    /// `Policy` for sandbox policies).
    #[must_use]
    pub fn with_type_id(mut self, type_id: ManagedEntityTypeId) -> Self {
        self.type_id = type_id;
        self
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
    fn entity_round_trips_with_type_pair() {
        let entity = ManagedEntity::new("workspace", "ws-1").with_name("team-a");
        let json = serde_json::to_value(&entity).unwrap();
        assert_eq!(json["type_id"], 99);
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

    #[test]
    fn emitted_entity_matches_vendored_schema() {
        use crate::validation::schema::{
            load_object_schema, validate_enum_value, validate_required_fields,
        };

        let schema = load_object_schema("managed_entity");
        for entity in [
            ManagedEntity::new("workspace", "ws-1"),
            ManagedEntity::new("workspace_member", "oidc|bob")
                .with_type_id(ManagedEntityTypeId::User),
            ManagedEntity::new("policy", "sb-1").with_type_id(ManagedEntityTypeId::Policy),
        ] {
            let json = serde_json::to_value(&entity).unwrap();
            validate_required_fields(&json, &schema);
            validate_enum_value(&json, "type_id", &schema);
        }
    }
}
