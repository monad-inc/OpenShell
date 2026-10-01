// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Entity Management [3004] event class.

use serde::{Deserialize, Serialize};

use crate::events::base_event::BaseEventData;
use crate::objects::{Actor, ManagedEntity};

/// OCSF Entity Management Event [3004].
///
/// CRUD operations on platform resources — workspaces, members, providers,
/// sandboxes, credentials — performed by an authenticated actor. The
/// gateway's governance paper trail.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EntityManagementEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// The resource the operation acted on (required).
    pub entity: ManagedEntity,

    /// Who performed the operation (recommended).
    #[serde(default)]
    pub actor: Option<Actor>,
}

impl Serialize for EntityManagementEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::events::serde_helpers::{insert_optional, insert_required};

        let mut base_val = serde_json::to_value(&self.base).map_err(serde::ser::Error::custom)?;
        let obj = base_val
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected object"))?;

        insert_required!(obj, "entity", self.entity);
        insert_optional!(obj, "actor", self.actor);

        base_val.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{SeverityId, UserTypeId};
    use crate::objects::{Metadata, Product, User};

    #[test]
    fn entity_management_round_trips() {
        let base = BaseEventData::new(
            3004,
            "Entity Management",
            3,
            "Identity & Access Management",
            1,
            "Create",
            SeverityId::Informational,
            Metadata {
                version: "1.8.0".to_string(),
                product: Product::openshell_gateway("0.1.0"),
                profiles: vec!["security_control".to_string()],
                uid: None,
                log_source: None,
            },
        );
        let event = EntityManagementEvent {
            base,
            entity: ManagedEntity::new("workspace", "ws-1").with_name("team-a"),
            actor: Some(Actor::from_user(User::new(
                "alice",
                "oidc|alice-123",
                UserTypeId::User,
            ))),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 3004);
        assert_eq!(json["type_uid"], 300_401);
        assert_eq!(json["entity"]["type"], "workspace");
        assert_eq!(json["entity"]["type_id"], 99);
        assert_eq!(json["actor"]["user"]["uid"], "oidc|alice-123");
        assert!(
            json["actor"].get("process").is_none(),
            "user actors serialize without a process"
        );

        let back: EntityManagementEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back, event);
    }
}
