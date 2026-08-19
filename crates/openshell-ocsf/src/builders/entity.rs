// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for Entity Management [3004] events.

use crate::builders::SandboxContext;
use crate::enums::{EntityActivityId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{EntityManagementEvent, OcsfEvent};
use crate::objects::{Actor, ManagedEntity, User};

/// Builder for Entity Management [3004] events — CRUD on platform resources
/// (workspaces, members, providers, sandboxes, credentials) performed by an
/// authenticated actor.
pub struct EntityManagementBuilder<'a> {
    ctx: &'a SandboxContext,
    activity: EntityActivityId,
    entity: Option<ManagedEntity>,
    actor: Option<Actor>,
    severity: SeverityId,
    status: Option<StatusId>,
    message: Option<String>,
    unmapped: serde_json::Map<String, serde_json::Value>,
}

impl<'a> EntityManagementBuilder<'a> {
    #[must_use]
    pub fn new(ctx: &'a SandboxContext) -> Self {
        Self {
            ctx,
            activity: EntityActivityId::Unknown,
            entity: None,
            actor: None,
            severity: SeverityId::Informational,
            status: None,
            message: None,
            unmapped: serde_json::Map::new(),
        }
    }

    /// Set the event activity (Create / Update / Delete).
    #[must_use]
    pub fn activity(mut self, id: EntityActivityId) -> Self {
        self.activity = id;
        self
    }

    /// Set the resource the operation acts on.
    #[must_use]
    pub fn entity(mut self, entity: ManagedEntity) -> Self {
        self.entity = Some(entity);
        self
    }

    /// Set the authenticated identity performing the operation.
    #[must_use]
    pub fn actor_user(mut self, user: User) -> Self {
        self.actor = Some(Actor::from_user(user));
        self
    }

    /// Add an unmapped field (e.g. `operation`, `workspace`).
    #[must_use]
    pub fn unmapped(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.unmapped.insert(key.to_string(), value.into());
        self
    }

    #[must_use]
    pub fn build(self) -> OcsfEvent {
        let mut base = BaseEventData::new(
            3004,
            "Entity Management",
            3,
            "Identity & Access Management",
            self.activity.as_u8(),
            self.activity.label(),
            self.severity,
            self.ctx.metadata(&["security_control"]),
        );
        if !self.unmapped.is_empty() {
            base.unmapped = Some(serde_json::Value::Object(self.unmapped));
        }
        self.ctx
            .apply_common_fields(&mut base, self.status, self.message);

        OcsfEvent::EntityManagement(EntityManagementEvent {
            base,
            // A managed entity is the class's whole point; an unset one is a
            // caller bug surfaced as an unmistakable placeholder rather than
            // a panic on the logging path.
            entity: self
                .entity
                .unwrap_or_else(|| ManagedEntity::new("unknown", "unknown")),
            actor: self.actor,
        })
    }
}

impl_builder_setters!(EntityManagementBuilder);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::test_sandbox_context;
    use crate::objects::UserTypeId;

    #[test]
    fn entity_management_builder_produces_audit_event() {
        let ctx = test_sandbox_context();
        let event = EntityManagementBuilder::new(&ctx)
            .activity(EntityActivityId::Create)
            .entity(ManagedEntity::new("workspace", "ws-1").with_name("team-a"))
            .actor_user(User::new("alice", "oidc|alice-123", UserTypeId::User))
            .status(StatusId::Success)
            .unmapped("request_id", serde_json::json!("req-42"))
            .message("workspace team-a created")
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 3004);
        assert_eq!(json["activity_id"], 1);
        assert_eq!(json["type_uid"], 300_401);
        assert_eq!(json["category_uid"], 3);
        assert_eq!(json["entity"]["type"], "workspace");
        assert_eq!(json["entity"]["name"], "team-a");
        assert_eq!(json["actor"]["user"]["name"], "alice");
        assert_eq!(json["unmapped"]["request_id"], "req-42");

        let line = event.format_shorthand();
        assert!(
            line.starts_with("ENTITY:CREATE [INFO] workspace \"team-a\" by alice"),
            "unexpected shorthand: {line}"
        );
    }

    #[test]
    fn failed_operations_render_failed_in_shorthand() {
        let ctx = test_sandbox_context();
        let event = EntityManagementBuilder::new(&ctx)
            .activity(EntityActivityId::Delete)
            .entity(ManagedEntity::new("provider", "aws-prod"))
            .status(StatusId::Failure)
            .build();
        let line = event.format_shorthand();
        assert!(
            line.starts_with("ENTITY:DELETE [INFO] FAILED provider \"aws-prod\""),
            "unexpected shorthand: {line}"
        );
    }
}
