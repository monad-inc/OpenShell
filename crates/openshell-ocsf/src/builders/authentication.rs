// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for Authentication [3002] events.

use crate::builders::SandboxContext;
use crate::enums::{AuthActivityId, AuthProtocolId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{AuthenticationEvent, OcsfEvent};
use crate::objects::{Endpoint, User};

/// Builder for Authentication [3002] events — authentication outcomes at the
/// gateway boundary. Never carry token or credential material; the identity
/// and a low-cardinality failure reason are the payload.
pub struct AuthenticationBuilder<'a> {
    ctx: &'a SandboxContext,
    activity: AuthActivityId,
    user: Option<User>,
    auth_protocol: Option<AuthProtocolId>,
    src_endpoint: Option<Endpoint>,
    severity: SeverityId,
    status: Option<StatusId>,
    status_detail: Option<String>,
    message: Option<String>,
    unmapped: serde_json::Map<String, serde_json::Value>,
}

impl<'a> AuthenticationBuilder<'a> {
    #[must_use]
    pub fn new(ctx: &'a SandboxContext) -> Self {
        Self {
            ctx,
            activity: AuthActivityId::Logon,
            user: None,
            auth_protocol: None,
            src_endpoint: None,
            severity: SeverityId::Medium,
            status: None,
            status_detail: None,
            message: None,
            unmapped: serde_json::Map::new(),
        }
    }

    /// Set the event activity (defaults to Logon).
    #[must_use]
    pub fn activity(mut self, id: AuthActivityId) -> Self {
        self.activity = id;
        self
    }

    /// Set the identity that attempted to authenticate, as far as known.
    #[must_use]
    pub fn user(mut self, user: User) -> Self {
        self.user = Some(user);
        self
    }

    /// Set the authentication mechanism.
    #[must_use]
    pub fn auth_protocol(mut self, id: AuthProtocolId) -> Self {
        self.auth_protocol = Some(id);
        self
    }

    /// Set where the attempt came from.
    #[must_use]
    pub fn src_endpoint(mut self, endpoint: Endpoint) -> Self {
        self.src_endpoint = Some(endpoint);
        self
    }

    /// Set the low-cardinality failure reason (e.g. `token expired`).
    #[must_use]
    pub fn status_detail(mut self, detail: impl Into<String>) -> Self {
        self.status_detail = Some(detail.into());
        self
    }

    /// Add an unmapped field.
    #[must_use]
    pub fn unmapped(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.unmapped.insert(key.to_string(), value.into());
        self
    }

    #[must_use]
    pub fn build(self) -> OcsfEvent {
        let mut base = BaseEventData::new(
            3002,
            "Authentication",
            3,
            "Identity & Access Management",
            self.activity.as_u8(),
            self.activity.label(),
            self.severity,
            self.ctx.metadata(&["security_control"]),
        );
        if let Some(detail) = self.status_detail {
            base.set_status_detail(detail);
        }
        if !self.unmapped.is_empty() {
            base.unmapped = Some(serde_json::Value::Object(self.unmapped));
        }
        self.ctx
            .apply_common_fields(&mut base, self.status, self.message);

        OcsfEvent::Authentication(AuthenticationEvent {
            base,
            user: self.user,
            auth_protocol: self.auth_protocol,
            src_endpoint: self.src_endpoint,
        })
    }
}

impl_builder_setters!(AuthenticationBuilder);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::test_sandbox_context;

    #[test]
    fn authentication_failure_builder_produces_audit_event() {
        let ctx = test_sandbox_context();
        let event = AuthenticationBuilder::new(&ctx)
            .auth_protocol(AuthProtocolId::OpenId)
            .user(User::named("oidc|alice-123"))
            .src_endpoint(Endpoint::from_ip("10.0.0.9".parse().unwrap(), 51044))
            .status(StatusId::Failure)
            .status_detail("token expired")
            .message("OIDC token rejected")
            .build();

        let json = event.to_json().unwrap();
        assert_eq!(json["class_uid"], 3002);
        assert_eq!(json["activity_id"], 1);
        assert_eq!(json["auth_protocol_id"], 4);
        assert_eq!(json["status_detail"], "token expired");
        assert_eq!(json["user"]["name"], "oidc|alice-123");

        let line = event.format_shorthand();
        assert!(
            line.starts_with(
                "AUTHN:LOGON [MED] FAILED openid user:oidc|alice-123 from 10.0.0.9:51044"
            ),
            "unexpected shorthand: {line}"
        );
        assert!(
            line.contains("[reason:token expired]"),
            "reason missing: {line}"
        );
    }
}
