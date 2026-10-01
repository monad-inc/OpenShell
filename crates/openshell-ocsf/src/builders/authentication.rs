// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder for Authentication [3002] events.

use std::marker::PhantomData;

use crate::builders::EventContext;
use crate::enums::{AuthActivityId, AuthProtocolId, SeverityId, StatusId};
use crate::events::base_event::BaseEventData;
use crate::events::{AuthenticationEvent, OcsfEvent};
use crate::objects::{Endpoint, Service, User};

/// Marker for an Authentication builder without a target.
pub struct MissingAuthTarget;

/// Marker for an Authentication builder with a `service` or `dst_endpoint`.
pub struct HasAuthTarget;

/// Builder for Authentication [3002] events at the gateway boundary.
///
/// Never carry token or credential material; the identity and a
/// low-cardinality failure reason are the payload.
///
/// OCSF requires `user` and at least one of `service` / `dst_endpoint`. The
/// user is a constructor argument, and `build()` exists only after
/// [`service`](Self::service) or [`dst_endpoint`](Self::dst_endpoint):
///
/// ```compile_fail
/// use openshell_ocsf::{AuthenticationBuilder, EventContext, EventOrigin, User};
///
/// let ctx = EventContext {
///     sandbox_id: String::new(),
///     sandbox_name: String::new(),
///     container_image: String::new(),
///     hostname: String::new(),
///     product_version: String::new(),
///     proxy_ip: "127.0.0.1".parse().unwrap(),
///     proxy_port: 0,
///     origin: EventOrigin::Gateway { name: "gw".to_string() },
/// };
/// AuthenticationBuilder::new(&ctx, User::named("unknown")).build();
/// ```
pub struct AuthenticationBuilder<'a, Target = MissingAuthTarget> {
    ctx: &'a EventContext,
    activity: AuthActivityId,
    user: User,
    auth_protocol: Option<AuthProtocolId>,
    src_endpoint: Option<Endpoint>,
    dst_endpoint: Option<Endpoint>,
    service: Option<Service>,
    severity: SeverityId,
    status: Option<StatusId>,
    status_detail: Option<String>,
    message: Option<String>,
    unmapped: serde_json::Map<String, serde_json::Value>,
    target: PhantomData<Target>,
}

impl<'a> AuthenticationBuilder<'a, MissingAuthTarget> {
    /// Start building an Authentication event for `user`. Pass
    /// `User::named("unknown")` when the credential yielded no identity.
    #[must_use]
    pub fn new(ctx: &'a EventContext, user: User) -> Self {
        Self {
            ctx,
            activity: AuthActivityId::Logon,
            user,
            auth_protocol: None,
            src_endpoint: None,
            dst_endpoint: None,
            service: None,
            severity: SeverityId::Medium,
            status: None,
            status_detail: None,
            message: None,
            unmapped: serde_json::Map::new(),
            target: PhantomData,
        }
    }
}

impl<'a, Target> AuthenticationBuilder<'a, Target> {
    fn into_targeted(self) -> AuthenticationBuilder<'a, HasAuthTarget> {
        AuthenticationBuilder {
            ctx: self.ctx,
            activity: self.activity,
            user: self.user,
            auth_protocol: self.auth_protocol,
            src_endpoint: self.src_endpoint,
            dst_endpoint: self.dst_endpoint,
            service: self.service,
            severity: self.severity,
            status: self.status,
            status_detail: self.status_detail,
            message: self.message,
            unmapped: self.unmapped,
            target: PhantomData,
        }
    }

    /// Set the service the attempt targeted.
    #[must_use]
    pub fn service(mut self, service: Service) -> AuthenticationBuilder<'a, HasAuthTarget> {
        self.service = Some(service);
        self.into_targeted()
    }

    /// Set the endpoint the attempt targeted (e.g. the gateway listen address).
    #[must_use]
    pub fn dst_endpoint(mut self, endpoint: Endpoint) -> AuthenticationBuilder<'a, HasAuthTarget> {
        self.dst_endpoint = Some(endpoint);
        self.into_targeted()
    }

    /// Set the event activity (defaults to Logon).
    #[must_use]
    pub fn activity(mut self, id: AuthActivityId) -> Self {
        self.activity = id;
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

    /// Set the event severity (defaults to Medium).
    #[must_use]
    pub fn severity(mut self, id: SeverityId) -> Self {
        self.severity = id;
        self
    }

    /// Set the overall event status.
    #[must_use]
    pub fn status(mut self, id: StatusId) -> Self {
        self.status = Some(id);
        self
    }

    /// Set a human-readable event message.
    #[must_use]
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }
}

impl AuthenticationBuilder<'_, HasAuthTarget> {
    /// Finalize and return the `OcsfEvent`.
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
            self.ctx
                .metadata(&["security_control", "container", "host"]),
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
            dst_endpoint: self.dst_endpoint,
            service: self.service,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builders::{EventOrigin, test_sandbox_context};
    use crate::validation::schema::{
        load_class_schema, validate_enum_value, validate_required_fields,
    };

    fn gateway_context() -> EventContext {
        EventContext {
            sandbox_id: String::new(),
            sandbox_name: String::new(),
            container_image: String::new(),
            hostname: "openshell-gateway-0".to_string(),
            product_version: "0.1.0".to_string(),
            proxy_ip: "127.0.0.1".parse().unwrap(),
            proxy_port: 0,
            origin: EventOrigin::Gateway {
                name: "production".to_string(),
            },
        }
    }

    #[test]
    fn authentication_failure_builder_produces_audit_event() {
        let ctx = gateway_context();
        let event = AuthenticationBuilder::new(&ctx, User::named("oidc|alice-123"))
            .auth_protocol(AuthProtocolId::OpenId)
            .src_endpoint(Endpoint::from_ip("10.0.0.9".parse().unwrap(), 51044))
            .service(Service::new("openshell-gateway"))
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
        assert_eq!(json["service"]["name"], "openshell-gateway");
        assert!(json.get("container").is_none(), "gateway-scoped: {json}");
        assert_eq!(json["metadata"]["product"]["name"], "OpenShell Gateway");
        assert_eq!(json["device"]["type_id"], 1);

        let line = event.format_shorthand();
        assert!(
            line.starts_with(
                "AUTHN:LOGON [MED] FAILED openid user:oidc|alice-123 from 10.0.0.9:51044 to openshell-gateway"
            ),
            "unexpected shorthand: {line}"
        );
        assert!(
            line.contains("[reason:token expired]"),
            "reason missing: {line}"
        );
    }

    #[test]
    fn authentication_events_match_the_vendored_schema() {
        let schema = load_class_schema("authentication");
        for ctx in [gateway_context(), test_sandbox_context()] {
            for event in [
                AuthenticationBuilder::new(&ctx, User::named("unknown"))
                    .service(Service::new("openshell-gateway"))
                    .status(StatusId::Failure)
                    .build(),
                AuthenticationBuilder::new(&ctx, User::named("unknown"))
                    .dst_endpoint(Endpoint::from_ip("10.0.0.1".parse().unwrap(), 8080))
                    .activity(AuthActivityId::Logoff)
                    .auth_protocol(AuthProtocolId::Other)
                    .status(StatusId::Success)
                    .build(),
            ] {
                let json = event.to_json().unwrap();
                validate_required_fields(&json, &schema);
                for field in ["activity_id", "auth_protocol_id", "severity_id", "type_uid"] {
                    validate_enum_value(&json, field, &schema);
                }
            }
        }
    }
}
