// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Authentication [3002] event class.

use serde::{Deserialize, Serialize};

use crate::enums::AuthProtocolId;
use crate::events::base_event::BaseEventData;
use crate::objects::{Endpoint, Service, User};

/// OCSF Authentication Event [3002].
///
/// Authentication outcomes at the gateway boundary. The schema requires
/// `user` and at least one of `service` / `dst_endpoint`; the builder
/// enforces both at compile time.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuthenticationEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// The identity that attempted to authenticate, as far as it is known.
    /// A rejected credential that yields no identity is `User::named("unknown")`.
    pub user: User,

    /// Authentication mechanism.
    #[serde(rename = "auth_protocol_id", default)]
    pub auth_protocol: Option<AuthProtocolId>,

    /// Where the attempt came from.
    #[serde(default)]
    pub src_endpoint: Option<Endpoint>,

    /// The endpoint the attempt targeted (e.g. the gateway listen address).
    #[serde(default)]
    pub dst_endpoint: Option<Endpoint>,

    /// The service the attempt targeted (e.g. `openshell-gateway`).
    #[serde(default)]
    pub service: Option<Service>,
}

impl Serialize for AuthenticationEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::events::serde_helpers::{insert_enum_pair, insert_optional, insert_required};

        let mut base_val = serde_json::to_value(&self.base).map_err(serde::ser::Error::custom)?;
        let obj = base_val
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected object"))?;

        insert_required!(obj, "user", self.user);
        insert_enum_pair!(obj, "auth_protocol", self.auth_protocol);
        insert_optional!(obj, "src_endpoint", self.src_endpoint);
        insert_optional!(obj, "dst_endpoint", self.dst_endpoint);
        insert_optional!(obj, "service", self.service);

        base_val.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{SeverityId, StatusId};
    use crate::objects::{Metadata, Product};

    #[test]
    fn authentication_failure_round_trips() {
        let mut base = BaseEventData::new(
            3002,
            "Authentication",
            3,
            "Identity & Access Management",
            1,
            "Logon",
            SeverityId::Medium,
            Metadata {
                version: "1.8.0".to_string(),
                product: Product::openshell_gateway("0.1.0"),
                profiles: vec!["security_control".to_string()],
                uid: None,
                log_source: None,
            },
        );
        base.set_status(StatusId::Failure);
        base.set_status_detail("token expired");

        let event = AuthenticationEvent {
            base,
            user: User::named("oidc|alice-123"),
            auth_protocol: Some(AuthProtocolId::OpenId),
            src_endpoint: None,
            dst_endpoint: None,
            service: Some(Service::new("openshell-gateway")),
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 3002);
        assert_eq!(json["type_uid"], 300_201);
        assert_eq!(json["auth_protocol_id"], 4);
        assert_eq!(json["auth_protocol"], "OpenID");
        assert_eq!(json["status_detail"], "token expired");
        assert_eq!(json["service"]["name"], "openshell-gateway");

        let back: AuthenticationEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back, event);
    }
}
