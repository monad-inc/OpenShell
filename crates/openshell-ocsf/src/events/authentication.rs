// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Authentication [3002] event class.

use serde::{Deserialize, Serialize};

use crate::enums::AuthProtocolId;
use crate::events::base_event::BaseEventData;
use crate::events::serde_helpers::insert_enum_pair;
use crate::objects::{Endpoint, User};

/// OCSF Authentication Event [3002].
///
/// Authentication outcomes at the gateway boundary. Failures export by
/// default; successes are enabled by the gateway audit toggle.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AuthenticationEvent {
    /// Common base event fields.
    #[serde(flatten)]
    pub base: BaseEventData,

    /// The identity that attempted to authenticate, as far as it is known.
    /// A rejected token may yield no identity at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,

    /// Authentication mechanism.
    #[serde(
        rename = "auth_protocol_id",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_protocol: Option<AuthProtocolId>,

    /// Where the attempt came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_endpoint: Option<Endpoint>,
}

impl Serialize for AuthenticationEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut base_val = serde_json::to_value(&self.base).map_err(serde::ser::Error::custom)?;
        let obj = base_val
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected object"))?;

        if let Some(user) = &self.user {
            obj.insert(
                "user".to_string(),
                serde_json::to_value(user).map_err(serde::ser::Error::custom)?,
            );
        }
        insert_enum_pair!(obj, "auth_protocol", self.auth_protocol);
        if let Some(endpoint) = &self.src_endpoint {
            obj.insert(
                "src_endpoint".to_string(),
                serde_json::to_value(endpoint).map_err(serde::ser::Error::custom)?,
            );
        }

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
                version: "1.7.0".to_string(),
                product: Product::openshell_sandbox("0.1.0"),
                profiles: vec!["security_control".to_string()],
                uid: None,
                log_source: None,
            },
        );
        base.set_status(StatusId::Failure);
        base.set_status_detail("token expired");

        let event = AuthenticationEvent {
            base,
            user: Some(User::named("oidc|alice-123")),
            auth_protocol: Some(AuthProtocolId::OpenId),
            src_endpoint: None,
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["class_uid"], 3002);
        assert_eq!(json["type_uid"], 300_201);
        assert_eq!(json["auth_protocol_id"], 4);
        assert_eq!(json["auth_protocol"], "OpenID");
        assert_eq!(json["status_detail"], "token expired");

        let back: AuthenticationEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back, event);
    }
}
