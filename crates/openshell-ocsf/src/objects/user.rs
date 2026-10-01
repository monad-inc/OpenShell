// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF User object.

use serde::{Deserialize, Serialize};

use crate::enums::UserTypeId;

/// OCSF User object — an authenticated identity acting on or affected by an
/// event.
///
/// The schema requires at least one of `account`, `name` or `uid`; `name` is
/// always set here. Serialized with the OCSF `type_id`/`type` pair when a type
/// is known.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct User {
    /// Human-readable name (display name, username, or the uid when no
    /// friendlier form exists).
    pub name: String,

    /// Stable unique identifier (OIDC `sub`, certificate CN, sandbox id).
    #[serde(default)]
    pub uid: Option<String>,

    /// User type, when known. The sibling `type` label is derived on output.
    #[serde(default)]
    pub type_id: Option<UserTypeId>,
}

impl Serialize for User {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let len = 1 + usize::from(self.uid.is_some()) + 2 * usize::from(self.type_id.is_some());
        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("name", &self.name)?;
        if let Some(uid) = &self.uid {
            map.serialize_entry("uid", uid)?;
        }
        if let Some(type_id) = self.type_id {
            map.serialize_entry("type_id", &type_id.as_u8())?;
            map.serialize_entry("type", type_id.label())?;
        }
        map.end()
    }
}

impl User {
    /// A user identity with a stable uid.
    #[must_use]
    pub fn new(name: impl Into<String>, uid: impl Into<String>, type_id: UserTypeId) -> Self {
        Self {
            name: name.into(),
            uid: Some(uid.into()),
            type_id: Some(type_id),
        }
    }

    /// A name-only identity (e.g. `anonymous`, or `unknown` when a rejected
    /// credential yielded no identity).
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            uid: None,
            type_id: Some(UserTypeId::Unknown),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_serializes_type_pair_and_round_trips() {
        let user = User::new("alice", "oidc|alice-123", UserTypeId::User);
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["name"], "alice");
        assert_eq!(json["uid"], "oidc|alice-123");
        assert_eq!(json["type_id"], 1);
        assert_eq!(json["type"], "User");

        let back: User = serde_json::from_value(json).unwrap();
        assert_eq!(back, user);
    }

    #[test]
    fn named_user_omits_uid() {
        let json = serde_json::to_value(User::named("anonymous")).unwrap();
        assert!(json.get("uid").is_none());
        assert_eq!(json["type_id"], 0);
    }

    #[test]
    fn emitted_user_matches_vendored_schema() {
        use crate::validation::schema::{
            load_object_schema, validate_enum_value, validate_required_fields,
        };

        let schema = load_object_schema("user");
        for user in [
            User::new("alice", "oidc|alice-123", UserTypeId::User),
            User::new("sandbox:sb-1", "sb-1", UserTypeId::Other),
            User::named("unknown"),
        ] {
            let json = serde_json::to_value(&user).unwrap();
            validate_required_fields(&json, &schema);
            validate_enum_value(&json, "type_id", &schema);
        }
    }
}
