// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF User object.

use serde::{Deserialize, Serialize};

/// OCSF User Type ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum UserTypeId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — User
    User = 1,
    /// 2 — Admin
    Admin = 2,
    /// 3 — System
    System = 3,
    /// 99 — Other (service principals such as sandbox supervisors)
    Other = 99,
}

impl UserTypeId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::User => "User",
            Self::Admin => "Admin",
            Self::System => "System",
            Self::Other => "Other",
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// OCSF User object — an authenticated identity acting on or affected by an
/// event.
///
/// Serialized with the OCSF `type_id`/`type` pair when a type is set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct User {
    /// Human-readable name (display name, username, or the uid when no
    /// friendlier form exists).
    pub name: String,

    /// Stable unique identifier (OIDC `sub`, certificate CN, sandbox id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// User type, when known.
    #[serde(rename = "type_id", default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_user_type", alias = "type_id")]
    pub type_id: Option<UserTypeId>,
}

fn deserialize_user_type<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<UserTypeId>, D::Error> {
    let value = Option::<u8>::deserialize(deserializer)?;
    Ok(value.map(|id| match id {
        1 => UserTypeId::User,
        2 => UserTypeId::Admin,
        3 => UserTypeId::System,
        99 => UserTypeId::Other,
        _ => UserTypeId::Unknown,
    }))
}

impl Serialize for User {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut len = 1;
        if self.uid.is_some() {
            len += 1;
        }
        if self.type_id.is_some() {
            len += 2;
        }
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

    /// A name-only identity (e.g. `anonymous`).
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
}
