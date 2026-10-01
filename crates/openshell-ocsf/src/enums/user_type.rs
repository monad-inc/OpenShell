// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `user.type_id` enum.

use serde::{Deserialize, Serialize};

/// OCSF User Type ID.
///
/// Only the values valid in every schema version `OpenShell` can downgrade to
/// (1.1, 1.3, 1.8) are modelled. OCSF 1.8.0 adds `4 — Service`, which 1.1 and
/// 1.3 reject, so service principals (sandbox supervisors, the gateway itself)
/// use [`UserTypeId::Other`] and no downgrade remap is needed.
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

    /// Map a wire value back to a type. Values this crate does not model
    /// (e.g. 1.8.0's `4 — Service` from another producer) decode as
    /// [`UserTypeId::Unknown`] rather than failing the whole event.
    #[must_use]
    pub fn from_u8(id: u8) -> Self {
        match id {
            1 => Self::User,
            2 => Self::Admin,
            3 => Self::System,
            99 => Self::Other,
            _ => Self::Unknown,
        }
    }
}

impl Serialize for UserTypeId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for UserTypeId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u8::deserialize(deserializer).map(Self::from_u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_type_values_and_labels() {
        assert_eq!(UserTypeId::User.as_u8(), 1);
        assert_eq!(UserTypeId::Other.as_u8(), 99);
        assert_eq!(UserTypeId::Admin.label(), "Admin");
    }

    #[test]
    fn unmodelled_values_decode_as_unknown() {
        let decoded: UserTypeId = serde_json::from_value(serde_json::json!(4)).unwrap();
        assert_eq!(decoded, UserTypeId::Unknown);
        let decoded: UserTypeId = serde_json::from_value(serde_json::json!(99)).unwrap();
        assert_eq!(decoded, UserTypeId::Other);
    }
}
