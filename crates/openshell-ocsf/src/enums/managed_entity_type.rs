// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `managed_entity.type_id` enum.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Managed Entity Type ID.
///
/// `7 — Network Zone` exists only in 1.8.0 and is not modelled. The field
/// itself is absent from OCSF 1.1.0, so the schema downgrade strips it for
/// 1.1 targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum ManagedEntityTypeId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Device
    Device = 1,
    /// 2 — User
    User = 2,
    /// 3 — Group
    Group = 3,
    /// 4 — Organization
    Organization = 4,
    /// 5 — Policy
    Policy = 5,
    /// 6 — Email
    Email = 6,
    /// 99 — Other (platform resources: workspaces, providers, sandboxes, …)
    Other = 99,
}

impl ManagedEntityTypeId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Device => "Device",
            Self::User => "User",
            Self::Group => "Group",
            Self::Organization => "Organization",
            Self::Policy => "Policy",
            Self::Email => "Email",
            Self::Other => "Other",
        }
    }

    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_entity_type_json_roundtrip() {
        for (id, expected) in [
            (ManagedEntityTypeId::User, 2),
            (ManagedEntityTypeId::Policy, 5),
            (ManagedEntityTypeId::Other, 99),
        ] {
            let json = serde_json::to_value(id).unwrap();
            assert_eq!(json, serde_json::json!(expected));
            let decoded: ManagedEntityTypeId = serde_json::from_value(json).unwrap();
            assert_eq!(decoded, id);
        }
    }
}
