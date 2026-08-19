// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Entity Management [3004] activity ids.

use serde_repr::{Deserialize_repr, Serialize_repr};

/// OCSF Entity Management Activity ID (0-4, 99).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum EntityActivityId {
    /// 0 — Unknown
    Unknown = 0,
    /// 1 — Create
    Create = 1,
    /// 2 — Read
    Read = 2,
    /// 3 — Update
    Update = 3,
    /// 4 — Delete
    Delete = 4,
    /// 99 — Other
    Other = 99,
}

impl EntityActivityId {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Create => "Create",
            Self::Read => "Read",
            Self::Update => "Update",
            Self::Delete => "Delete",
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
    fn entity_activity_values_and_labels() {
        assert_eq!(EntityActivityId::Create.as_u8(), 1);
        assert_eq!(EntityActivityId::Delete.as_u8(), 4);
        assert_eq!(EntityActivityId::Update.label(), "Update");
        assert_eq!(EntityActivityId::Other.as_u8(), 99);
    }
}
