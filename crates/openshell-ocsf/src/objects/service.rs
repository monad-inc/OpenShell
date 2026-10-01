// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF Service object.

use serde::{Deserialize, Serialize};

/// OCSF Service object — the service an authentication targets.
///
/// The schema requires at least one of `name` or `uid`; `name` is always set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    /// Service name (e.g. `openshell-gateway`).
    pub name: String,

    /// Stable unique identifier (e.g. the operator-assigned gateway name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Service version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl Service {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            uid: None,
            version: None,
        }
    }

    /// Attach a stable identifier.
    #[must_use]
    pub fn with_uid(mut self, uid: impl Into<String>) -> Self {
        self.uid = Some(uid.into());
        self
    }

    /// Attach a version.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_matches_vendored_schema_and_round_trips() {
        use crate::validation::schema::{load_object_schema, validate_required_fields};

        let service = Service::new("openshell-gateway")
            .with_uid("production")
            .with_version("0.1.3");
        let json = serde_json::to_value(&service).unwrap();
        validate_required_fields(&json, &load_object_schema("service"));
        assert_eq!(json["name"], "openshell-gateway");
        let back: Service = serde_json::from_value(json).unwrap();
        assert_eq!(back, service);
    }
}
