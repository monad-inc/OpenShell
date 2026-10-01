// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! JSONL formatter — full OCSF JSON output.

use crate::events::OcsfEvent;
use crate::format::downgrade::{downgrade_event, is_downgrade_target};

/// The downgrade target to apply, if any: `None`, an empty string, or a
/// version at or above [`crate::OCSF_VERSION`] mean "current schema".
fn effective_target(target_version: Option<&str>) -> Option<&str> {
    target_version.filter(|version| !version.is_empty() && is_downgrade_target(version))
}

/// Serialize an event to JSON at the requested schema version.
///
/// The single place every structured sink — the JSONL layers, the gateway
/// JSONL file and OTLP export (`ocsf.raw`, flattened `ocsf.*`) — renders an
/// event, so they can never disagree about the document for one event.
/// `target_version` is an OCSF version such as `"1.1"`; `None` or an empty
/// string keeps the current schema.
pub fn event_json(
    event: &OcsfEvent,
    target_version: Option<&str>,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut json = event.to_json()?;
    if let Some(target) = effective_target(target_version) {
        downgrade_event(&mut json, target);
    }
    Ok(json)
}

/// Serialize an event to a compact JSON string at the requested schema
/// version. Same document as [`event_json`]; skips the intermediate
/// `serde_json::Value` tree when no downgrade applies.
pub fn event_json_string(
    event: &OcsfEvent,
    target_version: Option<&str>,
) -> Result<String, serde_json::Error> {
    if effective_target(target_version).is_none() {
        return serde_json::to_string(event);
    }
    serde_json::to_string(&event_json(event, target_version)?)
}

impl OcsfEvent {
    /// Serialize to a `serde_json::Value`.
    ///
    /// Returns the full OCSF JSON object, or an error if serialization fails.
    pub fn to_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    /// Serialize as a single JSONL line (no pretty-printing, trailing newline).
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        let mut line = serde_json::to_string(self)?;
        line.push('\n');
        Ok(line)
    }
}

#[cfg(test)]
mod tests {
    use crate::enums::SeverityId;
    use crate::events::base_event::BaseEventData;
    use crate::events::{BaseEvent, OcsfEvent};
    use crate::objects::{Metadata, Product};

    fn test_event() -> OcsfEvent {
        let mut base = BaseEventData::new(
            0,
            "Base Event",
            0,
            "Uncategorized",
            99,
            "Other",
            SeverityId::Informational,
            Metadata {
                version: "1.8.0".to_string(),
                product: Product::openshell_sandbox("0.1.0"),
                profiles: vec!["container".to_string()],
                uid: Some("sandbox-abc123".to_string()),
                log_source: None,
            },
        );
        base.set_time(1_742_054_400_000);
        base.set_message("Test event");
        OcsfEvent::Base(BaseEvent { base })
    }

    #[test]
    fn test_to_json_has_required_fields() {
        let event = test_event();
        let json = event.to_json().unwrap();

        assert_eq!(json["class_uid"], 0);
        assert_eq!(json["class_name"], "Base Event");
        assert_eq!(json["category_uid"], 0);
        assert_eq!(json["activity_id"], 99);
        assert_eq!(json["type_uid"], 99);
        assert_eq!(json["time"], 1_742_054_400_000_i64);
        assert_eq!(json["severity_id"], 1);
        assert_eq!(json["severity"], "Informational");
        assert_eq!(json["metadata"]["version"], "1.8.0");
    }

    #[test]
    fn test_to_json_line_format() {
        let event = test_event();
        let line = event.to_json_line().unwrap();

        // Must be a single line ending with \n
        assert!(line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);

        // Must parse back to the same JSON
        let parsed: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(parsed, event.to_json().unwrap());
    }

    #[test]
    fn test_optional_fields_omitted() {
        let event = test_event();
        let json = event.to_json().unwrap();

        // Optional fields should not appear when None
        assert!(json.get("device").is_none());
        assert!(json.get("container").is_none());
        assert!(json.get("unmapped").is_none());
        assert!(json.get("status_detail").is_none());
    }

    #[test]
    fn event_json_string_matches_event_json_at_every_target() {
        let event = test_event();
        for target in [
            None,
            Some(""),
            Some("1.1"),
            Some("1.3"),
            Some(crate::OCSF_VERSION),
        ] {
            let tree = super::event_json(&event, target).unwrap();
            let text = super::event_json_string(&event, target).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(parsed, tree, "target {target:?}");
        }
        let downgraded = super::event_json(&event, Some("1.1")).unwrap();
        assert_eq!(downgraded["metadata"]["version"], "1.1");
        let current = super::event_json(&event, Some("")).unwrap();
        assert_eq!(current, event.to_json().unwrap());
    }
}
