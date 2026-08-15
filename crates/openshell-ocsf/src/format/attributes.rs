// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Attribute formatter — OCSF events as flat key/value pairs.
//!
//! The shorthand formatter renders an event for a human reading a log, and the
//! JSONL formatter renders the whole event as one nested document. Neither fits
//! a transport whose unit is a flat string map: the sandbox pushes log lines to
//! the gateway as `map<string, string>` fields, and the gateway turns those into
//! OTLP log-record attributes.
//!
//! Flattening bridges that gap, so a SIEM can match `ocsf.dst_endpoint.port`
//! instead of pattern-matching a rendered line.

use std::collections::HashMap;

use crate::events::OcsfEvent;

/// Namespace for every key produced here.
///
/// Keeps flattened event data from colliding with the `log.*` and `sandbox.id`
/// attributes the gateway attaches to the same record.
const KEY_PREFIX: &str = "ocsf";

/// Key carrying the event's OCSF `severity_id` in a flattened event.
///
/// Exported so a consumer can rank events by the severity the emitter
/// assigned, rather than recovering it from the rendered line. A test pins
/// this to what [`flatten_event`] actually produces.
pub const SEVERITY_ID_KEY: &str = "ocsf.severity_id";

/// Max length of a single flattened value before truncation.
///
/// Event text is operator- and workload-influenced (a denial reason carries a
/// destination endpoint and policy name; a process event carries a command
/// line), so a single field must not be able to dominate a log record. Matches
/// the shorthand reason budget.
const MAX_VALUE_LEN: usize = 256;

/// Marker appended to a value cut at [`MAX_VALUE_LEN`], so a consumer can tell
/// truncation from a value that happened to end there.
const TRUNCATION_SUFFIX: &str = "…";

/// Flatten an OCSF event into dotted `ocsf.*` key/value pairs.
///
/// Nested objects join with `.` (`ocsf.dst_endpoint.port`). Arrays of scalars
/// join with `,` on one key, since OCSF uses them for small tag-like sets such
/// as `metadata.profiles`; arrays of objects index instead
/// (`ocsf.affected.0.name`) because their elements are individually meaningful.
/// Nulls are dropped rather than exported as empty strings.
///
/// Returns an empty map when the event cannot be serialized. Losing structure
/// must not cost the caller the event itself — the rendered line still carries
/// it, and this is a diagnostic path.
#[must_use]
pub fn flatten_event(event: &OcsfEvent) -> HashMap<String, String> {
    let mut out = HashMap::new();
    match event.to_json() {
        Ok(value) => flatten_value(KEY_PREFIX, &value, &mut out),
        Err(_) => return out,
    }
    out
}

/// Recursively flatten `value` into `out` under `key`.
fn flatten_value(key: &str, value: &serde_json::Value, out: &mut HashMap<String, String>) {
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::Object(map) => {
            for (name, child) in map {
                flatten_value(&format!("{key}.{name}"), child, out);
            }
        }
        serde_json::Value::Array(items) => flatten_array(key, items, out),
        scalar => {
            out.insert(key.to_string(), truncate(&scalar_to_string(scalar)));
        }
    }
}

/// Flatten an array, joining scalars and indexing everything else.
fn flatten_array(key: &str, items: &[serde_json::Value], out: &mut HashMap<String, String>) {
    if items.is_empty() {
        return;
    }
    if items
        .iter()
        .all(|item| !item.is_object() && !item.is_array())
    {
        let joined = items
            .iter()
            .filter(|item| !item.is_null())
            .map(scalar_to_string)
            .collect::<Vec<_>>()
            .join(",");
        if !joined.is_empty() {
            out.insert(key.to_string(), truncate(&joined));
        }
        return;
    }
    for (index, item) in items.iter().enumerate() {
        flatten_value(&format!("{key}.{index}"), item, out);
    }
}

/// Render a JSON scalar without the quoting `to_string` would add to strings.
fn scalar_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// Cut `value` to [`MAX_VALUE_LEN`] on a character boundary, marking the cut.
fn truncate(value: &str) -> String {
    if value.chars().count() <= MAX_VALUE_LEN {
        return value.to_string();
    }
    let mut cut: String = value.chars().take(MAX_VALUE_LEN).collect();
    cut.push_str(TRUNCATION_SUFFIX);
    cut
}

#[cfg(test)]
mod tests {
    use super::*;
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
            SeverityId::Medium,
            Metadata {
                version: "1.7.0".to_string(),
                product: Product::openshell_sandbox("0.1.0"),
                profiles: vec!["container".to_string(), "host".to_string()],
                uid: Some("sandbox-abc123".to_string()),
                log_source: None,
            },
        );
        base.set_time(1_742_054_400_000);
        base.set_message("Test event");
        OcsfEvent::Base(BaseEvent { base })
    }

    #[test]
    fn scalars_and_nested_objects_flatten_under_the_ocsf_prefix() {
        let fields = flatten_event(&test_event());

        assert_eq!(fields.get("ocsf.class_uid").map(String::as_str), Some("0"));
        // Pins SEVERITY_ID_KEY to the key flattening actually emits; the
        // gateway ranks events by it.
        assert_eq!(fields.get(SEVERITY_ID_KEY).map(String::as_str), Some("3"));
        // Nested object, not a JSON blob under one key.
        assert_eq!(
            fields.get("ocsf.metadata.version").map(String::as_str),
            Some("1.7.0")
        );
        // Strings arrive unquoted so a consumer can match them directly.
        assert_eq!(
            fields.get("ocsf.class_name").map(String::as_str),
            Some("Base Event")
        );
        assert!(fields.keys().all(|key| key.starts_with("ocsf.")));
    }

    #[test]
    fn scalar_arrays_join_on_one_key() {
        let fields = flatten_event(&test_event());
        assert_eq!(
            fields.get("ocsf.metadata.profiles").map(String::as_str),
            Some("container,host")
        );
    }

    #[test]
    fn object_arrays_are_indexed() {
        let mut out = HashMap::new();
        let value = serde_json::json!([{"name": "a"}, {"name": "b"}]);
        flatten_value("ocsf.affected", &value, &mut out);

        assert_eq!(
            out.get("ocsf.affected.0.name").map(String::as_str),
            Some("a")
        );
        assert_eq!(
            out.get("ocsf.affected.1.name").map(String::as_str),
            Some("b")
        );
    }

    #[test]
    fn nulls_and_empty_arrays_produce_no_keys() {
        let mut out = HashMap::new();
        let value = serde_json::json!({"absent": null, "none": [], "kept": 1});
        flatten_value("ocsf", &value, &mut out);

        assert_eq!(out.len(), 1);
        assert_eq!(out.get("ocsf.kept").map(String::as_str), Some("1"));
    }

    #[test]
    fn long_values_are_truncated_and_marked() {
        let mut out = HashMap::new();
        let long = "x".repeat(MAX_VALUE_LEN + 50);
        flatten_value("ocsf", &serde_json::json!({ "reason": long }), &mut out);

        let stored = out.get("ocsf.reason").expect("reason kept");
        assert_eq!(stored.chars().count(), MAX_VALUE_LEN + 1);
        assert!(stored.ends_with(TRUNCATION_SUFFIX));
    }

    #[test]
    fn truncation_does_not_split_a_multibyte_character() {
        let mut out = HashMap::new();
        // Truncating by bytes here would panic or produce invalid UTF-8.
        let long = "é".repeat(MAX_VALUE_LEN + 10);
        flatten_value("ocsf", &serde_json::json!({ "reason": long }), &mut out);

        let stored = out.get("ocsf.reason").expect("reason kept");
        assert_eq!(stored.chars().count(), MAX_VALUE_LEN + 1);
        assert!(stored.starts_with('é'));
    }
}
