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

/// Key carrying the complete event JSON when the sandbox pushes raw form.
///
/// The value is the same document the JSONL formatter writes — nothing
/// flattened, joined, or truncated — so a collector can parse it back into
/// full structure downstream (e.g. with OTTL's `ParseJSON`).
pub const RAW_KEY: &str = "ocsf.raw";

/// Max length of a single flattened value before truncation.
///
/// Event text is operator- and workload-influenced (a denial reason carries a
/// destination endpoint and policy name; a process event carries a command
/// line), so a single field must not be able to dominate a log record. Matches
/// the shorthand reason budget.
const MAX_VALUE_LEN: usize = 256;

/// Leaf count of a representative production event, used to size the output map
/// so filling it does not rehash. Overshooting costs a little memory per event;
/// undershooting costs repeated reallocation on the sandbox's hot path.
const TYPICAL_FIELD_COUNT: usize = 48;

/// Longest key path seen in practice (`ocsf.actor.process.parent_process…`),
/// used to size the scratch buffer so the walk never reallocates it.
const TYPICAL_KEY_LEN: usize = 64;

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
    let Ok(value) = event.to_json() else {
        return HashMap::new();
    };
    // A production event flattens to roughly this many leaves; sizing up front
    // avoids rehashing the map several times while filling it.
    let mut out = HashMap::with_capacity(TYPICAL_FIELD_COUNT);
    let mut path = String::with_capacity(TYPICAL_KEY_LEN);
    path.push_str(KEY_PREFIX);
    flatten_value(&mut path, &value, &mut out);
    out
}

/// Render an OCSF event as raw push fields: the complete event JSON under
/// [`RAW_KEY`] plus [`SEVERITY_ID_KEY`], so the gateway can rank the record
/// without parsing the document.
///
/// This is the cheap, full-fidelity alternative to [`flatten_event`]: one
/// serialization and two map entries instead of ~46, with no per-value
/// truncation. The cost moves downstream — a consumer that wants individual
/// fields parses the JSON after the collector receives it.
///
/// Returns an empty map when the event cannot be serialized, matching
/// [`flatten_event`]: losing structure must not cost the caller the event.
#[must_use]
pub fn raw_event_fields(event: &OcsfEvent) -> HashMap<String, String> {
    let Ok(json) = serde_json::to_string(event) else {
        return HashMap::new();
    };
    let mut out = HashMap::with_capacity(2);
    out.insert(RAW_KEY.to_string(), json);
    out.insert(
        SEVERITY_ID_KEY.to_string(),
        event.base().severity.as_u8().to_string(),
    );
    out
}

/// Recursively flatten `value` into `out` under the key currently in `path`.
///
/// `path` is a scratch buffer that grows and rewinds as the walk descends and
/// returns, so each nested level costs a push and a truncate rather than a fresh
/// allocation. Only leaves allocate, and only for the key they keep.
fn flatten_value(path: &mut String, value: &serde_json::Value, out: &mut HashMap<String, String>) {
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::Object(map) => {
            let base = path.len();
            for (name, child) in map {
                path.push('.');
                path.push_str(name);
                flatten_value(path, child, out);
                path.truncate(base);
            }
        }
        serde_json::Value::Array(items) => flatten_array(path, items, out),
        scalar => {
            let mut rendered = String::new();
            push_scalar(&mut rendered, scalar);
            out.insert(path.clone(), truncate(rendered));
        }
    }
}

/// Flatten an array, joining scalars and indexing everything else.
fn flatten_array(
    path: &mut String,
    items: &[serde_json::Value],
    out: &mut HashMap<String, String>,
) {
    if items.is_empty() {
        return;
    }
    if items
        .iter()
        .all(|item| !item.is_object() && !item.is_array())
    {
        let mut joined = String::new();
        for item in items.iter().filter(|item| !item.is_null()) {
            if !joined.is_empty() {
                joined.push(',');
            }
            push_scalar(&mut joined, item);
        }
        if !joined.is_empty() {
            out.insert(path.clone(), truncate(joined));
        }
        return;
    }
    let base = path.len();
    let mut index_buf = itoa::Buffer::new();
    for (index, item) in items.iter().enumerate() {
        path.push('.');
        path.push_str(index_buf.format(index));
        flatten_value(path, item, out);
        path.truncate(base);
    }
}

/// Append a JSON scalar to `out` without the quoting `to_string` adds to
/// strings, and without allocating a temporary for numbers.
fn push_scalar(out: &mut String, value: &serde_json::Value) {
    match value {
        serde_json::Value::String(text) => out.push_str(text),
        serde_json::Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        serde_json::Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                out.push_str(itoa::Buffer::new().format(int));
            } else if let Some(float) = number.as_f64() {
                out.push_str(ryu::Buffer::new().format(float));
            } else {
                out.push_str(&number.to_string());
            }
        }
        // Null is filtered before this point; objects and arrays never reach it.
        other => out.push_str(&other.to_string()),
    }
}

/// Cut `value` to [`MAX_VALUE_LEN`] characters, marking the cut.
///
/// Takes ownership so the overwhelmingly common short value is returned
/// untouched rather than copied. The byte-length check is a fast path: a string
/// short enough in bytes is always short enough in characters, which avoids
/// walking the string at all for the usual case.
fn truncate(value: String) -> String {
    if value.len() <= MAX_VALUE_LEN {
        return value;
    }
    if value.chars().count() <= MAX_VALUE_LEN {
        return value;
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
        flatten_value(&mut "ocsf.affected".to_string(), &value, &mut out);

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
        flatten_value(&mut "ocsf".to_string(), &value, &mut out);

        assert_eq!(out.len(), 1);
        assert_eq!(out.get("ocsf.kept").map(String::as_str), Some("1"));
    }

    #[test]
    fn raw_fields_carry_the_complete_event_and_its_severity() {
        let event = test_event();
        let fields = raw_event_fields(&event);

        assert_eq!(fields.len(), 2);
        // The raw value round-trips to exactly the document the JSONL
        // formatter writes — full fidelity is the contract.
        let raw = fields.get(RAW_KEY).expect("raw payload present");
        let parsed: serde_json::Value = serde_json::from_str(raw).expect("raw is valid JSON");
        assert_eq!(parsed, event.to_json().unwrap());
        // The severity travels beside it under the same key the flattened
        // form uses, so the gateway ranks both forms identically.
        assert_eq!(fields.get(SEVERITY_ID_KEY).map(String::as_str), Some("3"));
    }

    #[test]
    fn raw_fields_do_not_truncate_long_values() {
        let mut base = match test_event() {
            OcsfEvent::Base(event) => event.base,
            other => panic!("unexpected variant: {other:?}"),
        };
        let long_message = "x".repeat(MAX_VALUE_LEN * 4);
        base.set_message(&long_message);
        let event = OcsfEvent::Base(BaseEvent { base });

        let fields = raw_event_fields(&event);
        let parsed: serde_json::Value = serde_json::from_str(fields.get(RAW_KEY).unwrap()).unwrap();
        assert_eq!(
            parsed.get("message").and_then(|m| m.as_str()),
            Some(long_message.as_str()),
            "raw form must never truncate"
        );
    }

    #[test]
    fn long_values_are_truncated_and_marked() {
        let mut out = HashMap::new();
        let long = "x".repeat(MAX_VALUE_LEN + 50);
        flatten_value(
            &mut "ocsf".to_string(),
            &serde_json::json!({ "reason": long }),
            &mut out,
        );

        let stored = out.get("ocsf.reason").expect("reason kept");
        assert_eq!(stored.chars().count(), MAX_VALUE_LEN + 1);
        assert!(stored.ends_with(TRUNCATION_SUFFIX));
    }

    #[test]
    fn truncation_does_not_split_a_multibyte_character() {
        let mut out = HashMap::new();
        // Truncating by bytes here would panic or produce invalid UTF-8.
        let long = "é".repeat(MAX_VALUE_LEN + 10);
        flatten_value(
            &mut "ocsf".to_string(),
            &serde_json::json!({ "reason": long }),
            &mut out,
        );

        let stored = out.get("ocsf.reason").expect("reason kept");
        assert_eq!(stored.chars().count(), MAX_VALUE_LEN + 1);
        assert!(stored.starts_with('é'));
    }
}
