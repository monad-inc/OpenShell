// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cost of rendering an OCSF event, measured on the sandbox's logging hot path.
//!
//! A sandbox renders every security event inline in `on_event`, before the line
//! reaches the push queue. Whatever this costs is charged to the workload that
//! triggered the event — a denied connection pays for its own audit record — so
//! these numbers bound how much observability slows a sandbox down.
//!
//! The fixture is a policy denial with full process ancestry and container
//! context, matching what the proxy emits in production (~46 fields). Cheaper
//! fixtures would understate every number here.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use openshell_ocsf::enums::{ActionId, ActivityId, DispositionId, SeverityId, StatusId};
use openshell_ocsf::format::attributes::{flatten_event, raw_event_fields};
use openshell_ocsf::objects::{Endpoint, Process};
use openshell_ocsf::{NetworkActivityBuilder, OcsfEvent};

/// A policy denial carrying the context the proxy attaches in production.
fn denial_event() -> OcsfEvent {
    NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::Medium)
        .status(StatusId::Failure)
        .dst_endpoint(Endpoint::from_domain("blocked.invalid", 443))
        .src_endpoint_addr("10.200.0.2".parse().unwrap(), 48744)
        .actor_process(
            Process::from_bypass(
                "/usr/bin/curl",
                "64",
                "/usr/bin/bash,/usr/bin/containerd-shim",
            )
            .with_cmd_line("curl -sS https://blocked.invalid"),
        )
        .firewall_rule("-", "opa")
        .message("CONNECT denied blocked.invalid:443")
        .status_detail("endpoint blocked.invalid:443 is not allowed by any policy")
        .build()
}

/// A supervisor lifecycle event: the small end of the size range.
fn small_event() -> OcsfEvent {
    NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .dst_endpoint(Endpoint::from_domain("api.github.com", 443))
        .message("CONNECT allowed api.github.com:443")
        .build()
}

fn bench_rendering(c: &mut Criterion) {
    let denial = denial_event();
    let small = small_event();

    // Sanity: the fixture must be the size we claim to be measuring.
    let field_count = flatten_event(&denial).len();
    assert!(
        field_count >= 40,
        "denial fixture flattened to only {field_count} fields; \
         it no longer represents a production event"
    );

    let mut group = c.benchmark_group("sandbox_hot_path");

    // The pre-Phase-3 cost: shorthand only, what every event paid before
    // structured fields existed.
    group.bench_function("shorthand_only", |b| {
        b.iter(|| black_box(black_box(&denial).format_shorthand()));
    });

    // The Phase 3 addition, in isolation.
    group.bench_function("flatten_only", |b| {
        b.iter(|| black_box(flatten_event(black_box(&denial))));
    });

    // What a sandbox actually pays per security event today.
    group.bench_function("shorthand_and_flatten", |b| {
        b.iter(|| {
            let event = black_box(&denial);
            black_box((event.format_shorthand(), flatten_event(event)))
        });
    });

    // The raw default push format, in isolation. One serialization and two
    // map entries; compare against `flatten_only`.
    group.bench_function("raw_fields_only", |b| {
        b.iter(|| black_box(raw_event_fields(black_box(&denial))));
    });

    // What a sandbox pays per security event in raw mode.
    group.bench_function("shorthand_and_raw_fields", |b| {
        b.iter(|| {
            let event = black_box(&denial);
            black_box((event.format_shorthand(), raw_event_fields(event)))
        });
    });

    // JSONL is the existing full-fidelity renderer, as a reference point for
    // whether flattening is unusually expensive or just the cost of serializing.
    group.bench_function("jsonl_line", |b| {
        b.iter(|| black_box(black_box(&denial).to_json_line().unwrap()));
    });

    // Splits flattening into its two halves. `to_json` builds an intermediate
    // `serde_json::Value` tree that flattening then walks and discards; if this
    // dominates, the fix is to skip the tree rather than to tune the walk.
    group.bench_function("to_json_value_only", |b| {
        b.iter(|| black_box(black_box(&denial).to_json().unwrap()));
    });

    // Small events dominate by count in a quiet sandbox; large ones dominate
    // cost in a busy one. Both bound the range.
    group.bench_function("flatten_small_event", |b| {
        b.iter(|| black_box(flatten_event(black_box(&small))));
    });

    group.finish();
}

criterion_group!(benches, bench_rendering);
criterion_main!(benches);
