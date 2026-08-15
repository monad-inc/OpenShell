// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cost of the gateway's log fan-in, where every sandbox converges.
//!
//! One gateway serves many sandboxes, and every log line any of them produces
//! passes through `TracingLogBus::publish` before reaching OTLP export. That
//! makes this the point where per-sandbox cost becomes shared cost: if publish
//! serializes across sandboxes, adding sandboxes stops adding throughput.
//!
//! The scaling benchmark answers that directly. It holds total work constant and
//! varies how many threads (standing in for sandboxes) produce it, so perfect
//! scaling is a flat line and contention shows up as a rising one.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use openshell_core::proto::SandboxLogLine;
use openshell_server::tracing_bus::TracingLogBus;

/// Lines published per measured iteration, split across the producing threads.
const LINES_PER_ITER: usize = 2_000;

/// A sandbox-pushed OCSF line carrying flattened fields, as the supervisor
/// sends them today. `field_count` controls payload size: the gateway clones
/// this map several times per line, so its size drives fan-in cost.
fn ocsf_line(sandbox_id: &str, field_count: usize) -> SandboxLogLine {
    let mut fields = HashMap::with_capacity(field_count);
    for i in 0..field_count {
        fields.insert(
            format!("ocsf.field_{i}.nested_name"),
            format!("value-{i}-with-representative-length"),
        );
    }
    SandboxLogLine {
        sandbox_id: sandbox_id.to_string(),
        timestamp_ms: 1_742_054_400_000,
        level: "OCSF".to_string(),
        target: "ocsf".to_string(),
        message: "NET:OPEN [MED] DENIED /usr/bin/curl(64) -> blocked.invalid:443".to_string(),
        source: "sandbox".to_string(),
        fields,
    }
}

/// A raw-mode line: the whole event as one ~2 KB `ocsf.raw` JSON field plus
/// its severity, as `OPENSHELL_OCSF_PUSH_FORMAT=raw` pushes it. Field-map
/// clone cost collapses to two entries however large the event is.
fn raw_ocsf_line(sandbox_id: &str) -> SandboxLogLine {
    let mut line = ocsf_line(sandbox_id, 0);
    line.fields.insert(
        "ocsf.raw".to_string(),
        format!(
            "{{\"class_uid\":4001,\"severity_id\":3,\"padding\":\"{}\"}}",
            "x".repeat(2000)
        ),
    );
    line.fields
        .insert("ocsf.severity_id".to_string(), "3".to_string());
    line
}

/// Publish cost for a single line, by payload shape.
///
/// Isolates what the field map costs the gateway, separately from concurrency.
/// 0 fields is a pre-Phase-3 line; 46 matches a production denial pushed in
/// the default flattened format; `raw` is the same event pushed as one JSON
/// field.
fn bench_publish_by_payload(c: &mut Criterion) {
    let mut group = c.benchmark_group("gateway_publish");

    let mut cases: Vec<(String, SandboxLogLine)> = [0_usize, 10, 46, 100]
        .into_iter()
        .map(|count| (count.to_string(), ocsf_line("sb-0", count)))
        .collect();
    cases.push(("raw".to_string(), raw_ocsf_line("sb-0")));

    for (label, line) in cases {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(label), &line, |b, line| {
            // One long-lived bus, as the gateway has. Its tail fills to the
            // 2000-line cap and then evicts per publish, which is the
            // steady state a running gateway is in. Constructing a bus per
            // iteration instead would charge allocator churn to the cheap
            // payloads and invert the comparison.
            let bus = TracingLogBus::new();
            b.iter(|| bus.publish_external(black_box(line.clone())));
        });
    }
    group.finish();
}

/// Aggregate throughput as the number of concurrently-producing sandboxes grows.
///
/// Total work is fixed at `LINES_PER_ITER`, so if the bus scaled perfectly every
/// thread count would take the same wall time. Time rising with thread count is
/// contention on the shared bus, and it bounds how many busy sandboxes one
/// gateway can serve.
fn bench_fanin_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("gateway_fanin_scaling");
    group.sample_size(20);

    for sandboxes in [1_usize, 2, 4, 8, 16] {
        group.throughput(Throughput::Elements(LINES_PER_ITER as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(sandboxes),
            &sandboxes,
            |b, &sandboxes| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let bus = TracingLogBus::new();
                        let per_thread = LINES_PER_ITER / sandboxes;
                        // Each thread owns a distinct sandbox id, as real
                        // supervisors do, so any contention measured is the
                        // shared bus rather than same-key collisions.
                        let lines: Vec<SandboxLogLine> = (0..sandboxes)
                            .map(|i| ocsf_line(&format!("sb-{i}"), 46))
                            .collect();

                        let barrier = Arc::new(std::sync::Barrier::new(sandboxes));
                        let start = Instant::now();
                        std::thread::scope(|scope| {
                            for line in &lines {
                                let bus = bus.clone();
                                let barrier = Arc::clone(&barrier);
                                scope.spawn(move || {
                                    // Start together so the measurement covers
                                    // genuine overlap, not staggered ramp-up.
                                    barrier.wait();
                                    for _ in 0..per_thread {
                                        bus.publish_external(line.clone());
                                    }
                                });
                            }
                        });
                        total += start.elapsed();
                    }
                    total
                });
            },
        );
    }
    group.finish();
}

/// Confirms the fixture actually exercises the export tap rather than the
/// cheaper no-export path, so the numbers above describe the configuration
/// operators run with `export_logs = true`.
fn bench_publish_with_export_sink(c: &mut Criterion) {
    let counter = Arc::new(AtomicUsize::new(0));
    let line = ocsf_line("sb-export", 46);

    c.bench_function("gateway_publish_counted", |b| {
        let bus = TracingLogBus::new();
        let counter = Arc::clone(&counter);
        b.iter(|| {
            bus.publish_external(black_box(line.clone()));
            counter.fetch_add(1, Ordering::Relaxed);
        });
    });

    assert!(
        counter.load(Ordering::Relaxed) > 0,
        "publish benchmark never ran"
    );
}

criterion_group!(
    benches,
    bench_publish_by_payload,
    bench_fanin_scaling,
    bench_publish_with_export_sink
);
criterion_main!(benches);
