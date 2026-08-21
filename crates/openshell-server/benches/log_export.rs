// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cost of the gateway's OTLP export stage, where every sandbox's lines drain.
//!
//! The fan-in benchmark (`log_fanin`) measures the bus every line crosses; this
//! one measures what happens after the export tap: converting a line into an
//! OTLP log record and driving batches through the export worker. Together they
//! bound how many lines per second one gateway can ship off-box, which is the
//! number that decides when to scale gateways instead of adding sandboxes.
//!
//! Payload shape is the variable that matters. An OCSF event arrives either as
//! ~46 flattened `ocsf.*` fields or as one raw JSON field
//! (`OPENSHELL_OCSF_PUSH_FORMAT=raw`), and the conversion cost is dominated by
//! how many attribute strings the record carries, not by their total bytes.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use openshell_core::proto::SandboxLogLine;
use openshell_server::log_export;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::{LogBatch, LogExporter, SdkLoggerProvider};

/// Lines pushed through the pipeline per measured iteration. Fits inside the
/// worker's ingest queue so the measurement is pure drain rate, never
/// drop accounting.
const LINES_PER_ITER: usize = 32_768;

/// A sandbox-pushed OCSF line with its schema flattened into dotted fields, as
/// `OPENSHELL_OCSF_PUSH_FORMAT=flat` sends it. 46 fields matches a production
/// denial.
fn flattened_line(field_count: usize) -> SandboxLogLine {
    let mut fields = HashMap::with_capacity(field_count);
    for i in 0..field_count {
        fields.insert(
            format!("ocsf.field_{i}.nested_name"),
            format!("value-{i}-with-representative-length"),
        );
    }
    fields.insert("ocsf.severity_id".to_string(), "3".to_string());
    ocsf_line(fields)
}

/// The same event pushed as one raw JSON field plus the severity, as the
/// default push format sends it. The JSON body is sized like a
/// production denial (~2 KB), so the comparison holds bytes roughly constant
/// while collapsing the attribute count.
fn raw_line() -> SandboxLogLine {
    let payload = serde_json::json!({
        "activity_id": 1,
        "category_uid": 4,
        "class_uid": 4001,
        "severity_id": 3,
        "time": 1_742_054_400_000_i64,
        "message": "CONNECT denied blocked.invalid:443",
        "status_detail": "endpoint blocked.invalid:443 is not allowed by any policy",
        "dst_endpoint": {"hostname": "blocked.invalid", "port": 443},
        "src_endpoint": {"ip": "10.200.0.2", "port": 48744},
        "actor": {"process": {
            "name": "curl",
            "pid": 64,
            "file": {"path": "/usr/bin/curl"},
            "cmd_line": "curl -sS https://blocked.invalid",
            "parent_process": {"name": "bash", "file": {"path": "/usr/bin/bash"}},
        }},
        "firewall_rule": {"name": "-", "type": "opa"},
        "metadata": {
            "version": "1.7.0",
            "uid": "sandbox-abc123",
            "profiles": ["container", "host"],
            "product": {"name": "OpenShell Sandbox", "vendor_name": "NVIDIA", "version": "0.1.0"},
        },
        "padding": "x".repeat(600),
    });
    let mut fields = HashMap::with_capacity(2);
    fields.insert("ocsf.raw".to_string(), payload.to_string());
    fields.insert("ocsf.severity_id".to_string(), "3".to_string());
    ocsf_line(fields)
}

fn ocsf_line(fields: HashMap<String, String>) -> SandboxLogLine {
    SandboxLogLine {
        sandbox_id: "sb-0".to_string(),
        timestamp_ms: 1_742_054_400_000,
        level: "OCSF".to_string(),
        target: "ocsf".to_string(),
        message: "NET:OPEN [MED] DENIED /usr/bin/curl(64) -> blocked.invalid:443".to_string(),
        source: "sandbox".to_string(),
        fields,
    }
}

/// Every payload shape the pipeline benchmarks run over.
fn shapes() -> Vec<(&'static str, SandboxLogLine)> {
    vec![
        ("plain", ocsf_line(HashMap::new())),
        ("flattened_46", flattened_line(46)),
        ("raw_json", raw_line()),
    ]
}

/// Counts exported records and discards them: the SDK/tonic wire cost is not
/// this crate's code, so the benchmark stops at the exporter boundary.
#[derive(Debug, Clone)]
struct CountingExporter(Arc<AtomicUsize>);

impl LogExporter for CountingExporter {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        self.0.fetch_add(batch.iter().count(), Ordering::Relaxed);
        Ok(())
    }
}

/// Conversion cost of one line into an OTLP record, by payload shape.
///
/// This runs once per line on the worker, so at 100k lines/s each microsecond
/// here is 10% of a core.
fn bench_record_conversion(c: &mut Criterion) {
    let factory = SdkLoggerProvider::builder().build();
    let logger = openshell_otel::logger(&factory, "bench");

    let mut group = c.benchmark_group("export_record_for");
    for (name, line) in shapes() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(name), &line, |b, line| {
            // The conversion consumes its line, so each measurement gets a
            // fresh clone built outside the timed section.
            b.iter_batched(
                || line.clone(),
                |line| black_box(log_export::record_for(&logger, line, true)),
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Drain rate of the full export pipeline: enqueue → batch → convert → export.
///
/// One burst of `LINES_PER_ITER` lines is enqueued and the measurement runs
/// until the exporter has seen them all, so the number is the worker's
/// sustained lines-per-second ceiling for that payload shape.
fn bench_pipeline_throughput(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("bench runtime");

    let mut group = c.benchmark_group("export_pipeline");
    group.sample_size(10);

    for (name, line) in shapes() {
        group.throughput(Throughput::Elements(LINES_PER_ITER as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &line, |b, line| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let delivered = Arc::new(AtomicUsize::new(0));
                    let exporter = CountingExporter(Arc::clone(&delivered));
                    let (handle, worker) = runtime.block_on(async {
                        log_export::spawn(exporter, Resource::builder_empty().build(), true)
                    });

                    let start = Instant::now();
                    for _ in 0..LINES_PER_ITER {
                        handle.enqueue(line.clone());
                    }
                    while delivered.load(Ordering::Relaxed) < LINES_PER_ITER {
                        std::thread::yield_now();
                    }
                    total += start.elapsed();

                    runtime.block_on(worker.shutdown());
                }
                total
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_record_conversion, bench_pipeline_throughput);
criterion_main!(benches);
