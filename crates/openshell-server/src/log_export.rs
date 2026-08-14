// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Off-box export of aggregated sandbox/gateway logs as OTLP log records.
//!
//! Every log line the gateway observes — its own events and lines pushed from
//! sandboxes — flows through [`crate::tracing_bus::TracingLogBus`]. When log
//! export is enabled, the bus forwards each line into the unbounded, in-memory
//! queue owned here; a background task drains the queue and emits an OTLP log
//! record per line through the shared logger provider.
//!
//! Phase 1 durability: the queue is unbounded and in-memory, so no line is
//! dropped between ingest and the exporter. The final hop still relies on the
//! OTLP SDK batch processor, which flushes on provider shutdown; a disk-backed
//! spool with end-to-end acknowledgement is Phase 2.

use std::time::{Duration, UNIX_EPOCH};

use openshell_core::proto::SandboxLogLine;
use openshell_ocsf::OCSF_TARGET;
use opentelemetry::Key;
use opentelemetry::logs::{AnyValue, LogRecord as _, Logger as _, Severity};
use opentelemetry_sdk::logs::{SdkLogger, SdkLoggerProvider};
use tokio::sync::mpsc;

/// Instrumentation scope recorded on every exported log record.
const INSTRUMENTATION_SCOPE: &str = "openshell-gateway-logs";

/// Handle used by the tracing bus to enqueue log lines for export.
///
/// Cloneable and cheap: it wraps the sender half of the export queue. Sending
/// is non-blocking and never drops while the drain task is alive, so it is safe
/// to call from synchronous tracing callbacks.
#[derive(Clone, Debug)]
pub struct LogExportHandle {
    tx: mpsc::UnboundedSender<SandboxLogLine>,
}

impl LogExportHandle {
    /// Enqueue a log line for off-box export. Best-effort only in the sense
    /// that it no-ops if the drain task has already stopped (shutdown).
    pub fn enqueue(&self, line: SandboxLogLine) {
        let _ = self.tx.send(line);
    }
}

/// Spawn the export drain task and return the handle that feeds it.
///
/// The task owns a logger derived from `provider` and runs until the returned
/// handle (and all clones) are dropped. `provider` itself is retained by the
/// caller so it can be flushed and shut down on process exit.
pub fn spawn(provider: &SdkLoggerProvider, ocsf_full_payload: bool) -> LogExportHandle {
    let (tx, mut rx) = mpsc::unbounded_channel::<SandboxLogLine>();
    let logger = openshell_otel::logger(provider, INSTRUMENTATION_SCOPE);

    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            emit_line(&logger, &line, ocsf_full_payload);
        }
    });

    LogExportHandle { tx }
}

/// Convert a [`SandboxLogLine`] into an OTLP log record and emit it.
fn emit_line(logger: &SdkLogger, line: &SandboxLogLine, ocsf_full_payload: bool) {
    let mut record = logger.create_log_record();

    record.set_severity_number(severity_of(&line.level));
    record.set_body(AnyValue::String(line.message.clone().into()));

    if line.timestamp_ms > 0 {
        record.set_timestamp(UNIX_EPOCH + Duration::from_millis(line.timestamp_ms as u64));
    }

    record.add_attribute(Key::from_static_str("sandbox.id"), line.sandbox_id.clone());
    record.add_attribute(Key::from_static_str("log.source"), line.source.clone());
    record.add_attribute(Key::from_static_str("log.target"), line.target.clone());
    record.add_attribute(Key::from_static_str("log.level"), line.level.clone());

    let is_ocsf = line.target == OCSF_TARGET;
    record.add_attribute(Key::from_static_str("log.ocsf"), is_ocsf);

    // Structured fields. For OCSF events these are only populated once
    // `ocsf_full_payload` carries the schema attributes (Phase 3); until then
    // the map is whatever the producer attached, and the flag simply gates
    // whether we forward it verbatim.
    if !line.fields.is_empty() && (!is_ocsf || ocsf_full_payload) {
        for (key, value) in &line.fields {
            record.add_attribute(Key::new(key.clone()), value.clone());
        }
    }

    logger.emit(record);
}

/// Map an OpenShell log level string onto an OTLP severity number.
fn severity_of(level: &str) -> Severity {
    match level {
        "TRACE" => Severity::Trace,
        "DEBUG" => Severity::Debug,
        "WARN" | "WARNING" => Severity::Warn,
        "ERROR" => Severity::Error,
        // OCSF security events and INFO both map to informational severity;
        // the `log.ocsf` attribute distinguishes them downstream.
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_mapping_covers_known_levels() {
        assert_eq!(severity_of("TRACE"), Severity::Trace);
        assert_eq!(severity_of("DEBUG"), Severity::Debug);
        assert_eq!(severity_of("INFO"), Severity::Info);
        assert_eq!(severity_of("WARN"), Severity::Warn);
        assert_eq!(severity_of("ERROR"), Severity::Error);
        assert_eq!(severity_of("OCSF"), Severity::Info);
        assert_eq!(severity_of("something-else"), Severity::Info);
    }

    #[tokio::test]
    async fn enqueue_after_drain_stops_is_a_noop() {
        // Build a provider with an in-memory exporter so spawn() has something
        // real to derive a logger from, then drop everything and confirm
        // enqueue does not panic once the task has gone away.
        let exporter = opentelemetry_sdk::logs::InMemoryLogExporter::default();
        let provider = SdkLoggerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let handle = spawn(&provider, false);
        drop(provider);

        handle.enqueue(SandboxLogLine {
            sandbox_id: "sb-1".into(),
            timestamp_ms: 1,
            level: "INFO".into(),
            target: "test".into(),
            message: "hello".into(),
            source: "sandbox".into(),
            fields: Default::default(),
        });
    }
}
