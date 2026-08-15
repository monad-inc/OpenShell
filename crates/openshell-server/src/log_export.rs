// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Off-box export of aggregated sandbox/gateway logs as OTLP log records.
//!
//! Every log line the gateway observes — its own events and lines pushed from
//! sandboxes — flows through [`crate::tracing_bus::TracingLogBus`]. When log
//! export is enabled, the bus forwards each line into the bounded queue owned
//! here; a background worker drains the queue in batches and drives the OTLP
//! exporter directly.
//!
//! # Accountable delivery
//!
//! No stage of this pipeline drops silently. The SDK's `BatchLogProcessor` is
//! deliberately not used: past its bounded queue it discards records with only
//! a WARN and a private counter, which is silent loss for security telemetry.
//! Instead the worker owns batching and calls the exporter itself, so every
//! batch's outcome is observable:
//!
//! - A full ingest queue (collector outage, sustained overload) counts each
//!   rejected line instead of enqueueing it.
//! - A batch that still fails after bounded retries is counted rather than
//!   retried forever, so one poison batch cannot dam the stream.
//! - The next successful batch carries a synthetic `telemetry_gap` record with
//!   the dropped count and the window it covers, mirroring the accounting the
//!   sandbox push path performs (`openshell-supervisor-process/src/log_push.rs`).
//!
//! Loss therefore remains possible — under outage the gateway prefers bounded
//! memory over unbounded buffering — but it is always visible and alertable
//! downstream. Crash durability (a disk spool with acknowledged checkpoints) is
//! Phase 2.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openshell_core::proto::SandboxLogLine;
use openshell_ocsf::OCSF_TARGET;
use openshell_ocsf::format::attributes::SEVERITY_ID_KEY;
use openshell_ocsf::format::shorthand::severity_id_from_shorthand;
use opentelemetry::logs::{AnyValue, LogRecord as _, Logger as _, Severity};
use opentelemetry::{InstrumentationScope, Key};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::{LogBatch, LogExporter, SdkLogRecord, SdkLogger, SdkLoggerProvider};
use tokio::sync::{mpsc, watch};

/// Instrumentation scope recorded on every exported log record.
const INSTRUMENTATION_SCOPE: &str = "openshell-gateway-logs";

/// Ingest queue capacity in log lines. Bounds export memory during a collector
/// outage; lines beyond it are counted and reported as a `telemetry_gap`.
const QUEUE_CAPACITY: usize = 65_536;

/// Maximum records per exported batch.
const MAX_BATCH: usize = 512;

/// Attempts per batch before it is dropped and accounted. With the backoff
/// below this rides out ~30s of collector unavailability per batch while
/// preventing a batch the collector deterministically rejects from damming
/// the stream behind it.
const MAX_EXPORT_ATTEMPTS: u32 = 5;

/// Initial backoff delay after a failed export attempt.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Maximum backoff delay between export attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// How long shutdown waits for the worker to flush before giving up.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Handle used by the tracing bus to enqueue log lines for export.
///
/// Cloneable and cheap: it wraps the sender half of the export queue. Sending
/// is non-blocking, so it is safe to call from synchronous tracing callbacks.
/// When the queue is full the line is dropped and counted; the worker reports
/// the accumulated count as a `telemetry_gap` record on its next export.
#[derive(Clone, Debug)]
pub struct LogExportHandle {
    tx: mpsc::Sender<SandboxLogLine>,
    dropped: Arc<AtomicU64>,
    dropped_since_ms: Arc<AtomicI64>,
}

impl LogExportHandle {
    /// Enqueue a log line for off-box export.
    ///
    /// Never blocks. A full queue counts the line as dropped; a stopped worker
    /// (shutdown) discards it silently, since the process is exiting anyway.
    pub fn enqueue(&self, line: SandboxLogLine) {
        match self.tx.try_send(line) {
            Err(mpsc::error::TrySendError::Full(_)) => {
                let now = openshell_core::time::now_ms();
                // Keep the earliest drop as the window start until reported.
                let _ = self.dropped_since_ms.compare_exchange(
                    0,
                    now,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

/// Owner of the export worker task, retained for shutdown.
pub struct LogExportWorker {
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl LogExportWorker {
    /// Stop the worker, flushing queued lines with a final best-effort export.
    ///
    /// Bounded by [`SHUTDOWN_TIMEOUT`]: an unreachable collector cannot hold
    /// the gateway's exit hostage.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        if tokio::time::timeout(SHUTDOWN_TIMEOUT, self.task)
            .await
            .is_err()
        {
            tracing::warn!("OTLP log export worker did not flush before the shutdown deadline");
        }
    }
}

/// Spawn the export worker and return the handle that feeds it.
pub fn spawn<E>(
    exporter: E,
    resource: Resource,
    ocsf_full_payload: bool,
) -> (LogExportHandle, LogExportWorker)
where
    E: LogExporter + 'static,
{
    spawn_with_capacity(exporter, resource, ocsf_full_payload, QUEUE_CAPACITY)
}

fn spawn_with_capacity<E>(
    mut exporter: E,
    resource: Resource,
    ocsf_full_payload: bool,
    capacity: usize,
) -> (LogExportHandle, LogExportWorker)
where
    E: LogExporter + 'static,
{
    let (tx, rx) = mpsc::channel::<SandboxLogLine>(capacity);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let dropped = Arc::new(AtomicU64::new(0));
    let dropped_since_ms = Arc::new(AtomicI64::new(0));

    exporter.set_resource(&resource);

    let task = tokio::spawn(run_export_loop(
        exporter,
        rx,
        shutdown_rx,
        Arc::clone(&dropped),
        Arc::clone(&dropped_since_ms),
        ocsf_full_payload,
    ));

    (
        LogExportHandle {
            tx,
            dropped,
            dropped_since_ms,
        },
        LogExportWorker { shutdown_tx, task },
    )
}

async fn run_export_loop<E: LogExporter>(
    exporter: E,
    mut rx: mpsc::Receiver<SandboxLogLine>,
    mut shutdown_rx: watch::Receiver<bool>,
    dropped: Arc<AtomicU64>,
    dropped_since_ms: Arc<AtomicI64>,
    ocsf_full_payload: bool,
) {
    let scope = InstrumentationScope::builder(INSTRUMENTATION_SCOPE).build();
    // A processor-less provider serves purely as the record factory: the SDK
    // offers no other way to mint an `SdkLogRecord`, and nothing is ever
    // emitted through it.
    let factory = SdkLoggerProvider::builder().build();
    let logger = openshell_otel::logger(&factory, INSTRUMENTATION_SCOPE);

    let mut records: Vec<SdkLogRecord> = Vec::with_capacity(MAX_BATCH);
    loop {
        records.clear();

        let first = tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(line) => line,
                None => break,
            },
            _ = shutdown_rx.wait_for(|&stop| stop) => break,
        };
        records.push(record_for(&logger, &first, ocsf_full_payload));
        while records.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(line) => records.push(record_for(&logger, &line, ocsf_full_payload)),
                Err(_) => break,
            }
        }
        if let Some(gap) = gap_record(&logger, &dropped, &dropped_since_ms) {
            records.push(gap);
        }

        match export_with_retry(&exporter, &records, &scope, &mut shutdown_rx).await {
            ExportOutcome::Delivered => {}
            ExportOutcome::GaveUp => {
                account_dropped_batch(&dropped, &dropped_since_ms, records.len());
            }
            ExportOutcome::ShuttingDown => break,
        }
    }

    // Final flush: drain whatever is queued, one attempt per batch. Retrying
    // here would race the shutdown deadline for nothing — the collector that
    // just failed is not coming back within it.
    loop {
        records.clear();
        while records.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(line) => records.push(record_for(&logger, &line, ocsf_full_payload)),
                Err(_) => break,
            }
        }
        if let Some(gap) = gap_record(&logger, &dropped, &dropped_since_ms) {
            records.push(gap);
        }
        if records.is_empty() {
            break;
        }
        if export_once(&exporter, &records, &scope).await.is_err() {
            break;
        }
    }
    let _ = exporter.shutdown();
}

enum ExportOutcome {
    Delivered,
    GaveUp,
    ShuttingDown,
}

/// Export one batch, retrying with backoff up to [`MAX_EXPORT_ATTEMPTS`].
async fn export_with_retry<E: LogExporter>(
    exporter: &E,
    records: &[SdkLogRecord],
    scope: &InstrumentationScope,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> ExportOutcome {
    let mut backoff = INITIAL_BACKOFF;
    for attempt in 1..=MAX_EXPORT_ATTEMPTS {
        match export_once(exporter, records, scope).await {
            Ok(()) => return ExportOutcome::Delivered,
            Err(err) => {
                // No `sandbox_id` field, so the bus tap ignores this event and
                // it cannot feed back into the very queue that is failing.
                tracing::warn!(
                    error = %err,
                    attempt,
                    batch_len = records.len(),
                    "OTLP log export failed"
                );
            }
        }
        if attempt == MAX_EXPORT_ATTEMPTS {
            break;
        }
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            _ = shutdown_rx.wait_for(|&stop| stop) => return ExportOutcome::ShuttingDown,
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
    ExportOutcome::GaveUp
}

async fn export_once<E: LogExporter>(
    exporter: &E,
    records: &[SdkLogRecord],
    scope: &InstrumentationScope,
) -> opentelemetry_sdk::error::OTelSdkResult {
    let refs: Vec<(&SdkLogRecord, &InstrumentationScope)> =
        records.iter().map(|record| (record, scope)).collect();
    exporter.export(LogBatch::new(&refs)).await
}

/// Fold a batch that could not be delivered into the same accounting stream as
/// queue-full drops, so the next successful export reports it.
fn account_dropped_batch(dropped: &AtomicU64, dropped_since_ms: &AtomicI64, len: usize) {
    let now = openshell_core::time::now_ms();
    let _ = dropped_since_ms.compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed);
    dropped.fetch_add(u64::try_from(len).unwrap_or(u64::MAX), Ordering::Relaxed);
}

/// If any records were dropped since the last report, reset the counters and
/// mint a `telemetry_gap` record carrying the count and window.
///
/// Minted directly rather than enqueued, so it bypasses the congestion that
/// caused the drops — the same pattern as the sandbox push task.
fn gap_record(
    logger: &SdkLogger,
    dropped: &AtomicU64,
    dropped_since_ms: &AtomicI64,
) -> Option<SdkLogRecord> {
    let n = dropped.swap(0, Ordering::Relaxed);
    if n == 0 {
        return None;
    }
    let since_ms = dropped_since_ms.swap(0, Ordering::Relaxed);
    let now = SystemTime::now();

    let mut record = logger.create_log_record();
    record.set_severity_number(Severity::Warn);
    record.set_timestamp(now);
    record.set_observed_timestamp(now);
    record.set_body(AnyValue::String(
        format!("telemetry gap: {n} gateway log record(s) dropped under backpressure").into(),
    ));
    record.add_attribute(Key::from_static_str("log.source"), "gateway");
    record.add_attribute(Key::from_static_str("log.target"), "telemetry_gap");
    record.add_attribute(Key::from_static_str("log.level"), "WARN");
    record.add_attribute(Key::from_static_str("log.ocsf"), false);
    record.add_attribute(
        Key::from_static_str("dropped"),
        i64::try_from(n).unwrap_or(i64::MAX),
    );
    record.add_attribute(Key::from_static_str("dropped.since_ms"), since_ms);
    Some(record)
}

/// Convert a [`SandboxLogLine`] into an OTLP log record.
fn record_for(logger: &SdkLogger, line: &SandboxLogLine, ocsf_full_payload: bool) -> SdkLogRecord {
    let mut record = logger.create_log_record();
    let is_ocsf = line.target == OCSF_TARGET;

    record.set_severity_number(severity_for(line, is_ocsf));
    record.set_body(AnyValue::String(line.message.clone().into()));
    record.set_observed_timestamp(SystemTime::now());

    if line.timestamp_ms > 0 {
        record.set_timestamp(UNIX_EPOCH + Duration::from_millis(line.timestamp_ms.cast_unsigned()));
    }

    record.add_attribute(Key::from_static_str("sandbox.id"), line.sandbox_id.clone());
    record.add_attribute(Key::from_static_str("log.source"), line.source.clone());
    record.add_attribute(Key::from_static_str("log.target"), line.target.clone());
    record.add_attribute(Key::from_static_str("log.level"), line.level.clone());

    record.add_attribute(Key::from_static_str("log.ocsf"), is_ocsf);

    // Structured fields. A sandbox pushes OCSF events with their schema
    // flattened into `ocsf.*` keys, which is the bulk of a security event's
    // size, so `ocsf_full_payload` gates whether that detail leaves the box.
    // Non-OCSF lines carry whatever their producer attached and always travel.
    if !line.fields.is_empty() && (!is_ocsf || ocsf_full_payload) {
        for (key, value) in &line.fields {
            record.add_attribute(Key::new(key.clone()), value.clone());
        }
    }

    record
}

/// Resolve the OTLP severity for an exported log line.
///
/// OCSF events all carry the level `OCSF`, so the level alone cannot rank a
/// blocked nonce replay above a routine policy load.
///
/// Prefer the structured `severity_id` the sandbox pushed: it is the value the
/// emitter assigned rather than one recovered from rendered text. Fall back to
/// the shorthand tag for lines pushed by a sandbox predating structured fields,
/// then to the level when neither is present. Note this reads the field even
/// when `ocsf_full_payload` is off — that flag governs what leaves the box, not
/// what the gateway may use to rank a record.
fn severity_for(line: &SandboxLogLine, is_ocsf: bool) -> Severity {
    if !is_ocsf {
        return severity_of(&line.level);
    }
    line.fields
        .get(SEVERITY_ID_KEY)
        .and_then(|id| id.parse::<u8>().ok())
        .or_else(|| severity_id_from_shorthand(&line.message))
        .map_or_else(|| severity_of(&line.level), ocsf_severity)
}

/// Map an OCSF `severity_id` onto an OTLP severity number.
///
/// OCSF ranks six levels where OTLP offers four bands of four. Low and Medium
/// share the WARN band and High and Critical the ERROR band, using the second
/// slot of each so the OCSF ordering survives instead of collapsing.
fn ocsf_severity(severity_id: u8) -> Severity {
    match severity_id {
        2 => Severity::Warn,   // Low
        3 => Severity::Warn2,  // Medium
        4 => Severity::Error,  // High
        5 => Severity::Error2, // Critical
        6 => Severity::Fatal,  // Fatal
        // Unknown and Informational.
        _ => Severity::Info,
    }
}

/// Map an `OpenShell` log level string onto an OTLP severity number.
fn severity_of(level: &str) -> Severity {
    match level {
        "TRACE" => Severity::Trace,
        "DEBUG" => Severity::Debug,
        "WARN" | "WARNING" => Severity::Warn,
        "ERROR" => Severity::Error,
        // An OCSF line reaching here carried no severity tag; the `log.ocsf`
        // attribute still distinguishes it downstream.
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
    use opentelemetry_sdk::logs::InMemoryLogExporter;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicU32;

    fn ocsf_line(message: &str) -> SandboxLogLine {
        SandboxLogLine {
            sandbox_id: "sb-1".into(),
            timestamp_ms: 1,
            level: "OCSF".into(),
            target: OCSF_TARGET.into(),
            message: message.into(),
            source: "sandbox".into(),
            fields: HashMap::default(),
        }
    }

    fn plain_line(message: &str) -> SandboxLogLine {
        SandboxLogLine {
            sandbox_id: "sb-1".into(),
            timestamp_ms: 1,
            level: "INFO".into(),
            target: "test".into(),
            message: message.into(),
            source: "sandbox".into(),
            fields: HashMap::default(),
        }
    }

    fn body_of(record: &SdkLogRecord) -> String {
        match record.body() {
            Some(AnyValue::String(s)) => s.to_string(),
            other => panic!("unexpected body: {other:?}"),
        }
    }

    fn attribute(record: &SdkLogRecord, key: &str) -> Option<AnyValue> {
        record
            .attributes_iter()
            .find(|(k, _)| k.as_str() == key)
            .map(|(_, v)| v.clone())
    }

    /// Forwards exports to an in-memory exporter but keeps the trait's no-op
    /// shutdown, so records survive the worker's final `exporter.shutdown()`
    /// for assertion (`InMemoryLogExporter` clears itself on shutdown).
    #[derive(Debug, Clone)]
    struct KeptExporter(InMemoryLogExporter);

    impl LogExporter for KeptExporter {
        async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
            self.0.export(batch).await
        }
    }

    /// An exporter that fails its first `failures` export calls, then delegates
    /// to an in-memory exporter.
    #[derive(Debug)]
    struct FlakyExporter {
        remaining_failures: AtomicU32,
        attempts: Arc<AtomicU32>,
        inner: InMemoryLogExporter,
    }

    impl FlakyExporter {
        fn new(failures: u32, attempts: Arc<AtomicU32>, inner: InMemoryLogExporter) -> Self {
            Self {
                remaining_failures: AtomicU32::new(failures),
                attempts,
                inner,
            }
        }
    }

    impl LogExporter for FlakyExporter {
        async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            let remaining = self.remaining_failures.load(Ordering::Relaxed);
            if remaining > 0 {
                self.remaining_failures.fetch_sub(1, Ordering::Relaxed);
                return Err(OTelSdkError::InternalFailure("synthetic failure".into()));
            }
            self.inner.export(batch).await
        }
    }

    #[test]
    fn ocsf_events_export_at_their_own_severity() {
        // Every OCSF line carries the level "OCSF", so without reading the
        // shorthand tag a blocked denial exports as INFO and cannot be alerted
        // on downstream.
        let denial = ocsf_line("NET:OPEN [MED] DENIED curl(1) -> blocked.invalid:443");
        assert_eq!(severity_for(&denial, true), Severity::Warn2);

        let finding = ocsf_line("FINDING:BLOCKED [HIGH] \"NSSH1 Nonce Replay Attack\"");
        assert_eq!(severity_for(&finding, true), Severity::Error);

        let routine = ocsf_line("CONFIG:LOADED [INFO] Loaded sandbox policy");
        assert_eq!(severity_for(&routine, true), Severity::Info);
    }

    #[test]
    fn ocsf_severity_ordering_survives_the_mapping() {
        // Distinct OCSF levels must not collapse onto one OTLP number, or
        // "medium and above" stops being expressible.
        let severities: Vec<_> = (1..=6u8).map(|id| ocsf_severity(id) as u8).collect();
        let mut sorted = severities.clone();
        sorted.dedup();
        assert_eq!(severities, sorted, "OCSF levels collapsed: {severities:?}");
        assert!(severities.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn a_structured_severity_outranks_the_rendered_tag() {
        // The pushed field is what the emitter assigned; the tag is a
        // rendering of it. When they disagree the field wins.
        let mut line = ocsf_line("NET:OPEN [INFO] DENIED curl(1) -> host:443");
        line.fields
            .insert(SEVERITY_ID_KEY.to_string(), "4".to_string());
        assert_eq!(severity_for(&line, true), Severity::Error);
    }

    #[test]
    fn a_malformed_structured_severity_falls_back_to_the_tag() {
        let mut line = ocsf_line("NET:OPEN [MED] DENIED curl(1) -> host:443");
        line.fields
            .insert(SEVERITY_ID_KEY.to_string(), "not-a-number".to_string());
        assert_eq!(severity_for(&line, true), Severity::Warn2);
    }

    #[test]
    fn an_untagged_ocsf_line_falls_back_to_its_level() {
        let untagged = ocsf_line("NET:OPEN no severity tag here");
        assert_eq!(severity_for(&untagged, true), Severity::Info);
    }

    #[test]
    fn non_ocsf_lines_still_use_their_level() {
        // A gateway line whose text happens to contain a tag must not be
        // reranked by it.
        let mut line = ocsf_line("connection refused [HIGH] load");
        line.level = "WARN".into();
        line.target = "openshell_server::compute".into();
        line.source = "gateway".into();
        assert_eq!(severity_for(&line, false), Severity::Warn);
    }

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
    async fn enqueued_lines_reach_the_exporter_and_shutdown_flushes() {
        let exporter = InMemoryLogExporter::default();
        let (handle, worker) = spawn(
            KeptExporter(exporter.clone()),
            Resource::builder_empty().build(),
            false,
        );

        handle.enqueue(plain_line("one"));
        handle.enqueue(plain_line("two"));
        handle.enqueue(ocsf_line(
            "NET:OPEN [MED] DENIED curl(1) -> blocked.invalid:443",
        ));
        worker.shutdown().await;

        let emitted = exporter.get_emitted_logs().unwrap();
        assert_eq!(emitted.len(), 3, "all enqueued lines are exported");
        let denial = &emitted[2].record;
        assert_eq!(denial.severity_number(), Some(Severity::Warn2));
        assert_eq!(
            attribute(denial, "sandbox.id"),
            Some(AnyValue::String("sb-1".into()))
        );
        assert_eq!(attribute(denial, "log.ocsf"), Some(AnyValue::Boolean(true)));
    }

    #[tokio::test]
    async fn queue_overflow_is_accounted_as_a_telemetry_gap() {
        // A current-thread runtime never polls the worker while the test body
        // runs synchronously, so the queue fills deterministically: capacity
        // lines are accepted, the rest are dropped and counted.
        let exporter = InMemoryLogExporter::default();
        let (handle, worker) = spawn_with_capacity(
            KeptExporter(exporter.clone()),
            Resource::builder_empty().build(),
            false,
            2,
        );

        for i in 0..10 {
            handle.enqueue(plain_line(&format!("line-{i}")));
        }
        worker.shutdown().await;

        let emitted = exporter.get_emitted_logs().unwrap();
        let (gaps, lines): (Vec<_>, Vec<_>) = emitted.iter().partition(|log| {
            attribute(&log.record, "log.target") == Some(AnyValue::String("telemetry_gap".into()))
        });

        assert_eq!(lines.len(), 2, "the queued lines are exported");
        assert_eq!(gaps.len(), 1, "one gap record accounts for the rest");
        let gap = &gaps[0].record;
        assert_eq!(gap.severity_number(), Some(Severity::Warn));
        assert_eq!(attribute(gap, "dropped"), Some(AnyValue::Int(8)));
        assert!(
            matches!(attribute(gap, "dropped.since_ms"), Some(AnyValue::Int(ms)) if ms > 0),
            "the gap carries its window start"
        );
        assert!(body_of(gap).contains("8 gateway log record(s) dropped"));
    }

    #[tokio::test(start_paused = true)]
    async fn export_failures_are_retried_until_delivery() {
        let inner = InMemoryLogExporter::default();
        let attempts = Arc::new(AtomicU32::new(0));
        let exporter = FlakyExporter::new(2, Arc::clone(&attempts), inner.clone());
        let (handle, worker) = spawn(exporter, Resource::builder_empty().build(), false);

        handle.enqueue(plain_line("survives retries"));
        // Paused time fast-forwards the retry backoff whenever the runtime is
        // otherwise idle, so this loop converges immediately.
        while inner.get_emitted_logs().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        worker.shutdown().await;

        assert_eq!(
            attempts.load(Ordering::Relaxed),
            3,
            "two failures, one success"
        );
        let emitted = inner.get_emitted_logs().unwrap();
        assert_eq!(emitted.len(), 1);
        assert_eq!(body_of(&emitted[0].record), "survives retries");
    }

    #[tokio::test(start_paused = true)]
    async fn a_batch_exhausting_its_retries_is_dropped_and_accounted() {
        let inner = InMemoryLogExporter::default();
        let attempts = Arc::new(AtomicU32::new(0));
        // Fail the first batch's full retry budget; everything after delivers.
        let exporter =
            FlakyExporter::new(MAX_EXPORT_ATTEMPTS, Arc::clone(&attempts), inner.clone());
        let (handle, worker) = spawn(exporter, Resource::builder_empty().build(), false);

        handle.enqueue(plain_line("poison"));
        while attempts.load(Ordering::Relaxed) < MAX_EXPORT_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        handle.enqueue(plain_line("after the gap"));
        while inner.get_emitted_logs().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        worker.shutdown().await;

        let emitted = inner.get_emitted_logs().unwrap();
        let bodies: Vec<String> = emitted.iter().map(|log| body_of(&log.record)).collect();
        assert!(
            !bodies.iter().any(|b| b == "poison"),
            "the undeliverable batch is gone: {bodies:?}"
        );
        assert!(
            bodies.iter().any(|b| b == "after the gap"),
            "the stream continues past it: {bodies:?}"
        );
        let gap = emitted
            .iter()
            .find(|log| {
                attribute(&log.record, "log.target")
                    == Some(AnyValue::String("telemetry_gap".into()))
            })
            .expect("the dropped batch is reported");
        assert_eq!(attribute(&gap.record, "dropped"), Some(AnyValue::Int(1)));
    }

    #[tokio::test]
    async fn enqueue_after_shutdown_is_a_noop() {
        let exporter = InMemoryLogExporter::default();
        let (handle, worker) = spawn(exporter, Resource::builder_empty().build(), false);
        worker.shutdown().await;

        // The worker is gone and the channel closed; enqueue must not panic
        // and must not count the line as a drop worth reporting.
        handle.enqueue(plain_line("hello"));
        assert_eq!(handle.dropped.load(Ordering::Relaxed), 0);
    }
}
