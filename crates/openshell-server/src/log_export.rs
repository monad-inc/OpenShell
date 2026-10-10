// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Off-box export of gateway and sandbox logs as OTLP log records.
//!
//! When `[openshell.gateway.otlp] export_logs` is set, two feeds converge on
//! one bounded queue owned here:
//!
//! - **Gateway-produced events.** [`LogExport::layer`] is a tracing layer that
//!   sits beside the OCSF JSONL sink ([`crate::ocsf_log`]). OCSF events are read
//!   from the event bridge's thread-local exactly as the JSONL sink and the
//!   sandbox log bus read them: routed to a sandbox by `container.uid`, with
//!   the shorthand as the body and the structured document as `ocsf.raw`.
//!   Gateway-wide events (no container) are exported without a `sandbox.id`.
//!   Other gateway diagnostics are exported with their structured fields when
//!   they pass the operator's log filter.
//! - **Supervisor-pushed lines.** [`crate::tracing_bus::TracingLogBus`] taps
//!   `publish_external` (the `PushSandboxLogs` ingest path) and forwards each
//!   line here before it enters the per-sandbox tail.
//!
//! A background worker drains the queue in batches and drives the OTLP
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
//!   sandbox push path performs.
//!
//! Every outcome is also counted in Prometheus metrics, matching the
//! `openshell_ocsf_log_*` convention: `openshell_otlp_log_queued_total`,
//! `openshell_otlp_log_exported_total`, `openshell_otlp_log_export_errors_total`
//! and `openshell_otlp_log_dropped_total{reason}` with `reason` one of
//! `queue_full`, `agent_budget`, `export_failed`, `closed`, `shutdown` or
//! `shutdown_uncertain`. Loss at shutdown has no later export to carry a gap
//! record, so the metrics are its only trace.
//!
//! Delivery is at-least-once: an export whose response is lost after the
//! collector committed the batch is retried, so consumers must tolerate
//! occasional duplicate records.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use openshell_core::proto::SandboxLogLine;
use openshell_ocsf::format::attributes::{SEVERITY_ID_KEY, raw_event_fields};
use openshell_ocsf::format::shorthand::severity_id_from_shorthand;
use openshell_ocsf::{OCSF_TARGET, OcsfEvent};
use opentelemetry::logs::{AnyValue, LogRecord as _, Logger as _, Severity};
use opentelemetry::{InstrumentationScope, Key};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::{LogBatch, LogExporter, SdkLogRecord, SdkLogger, SdkLoggerProvider};
use tokio::sync::{mpsc, watch};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

use crate::config_file::OtlpConfig;
use crate::otel_tracing::{GatewayResourceAttributes, SetupError};

/// Instrumentation scope recorded on every exported log record.
const INSTRUMENTATION_SCOPE: &str = "openshell-gateway-logs";

/// Ingest queue capacity in log lines. Bounds export memory during a collector
/// outage; lines beyond it are counted and reported as a `telemetry_gap`.
const QUEUE_CAPACITY: usize = 65_536;

/// Maximum records per exported batch.
const MAX_BATCH: usize = 512;

/// Approximate payload bytes per exported batch. A sandbox exporting its
/// agent's output pushes records of up to 64 KiB, so 512 of them could pass
/// the 4 MiB default gRPC receive limit of an OpenTelemetry Collector and be
/// rejected on every attempt. A batch closes once it carries this much.
const MAX_BATCH_BYTES: usize = 2 * 1024 * 1024;

/// Approximate bytes held by queued lines. Bounds export memory during a
/// collector outage when lines are large, alongside [`QUEUE_CAPACITY`] for
/// when they are many. Lines beyond it are counted like a full queue.
const QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Bytes of the queue that agent output lines, from all sandboxes together,
/// may hold. The rest is reserved for OCSF, audit and diagnostic records, so a
/// sandbox flooding its agent's output cannot get other records dropped.
const AGENT_QUEUE_MAX_BYTES: usize = QUEUE_MAX_BYTES / 4;

/// Bytes of the queue one sandbox's agent output may hold, so one sandbox
/// cannot take the whole agent share from the others.
const AGENT_QUEUE_MAX_BYTES_PER_SANDBOX: usize = 4 * 1024 * 1024;

/// Queue slots agent output lines may hold, from all sandboxes together.
const AGENT_QUEUE_MAX_LINES: usize = QUEUE_CAPACITY / 2;

fn is_agent_line(line: &SandboxLogLine) -> bool {
    line.source == openshell_core::agent_output::AGENT_LOG_SOURCE
}

/// Agent output's share of the queue, and what it had to drop.
#[derive(Debug, Default)]
struct AgentQueue {
    bytes: usize,
    lines: usize,
    bytes_by_sandbox: HashMap<String, usize>,
    /// Agent lines refused since the last report, per sandbox.
    dropped_by_sandbox: BTreeMap<String, u64>,
}

/// Byte accounting for the export queue, shared by the handle that admits
/// lines and the worker that takes them.
#[derive(Debug)]
struct QueueBudget {
    bytes: AtomicUsize,
    max_bytes: usize,
    agent: Mutex<AgentQueue>,
}

/// Why [`QueueBudget::admit`] refused a line.
enum Refusal {
    /// The queue as a whole is full; counted toward the shared gap record.
    QueueFull,
    /// Agent output is over its share; reported per sandbox.
    AgentBudget,
}

impl QueueBudget {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: AtomicUsize::new(0),
            max_bytes,
            agent: Mutex::new(AgentQueue::default()),
        }
    }

    fn admit(&self, line: &SandboxLogLine, bytes: usize) -> Result<(), Refusal> {
        let agent = is_agent_line(line);
        if agent {
            let mut queue = self.agent.lock().expect("agent queue lock poisoned");
            let sandbox_bytes = queue
                .bytes_by_sandbox
                .get(&line.sandbox_id)
                .copied()
                .unwrap_or(0);
            if queue.bytes + bytes > AGENT_QUEUE_MAX_BYTES
                || sandbox_bytes + bytes > AGENT_QUEUE_MAX_BYTES_PER_SANDBOX
                || queue.lines >= AGENT_QUEUE_MAX_LINES
            {
                *queue
                    .dropped_by_sandbox
                    .entry(line.sandbox_id.clone())
                    .or_default() += 1;
                return Err(Refusal::AgentBudget);
            }
            queue.bytes += bytes;
            queue.lines += 1;
            *queue
                .bytes_by_sandbox
                .entry(line.sandbox_id.clone())
                .or_default() += bytes;
        }
        let queued = self.bytes.fetch_add(bytes, Ordering::Relaxed);
        if queued + bytes > self.max_bytes {
            self.release(agent, &line.sandbox_id, bytes);
            return Err(Refusal::QueueFull);
        }
        Ok(())
    }

    /// Return an admitted line's bytes: to the queue total and, for agent
    /// output, to the agent share.
    fn release(&self, agent: bool, sandbox_id: &str, bytes: usize) {
        self.bytes.fetch_sub(bytes, Ordering::Relaxed);
        if !agent {
            return;
        }
        let mut queue = self.agent.lock().expect("agent queue lock poisoned");
        queue.bytes -= bytes;
        queue.lines -= 1;
        if let Some(sandbox_bytes) = queue.bytes_by_sandbox.get_mut(sandbox_id) {
            *sandbox_bytes -= bytes;
            if *sandbox_bytes == 0 {
                queue.bytes_by_sandbox.remove(sandbox_id);
            }
        }
    }

    fn release_line(&self, line: &SandboxLogLine) {
        self.release(is_agent_line(line), &line.sandbox_id, line_bytes(line));
    }

    fn take_agent_drops(&self) -> BTreeMap<String, u64> {
        let mut queue = self.agent.lock().expect("agent queue lock poisoned");
        std::mem::take(&mut queue.dropped_by_sandbox)
    }
}

/// Rough size of a queued line, for the byte bounds above.
fn line_bytes(line: &SandboxLogLine) -> usize {
    let fields: usize = line
        .fields
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum();
    line.message.len() + line.target.len() + line.sandbox_id.len() + fields + 64
}

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

const DROPPED_METRIC: &str = "openshell_otlp_log_dropped_total";

fn count_dropped(reason: &'static str, n: usize) {
    metrics::counter!(DROPPED_METRIC, "reason" => reason).increment(n as u64);
}

/// Handle used to enqueue log lines for export.
///
/// Cloneable and cheap: it wraps the sender half of the export queue. Sending
/// is non-blocking, so it is safe to call from synchronous tracing callbacks.
/// When the queue is full the line is dropped and counted; the worker reports
/// the accumulated count as a `telemetry_gap` record on its next export.
#[derive(Clone, Debug)]
pub struct LogExportHandle {
    tx: mpsc::Sender<SandboxLogLine>,
    budget: Arc<QueueBudget>,
    dropped: Arc<AtomicU64>,
    dropped_since_ms: Arc<AtomicI64>,
}

impl LogExportHandle {
    /// Enqueue a log line for off-box export.
    ///
    /// Never blocks. A full queue counts the line toward the next
    /// `telemetry_gap`; a stopped worker (shutdown) cannot carry a gap record
    /// any more, so that loss is counted in metrics only.
    pub fn enqueue(&self, line: SandboxLogLine) {
        let bytes = line_bytes(&line);
        match self.budget.admit(&line, bytes) {
            Ok(()) => {}
            Err(Refusal::QueueFull) => {
                self.count_queue_full();
                return;
            }
            Err(Refusal::AgentBudget) => {
                // Reported per sandbox by the worker's next export.
                count_dropped("agent_budget", 1);
                return;
            }
        }
        match self.tx.try_send(line) {
            Ok(()) => metrics::counter!("openshell_otlp_log_queued_total").increment(1),
            Err(mpsc::error::TrySendError::Full(line)) => {
                self.budget.release_line(&line);
                self.count_queue_full();
            }
            Err(mpsc::error::TrySendError::Closed(line)) => {
                self.budget.release_line(&line);
                count_dropped("closed", 1);
            }
        }
    }

    fn count_queue_full(&self) {
        note_drop_window(&self.dropped_since_ms, openshell_core::time::now_ms());
        self.dropped.fetch_add(1, Ordering::Relaxed);
        count_dropped("queue_full", 1);
    }
}

/// Owner of the export worker task, retained for shutdown.
pub struct LogExportWorker {
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    /// Kept only to measure what is still queued if the flush times out.
    probe: mpsc::WeakSender<SandboxLogLine>,
}

impl LogExportWorker {
    /// Stop the worker, flushing queued lines with a final best-effort export.
    ///
    /// Bounded by [`SHUTDOWN_TIMEOUT`]: an unreachable collector cannot hold
    /// the gateway's exit hostage.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let abort = self.task.abort_handle();
        if tokio::time::timeout(SHUTDOWN_TIMEOUT, self.task)
            .await
            .is_err()
        {
            abort.abort();
            let queued = self
                .probe
                .upgrade()
                .map_or(0, |tx| tx.max_capacity() - tx.capacity());
            // The batch in flight is uncounted: it may or may not have landed.
            count_dropped("shutdown_uncertain", queued.max(1));
            tracing::warn!(
                queued,
                "OTLP log export worker did not flush before the shutdown deadline"
            );
        }
    }
}

/// A running log export pipeline: the worker plus how gateway events are
/// rendered into it.
pub struct LogExport {
    handle: LogExportHandle,
    worker: LogExportWorker,
    ocsf_full_payload: bool,
    ocsf_schema_version: Option<&'static str>,
}

impl LogExport {
    /// Start log export for the gateway's `[openshell.gateway.otlp]` table.
    ///
    /// Returns `(None, None)` when the table is absent or `export_logs` is
    /// off, and `(None, Some(err))` when export is configured but unusable;
    /// the error is returned for the caller to report once tracing is up.
    ///
    /// `ocsf_schema_version` is the gateway's OCSF JSONL target version
    /// (`[openshell.gateway.ocsf_log] schema_version`), so a gateway-produced
    /// event carries the same document in `ocsf.raw` as in the JSONL file.
    /// Supervisor-pushed `ocsf.raw` is forwarded as pushed.
    ///
    /// Must be called from within a Tokio runtime.
    pub(crate) fn start(
        otlp: Option<&OtlpConfig>,
        gateway: GatewayResourceAttributes<'_>,
        ocsf_schema_version: Option<&'static str>,
    ) -> (Option<Self>, Option<SetupError>) {
        let (parts, error) = crate::otel_tracing::log_exporter_for(otlp, gateway);
        let export = parts.map(|(exporter, resource)| {
            let ocsf_full_payload = otlp.is_some_and(|cfg| cfg.ocsf_full_payload);
            let (handle, worker) = spawn(exporter, resource, ocsf_full_payload);
            Self {
                handle,
                worker,
                ocsf_full_payload,
                ocsf_schema_version,
            }
        });
        (export, error)
    }

    /// The enqueue handle, for the log bus's supervisor-push tap.
    pub fn handle(&self) -> LogExportHandle {
        self.handle.clone()
    }

    /// The tracing layer that captures gateway-produced events.
    ///
    /// Register it with the same filter as the log bus — the operator's
    /// directives OR the OCSF target — so OCSF events bypass `RUST_LOG`.
    pub(crate) fn layer<S: Subscriber>(&self) -> impl Layer<S> + use<S> {
        ExportLayer {
            handle: self.handle.clone(),
            ocsf_full_payload: self.ocsf_full_payload,
            ocsf_schema_version: self.ocsf_schema_version,
        }
    }

    /// Flush queued records and stop the worker. Call it last, after every
    /// other subsystem has emitted its shutdown events.
    pub async fn shutdown(self) {
        self.worker.shutdown().await;
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
    spawn_with_capacity(
        exporter,
        resource,
        ocsf_full_payload,
        QUEUE_CAPACITY,
        QUEUE_MAX_BYTES,
    )
}

fn spawn_with_capacity<E>(
    mut exporter: E,
    resource: Resource,
    ocsf_full_payload: bool,
    capacity: usize,
    max_queued_bytes: usize,
) -> (LogExportHandle, LogExportWorker)
where
    E: LogExporter + 'static,
{
    let (tx, rx) = mpsc::channel::<SandboxLogLine>(capacity);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let dropped = Arc::new(AtomicU64::new(0));
    let dropped_since_ms = Arc::new(AtomicI64::new(0));
    let budget = Arc::new(QueueBudget::new(max_queued_bytes));

    exporter.set_resource(&resource);

    let task = tokio::spawn(run_export_loop(
        exporter,
        QueueReceiver {
            rx,
            budget: Arc::clone(&budget),
        },
        shutdown_rx,
        Arc::clone(&dropped),
        Arc::clone(&dropped_since_ms),
        ocsf_full_payload,
    ));

    let probe = tx.downgrade();
    (
        LogExportHandle {
            tx,
            budget,
            dropped,
            dropped_since_ms,
        },
        LogExportWorker {
            shutdown_tx,
            task,
            probe,
        },
    )
}

/// The batch being exported, plus the drop count its gap record (if any)
/// stands for, so a failed batch can restore that count instead of losing it.
struct Batch {
    records: Vec<SdkLogRecord>,
    gap: Option<(u64, i64)>,
}

impl Batch {
    fn lines(&self) -> usize {
        self.records.len() - usize::from(self.gap.is_some())
    }
}

/// The worker's end of the export queue, releasing each line's bytes from the
/// shared byte budget as it is taken.
struct QueueReceiver {
    rx: mpsc::Receiver<SandboxLogLine>,
    budget: Arc<QueueBudget>,
}

impl QueueReceiver {
    fn release(&self, line: &SandboxLogLine) {
        self.budget.release_line(line);
    }

    async fn recv(&mut self) -> Option<SandboxLogLine> {
        let line = self.rx.recv().await?;
        self.release(&line);
        Some(line)
    }

    fn try_recv(&mut self) -> Option<SandboxLogLine> {
        let line = self.rx.try_recv().ok()?;
        self.release(&line);
        Some(line)
    }

    fn len(&self) -> usize {
        self.rx.len()
    }
}

async fn run_export_loop<E: LogExporter>(
    exporter: E,
    mut rx: QueueReceiver,
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

    let mut batch = Batch {
        records: Vec::with_capacity(MAX_BATCH),
        gap: None,
    };
    loop {
        batch.records.clear();

        let first = tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(line) => line,
                None => break,
            },
            _ = shutdown_rx.wait_for(|&stop| stop) => break,
        };
        let first_bytes = line_bytes(&first);
        batch
            .records
            .push(record_for(&logger, first, ocsf_full_payload));
        fill(
            &mut batch.records,
            first_bytes,
            &mut rx,
            &logger,
            ocsf_full_payload,
        );
        batch.gap = push_gap_record(&mut batch.records, &logger, &dropped, &dropped_since_ms);
        push_agent_gap_records(&mut batch.records, &logger, &rx.budget);

        match export_with_retry(&exporter, &batch.records, &scope, &mut shutdown_rx).await {
            ExportOutcome::Delivered => {
                metrics::counter!("openshell_otlp_log_exported_total")
                    .increment(batch.lines() as u64);
            }
            ExportOutcome::GaveUp => {
                count_dropped("export_failed", batch.lines());
                restore_dropped(&batch, &dropped, &dropped_since_ms);
            }
            ExportOutcome::ShuttingDown => {
                // Not yet delivered: give the final flush one attempt at it.
                if export_once(&exporter, &batch.records, &scope).await.is_ok() {
                    metrics::counter!("openshell_otlp_log_exported_total")
                        .increment(batch.lines() as u64);
                } else {
                    count_dropped("shutdown", batch.lines());
                }
                break;
            }
        }
    }

    // Final flush: drain whatever is queued, one attempt per batch. Retrying
    // here would race the shutdown deadline for nothing — the collector that
    // just failed is not coming back within it.
    loop {
        batch.records.clear();
        fill(&mut batch.records, 0, &mut rx, &logger, ocsf_full_payload);
        batch.gap = push_gap_record(&mut batch.records, &logger, &dropped, &dropped_since_ms);
        push_agent_gap_records(&mut batch.records, &logger, &rx.budget);
        if batch.records.is_empty() {
            break;
        }
        if export_once(&exporter, &batch.records, &scope).await.is_ok() {
            metrics::counter!("openshell_otlp_log_exported_total").increment(batch.lines() as u64);
        } else {
            // No later export can carry a gap record; count what is lost.
            count_dropped("shutdown", batch.lines() + rx.len());
            break;
        }
    }
    let _ = exporter.shutdown();
}

/// Top up `records` from the queue until the batch holds [`MAX_BATCH`]
/// records or about [`MAX_BATCH_BYTES`], starting from `bytes` already in it.
fn fill(
    records: &mut Vec<SdkLogRecord>,
    mut bytes: usize,
    rx: &mut QueueReceiver,
    logger: &SdkLogger,
    ocsf_full_payload: bool,
) {
    while records.len() < MAX_BATCH && bytes < MAX_BATCH_BYTES {
        let Some(line) = rx.try_recv() else {
            break;
        };
        bytes += line_bytes(&line);
        records.push(record_for(logger, line, ocsf_full_payload));
    }
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
                metrics::counter!("openshell_otlp_log_export_errors_total").increment(1);
                // The export layer excludes this module's target (and the
                // OTLP transport stack), so this warning cannot feed back
                // into the very queue that is failing.
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

/// Record `at_ms` as the drop window start unless an earlier one is pending.
fn note_drop_window(dropped_since_ms: &AtomicI64, at_ms: i64) {
    let _ = dropped_since_ms.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        (current == 0 || at_ms < current).then_some(at_ms)
    });
}

/// Fold a batch that could not be delivered back into the accounting stream,
/// so the next successful export reports it. A gap record inside the failed
/// batch restores the count it stood for, not one record.
fn restore_dropped(batch: &Batch, dropped: &AtomicU64, dropped_since_ms: &AtomicI64) {
    let (gap_count, gap_since) = batch.gap.unwrap_or((0, 0));
    let since = if gap_since > 0 {
        gap_since
    } else {
        openshell_core::time::now_ms()
    };
    note_drop_window(dropped_since_ms, since);
    let lines = u64::try_from(batch.lines()).unwrap_or(u64::MAX);
    dropped.fetch_add(lines.saturating_add(gap_count), Ordering::Relaxed);
}

/// If any records were dropped since the last report, reset the counters and
/// append a `telemetry_gap` record carrying the count and window. Returns the
/// count and window start the record stands for.
///
/// Minted directly rather than enqueued, so it bypasses the congestion that
/// caused the drops — the same pattern as the sandbox push task.
fn push_gap_record(
    records: &mut Vec<SdkLogRecord>,
    logger: &SdkLogger,
    dropped: &AtomicU64,
    dropped_since_ms: &AtomicI64,
) -> Option<(u64, i64)> {
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
    records.push(record);
    Some((n, since_ms))
}

/// Append one `telemetry_gap` record per sandbox whose agent output was
/// refused for exceeding its share of the queue. Each names the sandbox, so
/// the loss is attributed to the sandbox that caused it rather than folded
/// into the shared count.
fn push_agent_gap_records(
    records: &mut Vec<SdkLogRecord>,
    logger: &SdkLogger,
    budget: &QueueBudget,
) {
    for (sandbox_id, n) in budget.take_agent_drops() {
        let now = SystemTime::now();
        let mut record = logger.create_log_record();
        record.set_severity_number(Severity::Warn);
        record.set_timestamp(now);
        record.set_observed_timestamp(now);
        record.set_body(AnyValue::String(
            format!(
                "telemetry gap: {n} agent output record(s) dropped over the sandbox's export share"
            )
            .into(),
        ));
        record.add_attribute(Key::from_static_str("log.source"), "gateway");
        record.add_attribute(Key::from_static_str("log.target"), "telemetry_gap");
        record.add_attribute(Key::from_static_str("log.level"), "WARN");
        record.add_attribute(Key::from_static_str("log.ocsf"), false);
        record.add_attribute(Key::from_static_str("sandbox.id"), sandbox_id);
        record.add_attribute(Key::from_static_str("stream"), "agent");
        record.add_attribute(
            Key::from_static_str("dropped"),
            i64::try_from(n).unwrap_or(i64::MAX),
        );
        records.push(record);
    }
}

/// Convert a [`SandboxLogLine`] into an OTLP log record.
///
/// Consumes the line: the worker owns it once it leaves the queue, so every
/// string moves into the record instead of being cloned.
///
/// Public only so the `log_export` benchmark can measure conversion cost per
/// payload shape; not a stable API surface.
#[doc(hidden)]
#[must_use]
pub fn record_for(
    logger: &SdkLogger,
    line: SandboxLogLine,
    ocsf_full_payload: bool,
) -> SdkLogRecord {
    let mut record = logger.create_log_record();
    let is_ocsf = line.target == OCSF_TARGET;

    record.set_severity_number(severity_for(&line, is_ocsf));
    record.set_observed_timestamp(SystemTime::now());

    if let Some(ts) = line.event_time
        && let Ok(time) = SystemTime::try_from(ts)
    {
        record.set_timestamp(time);
    }

    record.set_body(AnyValue::String(line.message.into()));
    // Gateway-scoped lines (governance, auth, TLS) have no sandbox; an empty
    // sandbox.id attribute would read as a sandbox with an empty name.
    if !line.sandbox_id.is_empty() {
        record.add_attribute(Key::from_static_str("sandbox.id"), line.sandbox_id);
    }
    record.add_attribute(Key::from_static_str("log.source"), line.source);
    record.add_attribute(Key::from_static_str("log.target"), line.target);
    record.add_attribute(Key::from_static_str("log.level"), line.level);

    record.add_attribute(Key::from_static_str("log.ocsf"), is_ocsf);

    // Structured fields. OCSF events carry their document as one `ocsf.raw`
    // JSON field (the default) or with their schema flattened into `ocsf.*`
    // keys — either way the bulk of a security event's size, so
    // `ocsf_full_payload` gates whether that detail leaves the box. Non-OCSF
    // lines carry whatever their producer attached and always travel.
    if !line.fields.is_empty() && (!is_ocsf || ocsf_full_payload) {
        for (key, value) in line.fields {
            record.add_attribute(Key::new(key), value);
        }
    }

    record
}

/// Resolve the OTLP severity for an exported log line.
///
/// OCSF events all carry the level `OCSF`, so the level alone cannot rank a
/// blocked nonce replay above a routine policy load.
///
/// Prefer the structured `severity_id` the producer attached: it is the value
/// the emitter assigned rather than one recovered from rendered text. Fall back
/// to the shorthand tag for lines from supervisors that push no fields (as
/// upstream supervisors do), then to the level when neither is present. This
/// reads the field even when `ocsf_full_payload` is off — that flag governs
/// what leaves the box, not what the gateway may use to rank a record.
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

/// Whether events from `target` could be produced by the export path itself.
///
/// The export worker logs its own failures, and the OTLP/tonic stack beneath
/// it logs transport errors. Forwarding those into the export queue would turn
/// every export failure into fresh queue traffic — a feedback loop that is
/// loudest exactly when the collector is down. They stay on gateway stdout.
fn is_export_feedback_target(target: &str) -> bool {
    target.starts_with("openshell_server::log_export")
        || target.starts_with("opentelemetry")
        || target.starts_with("tonic")
        // `tower::buffer` drives the tonic export channel; `tower_http`
        // (server middleware) is deliberately not matched.
        || target == "tower"
        || target.starts_with("tower::")
        || target.starts_with("h2")
        || target.starts_with("hyper")
        || target.starts_with("rustls")
}

/// Tracing layer that feeds gateway-produced events into the export queue.
struct ExportLayer {
    handle: LogExportHandle,
    ocsf_full_payload: bool,
    ocsf_schema_version: Option<&'static str>,
}

impl ExportLayer {
    fn ocsf_line(&self, event: &OcsfEvent) -> SandboxLogLine {
        let base = event.base();
        // Same routing rule as the sandbox log bus: the affected sandbox, not
        // the gateway that produced the event. No container = gateway-wide.
        let sandbox_id = base
            .container
            .as_ref()
            .and_then(|container| container.uid.clone())
            .unwrap_or_default();
        // Rendering `ocsf.raw` is the expensive part; skip it when the
        // payload is not going to leave the box, but keep the severity so the
        // record still ranks correctly.
        let fields = if self.ocsf_full_payload {
            raw_event_fields(event, self.ocsf_schema_version)
        } else {
            HashMap::from([(
                SEVERITY_ID_KEY.to_string(),
                base.severity.as_u8().to_string(),
            )])
        };
        SandboxLogLine {
            sandbox_id,
            event_time: openshell_core::time::timestamp_from_millis(base.time).ok(),
            level: "OCSF".to_string(),
            target: OCSF_TARGET.to_string(),
            message: event.format_shorthand(),
            source: "gateway".to_string(),
            fields,
        }
    }
}

impl<S: Subscriber> Layer<S> for ExportLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if is_export_feedback_target(meta.target()) {
            return;
        }

        if meta.target() == OCSF_TARGET
            && let Some(ocsf) = openshell_ocsf::clone_current_event()
        {
            let mut line = self.ocsf_line(&ocsf);
            if line.sandbox_id.is_empty() {
                // `emit_ocsf_event_routed` names the sandbox in a tracing
                // field rather than in `container.uid`.
                let mut visitor = LogVisitor::default();
                event.record(&mut visitor);
                line.sandbox_id = visitor.sandbox_id.unwrap_or_default();
            }
            self.handle.enqueue(line);
            return;
        }

        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);
        let level = if meta.target() == OCSF_TARGET {
            "OCSF".to_string()
        } else {
            meta.level().to_string()
        };
        self.handle.enqueue(SandboxLogLine {
            sandbox_id: visitor.sandbox_id.unwrap_or_default(),
            event_time: openshell_core::time::timestamp_from_millis(openshell_core::time::now_ms())
                .ok(),
            level,
            target: meta.target().to_string(),
            message: visitor.message.unwrap_or_else(|| meta.name().to_string()),
            source: "gateway".to_string(),
            fields: visitor.fields,
        });
    }
}

/// Collects an event's message, sandbox id and every other structured field,
/// so exported records keep the data operators otherwise find only on stdout
/// (e.g. an auth denial's principal and requested sandbox).
#[derive(Debug, Default)]
struct LogVisitor {
    sandbox_id: Option<String>,
    message: Option<String>,
    fields: HashMap<String, String>,
}

impl LogVisitor {
    fn put(&mut self, name: &str, value: String) {
        match name {
            "sandbox_id" => self.sandbox_id = Some(value).filter(|id| !id.is_empty()),
            "message" => self.message = Some(value),
            name => {
                self.fields.insert(name.to_string(), value);
            }
        }
    }
}

impl tracing::field::Visit for LogVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.put(field.name(), value.to_string());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.put(field.name(), format!("{value:?}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
    use opentelemetry_sdk::logs::InMemoryLogExporter;
    use std::sync::atomic::AtomicU32;

    fn ocsf_line(message: &str) -> SandboxLogLine {
        SandboxLogLine {
            sandbox_id: "sb-1".into(),
            event_time: openshell_core::time::timestamp_from_millis(1).ok(),
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
            event_time: openshell_core::time::timestamp_from_millis(1).ok(),
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

    fn is_gap(record: &SdkLogRecord) -> bool {
        attribute(record, "log.target") == Some(AnyValue::String("telemetry_gap".into()))
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

    #[test]
    fn event_time_becomes_the_record_timestamp() {
        let factory = SdkLoggerProvider::builder().build();
        let logger = openshell_otel::logger(&factory, INSTRUMENTATION_SCOPE);
        let mut line = plain_line("timed");
        line.event_time = openshell_core::time::timestamp_from_millis(1_700_000_000_123).ok();
        let record = record_for(&logger, line, true);
        assert_eq!(
            record.timestamp(),
            Some(SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123))
        );

        let mut untimed = plain_line("untimed");
        untimed.event_time = None;
        assert_eq!(record_for(&logger, untimed, true).timestamp(), None);
    }

    #[test]
    fn ocsf_payload_is_gated_but_other_fields_always_travel() {
        let factory = SdkLoggerProvider::builder().build();
        let logger = openshell_otel::logger(&factory, INSTRUMENTATION_SCOPE);
        let mut ocsf = ocsf_line("NET:OPEN [MED] DENIED curl(1) -> host:443");
        ocsf.fields
            .insert("ocsf.raw".to_string(), "{\"class_uid\":4001}".to_string());
        let mut plain = plain_line("principal denied");
        plain
            .fields
            .insert("principal".to_string(), "user:alice".to_string());

        let shorthand_only = record_for(&logger, ocsf.clone(), false);
        assert!(attribute(&shorthand_only, "ocsf.raw").is_none());
        assert!(attribute(&record_for(&logger, ocsf, true), "ocsf.raw").is_some());
        assert_eq!(
            attribute(&record_for(&logger, plain, false), "principal"),
            Some(AnyValue::String("user:alice".into()))
        );
    }

    #[tokio::test]
    async fn a_raw_mode_line_ranks_by_severity_and_carries_its_payload() {
        // A supervisor pushes the event as one JSON field plus its severity.
        // The gateway must rank it by that severity and pass the document
        // through untouched.
        let mut line = ocsf_line("NET:OPEN [MED] DENIED curl(1) -> blocked.invalid:443");
        line.fields.insert(
            "ocsf.raw".to_string(),
            "{\"class_uid\":4001,\"severity_id\":4}".to_string(),
        );
        line.fields
            .insert(SEVERITY_ID_KEY.to_string(), "4".to_string());

        let exporter = InMemoryLogExporter::default();
        let (handle, worker) = spawn(
            KeptExporter(exporter.clone()),
            Resource::builder_empty().build(),
            true,
        );
        handle.enqueue(line);
        worker.shutdown().await;

        let emitted = exporter.get_emitted_logs().unwrap();
        assert_eq!(emitted.len(), 1);
        let record = &emitted[0].record;
        // The pushed severity field wins over the rendered [MED] tag.
        assert_eq!(record.severity_number(), Some(Severity::Error));
        assert_eq!(
            attribute(record, "ocsf.raw"),
            Some(AnyValue::String(
                "{\"class_uid\":4001,\"severity_id\":4}".into()
            ))
        );
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
            usize::MAX,
        );

        for i in 0..10 {
            handle.enqueue(plain_line(&format!("line-{i}")));
        }
        worker.shutdown().await;

        let emitted = exporter.get_emitted_logs().unwrap();
        let (gaps, lines): (Vec<_>, Vec<_>) = emitted.iter().partition(|log| is_gap(&log.record));

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

    #[tokio::test]
    async fn queued_bytes_are_bounded_and_overflow_is_accounted() {
        // Room for many lines but only about three 64 KiB ones.
        let exporter = InMemoryLogExporter::default();
        let (handle, worker) = spawn_with_capacity(
            KeptExporter(exporter.clone()),
            Resource::builder_empty().build(),
            false,
            1024,
            3 * 64 * 1024 + 1024,
        );

        for _ in 0..10 {
            handle.enqueue(plain_line(&"x".repeat(64 * 1024)));
        }
        worker.shutdown().await;

        let emitted = exporter.get_emitted_logs().unwrap();
        let (gaps, lines): (Vec<_>, Vec<_>) = emitted.iter().partition(|log| is_gap(&log.record));
        assert_eq!(lines.len(), 3, "lines within the byte budget are exported");
        assert_eq!(gaps.len(), 1);
        assert_eq!(
            attribute(&gaps[0].record, "dropped"),
            Some(AnyValue::Int(7))
        );
    }

    fn agent_line(sandbox_id: &str, message: &str) -> SandboxLogLine {
        SandboxLogLine {
            sandbox_id: sandbox_id.to_string(),
            source: openshell_core::agent_output::AGENT_LOG_SOURCE.to_string(),
            target: openshell_core::agent_output::AGENT_STDOUT_TARGET.to_string(),
            ..plain_line(message)
        }
    }

    #[tokio::test]
    async fn one_sandboxs_agent_output_cannot_crowd_out_other_records() {
        let exporter = InMemoryLogExporter::default();
        let (handle, worker) = spawn(
            KeptExporter(exporter.clone()),
            Resource::builder_empty().build(),
            false,
        );

        // Far more than one sandbox's agent share, then ordinary records.
        let big = "x".repeat(64 * 1024);
        for _ in 0..1000 {
            handle.enqueue(agent_line("sb-noisy", &big));
        }
        handle.enqueue(agent_line("sb-quiet", "quiet agent line"));
        for i in 0..100 {
            handle.enqueue(ocsf_line(&format!("NET:OPEN [INFO] ALLOWED {i}")));
        }
        worker.shutdown().await;

        let emitted = exporter.get_emitted_logs().unwrap();
        let ocsf = emitted
            .iter()
            .filter(|log| attribute(&log.record, "log.ocsf") == Some(AnyValue::Boolean(true)))
            .count();
        assert_eq!(ocsf, 100, "every OCSF record is exported");
        assert!(
            emitted
                .iter()
                .any(|log| body_of(&log.record) == "quiet agent line"),
            "another sandbox's agent output keeps its own share"
        );
        let noisy = emitted
            .iter()
            .filter(|log| body_of(&log.record) == big)
            .count();
        assert!(noisy * 64 * 1024 <= AGENT_QUEUE_MAX_BYTES_PER_SANDBOX);

        let gap = emitted
            .iter()
            .find(|log| is_gap(&log.record) && attribute(&log.record, "stream").is_some())
            .expect("agent gap record");
        assert_eq!(
            attribute(&gap.record, "sandbox.id"),
            Some(AnyValue::String("sb-noisy".into()))
        );
        assert_eq!(
            attribute(&gap.record, "dropped"),
            Some(AnyValue::Int(i64::try_from(1000 - noisy).unwrap()))
        );
        assert!(
            !emitted
                .iter()
                .any(|log| is_gap(&log.record) && attribute(&log.record, "stream").is_none()),
            "nothing else was dropped"
        );
    }

    #[test]
    fn fill_closes_a_batch_at_the_byte_cap() {
        let (tx, rx) = mpsc::channel(1024);
        let mut rx = QueueReceiver {
            rx,
            budget: Arc::new(QueueBudget::new(usize::MAX)),
        };
        for _ in 0..100 {
            tx.try_send(plain_line(&"y".repeat(64 * 1024))).unwrap();
        }
        let factory = SdkLoggerProvider::builder().build();
        let logger = openshell_otel::logger(&factory, INSTRUMENTATION_SCOPE);
        let mut records = Vec::new();
        fill(&mut records, 0, &mut rx, &logger, false);
        assert!(
            records.len() < 100,
            "a byte-capped batch leaves lines queued"
        );
        assert!(records.len() * 64 * 1024 <= MAX_BATCH_BYTES + 64 * 1024);
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
            .find(|log| is_gap(&log.record))
            .expect("the dropped batch is reported");
        assert_eq!(attribute(&gap.record, "dropped"), Some(AnyValue::Int(1)));
    }

    #[test]
    fn a_failed_gap_record_restores_the_count_it_stood_for() {
        // A gap record riding in a batch that is then dropped must not turn
        // "8 lines lost" into "1 record lost".
        let factory = SdkLoggerProvider::builder().build();
        let logger = openshell_otel::logger(&factory, INSTRUMENTATION_SCOPE);
        let dropped = AtomicU64::new(8);
        let since = AtomicI64::new(42);
        let mut batch = Batch {
            records: vec![record_for(&logger, plain_line("a"), false)],
            gap: None,
        };
        batch.gap = push_gap_record(&mut batch.records, &logger, &dropped, &since);
        assert_eq!(batch.gap, Some((8, 42)));
        assert_eq!(batch.lines(), 1);

        restore_dropped(&batch, &dropped, &since);
        assert_eq!(dropped.load(Ordering::Relaxed), 9);
        assert_eq!(since.load(Ordering::Relaxed), 42, "window start is kept");
    }

    #[tokio::test]
    async fn enqueue_after_shutdown_is_a_noop() {
        let exporter = InMemoryLogExporter::default();
        let (handle, worker) = spawn(exporter, Resource::builder_empty().build(), false);
        worker.shutdown().await;

        // The worker is gone and the channel closed; enqueue must not panic
        // and must not count the line toward a gap no export will carry.
        handle.enqueue(plain_line("hello"));
        assert_eq!(handle.dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn export_feedback_targets_are_excluded() {
        assert!(is_export_feedback_target("openshell_server::log_export"));
        assert!(is_export_feedback_target("opentelemetry_otlp::exporter"));
        assert!(is_export_feedback_target("tonic::transport"));
        assert!(is_export_feedback_target("tower::buffer::worker"));
        assert!(is_export_feedback_target("h2::codec"));
        // The rest of the gateway must not be swept up by the guard.
        assert!(!is_export_feedback_target("openshell_server::auth::guard"));
        assert!(!is_export_feedback_target("openshell_server::grpc::policy"));
        assert!(!is_export_feedback_target("openshell_server::ocsf_log"));
        assert!(!is_export_feedback_target("tower_http::trace"));
    }

    fn test_export(exporter: InMemoryLogExporter, full_payload: bool) -> LogExport {
        let (handle, worker) = spawn(
            KeptExporter(exporter),
            Resource::builder_empty().build(),
            full_payload,
        );
        LogExport {
            handle,
            worker,
            ocsf_full_payload: full_payload,
            ocsf_schema_version: None,
        }
    }

    /// The gateway lane: gateway events with and without a sandbox reach the
    /// exporter with their structured fields, OCSF events are routed by
    /// `container.uid` and carry `ocsf.raw`, and export-path warnings do not
    /// re-enter the queue.
    #[tokio::test]
    async fn gateway_events_export_through_the_layer() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = InMemoryLogExporter::default();
        let export = test_export(exporter.clone(), true);
        let sandbox_event = openshell_ocsf::ConfigStateChangeBuilder::new(
            &crate::gateway_ocsf::context("sb-audit", "audit"),
        )
        .severity(openshell_ocsf::SeverityId::High)
        .message("policy approved")
        .build();
        let shorthand = sandbox_event.format_shorthand();
        {
            let subscriber = tracing_subscriber::registry().with(export.layer());
            let _guard = crate::otel_tracing::test_exporter::install_scoped(subscriber);
            // Explicit targets: this module's own target is a feedback target.
            tracing::info!(target: "openshell_server::grpc", principal = "user:alice", "workspace created");
            tracing::warn!(target: "openshell_server::log_export", "OTLP log export failed");
            tracing::info!(target: "openshell_server::grpc", sandbox_id = "sb-1", "sandbox event");
            openshell_ocsf::ocsf_emit!(sandbox_event);
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(&crate::gateway_ocsf::context(
                    "", ""
                ))
                .message("gateway-wide event")
                .build()
            );
        }
        export.shutdown().await;

        let emitted = exporter.get_emitted_logs().unwrap();
        let records: Vec<_> = emitted.iter().map(|log| &log.record).collect();
        let bodies: Vec<String> = records.iter().map(|r| body_of(r)).collect();
        assert_eq!(
            records.len(),
            4,
            "the export-path warning must not export: {bodies:?}"
        );

        let gateway = records[0];
        assert!(attribute(gateway, "sandbox.id").is_none());
        assert_eq!(
            attribute(gateway, "principal"),
            Some(AnyValue::String("user:alice".into())),
            "structured fields survive export"
        );
        assert_eq!(
            attribute(gateway, "log.source"),
            Some(AnyValue::String("gateway".into()))
        );
        assert_eq!(
            attribute(records[1], "sandbox.id"),
            Some(AnyValue::String("sb-1".into()))
        );

        let audit = records[2];
        assert_eq!(body_of(audit), shorthand);
        assert_eq!(
            attribute(audit, "sandbox.id"),
            Some(AnyValue::String("sb-audit".into())),
            "OCSF events route by container.uid"
        );
        assert_eq!(audit.severity_number(), Some(Severity::Error));
        let Some(AnyValue::String(raw)) = attribute(audit, "ocsf.raw") else {
            panic!("gateway OCSF events carry ocsf.raw");
        };
        let raw: serde_json::Value = serde_json::from_str(raw.as_str()).unwrap();
        assert_eq!(raw["class_uid"], 5019);
        assert_eq!(raw["metadata"]["product"]["name"], "OpenShell Gateway");

        let wide = records[3];
        assert!(attribute(wide, "sandbox.id").is_none());
        assert_eq!(attribute(wide, "log.ocsf"), Some(AnyValue::Boolean(true)));
    }

    #[tokio::test]
    async fn routed_ocsf_events_keep_their_sandbox() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = InMemoryLogExporter::default();
        let export = test_export(exporter.clone(), true);
        {
            let subscriber = tracing_subscriber::registry().with(export.layer());
            let _guard = crate::otel_tracing::test_exporter::install_scoped(subscriber);
            openshell_ocsf::emit_ocsf_event_routed(
                "sb-routed",
                openshell_ocsf::ConfigStateChangeBuilder::new(&crate::gateway_ocsf::context(
                    "", "",
                ))
                .message("etw event")
                .build(),
            );
        }
        export.shutdown().await;

        let emitted = exporter.get_emitted_logs().unwrap();
        assert_eq!(
            attribute(&emitted[0].record, "sandbox.id"),
            Some(AnyValue::String("sb-routed".into()))
        );
    }

    #[tokio::test]
    async fn shorthand_only_mode_skips_rendering_the_document() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = InMemoryLogExporter::default();
        let export = test_export(exporter.clone(), false);
        {
            let subscriber = tracing_subscriber::registry().with(export.layer());
            let _guard = crate::otel_tracing::test_exporter::install_scoped(subscriber);
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(&crate::gateway_ocsf::context(
                    "", ""
                ))
                .severity(openshell_ocsf::SeverityId::Medium)
                .message("tls reloaded")
                .build()
            );
        }
        export.shutdown().await;

        let emitted = exporter.get_emitted_logs().unwrap();
        let record = &emitted[0].record;
        assert!(attribute(record, "ocsf.raw").is_none());
        assert_eq!(record.severity_number(), Some(Severity::Warn2));
    }

    /// One `ocsf_emit!` reaches both upstream's JSONL sink and the OTLP
    /// exporter even when the console filter is `off`, because both layers
    /// accept the OCSF target regardless of the operator's directives.
    #[tokio::test]
    async fn one_ocsf_event_reaches_jsonl_and_otlp_with_console_off() {
        use tracing_subscriber::filter::{FilterExt as _, filter_fn};
        use tracing_subscriber::layer::SubscriberExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let config: crate::config_file::OcsfLogConfig =
            toml::from_str(&format!("path = {path:?}\nrotation = 'never'\n")).unwrap();
        let ocsf_log = crate::ocsf_log::OcsfLog::start(config).unwrap();

        let exporter = InMemoryLogExporter::default();
        let export = test_export(exporter.clone(), true);
        let ocsf_only = || filter_fn(|meta| meta.target() == OCSF_TARGET);
        {
            let subscriber = tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::sink)
                        .with_filter(tracing_subscriber::EnvFilter::new("off")),
                )
                .with(ocsf_log.layer().with_filter(ocsf_only()))
                .with(
                    export
                        .layer()
                        .with_filter(tracing_subscriber::EnvFilter::new("off").or(ocsf_only())),
                );
            let _guard = crate::otel_tracing::test_exporter::install_scoped(subscriber);
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(&crate::gateway_ocsf::context(
                    "sb-1", "one"
                ))
                .message("policy approved")
                .build()
            );
            tracing::info!(target: "openshell_server::grpc", "filtered diagnostic");
        }
        ocsf_log.shutdown().await;
        export.shutdown().await;

        let jsonl = std::fs::read_to_string(&path).unwrap();
        assert_eq!(jsonl.lines().count(), 1, "JSONL: {jsonl}");
        let emitted = exporter.get_emitted_logs().unwrap();
        assert_eq!(emitted.len(), 1, "only the OCSF event passes 'off'");
        let Some(AnyValue::String(raw)) = attribute(&emitted[0].record, "ocsf.raw") else {
            panic!("missing ocsf.raw");
        };
        let from_jsonl: serde_json::Value = serde_json::from_str(jsonl.trim()).unwrap();
        let from_otlp: serde_json::Value = serde_json::from_str(raw.as_str()).unwrap();
        assert_eq!(from_jsonl, from_otlp, "both sinks carry the same document");
    }
}
