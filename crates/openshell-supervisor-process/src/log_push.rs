// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Push sandbox tracing events to the `OpenShell` server via gRPC.
//!
//! A [`tracing`] layer captures log events and sends them through an mpsc
//! channel to a background task. The task batches lines and streams them to
//! the server using the `PushSandboxLogs` client-streaming RPC.
//!
//! Delivery is bounded but accounted: a line that cannot be queued (or
//! buffered across a reconnect) increments a shared counter, and the push task
//! reports the count to the gateway as a `telemetry_gap` line. Loss on this
//! hop is therefore countable downstream instead of silent.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use openshell_core::grpc_client::CachedOpenShellClient;
use openshell_core::proto::{PushSandboxLogsRequest, SandboxLogLine};
use tokio::sync::mpsc;
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Default upper bound on how long an event may block waiting for queue space
/// before it is accounted as a dropped line. Overridable via
/// `OPENSHELL_LOG_PUSH_BLOCK_MS`; `0` restores pure best-effort `try_send`.
const DEFAULT_BLOCK_TIMEOUT_MS: u64 = 25;

/// Poll interval while blocking for queue space.
const ENQUEUE_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(2);

/// Lines per `PushSandboxLogsRequest`. Kept below the gateway's per-request
/// ingest limit so a reconnect flush is never truncated there.
const MAX_LINES_PER_REQUEST: usize = 50;

/// Target of the accounted loss line, shared with the gateway.
pub const TELEMETRY_GAP_TARGET: &str = "telemetry_gap";

/// How OCSF events are rendered into a pushed line's fields.
///
/// Selected once at startup via `OPENSHELL_OCSF_PUSH_FORMAT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OcsfPushFormat {
    /// Flatten the event into dotted `ocsf.*` fields (opt-in via `flat`).
    /// A consumer can match individual fields with no parse step, but
    /// rendering costs one entry per leaf on this hot path and values are
    /// truncated and stringified.
    Flat,
    /// Push the complete event JSON as one `ocsf.raw` field plus
    /// `ocsf.severity_id` so the gateway can rank the record without parsing
    /// it. The default: full fidelity, no truncation, and a fraction of the
    /// per-event cost.
    Raw,
}

impl OcsfPushFormat {
    fn from_env() -> Self {
        Self::parse(std::env::var("OPENSHELL_OCSF_PUSH_FORMAT").ok().as_deref())
    }

    /// `flat` opts into flattened fields; anything else (unset, `raw`, or an
    /// unrecognized value) keeps the default, so a typo cannot change what a
    /// SIEM receives.
    fn parse(value: Option<&str>) -> Self {
        match value {
            Some(v) if v.trim().eq_ignore_ascii_case("flat") => Self::Flat,
            _ => Self::Raw,
        }
    }
}

/// Tracing layer that pushes log events to the `OpenShell` server.
///
/// An event first tries the queue without blocking. If the queue is full it
/// blocks briefly (bounded by `block_timeout`) and then gives up, counting the
/// line in a counter shared with the push task, which reports it as an
/// accounted `telemetry_gap` line. Blocking is bounded because `on_event` must
/// never hang the sandbox.
#[derive(Clone)]
pub struct LogPushLayer {
    sandbox_id: String,
    tx: mpsc::Sender<SandboxLogLine>,
    max_level: tracing::Level,
    block_timeout: std::time::Duration,
    ocsf_format: OcsfPushFormat,
    /// OCSF schema version for the pushed document (the sandbox's
    /// `ocsf_schema_version` setting). Empty or unset means current schema.
    target_version: Option<Arc<Mutex<String>>>,
    dropped: Arc<AtomicU64>,
}

impl LogPushLayer {
    pub fn new(
        sandbox_id: String,
        tx: mpsc::Sender<SandboxLogLine>,
        dropped: Arc<AtomicU64>,
    ) -> Self {
        let max_level = parse_max_level(std::env::var("OPENSHELL_LOG_PUSH_LEVEL").ok().as_deref());
        let block_timeout =
            parse_block_timeout(std::env::var("OPENSHELL_LOG_PUSH_BLOCK_MS").ok().as_deref());
        Self {
            sandbox_id,
            tx,
            max_level,
            block_timeout,
            ocsf_format: OcsfPushFormat::from_env(),
            target_version: None,
            dropped,
        }
    }

    /// Render pushed OCSF documents at this schema version, the same shared
    /// setting the local `OcsfJsonlLayer` follows, so `ocsf.raw` matches the
    /// sandbox's JSONL file for the same event.
    #[must_use]
    pub fn with_target_version(mut self, version: Arc<Mutex<String>>) -> Self {
        self.target_version = Some(version);
        self
    }

    fn ocsf_fields(
        &self,
        event: &openshell_ocsf::OcsfEvent,
    ) -> std::collections::HashMap<String, String> {
        let target = self
            .target_version
            .as_ref()
            .and_then(|version| version.lock().ok().map(|v| v.clone()));
        let target = target.as_deref();
        match self.ocsf_format {
            OcsfPushFormat::Flat => {
                openshell_ocsf::format::attributes::flatten_event(event, target)
            }
            OcsfPushFormat::Raw => {
                openshell_ocsf::format::attributes::raw_event_fields(event, target)
            }
        }
    }

    /// Enqueue a line: a non-blocking attempt, then a bounded block, then an
    /// accounted drop. Never blocks longer than `block_timeout`.
    fn enqueue(&self, line: SandboxLogLine) {
        let mut line = match self.tx.try_send(line) {
            // A closed receiver means the push task has stopped (shutdown or a
            // fatal auth failure); there is no one left to report a gap to.
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => return,
            Err(mpsc::error::TrySendError::Full(line)) => line,
        };

        // `on_event` is synchronous and may run on a runtime worker, so bound
        // the block on this thread instead of awaiting.
        let deadline = std::time::Instant::now() + self.block_timeout;
        loop {
            if std::time::Instant::now() >= deadline {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            std::thread::sleep(ENQUEUE_RETRY_INTERVAL);
            match self.tx.try_send(line) {
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => return,
                Err(mpsc::error::TrySendError::Full(unsent)) => line = unsent,
            }
        }
    }
}

/// Resolve the enqueue block bound, defaulting when unset or unparseable.
fn parse_block_timeout(raw: Option<&str>) -> std::time::Duration {
    std::time::Duration::from_millis(
        raw.and_then(|s| s.trim().parse().ok())
            .unwrap_or(DEFAULT_BLOCK_TIMEOUT_MS),
    )
}

/// Resolve the push level filter, defaulting to `INFO` when unset or unparseable.
fn parse_max_level(raw: Option<&str>) -> tracing::Level {
    raw.and_then(|s| s.parse().ok())
        .unwrap_or(tracing::Level::INFO)
}

impl<S: Subscriber> Layer<S> for LogPushLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();

        // Filter by configured max level (default: info).
        if *meta.level() > self.max_level {
            return;
        }

        // OCSF events carry their payload in a thread-local. Push the rendered
        // shorthand as the message and the event's structure as fields: one
        // raw `ocsf.raw` document by default, or flattened `ocsf.*` keys when
        // `OPENSHELL_OCSF_PUSH_FORMAT=flat`. Non-OCSF events use the
        // visitor-based extraction.
        let (msg, fields) = if meta.target() == openshell_ocsf::OCSF_TARGET {
            if let Some(ocsf_event) = openshell_ocsf::clone_current_event() {
                let fields = self.ocsf_fields(&ocsf_event);
                (ocsf_event.format_shorthand(), fields)
            } else {
                return;
            }
        } else {
            let mut visitor = LogVisitor::default();
            event.record(&mut visitor);
            visitor.into_parts(meta.name())
        };

        let ts = openshell_core::time::now_ms();

        let is_ocsf = meta.target() == openshell_ocsf::OCSF_TARGET;

        let log = SandboxLogLine {
            sandbox_id: self.sandbox_id.clone(),
            event_time: openshell_core::time::timestamp_from_millis(ts).ok(),
            level: if is_ocsf {
                "OCSF".to_string()
            } else {
                meta.level().to_string()
            },
            target: meta.target().to_string(),
            message: msg,
            source: "sandbox".to_string(),
            fields,
        };

        self.enqueue(log);
    }
}

/// Spawn a background task that batches and pushes log lines to the server.
///
/// Returns the sender half of the channel and the shared drop counter (both
/// for the [`LogPushLayer`]), and the task handle. The task runs until the
/// sender is dropped or authentication fails.
pub fn spawn_log_push_task(
    endpoint: String,
    sandbox_id: String,
) -> (
    mpsc::Sender<SandboxLogLine>,
    Arc<AtomicU64>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::channel::<SandboxLogLine>(1024);
    let dropped = Arc::new(AtomicU64::new(0));

    let handle = tokio::spawn(run_push_loop(
        endpoint,
        sandbox_id,
        rx,
        Arc::clone(&dropped),
    ));

    (tx, dropped, handle)
}

/// Build an accounted `telemetry_gap` line describing lines dropped since the
/// last report. The push task adds it straight to its outbound batch,
/// bypassing the congested channel that caused the drops.
fn telemetry_gap_line(sandbox_id: &str, dropped: u64) -> SandboxLogLine {
    let mut fields = std::collections::HashMap::new();
    fields.insert("dropped".to_string(), dropped.to_string());
    SandboxLogLine {
        sandbox_id: sandbox_id.to_string(),
        // The gateway rejects the whole stream on an invalid event_time, so
        // this must be a valid timestamp like every other pushed line.
        event_time: openshell_core::time::timestamp_from_millis(openshell_core::time::now_ms())
            .ok(),
        level: "WARN".to_string(),
        target: TELEMETRY_GAP_TARGET.to_string(),
        message: format!("telemetry gap: {dropped} sandbox log line(s) dropped"),
        source: "sandbox".to_string(),
        fields,
    }
}

/// If any lines were dropped since the last check, reset the counter and add a
/// single accounted gap line to `batch`.
fn record_gap_if_any(sandbox_id: &str, dropped: &AtomicU64, batch: &mut Vec<SandboxLogLine>) {
    let n = dropped.swap(0, Ordering::Relaxed);
    if n > 0 {
        batch.push(telemetry_gap_line(sandbox_id, n));
    }
}

/// Maximum backoff delay between reconnection attempts.
const MAX_BACKOFF: tokio::time::Duration = tokio::time::Duration::from_secs(30);
/// Initial backoff delay after a connection failure.
const INITIAL_BACKOFF: tokio::time::Duration = tokio::time::Duration::from_secs(1);

async fn run_push_loop(
    endpoint: String,
    sandbox_id: String,
    mut rx: mpsc::Receiver<SandboxLogLine>,
    dropped: Arc<AtomicU64>,
) {
    let mut batch = Vec::with_capacity(MAX_LINES_PER_REQUEST);
    let mut backoff = INITIAL_BACKOFF;
    let mut attempt: u64 = 0;

    // Outer reconnect loop — runs for the entire sandbox lifetime.
    loop {
        attempt += 1;

        // --- Connect ---
        let client = match CachedOpenShellClient::connect(&endpoint).await {
            Ok(c) => {
                if attempt > 1 {
                    eprintln!("openshell: log push reconnected (attempt {attempt})");
                }
                backoff = INITIAL_BACKOFF;
                c
            }
            Err(e) => {
                eprintln!("openshell: log push connect failed: {e}");
                // Drain the channel during backoff so the tracing layer doesn't
                // block, but discard lines we can't deliver.
                drain_during_backoff(&mut rx, &mut batch, &dropped, backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };

        // --- Open the client-streaming RPC ---
        let (push_tx, push_rx) = mpsc::channel::<PushSandboxLogsRequest>(32);
        let stream = tokio_stream::wrappers::ReceiverStream::new(push_rx);

        // Spawn the gRPC streaming call. When the call ends (success or error),
        // `rpc_done_tx` fires so the batch loop below knows whether to retry.
        let (rpc_done_tx, mut rpc_done_rx) = mpsc::channel::<bool>(1);
        tokio::spawn({
            let mut nav_client = client.raw_client();
            async move {
                let fatal_auth = match nav_client.push_sandbox_logs(stream).await {
                    Ok(_) => false,
                    Err(e) => {
                        let fatal_auth = e.code() == tonic::Code::Unauthenticated;
                        eprintln!("openshell: log push RPC failed: {e}");
                        fatal_auth
                    }
                };
                let _ = rpc_done_tx.send(fatal_auth).await;
            }
        });

        // --- Flush any lines buffered during reconnect ---
        // Report outage loss first so it reaches the gateway immediately, then
        // send in request-sized chunks: the reconnect buffer can exceed the
        // gateway's per-request ingest limit.
        record_gap_if_any(&sandbox_id, &dropped, &mut batch);
        let mut flush_failed = false;
        while !batch.is_empty() {
            let rest = batch.split_off(batch.len().min(MAX_LINES_PER_REQUEST));
            let lines = std::mem::replace(&mut batch, rest);
            if let Err(unsent) = push_tx
                .send(PushSandboxLogsRequest {
                    sandbox_id: sandbox_id.clone(),
                    logs: lines,
                })
                .await
            {
                // Keep the unsent chunk ahead of the rest for the next attempt.
                let mut restored = unsent.0.logs;
                restored.append(&mut batch);
                batch = restored;
                flush_failed = true;
                break;
            }
        }
        if flush_failed {
            // RPC died immediately — go back to reconnect.
            backoff = INITIAL_BACKOFF;
            continue;
        }

        // --- Batch and send loop (runs until stream breaks) ---
        let flush_interval = tokio::time::Duration::from_millis(500);
        let mut timer = tokio::time::interval(flush_interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut fatal_auth = false;
        let stream_broken = loop {
            tokio::select! {
                line = rx.recv() => {
                    let Some(line) = line else {
                        // Tracing layer dropped — sandbox is shutting down.
                        // Flush remaining (including any final gap) and exit.
                        record_gap_if_any(&sandbox_id, &dropped, &mut batch);
                        if !batch.is_empty() {
                            let lines = std::mem::take(&mut batch);
                            let _ = push_tx.send(PushSandboxLogsRequest {
                                sandbox_id: sandbox_id.clone(),
                                logs: lines,
                            }).await;
                        }
                        return;
                    };
                    batch.push(line);
                    if batch.len() >= MAX_LINES_PER_REQUEST {
                        let lines = std::mem::take(&mut batch);
                        if push_tx.send(PushSandboxLogsRequest {
                            sandbox_id: sandbox_id.clone(),
                            logs: lines,
                        }).await.is_err() {
                            break true;
                        }
                    }
                }
                _ = timer.tick() => {
                    // Report drops on the periodic flush, even while the
                    // channel is congested.
                    record_gap_if_any(&sandbox_id, &dropped, &mut batch);
                    if !batch.is_empty() {
                        let lines = std::mem::take(&mut batch);
                        if push_tx.send(PushSandboxLogsRequest {
                            sandbox_id: sandbox_id.clone(),
                            logs: lines,
                        }).await.is_err() {
                            break true;
                        }
                    }
                }
                rpc_done = rpc_done_rx.recv() => {
                    // The gRPC streaming call ended (server closed / error).
                    fatal_auth = rpc_done.unwrap_or(false);
                    break true;
                }
            }
        };

        if fatal_auth {
            eprintln!("openshell: log push disabled after authentication failure");
            return;
        }

        if stream_broken {
            eprintln!("openshell: log push stream lost, reconnecting after backoff...");
            drain_during_backoff(&mut rx, &mut batch, &dropped, backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }
}

/// Drain incoming log lines during a backoff delay so the tracing layer's
/// `try_send` doesn't fill up. Lines received during backoff are kept in `batch`
/// (up to a limit) so they can be sent after reconnecting; lines beyond the
/// limit are counted in `dropped` and reported as a `telemetry_gap`.
async fn drain_during_backoff(
    rx: &mut mpsc::Receiver<SandboxLogLine>,
    batch: &mut Vec<SandboxLogLine>,
    dropped: &AtomicU64,
    delay: tokio::time::Duration,
) {
    // Keep at most 200 lines across reconnect attempts to bound memory.
    const MAX_BUFFERED: usize = 200;

    let deadline = tokio::time::Instant::now() + delay;
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => { return; }
            line = rx.recv() => {
                match line {
                    Some(l) => {
                        if batch.len() < MAX_BUFFERED {
                            batch.push(l);
                        } else {
                            // Over the reconnect buffer limit: account it.
                            dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    None => return, // channel closed, sandbox shutting down
                }
            }
        }
    }
}

#[derive(Debug, Default)]
struct LogVisitor {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl LogVisitor {
    /// Split into message and structured fields map.
    fn into_parts(self, fallback: &str) -> (String, std::collections::HashMap<String, String>) {
        let msg = self.message.unwrap_or_else(|| fallback.to_string());
        let fields = self.fields.into_iter().collect();
        (msg, fields)
    }
}

impl tracing::field::Visit for LogVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        } else {
            self.fields
                .push((field.name().to_string(), format!("{value:?}")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_ocsf::{
        ActionId, ActivityId, DispositionId, Endpoint, EventContext, EventOrigin,
        NetworkActivityBuilder, SeverityId, StatusId, ocsf_emit,
    };
    use tracing_subscriber::layer::SubscriberExt;

    fn ocsf_ctx() -> EventContext {
        EventContext {
            sandbox_id: "sb-test".to_string(),
            sandbox_name: "test-sandbox".to_string(),
            origin: EventOrigin::Supervisor,
            container_image: "openshell/sandbox:test".to_string(),
            hostname: "test-host".to_string(),
            product_version: "0.0.0".to_string(),
            proxy_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            proxy_port: 8888,
        }
    }

    fn test_layer(tx: mpsc::Sender<SandboxLogLine>, dropped: Arc<AtomicU64>) -> LogPushLayer {
        LogPushLayer {
            sandbox_id: "sb-test".to_string(),
            tx,
            max_level: tracing::Level::INFO,
            // Small, so tests that fill the channel don't sleep 25ms per line.
            block_timeout: std::time::Duration::from_millis(5),
            ocsf_format: OcsfPushFormat::Raw,
            target_version: None,
            dropped,
        }
    }

    /// Capture lines emitted by `f` through `layer`.
    fn capture_with(
        layer: LogPushLayer,
        mut rx: mpsc::Receiver<SandboxLogLine>,
        f: impl FnOnce(),
    ) -> Vec<SandboxLogLine> {
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, f);

        let mut out = Vec::new();
        while let Ok(line) = rx.try_recv() {
            out.push(line);
        }
        out
    }

    /// Capture lines emitted by `f` with an `INFO` level filter.
    fn capture(capacity: usize, f: impl FnOnce()) -> Vec<SandboxLogLine> {
        let (tx, rx) = mpsc::channel::<SandboxLogLine>(capacity);
        capture_with(test_layer(tx, Arc::new(AtomicU64::new(0))), rx, f)
    }

    fn denied_event() -> openshell_ocsf::OcsfEvent {
        NetworkActivityBuilder::new(&ocsf_ctx())
            .activity(ActivityId::Open)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .dst_endpoint(Endpoint::from_domain("blocked.example.com", 443))
            .message("CONNECT denied blocked.example.com:443".to_string())
            .build()
    }

    #[test]
    fn ocsf_events_push_shorthand_with_ocsf_level_and_raw_fields() {
        let event = denied_event();
        let expected_shorthand = event.format_shorthand();

        let lines = capture(16, || ocsf_emit!(event));

        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line.level, "OCSF");
        assert_eq!(line.target, openshell_ocsf::OCSF_TARGET);
        assert_eq!(line.source, "sandbox");
        assert_eq!(line.sandbox_id, "sb-test");
        assert_eq!(line.message, expected_shorthand);
        assert!(line.event_time.is_some());

        assert_eq!(
            line.fields.len(),
            2,
            "raw push is ocsf.raw + ocsf.severity_id"
        );
        let raw: serde_json::Value = serde_json::from_str(
            line.fields
                .get(openshell_ocsf::format::attributes::RAW_KEY)
                .expect("ocsf.raw"),
        )
        .expect("ocsf.raw parses as JSON");
        assert_eq!(raw["class_uid"], 4001);
        assert_eq!(raw["container"]["uid"], "sb-test");
        assert_eq!(
            line.fields
                .get(openshell_ocsf::format::attributes::SEVERITY_ID_KEY)
                .map(String::as_str),
            Some("3")
        );
    }

    #[test]
    fn ocsf_events_push_flattened_fields_when_flat_is_selected() {
        let (tx, rx) = mpsc::channel::<SandboxLogLine>(16);
        let mut layer = test_layer(tx, Arc::new(AtomicU64::new(0)));
        layer.ocsf_format = OcsfPushFormat::Flat;
        let event = denied_event();

        let lines = capture_with(layer, rx, || ocsf_emit!(event));

        assert_eq!(lines.len(), 1);
        let fields = &lines[0].fields;
        assert!(!fields.contains_key(openshell_ocsf::format::attributes::RAW_KEY));
        assert_eq!(
            fields.get("ocsf.class_uid").map(String::as_str),
            Some("4001")
        );
        assert_eq!(
            fields.get("ocsf.dst_endpoint.port").map(String::as_str),
            Some("443")
        );
    }

    #[test]
    fn ocsf_raw_push_follows_the_shared_schema_version() {
        let (tx, rx) = mpsc::channel::<SandboxLogLine>(16);
        let version = Arc::new(Mutex::new("1.1".to_string()));
        let layer =
            test_layer(tx, Arc::new(AtomicU64::new(0))).with_target_version(Arc::clone(&version));
        let event = denied_event();

        let lines = capture_with(layer, rx, || ocsf_emit!(event));

        let raw: serde_json::Value = serde_json::from_str(
            lines[0]
                .fields
                .get(openshell_ocsf::format::attributes::RAW_KEY)
                .expect("ocsf.raw"),
        )
        .unwrap();
        assert_eq!(raw["metadata"]["version"], "1.1");
        assert!(raw.get("container").is_none(), "1.1 has no container");
    }

    #[test]
    fn ocsf_push_format_parses_flat_and_defaults_everything_else_to_raw() {
        assert_eq!(OcsfPushFormat::parse(Some("flat")), OcsfPushFormat::Flat);
        assert_eq!(OcsfPushFormat::parse(Some(" FLAT ")), OcsfPushFormat::Flat);
        assert_eq!(OcsfPushFormat::parse(Some("raw")), OcsfPushFormat::Raw);
        // A typo must degrade to the default, never to silence.
        assert_eq!(OcsfPushFormat::parse(Some("flatt")), OcsfPushFormat::Raw);
        assert_eq!(OcsfPushFormat::parse(None), OcsfPushFormat::Raw);
    }

    #[test]
    fn parse_block_timeout_defaults_and_accepts_zero() {
        assert_eq!(
            parse_block_timeout(None),
            std::time::Duration::from_millis(DEFAULT_BLOCK_TIMEOUT_MS)
        );
        assert_eq!(
            parse_block_timeout(Some("nope")),
            std::time::Duration::from_millis(DEFAULT_BLOCK_TIMEOUT_MS)
        );
        assert_eq!(parse_block_timeout(Some("0")), std::time::Duration::ZERO);
        assert_eq!(
            parse_block_timeout(Some(" 100 ")),
            std::time::Duration::from_millis(100)
        );
    }

    #[test]
    fn telemetry_gap_line_carries_count_and_a_valid_event_time() {
        let line = telemetry_gap_line("sb-1", 7);
        assert_eq!(line.target, TELEMETRY_GAP_TARGET);
        assert_eq!(line.level, "WARN");
        assert_eq!(line.source, "sandbox");
        assert_eq!(line.sandbox_id, "sb-1");
        assert_eq!(line.fields.get("dropped").map(String::as_str), Some("7"));
        let event_time = line.event_time.expect("event_time is set");
        openshell_core::time::validate_timestamp(&event_time)
            .expect("gateway ingest accepts the gap line's timestamp");
    }

    #[test]
    fn record_gap_resets_counter_and_pushes_once() {
        let dropped = AtomicU64::new(3);
        let mut batch = Vec::new();
        record_gap_if_any("sb-1", &dropped, &mut batch);
        assert_eq!(batch.len(), 1);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        // Nothing dropped since: no additional gap line.
        record_gap_if_any("sb-1", &dropped, &mut batch);
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn enqueue_delivers_when_space_available() {
        let (tx, mut rx) = mpsc::channel::<SandboxLogLine>(1);
        let dropped = Arc::new(AtomicU64::new(0));
        test_layer(tx, Arc::clone(&dropped)).enqueue(test_line("m"));
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn enqueue_accounts_a_drop_when_full() {
        let (tx, _rx) = mpsc::channel::<SandboxLogLine>(1);
        tx.try_send(test_line("fill"))
            .expect("fill the single slot");
        let dropped = Arc::new(AtomicU64::new(0));
        // The receiver is held but never drains, so the block times out and
        // the line is counted rather than silently discarded.
        test_layer(tx, Arc::clone(&dropped)).enqueue(test_line("m"));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn enqueue_with_zero_block_drops_without_waiting() {
        let (tx, _rx) = mpsc::channel::<SandboxLogLine>(1);
        tx.try_send(test_line("fill"))
            .expect("fill the single slot");
        let dropped = Arc::new(AtomicU64::new(0));
        let mut layer = test_layer(tx, Arc::clone(&dropped));
        layer.block_timeout = std::time::Duration::ZERO;
        layer.enqueue(test_line("m"));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn enqueue_on_closed_channel_is_a_silent_noop() {
        let (tx, rx) = mpsc::channel::<SandboxLogLine>(1);
        drop(rx);
        let dropped = Arc::new(AtomicU64::new(0));
        // A closed channel means the push task has stopped, not backpressure.
        test_layer(tx, Arc::clone(&dropped)).enqueue(test_line("m"));
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn non_ocsf_events_use_visitor_extraction() {
        let lines = capture(16, || {
            tracing::info!(target: "test_target", answer = 42, name = "widget", "hello");
        });

        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line.level, "INFO");
        assert_eq!(line.target, "test_target");
        assert_eq!(line.source, "sandbox");
        assert_eq!(line.message, "hello");
        assert_eq!(line.fields.get("name").map(String::as_str), Some("widget"));
        assert_eq!(line.fields.get("answer").map(String::as_str), Some("42"));
        assert!(!line.fields.contains_key("message"));
    }

    #[test]
    fn events_without_a_message_field_fall_back_to_the_event_name() {
        let lines = capture(16, || {
            tracing::info!(target: "test_target", answer = 1);
        });

        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].message.starts_with("event "),
            "expected event-name fallback, got {:?}",
            lines[0].message
        );
    }

    #[test]
    fn events_below_the_max_level_are_filtered() {
        let lines = capture(16, || {
            tracing::debug!(target: "test_target", "debug line");
            tracing::trace!(target: "test_target", "trace line");
            tracing::info!(target: "test_target", "info line");
            tracing::warn!(target: "test_target", "warn line");
        });

        let messages: Vec<_> = lines.iter().map(|l| l.message.as_str()).collect();
        assert_eq!(messages, vec!["info line", "warn line"]);
    }

    #[test]
    fn lines_are_dropped_and_counted_when_the_channel_is_full() {
        let (tx, rx) = mpsc::channel::<SandboxLogLine>(2);
        let dropped = Arc::new(AtomicU64::new(0));
        let lines = capture_with(test_layer(tx, Arc::clone(&dropped)), rx, || {
            for i in 0..3 {
                tracing::info!(target: "test_target", "line {i}");
            }
        });

        assert_eq!(lines.len(), 2);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        assert_eq!(lines[0].message, "line 0");
        assert_eq!(lines[1].message, "line 1");
    }

    #[test]
    fn parse_max_level_defaults_to_info() {
        assert_eq!(parse_max_level(None), tracing::Level::INFO);
        assert_eq!(parse_max_level(Some("not-a-level")), tracing::Level::INFO);
        assert_eq!(parse_max_level(Some("debug")), tracing::Level::DEBUG);
        assert_eq!(parse_max_level(Some("TRACE")), tracing::Level::TRACE);
        assert_eq!(parse_max_level(Some("warn")), tracing::Level::WARN);
    }

    fn test_line(message: &str) -> SandboxLogLine {
        SandboxLogLine {
            sandbox_id: "sb-test".to_string(),
            event_time: openshell_core::time::timestamp_from_millis(1).ok(),
            level: "INFO".to_string(),
            target: "t".to_string(),
            message: message.to_string(),
            source: "sandbox".to_string(),
            fields: std::collections::HashMap::new(),
        }
    }

    #[tokio::test]
    async fn drain_during_backoff_buffers_up_to_the_cap_and_drops_the_rest() {
        let (tx, mut rx) = mpsc::channel::<SandboxLogLine>(1024);
        for i in 0..250 {
            tx.try_send(test_line(&format!("line {i}"))).unwrap();
        }
        drop(tx);

        let mut batch = Vec::new();
        let dropped = AtomicU64::new(0);
        drain_during_backoff(
            &mut rx,
            &mut batch,
            &dropped,
            tokio::time::Duration::from_secs(30),
        )
        .await;

        assert_eq!(batch.len(), 200);
        assert_eq!(dropped.load(Ordering::Relaxed), 50, "overflow is counted");
        assert_eq!(batch[0].message, "line 0");
        assert_eq!(batch[199].message, "line 199");
    }

    #[tokio::test]
    async fn drain_during_backoff_preserves_an_existing_batch() {
        let (tx, mut rx) = mpsc::channel::<SandboxLogLine>(16);
        tx.try_send(test_line("new")).unwrap();
        drop(tx);

        let mut batch = vec![test_line("buffered")];
        let dropped = AtomicU64::new(0);
        drain_during_backoff(
            &mut rx,
            &mut batch,
            &dropped,
            tokio::time::Duration::from_secs(30),
        )
        .await;
        assert_eq!(dropped.load(Ordering::Relaxed), 0);

        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].message, "buffered");
        assert_eq!(batch[1].message, "new");
    }

    #[tokio::test]
    async fn drain_during_backoff_returns_early_when_the_channel_closes() {
        let (tx, mut rx) = mpsc::channel::<SandboxLogLine>(16);
        tx.try_send(test_line("last")).unwrap();
        drop(tx);

        let mut batch = Vec::new();
        let dropped = AtomicU64::new(0);
        tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            drain_during_backoff(
                &mut rx,
                &mut batch,
                &dropped,
                tokio::time::Duration::from_secs(30),
            ),
        )
        .await
        .expect("closed channel should end the backoff drain");

        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn log_visitor_into_parts_uses_the_fallback_only_without_a_message() {
        let visitor = LogVisitor {
            message: Some("explicit".to_string()),
            fields: vec![("k".to_string(), "v".to_string())],
        };
        let (msg, fields) = visitor.into_parts("fallback");
        assert_eq!(msg, "explicit");
        assert_eq!(fields.get("k").map(String::as_str), Some("v"));

        let (msg, fields) = LogVisitor::default().into_parts("fallback");
        assert_eq!(msg, "fallback");
        assert!(fields.is_empty());
    }
}
