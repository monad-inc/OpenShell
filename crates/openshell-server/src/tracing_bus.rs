// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Capture openshell-server tracing logs for streaming over gRPC.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use openshell_core::proto::{SandboxLogLine, SandboxStreamEvent};
use openshell_ocsf::OCSF_TARGET;
use tokio::sync::broadcast;
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Bus that publishes server log lines keyed by sandbox id.
#[derive(Debug, Clone)]
pub struct TracingLogBus {
    inner: Arc<Mutex<Inner>>,
    pub(crate) platform_event_bus: PlatformEventBus,
    /// Off-box OTLP log export sink. Installed once at startup when
    /// `[openshell.gateway.otlp] export_logs` is set; `None` disables export.
    export: Arc<OnceLock<crate::log_export::LogExportHandle>>,
}

#[derive(Debug)]
struct Inner {
    per_id: HashMap<String, broadcast::Sender<SandboxStreamEvent>>,
    tails: HashMap<String, VecDeque<SandboxStreamEvent>>,
}

impl Default for TracingLogBus {
    fn default() -> Self {
        Self::new()
    }
}

impl TracingLogBus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                per_id: HashMap::new(),
                tails: HashMap::new(),
            })),
            platform_event_bus: PlatformEventBus::new(),
            export: Arc::new(OnceLock::new()),
        }
    }

    /// Install the off-box log-export sink.
    ///
    /// Every log line published after this call is forwarded for OTLP export in
    /// addition to the in-memory tail/broadcast used by the CLI/TUI. Idempotent:
    /// the first handle installed wins.
    pub(crate) fn set_export(&self, handle: crate::log_export::LogExportHandle) {
        let _ = self.export.set(handle);
    }

    /// Forward a gateway-scoped line to off-box export only.
    ///
    /// Gateway events without a sandbox — governance, auth, credential
    /// refresh, TLS — have no per-sandbox tail or watcher to serve, so they
    /// skip the visibility plane (the gateway's own stdout already shows
    /// them) and go straight to the export queue.
    fn export_only(&self, log: SandboxLogLine) {
        if let Some(export) = self.export.get() {
            export.enqueue(log);
        }
    }

    pub(crate) fn layer<S: Subscriber>(&self) -> impl Layer<S> {
        SandboxLogLayer {
            bus: self.clone(),
            default_tail: Self::DEFAULT_TAIL,
        }
    }

    fn sender_for(&self, sandbox_id: &str) -> broadcast::Sender<SandboxStreamEvent> {
        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner
            .per_id
            .entry(sandbox_id.to_string())
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(1024);
                tx
            })
            .clone()
    }

    pub fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<SandboxStreamEvent> {
        self.sender_for(sandbox_id).subscribe()
    }

    /// Remove all bus entries for the given sandbox id.
    ///
    /// This drops the broadcast sender (closing any active receivers with
    /// `RecvError::Closed`) and frees the tail buffer.
    pub fn remove(&self, sandbox_id: &str) {
        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner.per_id.remove(sandbox_id);
        inner.tails.remove(sandbox_id);
    }

    pub fn tail(&self, sandbox_id: &str, max: usize) -> Vec<SandboxStreamEvent> {
        let inner = self.inner.lock().expect("tracing bus lock poisoned");
        inner
            .tails
            .get(sandbox_id)
            .map(|d| d.iter().rev().take(max).cloned().collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .rev()
            .collect()
    }

    /// Publish a log line from an external source (e.g., sandbox push).
    ///
    /// Injects the line into the same broadcast channel and tail buffer
    /// used by the tracing layer, so it appears in `WatchSandbox` and
    /// `GetSandboxLogs` transparently.
    pub fn publish_external(&self, log: SandboxLogLine) {
        self.publish_log(log, Self::DEFAULT_TAIL);
    }

    /// Default tail buffer capacity (lines per sandbox).
    const DEFAULT_TAIL: usize = 2000;

    fn publish_log(&self, log: SandboxLogLine, tail_cap: usize) {
        // Tap for off-box export: forward log lines (gateway-origin and
        // sandbox-pushed alike, since both reach the bus through here) into the
        // accounted export queue before they enter the bounded in-memory tail.
        // The queue takes the one clone this path pays; the stream event below
        // takes the original. An OCSF line's field map is the expensive part of
        // that clone, so this stays a single copy however many fields it has.
        if let Some(export) = self.export.get() {
            export.enqueue(log.clone());
        }

        let sandbox_id = log.sandbox_id.clone();
        let event = SandboxStreamEvent {
            payload: Some(openshell_core::proto::sandbox_stream_event::Payload::Log(
                log,
            )),
        };

        // One lock acquisition covers both the broadcast lookup and the tail.
        // Every sandbox's lines converge here, so taking it twice per line
        // doubled the contention this point creates.
        let mut inner = self.inner.lock().expect("tracing bus lock poisoned");

        // Broadcast only when something is actually watching. A live watcher —
        // `openshell logs -f`, the TUI — is the exception rather than the rule,
        // and this clone copies the line's whole flattened field map, which is
        // the most expensive part of publishing an OCSF event. Skipping it when
        // there are no receivers changes nothing observable: the send was
        // already a discarded error in that case.
        if let Some(tx) = inner.per_id.get(&sandbox_id)
            && tx.receiver_count() > 0
        {
            let _ = tx.send(event.clone());
        }

        let deque = inner.tails.entry(sandbox_id).or_default();
        deque.push_back(event);
        while deque.len() > tail_cap {
            deque.pop_front();
        }
    }
}

#[derive(Debug, Clone)]
struct SandboxLogLayer {
    bus: TracingLogBus,
    default_tail: usize,
}

impl<S> Layer<S> for SandboxLogLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();

        // A sandbox-less event only matters here when export is installed, and
        // events from the export path itself must never re-enter the queue
        // they are trying to drain.
        let gateway_scoped_exportable =
            self.bus.export.get().is_some() && !is_export_feedback_target(meta.target());

        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);

        let sandbox_id = visitor.sandbox_id.filter(|id| !id.is_empty());
        if sandbox_id.is_none() && !gateway_scoped_exportable {
            return;
        }

        let msg = visitor.message.unwrap_or_else(|| meta.name().to_string());
        let level = display_level(meta.target(), &meta.level().to_string());

        let ts = openshell_core::time::now_ms();
        let log = SandboxLogLine {
            sandbox_id: sandbox_id.clone().unwrap_or_default(),
            timestamp_ms: ts,
            level,
            target: meta.target().to_string(),
            message: msg,
            source: "gateway".to_string(),
            fields: visitor.fields,
        };
        match sandbox_id {
            // Sandbox-scoped: visibility plane (tail/broadcast) + export tap.
            Some(_) => self.bus.publish_log(log, self.default_tail),
            // Gateway-scoped: export only.
            None => self.bus.export_only(log),
        }
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
        || target.starts_with("h2")
        || target.starts_with("hyper")
        || target.starts_with("rustls")
}

#[derive(Debug, Default)]
struct LogVisitor {
    sandbox_id: Option<String>,
    message: Option<String>,
    /// Every other structured field on the event, preserved so exported
    /// records keep the data operators can only otherwise find on stdout
    /// (e.g. an auth denial's principal and requested sandbox).
    fields: HashMap<String, String>,
}

impl tracing::field::Visit for LogVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "sandbox_id" => self.sandbox_id = Some(value.to_string()),
            "message" => self.message = Some(value.to_string()),
            name => {
                self.fields.insert(name.to_string(), value.to_string());
            }
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "sandbox_id" => self.sandbox_id = Some(format!("{value:?}")),
            "message" => self.message = Some(format!("{value:?}")),
            name => {
                self.fields.insert(name.to_string(), format!("{value:?}"));
            }
        }
    }
}

fn display_level(target: &str, level: &str) -> String {
    if target == OCSF_TARGET {
        "OCSF".to_string()
    } else {
        level.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log_event(sandbox_id: &str, message: &str) -> SandboxLogLine {
        SandboxLogLine {
            sandbox_id: sandbox_id.to_string(),
            timestamp_ms: 1000,
            level: "INFO".to_string(),
            target: "test".to_string(),
            message: message.to_string(),
            source: "gateway".to_string(),
            fields: HashMap::new(),
        }
    }

    #[test]
    fn tracing_log_bus_remove_cleans_up_all_maps() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-1";

        // Create entries via subscribe and publish
        let _rx = bus.subscribe(sandbox_id);
        bus.publish_external(make_log_event(sandbox_id, "hello"));

        // Verify entries exist
        assert_eq!(bus.tail(sandbox_id, 10).len(), 1);

        // Remove
        bus.remove(sandbox_id);

        // Verify entries are gone
        assert!(bus.tail(sandbox_id, 10).is_empty());
    }

    #[test]
    fn tracing_log_bus_subscribe_after_remove_creates_fresh_channel() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-2";

        // Create and remove
        bus.publish_external(make_log_event(sandbox_id, "old message"));
        bus.remove(sandbox_id);

        // Subscribe again — should get a fresh channel with no history
        let mut rx = bus.subscribe(sandbox_id);
        assert!(bus.tail(sandbox_id, 10).is_empty());

        // New publish should reach the new subscriber
        bus.publish_external(make_log_event(sandbox_id, "new message"));
        let evt = rx.try_recv().expect("should receive new event");
        assert!(evt.payload.is_some());
    }

    #[test]
    fn tracing_log_bus_remove_closes_active_receivers() {
        let bus = TracingLogBus::new();
        let sandbox_id = "sb-3";

        let mut rx = bus.subscribe(sandbox_id);

        // Remove drops the sender
        bus.remove(sandbox_id);

        // Existing receiver should get Closed error
        match rx.try_recv() {
            Err(broadcast::error::TryRecvError::Closed) => {} // expected
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn tracing_log_bus_remove_nonexistent_is_noop() {
        let bus = TracingLogBus::new();
        // Should not panic
        bus.remove("nonexistent");
    }

    #[test]
    fn export_feedback_targets_are_excluded() {
        assert!(is_export_feedback_target("openshell_server::log_export"));
        assert!(is_export_feedback_target("opentelemetry_otlp::exporter"));
        assert!(is_export_feedback_target("tonic::transport"));
        assert!(is_export_feedback_target("h2::codec"));
        // The rest of the gateway must not be swept up by the guard.
        assert!(!is_export_feedback_target("openshell_server::auth::guard"));
        assert!(!is_export_feedback_target("openshell_server::grpc::policy"));
    }

    /// The full lane: a gateway event with no `sandbox_id` must reach the OTLP
    /// exporter (with its structured fields and without a sandbox.id
    /// attribute), export-path events must not, and sandbox-scoped events must
    /// keep serving the visibility plane.
    #[tokio::test]
    async fn gateway_scoped_events_export_without_a_sandbox_id() {
        use opentelemetry::logs::AnyValue;

        let exporter = opentelemetry_sdk::logs::InMemoryLogExporter::default();
        let (handle, worker) = crate::log_export::spawn(
            exporter.clone(),
            opentelemetry_sdk::Resource::builder_empty().build(),
            false,
        );
        let bus = TracingLogBus::new();
        bus.set_export(handle);

        {
            use tracing_subscriber::layer::SubscriberExt as _;
            let subscriber = tracing_subscriber::registry().with(bus.layer());
            let _guard = crate::otel_tracing::test_exporter::install_scoped(subscriber);
            tracing::info!(principal = "user:alice", "workspace created");
            tracing::warn!(target: "openshell_server::log_export", "OTLP log export failed");
            tracing::info!(sandbox_id = "sb-1", "sandbox event");
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while exporter.get_emitted_logs().unwrap().len() < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "expected 2 exported records, got {:?}",
                exporter.get_emitted_logs().unwrap().len()
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let emitted = exporter.get_emitted_logs().unwrap();
        assert_eq!(emitted.len(), 2, "the export-path warning must not export");

        let attr = |record: &opentelemetry_sdk::logs::SdkLogRecord, key: &str| {
            record
                .attributes_iter()
                .find(|(k, _)| k.as_str() == key)
                .map(|(_, v)| v.clone())
        };
        let gateway = &emitted[0].record;
        assert!(
            attr(gateway, "sandbox.id").is_none(),
            "gateway-scoped records carry no sandbox.id"
        );
        assert_eq!(
            attr(gateway, "principal"),
            Some(AnyValue::String("user:alice".into())),
            "structured fields survive export"
        );
        assert_eq!(
            attr(gateway, "log.source"),
            Some(AnyValue::String("gateway".into()))
        );
        assert_eq!(
            attr(&emitted[1].record, "sandbox.id"),
            Some(AnyValue::String("sb-1".into()))
        );

        // Visibility plane unchanged: only the sandbox-scoped line has a tail.
        assert_eq!(bus.tail("sb-1", 10).len(), 1);
        assert!(bus.tail("", 10).is_empty());

        worker.shutdown().await;
    }

    /// Without an export sink, sandbox-less events cost nothing and go
    /// nowhere — local development keeps its Phase-0 behavior.
    #[test]
    fn gateway_scoped_events_are_ignored_when_export_is_off() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let bus = TracingLogBus::new();
        let subscriber = tracing_subscriber::registry().with(bus.layer());
        let _guard = crate::otel_tracing::test_exporter::install_scoped(subscriber);
        tracing::info!(principal = "user:alice", "workspace created");
        assert!(bus.tail("", 10).is_empty());
    }

    #[test]
    fn display_level_maps_ocsf_target_to_ocsf() {
        assert_eq!(display_level(OCSF_TARGET, "INFO"), "OCSF");
        assert_eq!(display_level("openshell_server", "WARN"), "WARN");
    }

    #[test]
    fn platform_event_bus_remove_cleans_up() {
        let bus = PlatformEventBus::new();
        let sandbox_id = "sb-4";

        let mut rx = bus.subscribe(sandbox_id);

        // Publish an event
        let evt = SandboxStreamEvent { payload: None };
        bus.publish(sandbox_id, evt);
        assert!(rx.try_recv().is_ok());

        // Remove
        bus.remove(sandbox_id);

        // Receiver should be closed
        match rx.try_recv() {
            Err(broadcast::error::TryRecvError::Closed) => {} // expected
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn platform_event_bus_subscribe_after_remove_creates_fresh_channel() {
        let bus = PlatformEventBus::new();
        let sandbox_id = "sb-5";

        let _old_rx = bus.subscribe(sandbox_id);
        bus.remove(sandbox_id);

        // New subscription should work
        let mut new_rx = bus.subscribe(sandbox_id);
        let evt = SandboxStreamEvent { payload: None };
        bus.publish(sandbox_id, evt);
        assert!(new_rx.try_recv().is_ok());
    }

    #[test]
    fn platform_event_bus_remove_nonexistent_is_noop() {
        let bus = PlatformEventBus::new();
        // Should not panic
        bus.remove("nonexistent");
    }

    #[test]
    fn platform_event_bus_tail_returns_buffered_events() {
        use openshell_core::proto::{PlatformEvent, sandbox_stream_event};

        let bus = PlatformEventBus::new();
        let sandbox_id = "sb-6";

        // Publish some events
        for i in 0..5 {
            let evt = SandboxStreamEvent {
                payload: Some(sandbox_stream_event::Payload::Event(PlatformEvent {
                    timestamp_ms: i,
                    source: "test".to_string(),
                    r#type: "Normal".to_string(),
                    reason: format!("Event{i}"),
                    message: format!("Message {i}"),
                    metadata: HashMap::new(),
                })),
            };
            bus.publish(sandbox_id, evt);
        }

        // Tail should return all events in order
        let events = bus.tail(sandbox_id, 10);
        assert_eq!(events.len(), 5);

        // Verify order (oldest first)
        for (i, evt) in events.iter().enumerate() {
            if let Some(sandbox_stream_event::Payload::Event(ref e)) = evt.payload {
                assert_eq!(e.reason, format!("Event{i}"));
            } else {
                panic!("expected Event payload");
            }
        }

        // Tail with smaller max should return most recent events
        let events = bus.tail(sandbox_id, 2);
        assert_eq!(events.len(), 2);
        if let Some(sandbox_stream_event::Payload::Event(ref e)) = events[0].payload {
            assert_eq!(e.reason, "Event3");
        }
        if let Some(sandbox_stream_event::Payload::Event(ref e)) = events[1].payload {
            assert_eq!(e.reason, "Event4");
        }
    }

    #[test]
    fn platform_event_bus_tail_empty_sandbox() {
        let bus = PlatformEventBus::new();
        let events = bus.tail("nonexistent", 10);
        assert!(events.is_empty());
    }

    #[test]
    fn platform_event_bus_remove_clears_tail() {
        let bus = PlatformEventBus::new();
        let sandbox_id = "sb-7";

        let evt = SandboxStreamEvent { payload: None };
        bus.publish(sandbox_id, evt);
        assert_eq!(bus.tail(sandbox_id, 10).len(), 1);

        bus.remove(sandbox_id);
        assert!(bus.tail(sandbox_id, 10).is_empty());
    }
}

/// Separate bus for platform event stream events.
///
/// This keeps platform events isolated from tracing capture.
#[derive(Debug, Clone)]
pub(crate) struct PlatformEventBus {
    inner: Arc<Mutex<PlatformEventBusInner>>,
}

#[derive(Debug)]
struct PlatformEventBusInner {
    senders: HashMap<String, broadcast::Sender<SandboxStreamEvent>>,
    tails: HashMap<String, VecDeque<SandboxStreamEvent>>,
}

impl PlatformEventBus {
    /// Default tail buffer capacity (events per sandbox).
    /// Platform events are infrequent (typically 5-10 per sandbox lifecycle).
    const DEFAULT_TAIL: usize = 50;

    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(PlatformEventBusInner {
                senders: HashMap::new(),
                tails: HashMap::new(),
            })),
        }
    }

    fn sender_for(&self, sandbox_id: &str) -> broadcast::Sender<SandboxStreamEvent> {
        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner
            .senders
            .entry(sandbox_id.to_string())
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(1024);
                tx
            })
            .clone()
    }

    pub(crate) fn subscribe(&self, sandbox_id: &str) -> broadcast::Receiver<SandboxStreamEvent> {
        self.sender_for(sandbox_id).subscribe()
    }

    pub(crate) fn publish(&self, sandbox_id: &str, event: SandboxStreamEvent) {
        let tx = self.sender_for(sandbox_id);
        let _ = tx.send(event.clone());

        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        let deque = inner.tails.entry(sandbox_id.to_string()).or_default();
        deque.push_back(event);
        while deque.len() > Self::DEFAULT_TAIL {
            deque.pop_front();
        }
    }

    /// Return buffered platform events for replay to late subscribers.
    pub(crate) fn tail(&self, sandbox_id: &str, max: usize) -> Vec<SandboxStreamEvent> {
        let inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner
            .tails
            .get(sandbox_id)
            .map(|d| d.iter().rev().take(max).cloned().collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .rev()
            .collect()
    }

    /// Remove the bus entry for the given sandbox id.
    ///
    /// This drops the broadcast sender, closing any active receivers,
    /// and frees the tail buffer.
    pub(crate) fn remove(&self, sandbox_id: &str) {
        let mut inner = self.inner.lock().expect("platform event bus lock poisoned");
        inner.senders.remove(sandbox_id);
        inner.tails.remove(sandbox_id);
    }
}
