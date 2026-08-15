// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-wide tracing subscriber setup for the gateway.
//!
//! This module routes gateway logs and spans to configured diagnostic outputs.
//! `OpenShell` product telemetry collected for maintainers is handled by
//! [`crate::telemetry`].

use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use crate::config_file::OtlpConfig;
use crate::otel_tracing::SetupError;
use crate::tracing_bus::TracingLogBus;

pub struct TracingHandle {
    tracer_provider: Option<SdkTracerProvider>,
    log_export: Option<crate::log_export::LogExportWorker>,
}

impl TracingHandle {
    pub async fn shutdown(self) {
        if let Some(provider) = &self.tracer_provider
            && let Err(err) = provider.shutdown()
        {
            tracing::warn!(error = %err, "OTLP tracer provider shutdown failed");
        }
        // Flush and stop the log export worker last so records enqueued during
        // shutdown of other subsystems still leave the box.
        if let Some(worker) = self.log_export {
            worker.shutdown().await;
        }
    }
}

pub fn install(
    env_filter: EnvFilter,
    tracing_log_bus: &TracingLogBus,
    otlp_config: Option<&OtlpConfig>,
) -> (TracingHandle, Option<SetupError>) {
    let (tracer_provider, trace_error) = crate::otel_tracing::provider_for(otlp_config);
    let (log_exporter, log_error) = crate::otel_tracing::log_exporter_for(otlp_config);

    // When a log exporter was built (export_logs enabled + usable endpoint),
    // spawn the export worker and point the log bus at its queue so every log
    // line the gateway observes is exported off-box.
    let log_export = log_exporter.map(|(exporter, resource)| {
        let ocsf_full_payload = otlp_config.is_some_and(|c| c.ocsf_full_payload);
        let (handle, worker) = crate::log_export::spawn(exporter, resource, ocsf_full_payload);
        tracing_log_bus.set_export(handle);
        worker
    });

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_log_bus.layer())
        .with(tracer_provider.as_ref().map(crate::otel_tracing::layer))
        .init();

    (
        TracingHandle {
            tracer_provider,
            log_export,
        },
        // Surface whichever setup failed; the trace error takes precedence
        // since both signals share one endpoint.
        trace_error.or(log_error),
    )
}
