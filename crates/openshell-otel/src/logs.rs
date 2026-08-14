// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP/gRPC log export support.
//!
//! Mirrors the span pipeline in [`crate`]: an [`OtlpLogConfig`] describes the
//! destination and resource identity, and [`build_log_provider`] constructs a
//! batching [`SdkLoggerProvider`] that ships [`opentelemetry`] log records over
//! OTLP/gRPC.
//!
//! Unlike the span layer, callers here do **not** bridge `tracing` events
//! automatically. The gateway already aggregates sandbox log lines as
//! structured records; it converts each one into a log record and emits it
//! through a [`Logger`] obtained from the provider. Keeping emission explicit
//! lets the gateway carry fields the `tracing` bridge would drop (sandbox id,
//! OCSF attributes) and control delivery accounting.

use opentelemetry::logs::LoggerProvider as _;
use opentelemetry_otlp::{LogExporter, WithExportConfig as _};
use opentelemetry_sdk::logs::SdkLoggerProvider;

use crate::{OtlpTraceConfig, SetupError, resource_for};

/// Inputs for an OTLP/gRPC log provider.
///
/// Shares [`OtlpTraceConfig`]'s shape so a caller with one OTLP endpoint can
/// build both signals from the same configuration.
pub type OtlpLogConfig<'a> = OtlpTraceConfig<'a>;

/// Build an OTLP/gRPC log provider.
///
/// Must be called from within a Tokio runtime; the tonic exporter binds to the
/// current reactor as it is constructed. It does not connect — an unreachable
/// collector produces export failures, never a construction failure.
pub fn build_log_provider(config: &OtlpLogConfig<'_>) -> Result<SdkLoggerProvider, SetupError> {
    let endpoint = config.endpoint.trim();
    if endpoint.is_empty() {
        return Err(SetupError::EmptyEndpoint);
    }
    endpoint
        .parse::<http::Uri>()
        .map_err(|source| SetupError::InvalidEndpoint {
            endpoint: endpoint.to_string(),
            source,
        })?;

    let exporter = LogExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    Ok(SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource_for(config))
        .build())
}

/// Build the provider for an optional OTLP log configuration.
///
/// Like [`crate::provider_for`], setup failures disable export and are returned
/// for the caller to report once its subscriber is installed.
#[must_use]
pub fn log_provider_for(
    config: Option<OtlpLogConfig<'_>>,
) -> (Option<SdkLoggerProvider>, Option<SetupError>) {
    match config.as_ref().map(build_log_provider) {
        None => (None, None),
        Some(Ok(provider)) => (Some(provider), None),
        Some(Err(error)) => (None, Some(error)),
    }
}

/// Obtain a named [`Logger`] for emitting records through `provider`.
///
/// `instrumentation_scope` is recorded as the scope on every record the logger
/// emits, matching the convention used for the span layer's tracer scope.
#[must_use]
pub fn logger(
    provider: &SdkLoggerProvider,
    instrumentation_scope: &'static str,
) -> opentelemetry_sdk::logs::SdkLogger {
    provider.logger(instrumentation_scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServiceName;
    use opentelemetry::logs::{AnyValue, LogRecord as _, Logger as _, Severity};

    #[tokio::test]
    async fn in_memory_provider_records_emitted_logs() {
        // A memory exporter stands in for the OTLP transport so the emit path
        // is exercised without a collector.
        let exporter = opentelemetry_sdk::logs::InMemoryLogExporter::default();
        let provider = SdkLoggerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .with_resource(resource_for(&OtlpLogConfig {
                endpoint: "http://127.0.0.1:4317",
                service_name: ServiceName::Fixed("openshell-gateway"),
                service_version: None,
                resource_attributes: Vec::new(),
            }))
            .build();

        let logger = logger(&provider, "openshell-gateway");
        let mut record = logger.create_log_record();
        record.set_severity_number(Severity::Info);
        record.set_body(AnyValue::String("hello".into()));
        logger.emit(record);

        provider.force_flush().unwrap();
        let emitted = exporter.get_emitted_logs().unwrap();
        assert_eq!(emitted.len(), 1);
    }

    #[tokio::test]
    async fn malformed_endpoint_disables_log_export_with_a_reportable_error() {
        let (provider, error) = log_provider_for(Some(OtlpLogConfig {
            endpoint: "definitely not a url",
            service_name: ServiceName::Fixed("test-service"),
            service_version: None,
            resource_attributes: Vec::new(),
        }));

        assert!(provider.is_none());
        assert!(matches!(error, Some(SetupError::InvalidEndpoint { .. })));
    }
}
