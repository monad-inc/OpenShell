// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP/gRPC log export support.
//!
//! Mirrors the span pipeline in [`crate`] up to the exporter: an
//! [`OtlpLogConfig`] describes the destination and resource identity, and
//! [`build_log_exporter`] constructs the OTLP/gRPC [`LogExporter`] plus the
//! [`Resource`] to stamp on it.
//!
//! Unlike the span pipeline, no SDK batch processor sits in front of the
//! exporter. The SDK's `BatchLogProcessor` drops records silently once its
//! bounded queue fills, and its drop counter is private, so a caller cannot
//! account for the loss. Security telemetry must never vanish silently, so the
//! caller owns batching and drives [`LogExporter::export`] directly — each
//! batch's outcome is observable, failed batches can be retried, and any drop
//! the caller takes is one it counted itself.
//!
//! [`LogExporter::export`]: opentelemetry_sdk::logs::LogExporter::export

use opentelemetry::logs::LoggerProvider as _;
use opentelemetry_otlp::{LogExporter, WithExportConfig as _, WithTonicConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;

use crate::{OtlpTraceConfig, SetupError, resource_for, tls_config_for, validated_endpoint};

/// Inputs for an OTLP/gRPC log exporter.
///
/// Shares [`OtlpTraceConfig`]'s shape so a caller with one OTLP endpoint can
/// build both signals from the same configuration.
pub type OtlpLogConfig<'a> = OtlpTraceConfig<'a>;

/// Build an OTLP/gRPC log exporter and the resource identity to export under.
///
/// The caller must call `set_resource` with the returned resource before the
/// first export; the exporter is returned unstamped so the caller can defer
/// that to the task that owns it.
///
/// Must be called from within a Tokio runtime; the tonic exporter binds to the
/// current reactor as it is constructed. It does not connect — an unreachable
/// collector produces export failures, never a construction failure.
pub fn build_log_exporter(
    config: &OtlpLogConfig<'_>,
) -> Result<(LogExporter, Resource), SetupError> {
    let (endpoint, uri) = validated_endpoint(config.endpoint)?;

    let mut builder = LogExporter::builder().with_tonic().with_endpoint(endpoint);
    if let Some(tls_config) = tls_config_for(&uri) {
        builder = builder.with_tls_config(tls_config);
    }
    let exporter = builder.build()?;

    Ok((exporter, resource_for(config)))
}

/// Build the exporter for an optional OTLP log configuration.
///
/// Like [`crate::provider_for`], setup failures disable export and are returned
/// for the caller to report once its subscriber is installed.
#[must_use]
pub fn log_exporter_for(
    config: Option<OtlpLogConfig<'_>>,
) -> (Option<(LogExporter, Resource)>, Option<SetupError>) {
    match config.as_ref().map(build_log_exporter) {
        None => (None, None),
        Some(Ok(parts)) => (Some(parts), None),
        Some(Err(error)) => (None, Some(error)),
    }
}

/// Obtain a named [`Logger`] for minting and emitting records.
///
/// `instrumentation_scope` is recorded as the scope on every record the logger
/// emits, matching the convention used for the span layer's tracer scope.
///
/// [`Logger`]: opentelemetry::logs::Logger
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
    async fn https_endpoint_builds_a_log_exporter_with_public_roots() {
        let (parts, error) = log_exporter_for(Some(OtlpLogConfig {
            endpoint: "https://collector.example.com:4317",
            service_name: ServiceName::Fixed("openshell-gateway"),
            service_version: None,
            resource_attributes: Vec::new(),
        }));

        assert!(error.is_none(), "unexpected setup error: {error:?}");
        let (_exporter, resource) = parts.expect("exporter builds");
        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str("service.name"))
                .map(|v| v.to_string()),
            Some("openshell-gateway".to_string())
        );
    }

    #[tokio::test]
    async fn malformed_endpoint_disables_log_export_with_a_reportable_error() {
        let (parts, error) = log_exporter_for(Some(OtlpLogConfig {
            endpoint: "definitely not a url",
            service_name: ServiceName::Fixed("test-service"),
            service_version: None,
            resource_attributes: Vec::new(),
        }));

        assert!(parts.is_none());
        assert!(matches!(error, Some(SetupError::InvalidEndpoint { .. })));
    }
}
