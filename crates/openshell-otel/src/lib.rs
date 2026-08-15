// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared OpenTelemetry trace export support for `OpenShell` services.

mod grpc;
mod logs;
mod propagation;

pub use grpc::RecordGrpcFailure;
pub use logs::{OtlpLogConfig, build_log_exporter, log_exporter_for, logger};
pub use opentelemetry_otlp::LogExporter as OtlpLogExporter;
pub use opentelemetry_sdk::logs::SdkLoggerProvider;
pub use propagation::{HeaderMapExtractor, MetadataMapInjector, TraceContextInterceptor};

use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{SpanExporter, WithExportConfig, WithTonicConfig as _};
pub use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracer;
pub use opentelemetry_sdk::trace::SdkTracerProvider;
use tonic::transport::ClientTlsConfig;
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::Layer as _;
use tracing_subscriber::registry::LookupSpan;

const SDK_UNKNOWN_SERVICE_PREFIX: &str = "unknown_service";

/// Mark `span` as failed.
///
/// The field must be declared on the span at creation because `tracing` drops
/// records for fields a span does not have.
pub fn mark_error(span: &tracing::Span) {
    span.record("otel.status_code", "ERROR");
}

/// Marks the current span when an instrumented operation returns an error.
pub fn record_error_result<T, E>(result: Result<T, E>) -> Result<T, E> {
    if result.is_err() {
        mark_error(&tracing::Span::current());
    }
    result
}

/// Marks an instrumented function's span when it exits before returning success.
///
/// Create the guard at the start of the instrumented function and return the
/// successful result through [`Self::finish`]. An early `?` or error return
/// drops the unfinished guard and marks the captured span as failed.
#[must_use]
pub struct ErrorStatusGuard {
    span: tracing::Span,
    finished: bool,
}

impl ErrorStatusGuard {
    /// Captures the current instrumented span.
    pub fn current() -> Self {
        Self {
            span: tracing::Span::current(),
            finished: false,
        }
    }

    /// Returns `result`, marking this guard complete when it is successful.
    pub fn finish<T, E>(mut self, result: Result<T, E>) -> Result<T, E> {
        self.finished = result.is_ok();
        result
    }
}

impl Drop for ErrorStatusGuard {
    fn drop(&mut self) {
        if !self.finished {
            mark_error(&self.span);
        }
    }
}

/// How a process chooses its OpenTelemetry `service.name`.
#[derive(Debug, Clone, Copy)]
pub enum ServiceName<'a> {
    /// Always use this name, overriding `OTEL_SERVICE_NAME`.
    Fixed(&'a str),
    /// Use `OTEL_SERVICE_NAME` when set, otherwise use this default.
    EnvironmentOr(&'a str),
}

/// Inputs for an OTLP/gRPC trace provider.
#[derive(Debug, Clone)]
pub struct OtlpTraceConfig<'a> {
    pub endpoint: &'a str,
    pub service_name: ServiceName<'a>,
    pub service_version: Option<&'a str>,
    pub resource_attributes: Vec<KeyValue>,
}

/// Failure to construct an OTLP trace provider.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("OTLP endpoint is empty")]
    EmptyEndpoint,

    #[error("invalid OTLP endpoint {endpoint:?}: {source}")]
    InvalidEndpoint {
        endpoint: String,
        source: http::uri::InvalidUri,
    },

    #[error("failed to build the OTLP span exporter: {0}")]
    Exporter(#[from] opentelemetry_otlp::ExporterBuildError),
}

/// Trim and validate an OTLP endpoint, returning it alongside its parsed URI.
pub(crate) fn validated_endpoint(endpoint: &str) -> Result<(&str, http::Uri), SetupError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(SetupError::EmptyEndpoint);
    }
    let uri = endpoint
        .parse::<http::Uri>()
        .map_err(|source| SetupError::InvalidEndpoint {
            endpoint: endpoint.to_string(),
            source,
        })?;
    Ok((endpoint, uri))
}

/// TLS settings for `uri`, or `None` when the endpoint is plaintext.
///
/// `opentelemetry-otlp` falls back to `ClientTlsConfig::new()` for an `https://`
/// endpoint, and that config starts with an empty root store, so every server
/// certificate is rejected. Supplying the config explicitly with the compiled-in
/// public roots lets the gateway reach a hosted OTLP collector. The roots travel
/// with the binary rather than coming from the host trust store, so a gateway on
/// a minimal image trusts the same anchors as one on a full distribution.
/// Collectors fronted by a private CA are not reachable over `https://` yet.
pub(crate) fn tls_config_for(uri: &http::Uri) -> Option<ClientTlsConfig> {
    (uri.scheme() == Some(&http::uri::Scheme::HTTPS))
        .then(|| ClientTlsConfig::new().with_webpki_roots())
}

fn resource_attributes(config: &OtlpTraceConfig<'_>) -> Vec<KeyValue> {
    let mut attributes = config.resource_attributes.clone();
    if let Some(version) = config
        .service_version
        .map(str::trim)
        .filter(|version| !version.is_empty())
    {
        attributes.push(KeyValue::new("service.version", version.to_string()));
    }
    attributes
}

/// Build the OpenTelemetry resource for a trace provider configuration.
#[must_use]
pub fn resource_for(config: &OtlpTraceConfig<'_>) -> Resource {
    let attributes = resource_attributes(config);
    match config.service_name {
        ServiceName::Fixed(name) => Resource::builder()
            .with_service_name(name.trim().to_string())
            .with_attributes(attributes)
            .build(),
        ServiceName::EnvironmentOr(default) => {
            let detected = Resource::builder()
                .with_attributes(attributes.clone())
                .build();
            if detected
                .get(&opentelemetry::Key::from_static_str("service.name"))
                .is_some_and(|value| !value.to_string().starts_with(SDK_UNKNOWN_SERVICE_PREFIX))
            {
                detected
            } else {
                Resource::builder()
                    .with_service_name(default.trim().to_string())
                    .with_attributes(attributes)
                    .build()
            }
        }
    }
}

/// Build an OTLP/gRPC trace provider.
pub fn build_provider(config: &OtlpTraceConfig<'_>) -> Result<SdkTracerProvider, SetupError> {
    let (endpoint, uri) = validated_endpoint(config.endpoint)?;

    let mut builder = SpanExporter::builder().with_tonic().with_endpoint(endpoint);
    if let Some(tls_config) = tls_config_for(&uri) {
        builder = builder.with_tls_config(tls_config);
    }
    let exporter = builder.build()?;

    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource_for(config))
        .build())
}

/// Build the provider for an optional OTLP configuration.
///
/// Telemetry setup failures disable export and remain available for the caller
/// to report after its tracing subscriber is installed.
#[must_use]
pub fn provider_for(
    config: Option<OtlpTraceConfig<'_>>,
) -> (Option<SdkTracerProvider>, Option<SetupError>) {
    match config.as_ref().map(build_provider) {
        None => (None, None),
        Some(Ok(provider)) => (Some(provider), None),
        Some(Err(error)) => (None, Some(error)),
    }
}

/// Filtered OpenTelemetry layer returned by [`layer`].
pub type OtlpLayer<S> = tracing_subscriber::filter::Filtered<
    OpenTelemetryLayer<S, SdkTracer>,
    tracing_subscriber::filter::FilterFn,
    S,
>;

/// Build a tracing layer that exports spans and excludes exporter callsites.
pub fn layer<S>(provider: &SdkTracerProvider, instrumentation_scope: &'static str) -> OtlpLayer<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    tracing_opentelemetry::layer()
        .with_tracer(provider.tracer(instrumentation_scope))
        .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
            metadata.is_span() && !metadata.target().starts_with("opentelemetry")
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_status_guard_marks_only_unfinished_results() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(layer(&provider, "guard-test"));

        tracing::subscriber::with_default(subscriber, || {
            let failed =
                tracing::info_span!("failed-operation", otel.status_code = tracing::field::Empty);
            {
                let _entered = failed.enter();
                drop(ErrorStatusGuard::current());
            }
            drop(failed);

            let succeeded = tracing::info_span!(
                "successful-operation",
                otel.status_code = tracing::field::Empty
            );
            {
                let _entered = succeeded.enter();
                ErrorStatusGuard::current().finish(Ok::<_, ()>(())).unwrap();
            }
            drop(succeeded);
        });

        let spans = exporter.get_finished_spans().unwrap();
        let failed = spans
            .iter()
            .find(|span| span.name == "failed-operation")
            .unwrap();
        assert!(matches!(
            failed.status,
            opentelemetry::trace::Status::Error { .. }
        ));
        let succeeded = spans
            .iter()
            .find(|span| span.name == "successful-operation")
            .unwrap();
        assert_eq!(succeeded.status, opentelemetry::trace::Status::Unset);
    }

    #[test]
    fn resource_uses_fixed_service_identity_and_custom_attributes() {
        let resource = resource_for(&OtlpTraceConfig {
            endpoint: "http://127.0.0.1:4317",
            service_name: ServiceName::Fixed("openshell-driver-vm"),
            service_version: Some("1.2.3"),
            resource_attributes: vec![KeyValue::new("openshell.gateway.name", "vm-dev")],
        });

        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str("service.name"))
                .map(|value| value.to_string()),
            Some("openshell-driver-vm".to_string())
        );
        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str("service.version"))
                .map(|value| value.to_string()),
            Some("1.2.3".to_string())
        );
        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str(
                    "openshell.gateway.name",
                ))
                .map(|value| value.to_string()),
            Some("vm-dev".to_string())
        );
    }

    #[tokio::test]
    async fn https_endpoint_builds_a_provider_with_public_roots() {
        // Without an explicit TLS config the exporter build fails outright for
        // an https:// endpoint, so a hosted collector would never be reached.
        let (provider, error) = provider_for(Some(OtlpTraceConfig {
            endpoint: "https://collector.example.com:4317",
            service_name: ServiceName::Fixed("openshell-gateway"),
            service_version: None,
            resource_attributes: Vec::new(),
        }));

        assert!(error.is_none(), "unexpected setup error: {error:?}");
        assert!(provider.is_some());
    }

    #[test]
    fn tls_is_configured_only_for_https_endpoints() {
        assert!(tls_config_for(&"https://collector.example.com:4317".parse().unwrap()).is_some());
        assert!(tls_config_for(&"http://127.0.0.1:4317".parse().unwrap()).is_none());
    }

    #[tokio::test]
    async fn malformed_endpoint_disables_export_with_a_reportable_error() {
        let (provider, error) = provider_for(Some(OtlpTraceConfig {
            endpoint: "definitely not a url",
            service_name: ServiceName::Fixed("test-service"),
            service_version: None,
            resource_attributes: Vec::new(),
        }));

        assert!(provider.is_none());
        assert!(matches!(error, Some(SetupError::InvalidEndpoint { .. })));
    }
}
