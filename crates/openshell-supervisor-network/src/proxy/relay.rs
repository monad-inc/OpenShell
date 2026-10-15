// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared relay primitives for authorized explicit-proxy egress.

use super::{EgressDecision, L7RouteSnapshot, emit_l7_tunnel_close_after_policy_change};
use crate::l7::relay::L7EvalContext;
use crate::opa::{NetworkAction, OpaEngine, PolicyGenerationGuard, TunnelPolicyEngine};
use miette::{IntoDiagnostic, Result};
use openshell_core::activity::ActivitySender;
use openshell_core::credential_rotation::{CredentialRotationWatch, RotatedCredential};
use openshell_core::endpoint_status::EndpointObservationSender;
use openshell_core::proto::ProviderProfileCredential;
use openshell_core::secrets::SecretResolver;
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, NetworkActivityBuilder, SeverityId, StatusId,
    ocsf_emit,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

type DynamicCredentials = Arc<std::sync::RwLock<HashMap<String, ProviderProfileCredential>>>;

enum PreparedHttpPolicy {
    Inspect {
        configs: Vec<crate::l7::L7EndpointConfig>,
        evaluator: Box<TunnelPolicyEngine>,
    },
    Passthrough {
        generation_guard: PolicyGenerationGuard,
    },
}

/// Everything an HTTP relay needs after authorization is complete.
///
/// The relay deliberately owns a generation-pinned policy primitive instead
/// of retaining access to the mutable OPA engine. Policy reloads therefore
/// fail closed through the guard or tunnel evaluator already attached here.
pub(super) struct RelayContext<'a> {
    request: &'a L7EvalContext,
    policy: PreparedHttpPolicy,
    middleware_engine: &'a OpaEngine,
}

/// Non-blocking observation channels attached to an authorized HTTP relay.
pub(super) struct RelaySignals {
    /// Receives general sandbox network activity.
    pub(super) activity: Option<ActivitySender>,
    /// Receives terminal tool server results for endpoint status reporting.
    pub(super) endpoint_observation: Option<EndpointObservationSender>,
}

/// Build the request-processing context shared by CONNECT and forward HTTP.
pub(super) fn http_context(
    decision: &EgressDecision,
    provider_credentials: Option<openshell_core::provider_credentials::ProviderCredentialState>,
    secret_resolver: Option<Arc<SecretResolver>>,
    dynamic_credentials: Option<DynamicCredentials>,
    agent_proposals: openshell_core::proposals::AgentProposals,
    workspace: String,
    signals: RelaySignals,
) -> L7EvalContext {
    // Provider-backed credentials must be acquired from the live state for
    // each request after middleware/token-grant awaits. Keep only the legacy
    // resolver fallback when no live provider state exists.
    let secret_resolver = provider_credentials
        .is_none()
        .then_some(secret_resolver)
        .flatten();
    let policy_name = match &decision.action {
        NetworkAction::Allow { matched_policy } => matched_policy.clone().unwrap_or_default(),
        NetworkAction::Deny { .. } => String::new(),
    };

    L7EvalContext {
        host: decision.intent.destination.host.clone(),
        port: decision.intent.destination.port,
        request_default_port: None,
        policy_name,
        binary_path: decision
            .binary
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
        ancestors: decision
            .ancestors
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        cmdline_paths: decision
            .cmdline_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        secret_resolver,
        provider_credentials,
        provider_credential_revision: None,
        provider_credential_installation_id: None,
        body_classifier: None,
        activity_tx: signals.activity,
        dynamic_credentials: dynamic_credentials.clone(),
        token_grant_resolver: dynamic_credentials
            .as_ref()
            .map(|_| crate::l7::token_grant_injection::default_resolver()),
        agent_proposals,
        workspace,
        endpoint_observation_tx: signals.endpoint_observation,
    }
}

/// Pin a generation for a relay or the forward HTTP single-request path.
pub(super) fn pin_policy_generation(
    opa_engine: &OpaEngine,
    expected_generation: u64,
) -> Result<PolicyGenerationGuard> {
    opa_engine.generation_guard(expected_generation)
}

/// Clone an L7 evaluator for a relay or the forward HTTP single-request path.
pub(super) fn pin_l7_evaluator(
    opa_engine: &OpaEngine,
    expected_generation: u64,
) -> Result<TunnelPolicyEngine> {
    opa_engine.clone_engine_for_tunnel(expected_generation)
}

pub(super) fn validate_route_generation(
    route: Option<&L7RouteSnapshot>,
    expected_generation: u64,
) -> Result<()> {
    if let Some(route) = route
        && route.l7_policy_generation != expected_generation
    {
        return Err(miette::miette!(
            "policy changed before CONNECT route hydration \
             [l4_generation:{} l7_generation:{}]",
            expected_generation,
            route.l7_policy_generation,
        ));
    }
    Ok(())
}

/// Prepare a generation-pinned HTTP relay at the adapter boundary.
///
/// A stale generation preserves the established CONNECT behavior: emit the
/// policy-change close event and let the adapter close the live tunnel without
/// attempting to write an HTTP response into it.
pub(super) fn prepare_http_relay<'a>(
    route: Option<&L7RouteSnapshot>,
    opa_engine: &'a OpaEngine,
    decision: &EgressDecision,
    request: &'a L7EvalContext,
) -> Option<RelayContext<'a>> {
    if let Err(error) = validate_route_generation(route, decision.policy_generation) {
        emit_l7_tunnel_close_after_policy_change(
            &decision.intent.destination.host,
            decision.intent.destination.port,
            error,
        );
        return None;
    }

    let policy = if let Some(route) = route.filter(|route| !route.configs.is_empty()) {
        let evaluator = match pin_l7_evaluator(opa_engine, decision.policy_generation) {
            Ok(evaluator) => evaluator,
            Err(error) => {
                emit_l7_tunnel_close_after_policy_change(
                    &decision.intent.destination.host,
                    decision.intent.destination.port,
                    error,
                );
                return None;
            }
        };
        let configs = route
            .configs
            .iter()
            .map(|snapshot| snapshot.config.clone())
            .collect();
        PreparedHttpPolicy::Inspect {
            configs,
            evaluator: Box::new(evaluator),
        }
    } else {
        let generation_guard = match pin_policy_generation(opa_engine, decision.policy_generation) {
            Ok(guard) => guard,
            Err(error) => {
                emit_l7_tunnel_close_after_policy_change(
                    &decision.intent.destination.host,
                    decision.intent.destination.port,
                    error,
                );
                return None;
            }
        };
        PreparedHttpPolicy::Passthrough { generation_guard }
    };

    Some(RelayContext {
        request,
        policy,
        middleware_engine: opa_engine,
    })
}

/// Pin the generation used by a raw relay so policy activation or quarantine
/// closes streams that otherwise have no request boundary at which to notice
/// a stale decision.
pub(super) fn prepare_raw_relay(
    route: Option<&L7RouteSnapshot>,
    opa_engine: &OpaEngine,
    decision: &EgressDecision,
) -> Option<PolicyGenerationGuard> {
    if let Err(error) = validate_route_generation(route, decision.policy_generation) {
        emit_l7_tunnel_close_after_policy_change(
            &decision.intent.destination.host,
            decision.intent.destination.port,
            error,
        );
        return None;
    }

    match pin_policy_generation(opa_engine, decision.policy_generation) {
        Ok(guard) => Some(guard),
        Err(error) => {
            emit_l7_tunnel_close_after_policy_change(
                &decision.intent.destination.host,
                decision.intent.destination.port,
                error,
            );
            None
        }
    }
}

/// Relay an HTTP/1 stream using an already-authorized, generation-pinned context.
///
/// CONNECT plaintext and TLS-terminated streams both enter through this
/// function. Forward HTTP will provide a buffered first request to the same
/// boundary in the next migration step.
pub(super) async fn relay_http_stream<C, U>(
    client: &mut C,
    upstream: &mut U,
    context: RelayContext<'_>,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Subscribe before any request can carry credential material, so a
    // rotation that lands while the relay starts still closes it.
    let rotation = context
        .request
        .provider_credentials
        .as_ref()
        .map(|credentials| credentials.rotation_watch(&context.request.host, context.request.port));
    match context.policy {
        PreparedHttpPolicy::Inspect { configs, evaluator } if configs.len() == 1 => {
            let generation_guard = evaluator.generation_guard().clone();
            tokio::select! {
                result = crate::l7::relay::relay_with_inspection(
                    &configs[0],
                    *evaluator,
                    client,
                    upstream,
                    context.request,
                ) => result,
                () = generation_guard.wait_until_stale() => {
                    emit_stale_relay_close(context.request, &generation_guard);
                    Ok(())
                }
                rotated = credential_rotated(rotation.as_ref()) => {
                    emit_rotated_relay_close(context.request, &rotated);
                    Ok(())
                }
            }
        }
        PreparedHttpPolicy::Inspect { configs, evaluator } => {
            let generation_guard = evaluator.generation_guard().clone();
            tokio::select! {
                result = crate::l7::relay::relay_with_route_selection(
                    &configs,
                    *evaluator,
                    client,
                    upstream,
                    context.request,
                ) => result,
                () = generation_guard.wait_until_stale() => {
                    emit_stale_relay_close(context.request, &generation_guard);
                    Ok(())
                }
                rotated = credential_rotated(rotation.as_ref()) => {
                    emit_rotated_relay_close(context.request, &rotated);
                    Ok(())
                }
            }
        }
        PreparedHttpPolicy::Passthrough { generation_guard } => {
            tokio::select! {
                result = crate::l7::relay::relay_passthrough_with_credentials(
                    client,
                    upstream,
                    context.request,
                    &generation_guard,
                    Some(context.middleware_engine),
                ) => result,
                () = generation_guard.wait_until_stale() => {
                    emit_stale_relay_close(context.request, &generation_guard);
                    Ok(())
                }
                rotated = credential_rotated(rotation.as_ref()) => {
                    emit_rotated_relay_close(context.request, &rotated);
                    Ok(())
                }
            }
        }
    }
}

// Exercise the production single/multiple-route dispatch from L7 fixtures.
#[cfg(test)]
pub async fn relay_inspected_http_stream_for_test<C, U>(
    client: &mut C,
    upstream: &mut U,
    configs: Vec<crate::l7::L7EndpointConfig>,
    evaluator: TunnelPolicyEngine,
    middleware_engine: &OpaEngine,
    request: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    relay_http_stream(
        client,
        upstream,
        RelayContext {
            request,
            policy: PreparedHttpPolicy::Inspect {
                configs,
                evaluator: Box::new(evaluator),
            },
            middleware_engine,
        },
    )
    .await
}

/// Relay a policy-authorized raw TCP stream.
pub(super) async fn relay_tcp<C, U>(
    client: &mut C,
    upstream: &mut U,
    generation_guard: &PolicyGenerationGuard,
    request: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    tokio::select! {
        result = tokio::io::copy_bidirectional(client, upstream) => {
            result.into_diagnostic()?;
        }
        () = generation_guard.wait_until_stale() => {
            emit_stale_relay_close(request, generation_guard);
        }
    }
    Ok(())
}

/// Resolve when a credential bound to this relay's destination rotates.
/// Relays without provider credentials never close for rotation.
pub(super) async fn credential_rotated(
    rotation: Option<&CredentialRotationWatch>,
) -> RotatedCredential {
    match rotation {
        Some(rotation) => rotation.rotated().await,
        None => std::future::pending().await,
    }
}

/// Why an established relay was closed by the supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayCloseReason {
    /// A static credential bound to the destination got a new value.
    CredentialRotated,
    /// The policy generation advanced: a policy, provider binding,
    /// attachment or credential revocation change.
    PolicyChanged,
}

impl RelayCloseReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::CredentialRotated => "credential_rotated",
            Self::PolicyChanged => "policy_changed",
        }
    }
}

fn emit_stale_relay_close(request: &L7EvalContext, guard: &PolicyGenerationGuard) {
    emit_relay_close(
        request,
        RelayCloseReason::PolicyChanged,
        &[],
        &format!(
            "captured_generation:{} current_generation:{}",
            guard.captured_generation(),
            guard.current_generation(),
        ),
    );
}

pub(super) fn emit_rotated_relay_close(request: &L7EvalContext, rotated: &RotatedCredential) {
    let detail = if rotated.keys.is_empty() {
        "rotation history overrun; closed conservatively".to_string()
    } else {
        format!("keys:{}", rotated.keys.join(","))
    };
    emit_relay_close(
        request,
        RelayCloseReason::CredentialRotated,
        &rotated.keys,
        &detail,
    );
}

/// One Close event per supervisor-closed relay. Keys are environment key
/// names, never values.
fn emit_relay_close(
    request: &L7EvalContext,
    reason: RelayCloseReason,
    credential_keys: &[String],
    detail: &str,
) {
    let severity = match reason {
        RelayCloseReason::CredentialRotated => SeverityId::Low,
        RelayCloseReason::PolicyChanged => SeverityId::Medium,
    };
    let event = NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Close)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(severity)
        .status(StatusId::Success)
        .dst_endpoint(Endpoint::from_domain(&request.host, request.port))
        .firewall_rule(&request.policy_name, "relay")
        .unmapped("close_reason", reason.as_str())
        .unmapped("credential_keys", credential_keys.to_vec())
        .message(format!("Tunnel closed: {} [{detail}]", reason.as_str()))
        .build();
    ocsf_emit!(event);
}

#[cfg(test)]
mod tests {
    use super::super::{EgressIntent, EndpointDecision, ProcessIdentityEvidence};
    use super::*;

    const POLICY_REGO: &str = include_str!("../../data/sandbox-policy.rego");
    const EMPTY_POLICY_DATA: &str = "network_policies: {}\n";

    fn decision(policy_generation: u64) -> EgressDecision {
        EgressDecision {
            intent: EgressIntent::connect("example.com".to_string(), 80),
            action: NetworkAction::Allow {
                matched_policy: Some("test".to_string()),
            },
            policy_generation,
            identity: ProcessIdentityEvidence::Available,
            endpoint: EndpointDecision::default(),
            binary: None,
            binary_pid: None,
            ancestors: vec![],
            cmdline_paths: vec![],
        }
    }

    fn request_context() -> L7EvalContext {
        L7EvalContext {
            host: "example.com".to_string(),
            port: 80,
            request_default_port: Some(80),
            policy_name: "test".to_string(),
            binary_path: String::new(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
            provider_credentials: None,
            provider_credential_revision: None,
            provider_credential_installation_id: None,
            body_classifier: None,
            activity_tx: None,
            dynamic_credentials: None,
            token_grant_resolver: None,
            agent_proposals: openshell_core::proposals::AgentProposals::default(),
            workspace: String::new(),
            endpoint_observation_tx: None,
        }
    }

    async fn assert_response_lifecycle<C, P>(mut caller: C, mut client: P)
    where
        C: AsyncRead + AsyncWrite + Unpin,
        P: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut upstream, mut server) = tokio::io::duplex(1024);
        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let decision = decision(engine.current_generation());
        let request = request_context();
        let context = prepare_http_relay(None, &engine, &decision, &request).unwrap();
        let persistent = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        // Larger than either transport buffer: closing must drain the body.
        let body = vec![b'x'; 64 * 1024];
        let mut closing = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        closing.extend_from_slice(&body);
        let relay = Box::pin(relay_http_stream(&mut client, &mut upstream, context));
        let serve = async {
            for response in [persistent.as_slice(), closing.as_slice()] {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(server.read_u8().await.unwrap());
                    assert!(request.len() < 4096);
                }
                assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
                server.write_all(response).await.unwrap();
                server.flush().await.unwrap();
            }
            // Retain the upstream socket: response headers decide persistence.
        };
        let receive = async {
            let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
            caller.write_all(request).await.unwrap();
            caller.flush().await.unwrap();
            let mut first = vec![0; persistent.len()];
            caller.read_exact(&mut first).await.unwrap();
            assert_eq!(first, persistent);
            // A real second exchange verifies reuse, without a timing assertion.
            caller.write_all(request).await.unwrap();
            caller.flush().await.unwrap();
            let mut second = Vec::new();
            // TLS must return clean EOF, not UnexpectedEof from a dropped socket.
            caller.read_to_end(&mut second).await.unwrap();
            assert_eq!(second, closing);
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (result, (), ()) = tokio::join!(relay, serve, receive);
            result.unwrap();
        })
        .await
        .expect("response delivery and EOF must not await another request");
    }

    #[tokio::test]
    async fn http_relay_reuses_then_closes_after_complete_response() {
        let (caller, client) = tokio::io::duplex(1024);
        assert_response_lifecycle(caller, client).await;
    }

    #[tokio::test]
    async fn tls_http_relay_reuses_then_sends_close_notify_after_complete_response() {
        use crate::l7::tls::{CertCache, ProxyTlsState, SandboxCa, tls_terminate_client};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let ca = SandboxCa::generate().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut ca.cert_pem().as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let state = ProxyTlsState::new(CertCache::new(ca), config.clone());
        let connector = tokio_rustls::TlsConnector::from(config);
        let (caller, client) = tokio::io::duplex(1024);
        let (caller, client) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                connector.connect(
                    rustls::pki_types::ServerName::try_from("example.com").unwrap(),
                    caller
                ),
                tls_terminate_client(client, &state, "example.com"),
            )
        })
        .await
        .expect("TLS handshake must complete");
        assert_response_lifecycle(caller.unwrap(), client.unwrap()).await;
    }

    #[test]
    fn relay_without_route_pins_l4_decision_generation() {
        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let decision = decision(engine.current_generation());
        let request = request_context();

        let context = prepare_http_relay(None, &engine, &decision, &request)
            .expect("current L4 generation should prepare a relay");
        let PreparedHttpPolicy::Passthrough { generation_guard } = context.policy else {
            panic!("route-less relay should use a generation guard");
        };

        assert_eq!(
            generation_guard.captured_generation(),
            decision.policy_generation
        );
    }

    #[test]
    fn empty_hydrated_route_cannot_replace_stale_l4_generation() {
        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let decision = decision(u64::MAX);
        let route = L7RouteSnapshot {
            configs: vec![],
            l7_policy_generation: engine.current_generation(),
        };
        let request = request_context();

        assert!(
            prepare_http_relay(Some(&route), &engine, &decision, &request).is_none(),
            "a current L7 lookup must not freshen a stale L4 allow"
        );
    }

    #[test]
    fn inspected_route_cannot_replace_stale_l4_generation() {
        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let decision = decision(u64::MAX);
        let route = L7RouteSnapshot {
            configs: vec![super::super::L7ConfigSnapshot {
                config: crate::l7::L7EndpointConfig {
                    protocol: crate::l7::L7Protocol::Rest,
                    endpoint_id: String::new(),
                    policy_hash: String::new(),
                    path: "/**".to_string(),
                    tls: crate::l7::TlsMode::Auto,
                    enforcement: crate::l7::EnforcementMode::Enforce,
                    graphql_max_body_bytes: crate::l7::graphql::DEFAULT_MAX_BODY_BYTES,
                    json_rpc_max_body_bytes: crate::l7::jsonrpc::DEFAULT_MAX_BODY_BYTES,
                    mcp_strict_tool_names: true,
                    mcp_versions: Vec::new(),
                    allow_encoded_slash: false,
                    websocket_credential_rewrite: false,
                    request_body_credential_rewrite: false,
                    allow_uninspected_credentials: false,
                    provider_credentialed: false,
                    websocket_graphql_policy: false,
                    credential_signing: crate::l7::CredentialSigning::None,
                    signing_service: String::new(),
                    signing_region: String::new(),
                },
            }],
            l7_policy_generation: engine.current_generation(),
        };
        let request = request_context();

        assert!(
            prepare_http_relay(Some(&route), &engine, &decision, &request).is_none(),
            "an inspected route must use the generation that authorized CONNECT"
        );
    }

    #[test]
    fn raw_route_cannot_replace_stale_l4_generation() {
        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let decision = decision(u64::MAX);
        let route = L7RouteSnapshot {
            configs: vec![],
            l7_policy_generation: engine.current_generation(),
        };

        assert!(
            prepare_raw_relay(Some(&route), &engine, &decision).is_none(),
            "a raw relay must not freshen a stale L4 allow"
        );
    }

    #[test]
    fn stale_generation_fails_before_relay_context_is_created() {
        let engine = OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();
        let decision = decision(engine.current_generation());
        let request = request_context();
        engine.reload(POLICY_REGO, EMPTY_POLICY_DATA).unwrap();

        assert!(
            prepare_http_relay(None, &engine, &decision, &request).is_none(),
            "policy reload must prevent a stale relay from starting"
        );
    }

    fn two_provider_credentials(
        a_value: &str,
    ) -> openshell_core::provider_credentials::ProviderCredentialState {
        use openshell_core::proto::{StaticCredentialBinding, StaticCredentialEndpointBinding};
        let binding = |host: &str, handle: char| StaticCredentialBinding {
            endpoints: vec![StaticCredentialEndpointBinding {
                host: host.into(),
                port: 80,
                path: "/**".into(),
            }],
            // Stable credentials carry their handle in the identity, as
            // the gateway issues them.
            credential_identity: format!("refresh:{}", handle.to_string().repeat(64)),
            workload_credential_handle: handle.to_string().repeat(64),
        };
        openshell_core::provider_credentials::ProviderCredentialState::from_bound_environment_with_stable_placeholders(
            7,
            HashMap::from([
                ("A_TOKEN".to_string(), a_value.to_string()),
                ("B_TOKEN".to_string(), "b-value".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                ("A_TOKEN".to_string(), binding("a.example.com", 'a')),
                ("B_TOKEN".to_string(), binding("b.example.com", 'b')),
            ]),
            Vec::new(),
            vec!["A_TOKEN".to_string(), "B_TOKEN".to_string()],
        )
        .expect("valid bindings")
    }

    /// A credential-bearing relay to `host`, with the sandbox side, the
    /// upstream side and the relay task.
    fn spawn_credential_relay(
        engine: &Arc<OpaEngine>,
        credentials: &openshell_core::provider_credentials::ProviderCredentialState,
        host: &str,
    ) -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (caller, mut client) = tokio::io::duplex(4096);
        let (mut upstream, server) = tokio::io::duplex(4096);
        let engine = Arc::clone(engine);
        let mut request = request_context();
        request.host = host.to_string();
        request.provider_credentials = Some(credentials.clone());
        let relay = tokio::spawn(async move {
            let decision = decision(engine.current_generation());
            let context = prepare_http_relay(None, &engine, &decision, &request)
                .expect("current generation prepares a relay");
            relay_http_stream(&mut client, &mut upstream, context).await
        });
        (caller, server, relay)
    }

    /// Send one request carrying `placeholder` and return what upstream saw.
    async fn exchange(
        caller: &mut tokio::io::DuplexStream,
        server: &mut tokio::io::DuplexStream,
        host: &str,
        placeholder: &str,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let request = format!(
            "GET /v1 HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {placeholder}\r\n\r\n"
        );
        caller.write_all(request.as_bytes()).await.unwrap();
        let mut received = Vec::new();
        while !received.ends_with(b"\r\n\r\n") {
            received.push(server.read_u8().await.unwrap());
        }
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        server.write_all(response).await.unwrap();
        let mut reply = vec![0; response.len()];
        caller.read_exact(&mut reply).await.unwrap();
        String::from_utf8(received).unwrap()
    }

    #[tokio::test]
    async fn credential_rotation_closes_only_the_rotated_providers_relays() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let credentials = two_provider_credentials("a-initial");
        let env = credentials.snapshot().child_env.clone();
        let (a_placeholder, b_placeholder) = (&env["A_TOKEN"], &env["B_TOKEN"]);
        let within = std::time::Duration::from_secs(5);

        let (mut a_caller, mut a_server, a_relay) =
            spawn_credential_relay(&engine, &credentials, "a.example.com");
        let (mut b_caller, mut b_server, b_relay) =
            spawn_credential_relay(&engine, &credentials, "b.example.com");
        let seen = tokio::time::timeout(
            within,
            exchange(&mut a_caller, &mut a_server, "a.example.com", a_placeholder),
        )
        .await
        .expect("provider A request relayed");
        assert!(seen.contains("Bearer a-initial"), "{seen}");
        let seen = tokio::time::timeout(
            within,
            exchange(&mut b_caller, &mut b_server, "b.example.com", b_placeholder),
        )
        .await
        .expect("provider B request relayed");
        assert!(seen.contains("Bearer b-value"), "{seen}");

        let candidate = two_provider_credentials("a-rotated");
        let rotated = credentials
            .value_only_rotation(&candidate)
            .expect("only A's value changed");
        assert_eq!(rotated, ["A_TOKEN"]);
        credentials.install_prepared(&candidate);
        let announced = credentials.announce_rotation(&rotated);
        assert_eq!(announced.tunnels, 1);
        assert_eq!(announced.endpoints, ["a.example.com:80"]);

        tokio::time::timeout(within, a_relay)
            .await
            .expect("provider A's relay closes on rotation")
            .expect("relay task should not panic")
            .expect("rotation closure is clean");
        assert!(!b_relay.is_finished(), "provider B's relay stays open");
        let seen = tokio::time::timeout(
            within,
            exchange(&mut b_caller, &mut b_server, "b.example.com", b_placeholder),
        )
        .await
        .expect("provider B's relay still carries requests");
        assert!(seen.contains("Bearer b-value"), "{seen}");

        // The workload's placeholder is unchanged; a reconnect sends the new value.
        let (mut a_caller, mut a_server, _a_relay) =
            spawn_credential_relay(&engine, &credentials, "a.example.com");
        let seen = tokio::time::timeout(
            within,
            exchange(&mut a_caller, &mut a_server, "a.example.com", a_placeholder),
        )
        .await
        .expect("reconnected provider A request relayed");
        assert!(seen.contains("Bearer a-rotated"), "{seen}");
        b_relay.abort();
    }

    #[tokio::test]
    async fn raw_relay_closes_immediately_when_fail_closed_generation_is_published() {
        let engine = Arc::new(OpaEngine::from_strings(POLICY_REGO, EMPTY_POLICY_DATA).unwrap());
        let guard = engine
            .generation_guard(engine.current_generation())
            .unwrap();
        let request = request_context();
        let (_client_peer, mut proxy_client) = tokio::io::duplex(64);
        let (_upstream_peer, mut proxy_upstream) = tokio::io::duplex(64);

        let relay = tokio::spawn(async move {
            relay_tcp(&mut proxy_client, &mut proxy_upstream, &guard, &request).await
        });
        tokio::task::yield_now().await;

        engine
            .enter_fail_closed("candidate policy validation failed")
            .unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), relay)
            .await
            .expect("raw relay should close when its generation becomes stale")
            .expect("relay task should not panic")
            .expect("stale relay closure should be clean");
    }
}
