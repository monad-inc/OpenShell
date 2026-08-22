// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authentication-related RPC handlers.
//!
//! Hosts authenticated identity RPCs:
//! - `GetCurrentUser` — report the gateway-validated caller identity
//! - `IssueSandboxToken` — bootstrap exchange (K8s SA token → gateway JWT)
//! - `RefreshSandboxToken` — renew a still-valid gateway JWT
//!
//! Both end in a fresh gateway-signed JWT minted by
//! [`crate::auth::sandbox_jwt::SandboxJwtIssuer`]. Older tokens remain valid
//! until their own `exp` and are bounded by the configured short TTL.

use crate::ServerState;
use crate::auth::identity::IdentityProvider;
use crate::auth::principal::{Principal, SandboxIdentitySource};
use openshell_core::proto::{
    ExtensionServiceCredential, GetCurrentUserRequest, GetCurrentUserResponse,
    GetSandboxConfigRequest, IssueSandboxTokenRequest, IssueSandboxTokenResponse,
    RefreshSandboxTokenRequest, RefreshSandboxTokenResponse, Sandbox,
};
use openshell_extension_core::{ExtensionAudience, ExtensionCallerKind, MAX_EXTENSION_TOKEN_TTL};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

#[allow(clippy::result_large_err, clippy::unused_async)]
pub async fn handle_get_current_user(
    request: Request<GetCurrentUserRequest>,
) -> Result<Response<GetCurrentUserResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let Principal::User(user) = principal else {
        return Err(Status::permission_denied(
            "GetCurrentUser requires a user principal",
        ));
    };

    let identity = user.identity;
    Ok(Response::new(GetCurrentUserResponse {
        subject: identity.subject,
        display_name: identity.display_name.unwrap_or_default(),
        roles: identity.roles,
        scopes: identity.scopes,
        identity_provider: match identity.provider {
            IdentityProvider::Oidc => "oidc",
            IdentityProvider::Mtls => "mtls",
            IdentityProvider::CloudflareAccess => "cloudflare_access",
            IdentityProvider::LocalDev => "local_dev",
        }
        .to_string(),
    }))
}

/// Emit the Entity Management \[3004\] audit event for a token mint/refresh.
///
/// Credential issuance with the sandbox principal as actor; the minted JWT
/// never enters the record — only the subject sandbox and expiry. Routed
/// into the sandbox's stream on success, the gateway lane on failure.
fn emit_token_audit(
    state: &ServerState,
    principal: &Principal,
    request_id: Option<&str>,
    operation: &'static str,
    activity: openshell_ocsf::enums::EntityActivityId,
    expires_at_ms: Option<i64>,
) {
    let sandbox_id = match principal {
        Principal::Sandbox(sandbox) => sandbox.sandbox_id.clone(),
        _ => String::new(),
    };
    let success = expires_at_ms.is_some();
    let mut unmapped = vec![
        ("operation", serde_json::Value::from(operation)),
        ("sandbox_id", serde_json::Value::from(sandbox_id.clone())),
    ];
    if let Some(expires_at_ms) = expires_at_ms {
        unmapped.push(("expires_at_ms", serde_json::Value::from(expires_at_ms)));
    }
    crate::audit::emit_entity(
        &state.config.audit,
        success,
        crate::audit::EntityOutcome {
            activity,
            entity: openshell_ocsf::objects::ManagedEntity::new(
                "sandbox_token",
                sandbox_id.clone(),
            ),
            sandbox: (success && !sandbox_id.is_empty()).then_some((sandbox_id.as_str(), "")),
            principal,
            request_id,
            success_message: format!("sandbox token {operation} for {sandbox_id}"),
            failure_message: format!("sandbox token {operation} failed"),
            unmapped,
        },
    );
}

#[allow(clippy::result_large_err, clippy::unused_async)]
pub async fn handle_issue_sandbox_token(
    state: &Arc<ServerState>,
    request: Request<IssueSandboxTokenRequest>,
) -> Result<Response<IssueSandboxTokenResponse>, Status> {
    let principal = crate::audit::principal(&request);
    let request_id = crate::audit::request_id(&request);
    let result = handle_issue_sandbox_token_inner(state, request).await;
    match &result {
        Ok(response) => emit_token_audit(
            state,
            &principal,
            request_id.as_deref(),
            "issued",
            openshell_ocsf::enums::EntityActivityId::Create,
            Some(response.get_ref().expires_at_ms),
        ),
        Err(status) if crate::audit::audited_failure(status) => emit_token_audit(
            state,
            &principal,
            request_id.as_deref(),
            "issued",
            openshell_ocsf::enums::EntityActivityId::Create,
            None,
        ),
        Err(_) => {}
    }
    result
}

#[allow(clippy::result_large_err, clippy::unused_async)]
async fn handle_issue_sandbox_token_inner(
    state: &Arc<ServerState>,
    request: Request<IssueSandboxTokenRequest>,
) -> Result<Response<IssueSandboxTokenResponse>, Status> {
    let principal = request
        .extensions()
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("missing principal"))?;

    let Principal::Sandbox(sandbox) = principal else {
        return Err(Status::permission_denied(
            "IssueSandboxToken requires a sandbox principal",
        ));
    };

    // Only the bootstrap K8s ServiceAccount path can mint a fresh gateway JWT
    // via this RPC. Sandboxes already holding a gateway JWT use
    // `RefreshSandboxToken` instead.
    if !matches!(
        sandbox.source,
        SandboxIdentitySource::K8sServiceAccount { .. }
    ) {
        debug!(
            sandbox_id = %sandbox.sandbox_id,
            "IssueSandboxToken rejected: non-bootstrap principal source"
        );
        return Err(Status::permission_denied(
            "this principal cannot mint a sandbox token; use RefreshSandboxToken",
        ));
    }

    let issuer = state.sandbox_jwt_issuer.as_ref().ok_or_else(|| {
        warn!(
            sandbox_id = %sandbox.sandbox_id,
            "IssueSandboxToken called but sandbox JWT issuer is not configured"
        );
        Status::unavailable("sandbox JWT minting is not configured on this gateway")
    })?;

    ensure_sandbox_exists(state, &sandbox.sandbox_id).await?;

    let minted = issuer.mint(&sandbox.sandbox_id)?;
    info!(
        sandbox_id = %sandbox.sandbox_id,
        "issued gateway sandbox JWT"
    );
    Ok(Response::new(IssueSandboxTokenResponse {
        token: minted.token,
        expires_at_ms: minted.expires_at_ms,
    }))
}

#[allow(clippy::result_large_err, clippy::unused_async)]
pub async fn handle_refresh_sandbox_token(
    state: &Arc<ServerState>,
    request: Request<RefreshSandboxTokenRequest>,
) -> Result<Response<RefreshSandboxTokenResponse>, Status> {
    let principal = crate::audit::principal(&request);
    let request_id = crate::audit::request_id(&request);
    let result = handle_refresh_sandbox_token_inner(state, request).await;
    match &result {
        Ok(response) => emit_token_audit(
            state,
            &principal,
            request_id.as_deref(),
            "refreshed",
            openshell_ocsf::enums::EntityActivityId::Update,
            Some(response.get_ref().expires_at_ms),
        ),
        Err(status) if crate::audit::audited_failure(status) => emit_token_audit(
            state,
            &principal,
            request_id.as_deref(),
            "refreshed",
            openshell_ocsf::enums::EntityActivityId::Update,
            None,
        ),
        Err(_) => {}
    }
    result
}

#[allow(clippy::result_large_err, clippy::unused_async)]
async fn handle_refresh_sandbox_token_inner(
    state: &Arc<ServerState>,
    request: Request<RefreshSandboxTokenRequest>,
) -> Result<Response<RefreshSandboxTokenResponse>, Status> {
    let requested_extension_services = request.get_ref().extension_service_names.clone();
    let principal = request
        .extensions()
        .get::<Principal>()
        .cloned()
        .ok_or_else(|| Status::unauthenticated("missing principal"))?;

    let Principal::Sandbox(sandbox) = principal else {
        return Err(Status::permission_denied(
            "RefreshSandboxToken requires a sandbox principal",
        ));
    };

    // Only callers already holding a gateway-minted JWT may refresh; the
    // K8s bootstrap path must use `IssueSandboxToken`.
    let SandboxIdentitySource::BootstrapJwt { .. } = &sandbox.source else {
        debug!(
            sandbox_id = %sandbox.sandbox_id,
            "RefreshSandboxToken rejected: non-gateway-JWT principal source"
        );
        return Err(Status::permission_denied(
            "this principal cannot refresh; use IssueSandboxToken for bootstrap",
        ));
    };

    let issuer = state.sandbox_jwt_issuer.as_ref().ok_or_else(|| {
        warn!(
            sandbox_id = %sandbox.sandbox_id,
            "RefreshSandboxToken called but sandbox JWT issuer is not configured"
        );
        Status::unavailable("sandbox JWT minting is not configured on this gateway")
    })?;

    ensure_sandbox_exists(state, &sandbox.sandbox_id).await?;

    let minted = issuer.mint(&sandbox.sandbox_id)?;
    let extension_credentials = if requested_extension_services.is_empty() {
        Vec::new()
    } else if !state
        .extension_mint_limiter
        .try_acquire(&sandbox.sandbox_id)
    {
        // Minting resolves the sandbox's effective policy, so an unbounded
        // caller could impose real gateway cost from inside a sandbox. The
        // supervisor keeps its last-known-good slots on error and retries at
        // its normal cadence, so refusing is safe.
        warn!(
            sandbox_id = %sandbox.sandbox_id,
            "extension credential minting rate limit exceeded"
        );
        return Err(Status::resource_exhausted(
            "extension credential minting rate limit exceeded for this sandbox",
        ));
    } else {
        let mut config_request = Request::new(GetSandboxConfigRequest {
            sandbox_id: sandbox.sandbox_id.clone(),
        });
        config_request
            .extensions_mut()
            .insert(Principal::Sandbox(sandbox.clone()));
        let available = super::policy::handle_get_sandbox_config(state, config_request)
            .await?
            .into_inner()
            .supervisor_middleware_services;
        mint_extension_credentials(
            issuer,
            &sandbox.sandbox_id,
            &requested_extension_services,
            &available,
        )?
    };
    info!(
        sandbox_id = %sandbox.sandbox_id,
        "renewed gateway sandbox JWT"
    );

    Ok(Response::new(RefreshSandboxTokenResponse {
        token: minted.token,
        expires_at_ms: minted.expires_at_ms,
        extension_credentials,
    }))
}

const MAX_EXTENSION_CREDENTIALS_PER_REFRESH: usize = 64;
const DEFAULT_EXTENSION_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

#[allow(clippy::result_large_err)]
fn mint_extension_credentials(
    issuer: &crate::auth::sandbox_jwt::SandboxJwtIssuer,
    sandbox_id: &str,
    requested_names: &[String],
    available_services: &[openshell_core::proto::SupervisorMiddlewareService],
) -> Result<Vec<ExtensionServiceCredential>, Status> {
    if requested_names.len() > MAX_EXTENSION_CREDENTIALS_PER_REFRESH {
        return Err(Status::invalid_argument(format!(
            "at most {MAX_EXTENSION_CREDENTIALS_PER_REFRESH} extension credentials may be requested"
        )));
    }
    let mut unique = HashSet::with_capacity(requested_names.len());
    for name in requested_names {
        if name.is_empty() {
            return Err(Status::invalid_argument(
                "extension service names must not be empty",
            ));
        }
        if !unique.insert(name.as_str()) {
            return Err(Status::invalid_argument(format!(
                "duplicate extension service name '{name}'"
            )));
        }
    }

    let available: HashMap<&str, &openshell_core::proto::SupervisorMiddlewareService> =
        available_services
            .iter()
            .map(|service| (service.name.as_str(), service))
            .collect();
    let ttl = if issuer.ttl().is_zero() {
        DEFAULT_EXTENSION_TOKEN_TTL
    } else {
        issuer.ttl().min(MAX_EXTENSION_TOKEN_TTL)
    };

    requested_names
        .iter()
        .map(|name| {
            let service = available.get(name.as_str()).ok_or_else(|| {
                Status::permission_denied(format!(
                    "extension service '{name}' is not selected by the sandbox policy"
                ))
            })?;
            if service.allow_insecure_transport {
                return Err(Status::failed_precondition(format!(
                    "extension service '{name}' opted out of extension authentication; \
                     no credential is minted for it"
                )));
            }
            let audience = ExtensionAudience::new(service.audience.clone())
                .map_err(|error| Status::failed_precondition(error.to_string()))?;
            let minted = issuer.mint_extension_token(
                &audience,
                ExtensionCallerKind::Supervisor,
                Some(sandbox_id),
                ttl,
            )?;
            Ok(ExtensionServiceCredential {
                service_name: name.clone(),
                token: minted.token,
                expires_at_ms: minted.expires_at_ms,
            })
        })
        .collect()
}

async fn ensure_sandbox_exists(state: &Arc<ServerState>, sandbox_id: &str) -> Result<(), Status> {
    if sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }

    state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServerState;
    use crate::auth::identity::Identity;
    use crate::auth::principal::{Principal, SandboxPrincipal, UserPrincipal};
    use crate::auth::sandbox_jwt::SandboxJwtIssuer;
    use crate::compute::new_test_runtime;
    use crate::persistence::Store;
    use crate::sandbox_index::SandboxIndex;
    use crate::sandbox_watch::SandboxWatchBus;
    use crate::supervisor_session::SupervisorSessionRegistry;
    use crate::tracing_bus::TracingLogBus;
    use openshell_bootstrap::jwt::generate_jwt_key;
    use openshell_core::Config;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{Sandbox, SandboxPhase, SandboxSpec};
    use std::collections::HashMap;
    use std::time::Duration;

    async fn state_with_issuer() -> Arc<ServerState> {
        let mat = generate_jwt_key().expect("jwt key");
        let store = Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );
        let compute = new_test_runtime(store.clone()).await;
        let mut state = ServerState::new(
            Config::new(None)
                .with_database_url("sqlite::memory:?cache=shared")
                .with_credential_drivers(["test-static"]),
            store,
            compute,
            SandboxIndex::new(),
            SandboxWatchBus::new(),
            TracingLogBus::new(),
            Arc::new(SupervisorSessionRegistry::new()),
            None,
        );
        // We don't need the authenticator for these tests; only the issuer.
        let issuer = SandboxJwtIssuer::from_pem(
            mat.signing_key_pem.as_bytes(),
            mat.kid,
            "test-gateway",
            Duration::from_secs(3600),
        )
        .unwrap();
        state.sandbox_jwt_issuer = Some(Arc::new(issuer));
        let state = Arc::new(state);
        insert_sandbox(&state, "sandbox-a").await;
        state
    }

    async fn insert_sandbox(state: &Arc<ServerState>, sandbox_id: &str) {
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: sandbox_id.to_string(),
                name: sandbox_id.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::default(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
    }

    fn sandbox_principal(sandbox_id: &str) -> Principal {
        use crate::auth::principal::SandboxIdentitySource;
        Principal::Sandbox(SandboxPrincipal {
            sandbox_id: sandbox_id.to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "openshell-gateway:test-gateway".to_string(),
            },
            trust_domain: Some("openshell".to_string()),
        })
    }

    #[tokio::test]
    async fn current_user_returns_gateway_validated_identity() {
        let mut req = Request::new(GetCurrentUserRequest {});
        req.extensions_mut().insert(Principal::User(UserPrincipal {
            identity: Identity {
                subject: "oidc-subject-123".to_string(),
                display_name: Some("Alice".to_string()),
                roles: vec!["openshell-user".to_string()],
                scopes: vec!["sandbox:read".to_string()],
                provider: IdentityProvider::Oidc,
            },
        }));

        let response = handle_get_current_user(req)
            .await
            .expect("current user")
            .into_inner();
        assert_eq!(response.subject, "oidc-subject-123");
        assert_eq!(response.display_name, "Alice");
        assert_eq!(response.roles, ["openshell-user"]);
        assert_eq!(response.scopes, ["sandbox:read"]);
        assert_eq!(response.identity_provider, "oidc");
    }

    #[tokio::test]
    async fn refresh_returns_new_token() {
        let state = state_with_issuer().await;
        let mut req = Request::new(RefreshSandboxTokenRequest {
            extension_service_names: Vec::new(),
        });
        req.extensions_mut().insert(sandbox_principal("sandbox-a"));
        let resp = handle_refresh_sandbox_token(&state, req)
            .await
            .expect("refresh OK")
            .into_inner();
        assert!(!resp.token.is_empty());
        assert!(resp.expires_at_ms > 0);
    }

    /// Token minting is credential issuance: it must leave a 3004 record
    /// carrying the sandbox actor and expiry — and never the JWT itself.
    #[tokio::test]
    async fn token_refresh_emits_an_audit_record_without_the_jwt() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::logs::InMemoryLogExporter::default();
        let (handle, worker) = crate::log_export::spawn(
            exporter.clone(),
            opentelemetry_sdk::Resource::builder_empty().build(),
            true,
        );
        let bus = TracingLogBus::new();
        bus.set_export(handle);
        let state = state_with_issuer().await;

        let token;
        {
            let subscriber = tracing_subscriber::registry().with(bus.layer());
            let _guard = crate::otel_tracing::test_exporter::install_scoped(subscriber);
            let mut req = Request::new(RefreshSandboxTokenRequest::default());
            req.extensions_mut().insert(sandbox_principal("sandbox-a"));
            token = handle_refresh_sandbox_token(&state, req)
                .await
                .expect("refresh OK")
                .into_inner()
                .token;
        }

        let audit_record = || {
            exporter.get_emitted_logs().unwrap().iter().find_map(|log| {
                log.record
                    .attributes_iter()
                    .find(|(k, _)| k.as_str() == "ocsf.raw")
                    .and_then(|(_, v)| match v {
                        opentelemetry::logs::AnyValue::String(s) => Some(s.as_str().to_string()),
                        _ => None,
                    })
            })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let raw = loop {
            if let Some(raw) = audit_record() {
                break raw;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "audit record never arrived"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let record: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(record["class_uid"], 3004);
        assert_eq!(record["entity"]["type"], "sandbox_token");
        assert_eq!(record["actor"]["user"]["uid"], "sandbox-a");
        assert_eq!(record["unmapped"]["operation"], "refreshed");
        assert!(record["unmapped"]["expires_at_ms"].is_i64());
        assert!(
            !raw.contains(&token),
            "the minted JWT must never appear in the audit record"
        );

        worker.shutdown().await;
    }

    #[tokio::test]
    async fn extension_credentials_are_minted_only_for_selected_registration_names() {
        let state = state_with_issuer().await;
        let issuer = state.sandbox_jwt_issuer.as_deref().expect("issuer");
        let available = vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "content-guard".to_string(),
            audience: "urn:example:content-guard".to_string(),
            ..Default::default()
        }];

        let credentials = mint_extension_credentials(
            issuer,
            "sandbox-a",
            &["content-guard".to_string()],
            &available,
        )
        .expect("selected service credential");
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].service_name, "content-guard");
        assert!(!credentials[0].token.is_empty());
        assert!(credentials[0].expires_at_ms > 0);

        let error = mint_extension_credentials(
            issuer,
            "sandbox-a",
            &["attacker-chosen-audience".to_string()],
            &available,
        )
        .expect_err("unselected name must be rejected");
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn refresh_refuses_extension_credentials_past_the_per_sandbox_bound() {
        let state = state_with_issuer().await;
        // The gateway credential path is unaffected; only requests that carry
        // extension service names consume the bound.
        for _ in 0..10 {
            assert!(state.extension_mint_limiter.try_acquire("sandbox-a"));
        }
        assert!(!state.extension_mint_limiter.try_acquire("sandbox-a"));
        assert!(state.extension_mint_limiter.try_acquire("sandbox-b"));
    }

    #[tokio::test]
    async fn opted_out_registrations_never_receive_a_minted_credential() {
        let state = state_with_issuer().await;
        let issuer = state.sandbox_jwt_issuer.as_deref().expect("issuer");
        let available = vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "legacy-guard".to_string(),
            audience: "urn:example:legacy-guard".to_string(),
            allow_insecure_transport: true,
            ..Default::default()
        }];

        // The registration is policy-selected, so authorization passes; the
        // opt-out is what withholds the credential. A supervisor must not be
        // able to obtain a bearer token it would then send over plaintext.
        let error = mint_extension_credentials(
            issuer,
            "sandbox-a",
            &["legacy-guard".to_string()],
            &available,
        )
        .expect_err("opted-out registration must not mint a credential");
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn extension_credential_request_rejects_duplicate_names_atomically() {
        let state = state_with_issuer().await;
        let issuer = state.sandbox_jwt_issuer.as_deref().expect("issuer");
        let available = vec![openshell_core::proto::SupervisorMiddlewareService {
            name: "content-guard".to_string(),
            audience: "urn:example:content-guard".to_string(),
            ..Default::default()
        }];
        let error = mint_extension_credentials(
            issuer,
            "sandbox-a",
            &["content-guard".to_string(), "content-guard".to_string()],
            &available,
        )
        .expect_err("duplicates must be rejected");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn refresh_rejects_missing_sandbox() {
        let state = state_with_issuer().await;
        let mut req = Request::new(RefreshSandboxTokenRequest {
            extension_service_names: Vec::new(),
        });
        req.extensions_mut()
            .insert(sandbox_principal("sandbox-deleted"));
        let err = handle_refresh_sandbox_token(&state, req)
            .await
            .expect_err("missing sandbox must not refresh");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn issue_returns_token_for_existing_sandbox() {
        use crate::auth::principal::SandboxIdentitySource;

        let state = state_with_issuer().await;
        let mut req = Request::new(IssueSandboxTokenRequest::default());
        req.extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "sandbox-a".to_string(),
                source: SandboxIdentitySource::K8sServiceAccount {
                    pod_name: "pod-a".to_string(),
                    pod_uid: "uid-a".to_string(),
                },
                trust_domain: Some("openshell".to_string()),
            }));
        let resp = handle_issue_sandbox_token(&state, req)
            .await
            .expect("issue OK")
            .into_inner();
        assert!(!resp.token.is_empty());
        assert!(resp.expires_at_ms > 0);
    }

    #[tokio::test]
    async fn issue_rejects_missing_sandbox() {
        use crate::auth::principal::SandboxIdentitySource;

        let state = state_with_issuer().await;
        let mut req = Request::new(IssueSandboxTokenRequest::default());
        req.extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "sandbox-deleted".to_string(),
                source: SandboxIdentitySource::K8sServiceAccount {
                    pod_name: "pod-a".to_string(),
                    pod_uid: "uid-a".to_string(),
                },
                trust_domain: Some("openshell".to_string()),
            }));
        let err = handle_issue_sandbox_token(&state, req)
            .await
            .expect_err("missing sandbox must not receive a token");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn refresh_rejects_user_principal() {
        use crate::auth::identity::{Identity, IdentityProvider};
        let state = state_with_issuer().await;
        let mut req = Request::new(RefreshSandboxTokenRequest {
            extension_service_names: Vec::new(),
        });
        req.extensions_mut().insert(Principal::User(UserPrincipal {
            identity: Identity {
                subject: "alice".to_string(),
                display_name: None,
                roles: vec![],
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        }));
        let err = handle_refresh_sandbox_token(&state, req)
            .await
            .expect_err("user must not refresh");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn refresh_rejects_k8s_sa_principal() {
        // K8s SA-bootstrap principals must use IssueSandboxToken, not
        // RefreshSandboxToken — the refresh path assumes a still-valid
        // gateway-minted JWT exists.
        use crate::auth::principal::SandboxIdentitySource;
        let state = state_with_issuer().await;
        let mut req = Request::new(RefreshSandboxTokenRequest {
            extension_service_names: Vec::new(),
        });
        req.extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: "sandbox-a".to_string(),
                source: SandboxIdentitySource::K8sServiceAccount {
                    pod_name: "pod-a".to_string(),
                    pod_uid: "uid-a".to_string(),
                },
                trust_domain: Some("openshell".to_string()),
            }));
        let err = handle_refresh_sandbox_token(&state, req)
            .await
            .expect_err("K8s SA principal must not refresh");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn refresh_fails_when_issuer_not_configured() {
        // Build a ServerState without the issuer to confirm the handler
        // returns Unavailable.
        let store = Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );
        let compute = new_test_runtime(store.clone()).await;
        let state = Arc::new(ServerState::new(
            Config::new(None)
                .with_database_url("sqlite::memory:?cache=shared")
                .with_credential_drivers(["test-static"]),
            store,
            compute,
            SandboxIndex::new(),
            SandboxWatchBus::new(),
            TracingLogBus::new(),
            Arc::new(SupervisorSessionRegistry::new()),
            None,
        ));
        insert_sandbox(&state, "sandbox-a").await;
        let mut req = Request::new(RefreshSandboxTokenRequest {
            extension_service_names: Vec::new(),
        });
        req.extensions_mut().insert(sandbox_principal("sandbox-a"));
        let err = handle_refresh_sandbox_token(&state, req)
            .await
            .expect_err("missing issuer must yield unavailable");
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }
}
