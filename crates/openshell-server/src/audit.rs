// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway audit event emission.
//!
//! Governance operations — workspace, provider, sandbox, credential, policy
//! and settings mutations, plus authentication outcomes — emit OCSF audit
//! events through here. The helpers own the two pieces every emission needs:
//! the gateway's OCSF context and the mapping from the authenticated
//! [`Principal`] to the OCSF actor, so a handler adds a few lines, not
//! thirty.
//!
//! Emitted events ride the tracing subscriber into the log bus: events tied
//! to a sandbox ([`emit_for_sandbox`]) appear in that sandbox's stream and
//! export with its `sandbox.id`; gateway-scoped events ([`emit`]) take the
//! gateway lane and export without one. Payloads travel raw
//! (`ocsf.raw` + `ocsf.severity_id`), like sandbox events in the default
//! push format.
//!
//! Convention (enforced by review, stated in AGENTS.md): every
//! state-changing RPC emits exactly one audit event, after the outcome is
//! known, carrying the authenticated principal via [`actor_user`]. Never
//! include tokens, credentials, or secret material.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;

use openshell_ocsf::enums::EntityActivityId;
use openshell_ocsf::objects::{ManagedEntity, User, UserTypeId};
use openshell_ocsf::{EntityManagementBuilder, OcsfEvent, SandboxContext, StatusId};

use crate::auth::principal::Principal;

/// Process-wide OCSF context for gateway-authored audit events.
///
/// The gateway is the product here — `metadata.uid` stays empty (no sandbox)
/// and the container image names the gateway itself, mirroring the identity
/// service-routing events already report.
static GATEWAY_CTX: LazyLock<SandboxContext> = LazyLock::new(|| SandboxContext {
    sandbox_id: String::new(),
    sandbox_name: String::new(),
    container_image: "openshell/gateway".to_string(),
    hostname: "openshell-gateway".to_string(),
    product_version: openshell_core::VERSION.to_string(),
    proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    proxy_port: 0,
});

/// The gateway's OCSF context, for constructing audit event builders.
pub fn ctx() -> &'static SandboxContext {
    &GATEWAY_CTX
}

/// A per-sandbox variant of the gateway context, for gateway-authored audit
/// events about a specific sandbox (paired with [`emit_for_sandbox`] so the
/// event lands in that sandbox's stream with matching metadata).
pub fn ctx_for_sandbox(sandbox_id: &str, sandbox_name: &str) -> SandboxContext {
    SandboxContext {
        sandbox_id: sandbox_id.to_string(),
        sandbox_name: sandbox_name.to_string(),
        ..GATEWAY_CTX.clone()
    }
}

/// Map the authenticated principal to the OCSF actor user.
///
/// Identity comes from the session, never from request payloads: users carry
/// their OIDC subject / certificate CN as the stable uid, sandbox principals
/// appear as service-type actors under their sandbox id (OCSF has no
/// `Service` user type; `Other` is its conventional home), and anonymous
/// callers are named as such so a permissive dev gateway still produces an
/// honest trail.
pub fn actor_user(principal: &Principal) -> User {
    match principal {
        Principal::User(user) => {
            let subject = user.identity.subject.clone();
            let name = user
                .identity
                .display_name
                .clone()
                .unwrap_or_else(|| subject.clone());
            User::new(name, subject, UserTypeId::User)
        }
        Principal::Sandbox(sandbox) => User::new(
            format!("sandbox:{}", sandbox.sandbox_id),
            sandbox.sandbox_id.clone(),
            UserTypeId::Other,
        ),
        Principal::Anonymous => User::named("anonymous"),
    }
}

/// The OCSF actor for background (principal-less) gateway mutations.
///
/// Convention: `system:<component>` (e.g. `system:provider-refresh`,
/// `system:compute-reconcile`, `system:gateway-startup`), user type Other —
/// timer- and reconciliation-driven state changes appear in the same trail
/// as request-driven ones, attributed to the component that made them.
pub fn system_actor(component: &str) -> User {
    User::new(
        format!("system:{component}"),
        format!("system:{component}"),
        UserTypeId::Other,
    )
}

/// One background mutation's audit facts — [`EntityOutcome`] without a
/// request principal. Consumed by [`emit_system_entity`].
pub struct SystemEntityOutcome<'a> {
    pub activity: EntityActivityId,
    pub entity: ManagedEntity,
    /// `Some((sandbox_id, sandbox_name))` routes into that sandbox's stream.
    pub sandbox: Option<(&'a str, &'a str)>,
    /// Component name; the actor renders as `system:<component>`.
    pub component: &'a str,
    pub success_message: String,
    pub failure_message: String,
    pub unmapped: Vec<(&'static str, serde_json::Value)>,
}

/// Emit an Entity Management \[3004\] audit event for a background mutation
/// with a [`system_actor`]. No-op when the master audit toggle is off.
pub fn emit_system_entity(
    audit: &openshell_core::GatewayAuditConfig,
    success: bool,
    outcome: SystemEntityOutcome<'_>,
) {
    if !audit.enabled {
        return;
    }
    let sandbox_ctx;
    let event_ctx = match outcome.sandbox {
        Some((id, name)) => {
            sandbox_ctx = ctx_for_sandbox(id, name);
            &sandbox_ctx
        }
        None => ctx(),
    };
    let mut builder = EntityManagementBuilder::new(event_ctx)
        .activity(outcome.activity)
        .entity(outcome.entity)
        .actor_user(system_actor(outcome.component))
        .status(if success {
            StatusId::Success
        } else {
            StatusId::Failure
        })
        .severity(if success {
            openshell_ocsf::SeverityId::Informational
        } else {
            openshell_ocsf::SeverityId::Low
        })
        .message(if success {
            outcome.success_message
        } else {
            outcome.failure_message
        });
    for (key, value) in outcome.unmapped {
        builder = builder.unmapped(key, value);
    }
    let built = builder.build();
    match outcome.sandbox {
        Some((id, _)) => emit_for_sandbox(id, built),
        None => emit(built),
    }
}

/// Emit a gateway-scoped audit event (no sandbox in play).
///
/// Exports on the gateway lane, without a `sandbox.id` attribute.
pub fn emit(event: OcsfEvent) {
    openshell_ocsf::emit_ocsf_event(event);
}

/// Emit an audit event about a specific sandbox.
///
/// Appears in that sandbox's visibility stream and exports under its
/// `sandbox.id`, alongside the supervisor's own events.
pub fn emit_for_sandbox(sandbox_id: &str, event: OcsfEvent) {
    openshell_ocsf::emit_ocsf_event_for_sandbox(sandbox_id, event);
}

/// The authenticated principal, for audit attribution.
///
/// Unlike [`crate::grpc::extract_principal`], a missing principal maps to
/// [`Principal::Anonymous`] instead of failing: the audit trail records the
/// mutation honestly either way and must never change handler behavior.
pub fn principal<T>(request: &tonic::Request<T>) -> Principal {
    request
        .extensions()
        .get::<Principal>()
        .cloned()
        .unwrap_or(Principal::Anonymous)
}

/// The request's correlation id — the `x-request-id` header the gateway's
/// request-id middleware stamps (or the client supplied). Carried in
/// `unmapped.request_id` to tie each audit event to its request trace.
pub fn request_id<T>(request: &tonic::Request<T>) -> Option<String> {
    request
        .metadata()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
}

/// Whether a setting key looks like it names credential material.
///
/// Values under matching keys are always redacted from audit events,
/// regardless of the `settings_values` toggle — the "never log secrets"
/// rule outranks audit completeness. Conservative by design: a false
/// positive redacts a harmless value, a false negative ships a secret.
pub fn is_credential_like_key(key: &str) -> bool {
    const PATTERNS: &[&str] = &[
        "secret",
        "token",
        "password",
        "passwd",
        "credential",
        "api_key",
        "apikey",
        "private_key",
        "auth",
    ];
    let key = key.to_ascii_lowercase();
    PATTERNS.iter().any(|p| key.contains(p)) || key.ends_with("_key") || key == "key"
}

/// Whether a failed mutation outcome belongs in the entity audit trail.
///
/// Authentication and authorization rejections are excluded: those are the
/// authentication boundary's events (Authentication \[3002\] + findings),
/// not per-handler mutation attempts by an authorized principal.
pub fn audited_failure(status: &tonic::Status) -> bool {
    !matches!(
        status.code(),
        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated
    )
}

/// Build and emit an Entity Management \[3004\] event on the gateway lane.
///
/// Private on purpose: callers go through [`emit_entity_outcome`] /
/// [`emit_entity_outcome_judged`], which apply the audit `enabled` toggle
/// and the denial-exclusion rule before reaching here.
fn emit_entity_event(success: bool, outcome: EntityOutcome<'_>) {
    let sandbox_ctx;
    let event_ctx = match outcome.sandbox {
        Some((id, name)) => {
            sandbox_ctx = ctx_for_sandbox(id, name);
            &sandbox_ctx
        }
        None => ctx(),
    };
    let mut builder = EntityManagementBuilder::new(event_ctx)
        .activity(outcome.activity)
        .entity(outcome.entity)
        .actor_user(actor_user(outcome.principal))
        .status(if success {
            StatusId::Success
        } else {
            StatusId::Failure
        })
        // Failed mutations at Low so Warn+ alerting can see them; routine
        // successes stay Informational.
        .severity(if success {
            openshell_ocsf::SeverityId::Informational
        } else {
            openshell_ocsf::SeverityId::Low
        })
        .message(if success {
            outcome.success_message
        } else {
            outcome.failure_message
        });
    for (key, value) in outcome.unmapped {
        builder = builder.unmapped(key, value);
    }
    if let Some(request_id) = outcome.request_id {
        builder = builder.unmapped("request_id", request_id);
    }
    let built = builder.build();
    match outcome.sandbox {
        Some((id, _)) => emit_for_sandbox(id, built),
        None => emit(built),
    }
}

/// One mutation's audit facts, gathered by a handler wrapper before/after
/// running its inner logic. Consumed by [`emit_entity_outcome`].
pub struct EntityOutcome<'a> {
    pub activity: EntityActivityId,
    pub entity: ManagedEntity,
    /// `Some((sandbox_id, sandbox_name))` routes the event into that
    /// sandbox's stream (mutations about a specific, resolved sandbox);
    /// `None` rides the gateway lane.
    pub sandbox: Option<(&'a str, &'a str)>,
    pub principal: &'a Principal,
    pub request_id: Option<&'a str>,
    pub success_message: String,
    pub failure_message: String,
    pub unmapped: Vec<(&'static str, serde_json::Value)>,
}

/// Emit the Entity Management \[3004\] audit event with an already-known
/// outcome — for handlers that emit at the store-commit point inside their
/// inner logic (where the sandbox identity is in scope) rather than from a
/// wrapper. No-op when the master audit toggle is off.
pub fn emit_entity(
    audit: &openshell_core::GatewayAuditConfig,
    success: bool,
    outcome: EntityOutcome<'_>,
) {
    if !audit.enabled {
        return;
    }
    emit_entity_event(success, outcome);
}

/// One gateway configuration mutation's audit facts, for a Device Config
/// State Change \[5019\] event on the gateway lane. Consumed by
/// [`emit_config_outcome`].
pub struct ConfigOutcome<'a> {
    /// Custom state label (e.g. `inference_route_set`).
    pub state_label: &'a str,
    pub principal: &'a Principal,
    pub request_id: Option<&'a str>,
    pub success_message: String,
    pub failure_message: String,
    pub unmapped: Vec<(&'static str, serde_json::Value)>,
}

/// Build and emit a Device Config State Change \[5019\] audit event with an
/// already-known outcome, carrying the acting principal. No-op when the
/// master audit toggle is off; callers apply [`audited_failure`] before
/// reporting a failure here.
pub fn emit_config_outcome(
    audit: &openshell_core::GatewayAuditConfig,
    success: bool,
    outcome: ConfigOutcome<'_>,
) {
    if !audit.enabled {
        return;
    }
    let mut builder = openshell_ocsf::ConfigStateChangeBuilder::new(ctx())
        .state(openshell_ocsf::enums::StateId::Other, outcome.state_label)
        // Failed mutations at Low so Warn+ alerting can see them.
        .severity(if success {
            openshell_ocsf::SeverityId::Informational
        } else {
            openshell_ocsf::SeverityId::Low
        })
        .status(if success {
            StatusId::Success
        } else {
            StatusId::Failure
        })
        .actor_user(actor_user(outcome.principal))
        .message(if success {
            outcome.success_message
        } else {
            outcome.failure_message
        });
    for (key, value) in outcome.unmapped {
        builder = builder.unmapped(key, value);
    }
    if let Some(request_id) = outcome.request_id {
        builder = builder.unmapped("request_id", request_id);
    }
    emit(builder.build());
}

/// One authentication outcome at the gateway boundary, for an
/// Authentication \[3002\] audit event. Never carries token or credential
/// material — `detail` must be a gateway-authored status message.
pub struct AuthnOutcome<'a> {
    /// Credential mechanism the request presented (`bearer`, `mtls`,
    /// `local_dev`, `none`).
    pub mechanism: &'a str,
    /// Low-cardinality failure category (`rejected_credential`,
    /// `authenticator_error`, `missing_credentials`,
    /// `missing_client_certificate`, `anonymous`). `None` for successes.
    pub reason: Option<&'a str>,
    /// Gateway-authored status message for failures.
    pub detail: Option<&'a str>,
    /// The authenticated principal, for success events.
    pub principal: Option<&'a Principal>,
    pub peer_addr: Option<std::net::SocketAddr>,
    /// Request path, for correlation (`/openshell.v1.OpenShell/...`).
    pub path: &'a str,
    pub request_id: Option<&'a str>,
}

fn build_authn_event(success: bool, outcome: &AuthnOutcome<'_>) -> OcsfEvent {
    use openshell_ocsf::enums::AuthProtocolId;

    // The OCSF auth-protocol vocabulary is coarse; the exact mechanism
    // travels in `unmapped.mechanism`.
    let mut builder = openshell_ocsf::AuthenticationBuilder::new(ctx())
        .auth_protocol(match outcome.mechanism {
            "bearer" => AuthProtocolId::OpenId,
            "mtls" => AuthProtocolId::Other,
            _ => AuthProtocolId::Unknown,
        })
        .status(if success {
            StatusId::Success
        } else {
            StatusId::Failure
        })
        .severity(if success {
            openshell_ocsf::SeverityId::Informational
        } else {
            openshell_ocsf::SeverityId::Medium
        })
        .unmapped("mechanism", outcome.mechanism)
        .unmapped("path", outcome.path);
    if let Some(principal) = outcome.principal {
        builder = builder.user(actor_user(principal));
    }
    if let Some(reason) = outcome.reason {
        builder = builder.unmapped("reason", reason);
    }
    if let Some(detail) = outcome.detail {
        builder = builder.status_detail(detail);
    }
    if let Some(addr) = outcome.peer_addr {
        builder = builder.src_endpoint(openshell_ocsf::Endpoint::from_ip(addr.ip(), addr.port()));
    }
    if let Some(request_id) = outcome.request_id {
        builder = builder.unmapped("request_id", request_id);
    }
    builder.build()
}

/// Emit an Authentication \[3002\] failure event — one per rejected request
/// at the authenticator boundary. Always on while audit events are enabled.
pub fn emit_authn_failure(audit: &openshell_core::GatewayAuditConfig, outcome: &AuthnOutcome<'_>) {
    if !audit.enabled {
        return;
    }
    emit(build_authn_event(false, outcome));
}

/// Emit an Authentication \[3002\] success event — one per authenticated
/// request. Behind `[openshell.gateway.audit] auth_success_events`
/// (`OPENSHELL_AUDIT_AUTH_SUCCESS_EVENTS`, default off): a complete
/// authentication ledger multiplies volume by the request rate.
pub fn emit_authn_success(audit: &openshell_core::GatewayAuditConfig, outcome: &AuthnOutcome<'_>) {
    if !audit.enabled || !audit.auth_success_events {
        return;
    }
    emit(build_authn_event(true, outcome));
}

/// Dual-emit a Detection Finding \[2004\] for a cross-sandbox access
/// attempt: a sandbox principal addressed a sandbox it does not own. The
/// domain denial log/status remains the primary record; this is the
/// escalation for security monitoring.
pub fn emit_cross_sandbox_finding(
    audit: &openshell_core::GatewayAuditConfig,
    principal_sandbox_id: &str,
    requested_sandbox_id: &str,
) {
    if !audit.enabled {
        return;
    }
    let event = openshell_ocsf::DetectionFindingBuilder::new(ctx())
        .finding_info(
            openshell_ocsf::FindingInfo::new("OSGW-CROSS-SANDBOX", "Cross-sandbox access attempt")
                .with_desc("a sandbox principal addressed a sandbox it does not own"),
        )
        .severity(openshell_ocsf::SeverityId::High)
        .is_alert(true)
        .evidence_pairs(&[
            ("principal_sandbox_id", principal_sandbox_id),
            ("requested_sandbox_id", requested_sandbox_id),
        ])
        .message(format!(
            "cross-sandbox access denied: {principal_sandbox_id} addressed {requested_sandbox_id}"
        ))
        .build();
    emit(event);
}

/// Dual-emit a Detection Finding \[2004\] for a sandbox principal that
/// attempted an operation reserved for users or platform admins.
pub fn emit_sandbox_admin_attempt_finding(
    audit: &openshell_core::GatewayAuditConfig,
    principal_sandbox_id: &str,
    operation: &str,
) {
    if !audit.enabled {
        return;
    }
    let event = openshell_ocsf::DetectionFindingBuilder::new(ctx())
        .finding_info(
            openshell_ocsf::FindingInfo::new(
                "OSGW-SANDBOX-ADMIN-ATTEMPT",
                "Sandbox principal attempted admin operation",
            )
            .with_desc("a sandbox principal attempted an operation reserved for users or admins"),
        )
        .severity(openshell_ocsf::SeverityId::High)
        .is_alert(true)
        .evidence_pairs(&[
            ("principal_sandbox_id", principal_sandbox_id),
            ("operation", operation),
        ])
        .message(format!(
            "sandbox principal {principal_sandbox_id} attempted admin operation {operation}"
        ))
        .build();
    emit(event);
}

/// Emit the Entity Management \[3004\] audit event for a finished handler.
///
/// No-op when the master audit toggle (`[openshell.gateway.audit] enabled`,
/// `OPENSHELL_AUDIT_EVENTS`) is off. Success emits with `Success`; a failure
/// emits with `Failure` unless the rejection was an authentication/
/// authorization denial (see [`audited_failure`]), which is the
/// authentication boundary's event, not a mutation attempt.
pub fn emit_entity_outcome<T>(
    audit: &openshell_core::GatewayAuditConfig,
    result: &Result<tonic::Response<T>, tonic::Status>,
    outcome: EntityOutcome<'_>,
) {
    emit_entity_outcome_judged(audit, result, |_| true, outcome);
}

/// Like [`emit_entity_outcome`], but an `Ok` response's success is judged
/// from its body — for RPCs that report a rejected mutation inside an `Ok`
/// response (e.g. profile import returning diagnostics with
/// `imported: false`).
pub fn emit_entity_outcome_judged<T>(
    audit: &openshell_core::GatewayAuditConfig,
    result: &Result<tonic::Response<T>, tonic::Status>,
    response_success: impl FnOnce(&T) -> bool,
    outcome: EntityOutcome<'_>,
) {
    if !audit.enabled {
        return;
    }
    let success = match result {
        Ok(response) => response_success(response.get_ref()),
        Err(status) => {
            if !audited_failure(status) {
                return;
            }
            false
        }
    };
    emit_entity_event(success, outcome);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::Identity;
    use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal, UserPrincipal};

    #[test]
    fn user_principals_map_subject_and_display_name() {
        let principal = Principal::User(UserPrincipal {
            identity: Identity {
                subject: "oidc|alice-123".to_string(),
                display_name: Some("alice".to_string()),
                roles: vec!["admin".to_string()],
                scopes: vec![],
                provider: crate::auth::identity::IdentityProvider::Oidc,
            },
        });
        let user = actor_user(&principal);
        assert_eq!(user.name, "alice");
        assert_eq!(user.uid.as_deref(), Some("oidc|alice-123"));
        assert_eq!(user.type_id, Some(UserTypeId::User));
    }

    #[test]
    fn user_principals_without_display_name_use_the_subject() {
        let principal = Principal::User(UserPrincipal {
            identity: Identity {
                subject: "CN=ops-cert".to_string(),
                display_name: None,
                roles: vec![],
                scopes: vec![],
                provider: crate::auth::identity::IdentityProvider::Mtls,
            },
        });
        assert_eq!(actor_user(&principal).name, "CN=ops-cert");
    }

    #[test]
    fn sandbox_principals_are_service_actors_under_their_sandbox_id() {
        let principal = Principal::Sandbox(SandboxPrincipal {
            sandbox_id: "sb-7f3a".to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "gateway".to_string(),
            },
            trust_domain: None,
        });
        let user = actor_user(&principal);
        assert_eq!(user.name, "sandbox:sb-7f3a");
        assert_eq!(user.uid.as_deref(), Some("sb-7f3a"));
        assert_eq!(user.type_id, Some(UserTypeId::Other));
    }

    #[test]
    fn anonymous_principals_are_named_honestly() {
        let user = actor_user(&Principal::Anonymous);
        assert_eq!(user.name, "anonymous");
        assert!(user.uid.is_none());
    }

    #[test]
    fn requests_without_a_principal_audit_as_anonymous() {
        let request = tonic::Request::new(());
        assert!(matches!(principal(&request), Principal::Anonymous));
    }

    #[test]
    fn request_id_reads_the_x_request_id_header() {
        let mut request = tonic::Request::new(());
        assert_eq!(request_id(&request), None);
        request
            .metadata_mut()
            .insert("x-request-id", "req-42".parse().unwrap());
        assert_eq!(request_id(&request).as_deref(), Some("req-42"));
    }

    #[test]
    fn authz_denials_are_not_audited_as_mutation_failures() {
        assert!(!audited_failure(&tonic::Status::permission_denied("no")));
        assert!(!audited_failure(&tonic::Status::unauthenticated("who")));
        assert!(audited_failure(&tonic::Status::not_found("missing")));
        assert!(audited_failure(&tonic::Status::invalid_argument("bad")));
        assert!(audited_failure(&tonic::Status::internal("broken")));
    }

    #[test]
    fn credential_like_keys_are_detected_conservatively() {
        for key in [
            "api_key",
            "provider_apikey",
            "oauth_client_secret",
            "refresh_token",
            "db_password",
            "signing_key",
            "key",
            "AUTH_HEADER",
        ] {
            assert!(is_credential_like_key(key), "{key} should be redacted");
        }
        for key in [
            "providers_v2_enabled",
            "proposal_approval_mode",
            "keyboard_layout",
        ] {
            assert!(!is_credential_like_key(key), "{key} should pass through");
        }
    }
}
