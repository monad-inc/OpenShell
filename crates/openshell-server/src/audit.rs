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

/// Emit an Entity Management \[3004\] audit event on the gateway lane.
///
/// One call per mutation, after the outcome is known. `unmapped` carries the
/// operation-specific context the taxonomy assigns (e.g. `workspace` on
/// membership events, `operation` on non-CRUD verbs); `request_id` is added
/// to it when present.
pub fn emit_entity_event(
    activity: EntityActivityId,
    entity: ManagedEntity,
    principal: &Principal,
    request_id: Option<&str>,
    success: bool,
    message: String,
    unmapped: Vec<(&'static str, serde_json::Value)>,
) {
    let mut builder = EntityManagementBuilder::new(ctx())
        .activity(activity)
        .entity(entity)
        .actor_user(actor_user(principal))
        .status(if success {
            StatusId::Success
        } else {
            StatusId::Failure
        })
        .message(message);
    for (key, value) in unmapped {
        builder = builder.unmapped(key, value);
    }
    if let Some(request_id) = request_id {
        builder = builder.unmapped("request_id", request_id);
    }
    emit(builder.build());
}

/// One mutation's audit facts, gathered by a handler wrapper before/after
/// running its inner logic. Consumed by [`emit_entity_outcome`].
pub struct EntityOutcome<'a> {
    pub activity: EntityActivityId,
    pub entity: ManagedEntity,
    pub principal: &'a Principal,
    pub request_id: Option<&'a str>,
    pub success_message: String,
    pub failure_message: String,
    pub unmapped: Vec<(&'static str, serde_json::Value)>,
}

/// Emit the Entity Management \[3004\] audit event for a finished handler.
///
/// Success emits with `Success`; a failure emits with `Failure` unless the
/// rejection was an authentication/authorization denial (see
/// [`audited_failure`]), which is the authentication boundary's event, not a
/// mutation attempt.
pub fn emit_entity_outcome<T>(
    result: &Result<tonic::Response<T>, tonic::Status>,
    outcome: EntityOutcome<'_>,
) {
    let success = match result {
        Ok(_) => true,
        Err(status) => {
            if !audited_failure(status) {
                return;
            }
            false
        }
    };
    let message = if success {
        outcome.success_message
    } else {
        outcome.failure_message
    };
    emit_entity_event(
        outcome.activity,
        outcome.entity,
        outcome.principal,
        outcome.request_id,
        success,
        message,
        outcome.unmapped,
    );
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
