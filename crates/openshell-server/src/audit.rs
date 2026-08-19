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

// The emission helpers land ahead of their callers: handler instrumentation
// (taxonomy waves 3+) consumes every item here. Remove with the first wave.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;

use openshell_ocsf::objects::{User, UserTypeId};
use openshell_ocsf::{OcsfEvent, SandboxContext};

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
}
