// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway control-plane audit events.
//!
//! Governance operations — workspace, provider, sandbox, credential, policy
//! and settings mutations, plus authentication outcomes and suspicious
//! authorization patterns — emit OCSF audit events through here. The helpers
//! own the mapping from the authenticated [`Principal`] to the OCSF actor and
//! the outcome rules (no-op mutations and failures emit `Failure` at `Low`),
//! so a handler adds a few lines, not thirty.
//!
//! Events ride the gateway OCSF path: they are built with
//! [`crate::gateway_ocsf::context`] (gateway origin and device identity) and
//! emitted with [`openshell_ocsf::ocsf_emit!`]. Every consumer of that path
//! sees them — the `[openshell.gateway.ocsf_log]` JSONL sink, the console, and
//! any other layer reading the thread-local event. Events about a sandbox
//! carry its id in `container.uid`, which also routes them into that
//! sandbox's log stream; gateway-scoped events carry no container.
//!
//! Convention: every state-changing RPC emits exactly one audit event after
//! the outcome is known, carrying the authenticated principal via
//! [`actor_user`]. Never include tokens, credentials, or secret material.

use std::sync::OnceLock;

use openshell_core::GatewayAuditConfig;
use openshell_ocsf::{
    AuthProtocolId, ConfigStateChangeBuilder, DetectionFindingBuilder, EntityActivityId,
    EntityManagementBuilder, EventContext, FindingInfo, ManagedEntity, OcsfEvent, SeverityId,
    StateId, StatusId, User, UserTypeId,
};

use crate::auth::principal::Principal;

static GLOBAL_CONFIG: OnceLock<GatewayAuditConfig> = OnceLock::new();

/// Install the process-wide audit configuration.
///
/// Handlers read the audit toggles from `ServerState`; this copy serves the
/// authorization guards that run without access to server state (for
/// example [`crate::auth::guard::ensure_sandbox_scope`]). Returns `false` if
/// it was already set.
pub fn set_global_config(config: GatewayAuditConfig) -> bool {
    GLOBAL_CONFIG.set(config).is_ok()
}

/// The process-wide audit configuration, falling back to the defaults
/// (audit on) before startup installs one.
pub fn global_config() -> &'static GatewayAuditConfig {
    static DEFAULT: OnceLock<GatewayAuditConfig> = OnceLock::new();
    GLOBAL_CONFIG
        .get()
        .unwrap_or_else(|| DEFAULT.get_or_init(GatewayAuditConfig::default))
}

/// The OCSF context for an audit event: about `sandbox` when given, else
/// gateway-scoped (no container).
fn context(sandbox: Option<(&str, &str)>) -> EventContext {
    let (id, name) = sandbox.unwrap_or(("", ""));
    crate::gateway_ocsf::context(id, name)
}

/// Emit an audit event on the gateway OCSF path.
pub fn emit(event: OcsfEvent) {
    openshell_ocsf::ocsf_emit!(event);
}

const fn outcome_status(success: bool) -> StatusId {
    if success {
        StatusId::Success
    } else {
        StatusId::Failure
    }
}

/// Failed mutations emit at `Low` so warn-and-above alerting sees them;
/// routine successes stay `Informational`.
const fn outcome_severity(success: bool) -> SeverityId {
    if success {
        SeverityId::Informational
    } else {
        SeverityId::Low
    }
}

/// Map the authenticated principal to the OCSF actor user.
///
/// Identity comes from the session, never from request payloads: users carry
/// their OIDC subject / certificate CN as the stable uid, sandbox principals
/// appear under their sandbox id, gateway peers under their replica id, and
/// anonymous callers are named as such so a permissive dev gateway still
/// produces an honest trail. Sandbox and peer principals use `Other`: OCSF
/// 1.1 and 1.3 have no `Service` user type.
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
        Principal::Peer(peer) => User::new(
            format!("peer:{}", peer.replica_id),
            peer.pod_uid.clone(),
            UserTypeId::Other,
        ),
        Principal::Anonymous => User::named("anonymous"),
    }
}

/// The OCSF actor for background (principal-less) gateway mutations.
///
/// Convention: `system:<component>` (e.g. `system:provider-refresh`,
/// `system:compute-reconcile`, `system:gateway-startup`), user type Other.
pub fn system_actor(component: &str) -> User {
    User::new(
        format!("system:{component}"),
        format!("system:{component}"),
        UserTypeId::Other,
    )
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
/// regardless of the `settings_values` toggle. Conservative by design: a
/// false positive redacts a harmless value, a false negative ships a secret.
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

/// A platform resource (OCSF type `Other`) with whatever identity is known.
pub fn entity(kind: &str, uid: Option<String>, name: Option<String>) -> ManagedEntity {
    ManagedEntity {
        type_id: openshell_ocsf::ManagedEntityTypeId::Other,
        entity_type: kind.to_string(),
        uid: uid.filter(|uid| !uid.is_empty()),
        name: name.filter(|name| !name.is_empty()),
    }
}

/// Whether a delete RPC's `DeletionOutcome` reports a state change.
///
/// `Completed` and `Accepted` changed state; `AlreadyAbsent` (an
/// `allow_missing` no-op) did not, so it audits as a `Failure`, like any
/// other mutation that did not happen.
pub fn deletion_changed_state(outcome: i32) -> bool {
    use openshell_core::proto::DeletionOutcome;
    matches!(
        DeletionOutcome::try_from(outcome),
        Ok(DeletionOutcome::Completed | DeletionOutcome::Accepted)
    )
}

// ── Entity Management [3004] ────────────────────────────────────────────

/// One mutation's audit facts, gathered by a handler before/after running
/// its inner logic.
pub struct EntityOutcome<'a> {
    pub activity: EntityActivityId,
    pub entity: ManagedEntity,
    /// `Some((sandbox_id, sandbox_name))` marks the event as about that
    /// sandbox (`container.uid`), which also routes it into the sandbox's
    /// stream; `None` is gateway-scoped.
    pub sandbox: Option<(&'a str, &'a str)>,
    pub principal: &'a Principal,
    pub request_id: Option<&'a str>,
    pub success_message: String,
    pub failure_message: String,
    pub unmapped: Vec<(&'static str, serde_json::Value)>,
}

#[allow(clippy::too_many_arguments)]
fn build_entity_event(
    success: bool,
    actor: User,
    activity: EntityActivityId,
    entity: ManagedEntity,
    sandbox: Option<(&str, &str)>,
    message: String,
    unmapped: Vec<(&'static str, serde_json::Value)>,
    request_id: Option<&str>,
) -> OcsfEvent {
    let ctx = context(sandbox);
    let mut builder = EntityManagementBuilder::new(&ctx, activity, entity)
        .actor_user(actor)
        .status(outcome_status(success))
        .severity(outcome_severity(success))
        .message(message);
    for (key, value) in unmapped {
        builder = builder.unmapped(key, value);
    }
    if let Some(request_id) = request_id {
        builder = builder.unmapped("request_id", request_id);
    }
    builder.build()
}

fn emit_entity_event(success: bool, outcome: EntityOutcome<'_>) {
    emit(build_entity_event(
        success,
        actor_user(outcome.principal),
        outcome.activity,
        outcome.entity,
        outcome.sandbox,
        if success {
            outcome.success_message
        } else {
            outcome.failure_message
        },
        outcome.unmapped,
        outcome.request_id,
    ));
}

/// Emit the Entity Management \[3004\] audit event with an already-known
/// outcome — for handlers that emit at the store-commit point inside their
/// inner logic (where the sandbox identity is in scope) rather than from a
/// wrapper. No-op when the master audit toggle is off.
pub fn emit_entity(audit: &GatewayAuditConfig, success: bool, outcome: EntityOutcome<'_>) {
    if !audit.enabled {
        return;
    }
    emit_entity_event(success, outcome);
}

/// Emit the Entity Management \[3004\] audit event for a finished handler.
///
/// No-op when the master audit toggle is off. Success emits with `Success`;
/// a failure emits with `Failure` unless the rejection was an
/// authentication/authorization denial (see [`audited_failure`]).
pub fn emit_entity_outcome<T>(
    audit: &GatewayAuditConfig,
    result: &Result<tonic::Response<T>, tonic::Status>,
    outcome: EntityOutcome<'_>,
) {
    emit_entity_outcome_judged(audit, result, |_| true, outcome);
}

/// Like [`emit_entity_outcome`], but an `Ok` response's success is judged
/// from its body — for RPCs that report a rejected or no-op mutation inside
/// an `Ok` response (e.g. a delete returning `deleted: false`).
pub fn emit_entity_outcome_judged<T>(
    audit: &GatewayAuditConfig,
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

/// One background mutation's audit facts — [`EntityOutcome`] without a
/// request principal.
pub struct SystemEntityOutcome<'a> {
    pub activity: EntityActivityId,
    pub entity: ManagedEntity,
    /// `Some((sandbox_id, sandbox_name))` marks the event as about that
    /// sandbox.
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
    audit: &GatewayAuditConfig,
    success: bool,
    outcome: SystemEntityOutcome<'_>,
) {
    if !audit.enabled {
        return;
    }
    emit(build_entity_event(
        success,
        system_actor(outcome.component),
        outcome.activity,
        outcome.entity,
        outcome.sandbox,
        if success {
            outcome.success_message
        } else {
            outcome.failure_message
        },
        outcome.unmapped,
        None,
    ));
}

// ── Device Config State Change [5019] ───────────────────────────────────

/// One configuration mutation's audit facts, for a Device Config State
/// Change \[5019\] event.
pub struct ConfigOutcome<'a> {
    /// Custom state label (e.g. `settings_updated`, `request_modified`).
    pub state_label: &'a str,
    /// `Some((sandbox_id, sandbox_name))` marks the event as about that
    /// sandbox; `None` is gateway-scoped.
    pub sandbox: Option<(&'a str, &'a str)>,
    pub principal: &'a Principal,
    pub request_id: Option<&'a str>,
    pub success_message: String,
    pub failure_message: String,
    pub unmapped: Vec<(&'static str, serde_json::Value)>,
}

/// Build the Device Config State Change \[5019\] audit event for an
/// already-known outcome, carrying the acting principal.
pub fn build_config_event(success: bool, outcome: ConfigOutcome<'_>) -> OcsfEvent {
    let ctx = context(outcome.sandbox);
    let mut builder = ConfigStateChangeBuilder::new(&ctx)
        .state(StateId::Other, outcome.state_label)
        .severity(outcome_severity(success))
        .status(outcome_status(success))
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
    builder.build()
}

/// Emit a Device Config State Change \[5019\] audit event with an
/// already-known outcome. No-op when the master audit toggle is off; callers
/// apply [`audited_failure`] before reporting a failure here.
pub fn emit_config_outcome(audit: &GatewayAuditConfig, success: bool, outcome: ConfigOutcome<'_>) {
    if !audit.enabled {
        return;
    }
    emit(build_config_event(success, outcome));
}

// ── Authentication [3002] ────────────────────────────────────────────────

/// One authentication outcome at the gateway boundary. Never carries token
/// or credential material — `detail` must be a gateway-authored message.
pub struct AuthnOutcome<'a> {
    /// Credential mechanism (`bearer`, `mtls`, `local_dev`, `none`).
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

/// Build an Authentication \[3002\] event.
///
/// OCSF requires `user` and at least one of `service`/`dst_endpoint`: the
/// target is the gateway service (named by the operator gateway name), and a
/// rejected credential that yielded no identity is attributed to `unknown`.
pub fn build_authn_event(success: bool, outcome: &AuthnOutcome<'_>) -> OcsfEvent {
    let ctx = context(None);
    let user = outcome
        .principal
        .map_or_else(|| User::named("unknown"), actor_user);
    let service = openshell_ocsf::Service::new("openshell-gateway")
        .with_uid(crate::gateway_ocsf::identity().name)
        .with_version(openshell_core::VERSION);
    let mut builder = openshell_ocsf::AuthenticationBuilder::new(&ctx, user)
        .service(service)
        // The OCSF auth-protocol vocabulary is coarse; the exact mechanism
        // travels in `unmapped.mechanism`.
        .auth_protocol(match outcome.mechanism {
            "bearer" => AuthProtocolId::OpenId,
            "mtls" => AuthProtocolId::Other,
            _ => AuthProtocolId::Unknown,
        })
        .status(outcome_status(success))
        .severity(if success {
            SeverityId::Informational
        } else {
            SeverityId::Medium
        })
        .unmapped("mechanism", outcome.mechanism)
        .unmapped("path", outcome.path);
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
pub fn emit_authn_failure(audit: &GatewayAuditConfig, outcome: &AuthnOutcome<'_>) {
    if !audit.enabled {
        return;
    }
    emit(build_authn_event(false, outcome));
}

/// Emit an Authentication \[3002\] success event — one per authenticated
/// request. Behind `[openshell.gateway.audit] auth_success_events` (default
/// off): a complete authentication ledger multiplies volume by the request
/// rate.
pub fn emit_authn_success(audit: &GatewayAuditConfig, outcome: &AuthnOutcome<'_>) {
    if !audit.enabled || !audit.auth_success_events {
        return;
    }
    emit(build_authn_event(true, outcome));
}

// ── Detection Finding [2004] ─────────────────────────────────────────────

/// Build the cross-sandbox access finding. It is about the *offending*
/// sandbox, so it carries that sandbox in `container.uid` and lands in its
/// stream.
pub fn build_cross_sandbox_finding(
    principal_sandbox_id: &str,
    requested_sandbox_id: &str,
    detail: &str,
) -> OcsfEvent {
    let ctx = context(Some((principal_sandbox_id, "")));
    DetectionFindingBuilder::new(&ctx)
        .finding_info(
            FindingInfo::new("OSGW-CROSS-SANDBOX", "Cross-sandbox access attempt")
                .with_desc("a sandbox principal addressed a sandbox it does not own"),
        )
        .severity(SeverityId::High)
        .is_alert(true)
        .evidence_pairs(&[
            ("principal_sandbox_id", principal_sandbox_id),
            ("requested_sandbox_id", requested_sandbox_id),
        ])
        .message(format!(
            "{detail}: {principal_sandbox_id} addressed {requested_sandbox_id}"
        ))
        .build()
}

/// Dual-emit a Detection Finding \[2004\] for a cross-sandbox access attempt:
/// a sandbox principal addressed a sandbox it does not own. The domain
/// denial log/status remains the primary record; this is the escalation for
/// security monitoring.
pub fn emit_cross_sandbox_finding(
    audit: &GatewayAuditConfig,
    principal_sandbox_id: &str,
    requested_sandbox_id: &str,
) {
    if !audit.enabled {
        return;
    }
    emit(build_cross_sandbox_finding(
        principal_sandbox_id,
        requested_sandbox_id,
        "cross-sandbox access denied",
    ));
}

/// Dual-emit a Detection Finding \[2004\] for a sandbox principal that
/// attempted an operation reserved for users or platform admins.
pub fn emit_sandbox_admin_attempt_finding(
    audit: &GatewayAuditConfig,
    principal_sandbox_id: &str,
    operation: &str,
) {
    if !audit.enabled {
        return;
    }
    let ctx = context(Some((principal_sandbox_id, "")));
    let event = DetectionFindingBuilder::new(&ctx)
        .finding_info(
            FindingInfo::new(
                "OSGW-SANDBOX-ADMIN-ATTEMPT",
                "Sandbox principal attempted admin operation",
            )
            .with_desc("a sandbox principal attempted an operation reserved for users or admins"),
        )
        .severity(SeverityId::High)
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

/// Capture of gateway OCSF events for tests: a tracing layer that clones the
/// structured event every `ocsf_emit!` publishes.
#[cfg(test)]
pub mod test_capture {
    use std::sync::{Arc, Mutex};

    use openshell_ocsf::OcsfEvent;
    use tracing_subscriber::layer::SubscriberExt as _;

    /// Collected events; clone it before installing to read afterwards.
    #[derive(Clone, Default)]
    pub struct Captured(Arc<Mutex<Vec<OcsfEvent>>>);

    impl Captured {
        /// Snapshot of every captured event, in emission order.
        pub fn events(&self) -> Vec<OcsfEvent> {
            self.0.lock().unwrap().clone()
        }

        /// Captured events rendered as OCSF JSON.
        pub fn json(&self) -> Vec<serde_json::Value> {
            self.events()
                .iter()
                .map(|event| event.to_json().expect("event serializes"))
                .collect()
        }
    }

    struct CaptureLayer(Captured);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() == openshell_ocsf::OCSF_TARGET
                && let Some(ocsf) = openshell_ocsf::clone_current_event()
            {
                (self.0).0.lock().unwrap().push(ocsf);
            }
        }
    }

    /// Install a capturing subscriber on this thread until the guard drops.
    #[must_use]
    pub fn install() -> (
        Captured,
        crate::otel_tracing::test_exporter::ScopedTracingTestGuard,
    ) {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::registry().with(CaptureLayer(captured.clone()));
        let guard = crate::otel_tracing::test_exporter::install_scoped(subscriber);
        (captured, guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::{
        PeerPrincipal, SandboxIdentitySource, SandboxPrincipal, UserPrincipal,
    };
    use openshell_ocsf::validation::schema::{
        load_class_schema, validate_enum_value, validate_required_fields,
    };

    fn alice() -> Principal {
        Principal::User(UserPrincipal {
            identity: Identity {
                subject: "oidc|alice-123".to_string(),
                display_name: Some("alice".to_string()),
                roles: vec!["admin".to_string()],
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        })
    }

    #[test]
    fn user_principals_map_subject_and_display_name() {
        let user = actor_user(&alice());
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
                provider: IdentityProvider::Mtls,
            },
        });
        assert_eq!(actor_user(&principal).name, "CN=ops-cert");
    }

    #[test]
    fn sandbox_principals_are_other_actors_under_their_sandbox_id() {
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
    fn peer_principals_are_named_by_replica() {
        let principal = Principal::Peer(PeerPrincipal {
            replica_id: "gw-1".to_string(),
            pod_uid: "pod-uid-1".to_string(),
        });
        let user = actor_user(&principal);
        assert_eq!(user.name, "peer:gw-1");
        assert_eq!(user.uid.as_deref(), Some("pod-uid-1"));
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

    #[test]
    fn entity_events_are_gateway_origin_and_schema_valid() {
        let principal = alice();
        let gateway_scoped = build_entity_event(
            true,
            actor_user(&principal),
            EntityActivityId::Create,
            ManagedEntity::new("workspace", "ws-1").with_name("team-a"),
            None,
            "workspace team-a created".to_string(),
            Vec::new(),
            Some("req-1"),
        );
        let json = gateway_scoped.to_json().unwrap();
        validate_required_fields(&json, &load_class_schema("entity_management"));
        validate_enum_value(
            &json,
            "activity_id",
            &load_class_schema("entity_management"),
        );
        assert_eq!(json["metadata"]["product"]["name"], "OpenShell Gateway");
        assert!(json.get("container").is_none(), "gateway-scoped: {json}");
        assert_eq!(json["actor"]["user"]["uid"], "oidc|alice-123");
        assert_eq!(json["unmapped"]["request_id"], "req-1");
        assert_eq!(json["severity_id"], 1);

        let sandbox_scoped = build_entity_event(
            false,
            system_actor("compute-reconcile"),
            EntityActivityId::Delete,
            ManagedEntity::new("sandbox", "sb-1"),
            Some(("sb-1", "agent")),
            "sandbox agent delete failed".to_string(),
            Vec::new(),
            None,
        );
        let json = sandbox_scoped.to_json().unwrap();
        assert_eq!(json["container"]["uid"], "sb-1");
        assert_eq!(json["status"], "Failure");
        assert_eq!(json["severity_id"], 2, "failures emit at Low");
        assert_eq!(json["actor"]["user"]["name"], "system:compute-reconcile");
    }

    #[test]
    fn authn_events_satisfy_the_ocsf_authentication_constraints() {
        let schema = load_class_schema("authentication");
        let failure = build_authn_event(
            false,
            &AuthnOutcome {
                mechanism: "bearer",
                reason: Some("rejected_credential"),
                detail: Some("token expired"),
                principal: None,
                peer_addr: Some("203.0.113.9:52011".parse().unwrap()),
                path: "/openshell.v1.OpenShell/ListSandboxes",
                request_id: None,
            },
        );
        let json = failure.to_json().unwrap();
        validate_required_fields(&json, &schema);
        assert_eq!(json["user"]["name"], "unknown");
        assert_eq!(json["service"]["name"], "openshell-gateway");
        assert_eq!(json["src_endpoint"]["ip"], "203.0.113.9");
        assert_eq!(json["severity_id"], 3, "failures are Medium");
        assert_eq!(json["unmapped"]["reason"], "rejected_credential");

        let principal = alice();
        let success = build_authn_event(
            true,
            &AuthnOutcome {
                mechanism: "bearer",
                reason: None,
                detail: None,
                principal: Some(&principal),
                peer_addr: None,
                path: "/openshell.v1.OpenShell/ListSandboxes",
                request_id: Some("req-9"),
            },
        );
        let json = success.to_json().unwrap();
        validate_required_fields(&json, &schema);
        assert_eq!(json["user"]["uid"], "oidc|alice-123");
        assert_eq!(json["status"], "Success");
    }

    #[test]
    fn config_events_carry_the_actor_and_validate() {
        let principal = alice();
        let event = build_config_event(
            true,
            ConfigOutcome {
                state_label: "settings_updated",
                sandbox: None,
                principal: &principal,
                request_id: Some("req-3"),
                success_message: "settings updated".to_string(),
                failure_message: String::new(),
                unmapped: vec![("keys", serde_json::json!(["a"]))],
            },
        );
        let json = event.to_json().unwrap();
        validate_required_fields(&json, &load_class_schema("device_config_state_change"));
        assert_eq!(json["actor"]["user"]["name"], "alice");
        assert_eq!(json["unmapped"]["request_id"], "req-3");
    }

    #[test]
    fn findings_route_to_the_offending_sandbox_and_validate() {
        let event = build_cross_sandbox_finding("sb-a", "sb-b", "cross-sandbox access denied");
        let json = event.to_json().unwrap();
        validate_required_fields(&json, &load_class_schema("detection_finding"));
        assert_eq!(json["container"]["uid"], "sb-a");
        assert_eq!(json["severity_id"], 4);
        assert_eq!(
            json["finding_info"]["title"],
            "Cross-sandbox access attempt"
        );
    }

    #[test]
    fn findings_and_authn_events_honor_the_master_toggle() {
        let disabled = GatewayAuditConfig {
            enabled: false,
            auth_success_events: true,
            ..Default::default()
        };
        let principal = alice();
        let authn = AuthnOutcome {
            mechanism: "bearer",
            reason: None,
            detail: None,
            principal: Some(&principal),
            peer_addr: None,
            path: "/p",
            request_id: None,
        };

        let (captured, guard) = test_capture::install();
        emit_cross_sandbox_finding(&disabled, "sb-a", "sb-b");
        emit_sandbox_admin_attempt_finding(&disabled, "sb-a", "platform_admin");
        emit_authn_failure(&disabled, &authn);
        emit_authn_success(&disabled, &authn);
        // Success ledger stays off by default even with audit on.
        emit_authn_success(&GatewayAuditConfig::default(), &authn);
        // Control: the only record this test may produce.
        emit_sandbox_admin_attempt_finding(&GatewayAuditConfig::default(), "sb-a", "op");
        drop(guard);

        let events = captured.json();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0]["class_uid"], 2004);
    }

    #[tokio::test]
    async fn audit_events_reach_the_gateway_ocsf_jsonl_sink() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let config = toml::from_str(&format!(
            "path = {:?}\nrotation = 'never'\n",
            path.display().to_string()
        ))
        .unwrap();
        let log = crate::ocsf_log::OcsfLog::start(config).unwrap();
        {
            let subscriber = tracing_subscriber::registry().with(log.layer());
            let _guard = crate::otel_tracing::test_exporter::install_scoped(subscriber);
            let principal = alice();
            emit_entity(
                &GatewayAuditConfig::default(),
                true,
                EntityOutcome {
                    activity: EntityActivityId::Create,
                    entity: ManagedEntity::new("workspace", "ws-1").with_name("team-a"),
                    sandbox: None,
                    principal: &principal,
                    request_id: Some("req-jsonl"),
                    success_message: "workspace team-a created".to_string(),
                    failure_message: String::new(),
                    unmapped: Vec::new(),
                },
            );
        }
        log.shutdown().await;

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = contents
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 1, "{contents}");
        assert_eq!(lines[0]["class_uid"], 3004);
        assert_eq!(lines[0]["unmapped"]["request_id"], "req-jsonl");
        assert_eq!(lines[0]["actor"]["user"]["uid"], "oidc|alice-123");
    }
}
