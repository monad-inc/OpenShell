// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Take over driver operations whose owning gateway process has stopped.
//!
//! A claimed driver operation stays pending until its owner records the
//! driver's response. If the owning process exits first, nothing else may
//! settle it, so the sandbox can never be retried, restarted or deleted.
//!
//! With an in-process driver the operation cannot outlive its process, apart
//! from API requests already sent, which the backend commits or rejects within
//! its own request timeout. Each process therefore heartbeats a presence row
//! keyed by a per-process incarnation, so a restarted container is a new owner
//! even though it keeps its replica ID.
//!
//! - A process whose last successful heartbeat began [`FENCE_AFTER`] ago,
//!   because writes fail or hang, abandons the operations it owns. So does a
//!   process that is shutting down.
//! - The reconciler takes over a pending operation once its owner's presence
//!   row has not changed for [`ORPHAN_AFTER`], measured on the reconciler's
//!   own clock, so clock skew between replicas cannot cause a takeover. The
//!   gap between the two delays covers requests that were already in flight.
//! - An operation with no recorded owner, claimed before owners were recorded
//!   or with its owner erased by an older gateway rewriting the record during
//!   a rolling upgrade, is taken over after [`UNOWNED_AFTER`], longer than any
//!   driver operation runs.
//!
//! Taking over settles the operation with an unknown outcome and rotates its
//! ID, as a driver error would. An automatic restart becomes due again, and
//! the restart sweep starts a fresh runtime generation, which stops whatever
//! the abandoned operation left behind first. Other operations are not
//! re-driven: the sandbox can be retried or deleted again, and its
//! provisioning deadline, if armed, still applies.
//!
//! Residual risk: a process frozen for longer than [`ORPHAN_AFTER`] (for
//! example a paused VM) cannot fence itself, and may resume one driver call it
//! had already started after the takeover. The restart that follows the
//! takeover stops stale generations first, which bounds the damage.
//!
//! Drivers that do not run inside the gateway process can keep working after
//! it stops, so their pending operations keep the original contract.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use openshell_core::proto::{Sandbox, SandboxCondition, SandboxPhase};
use openshell_core::{ObjectId, ObjectName};
use prost::Message;
use tokio::sync::watch;
use tracing::{info, warn};

use super::{
    ComputeRuntime, emit_reconcile_audit, is_automatic_restart_transition, next_restart_at_ms,
    provisioning_deadline, provisioning_operation, sandbox_provisioning_attempt_id,
    sandbox_resource_version, set_next_restart_at_ms, upsert_ready_condition,
};
use crate::persistence::{ObjectType, PersistenceError, Store, WriteCondition};

const PRESENCE_OBJECT_TYPE: &str = "gateway_process_presence";
const PAGE_SIZE: u32 = 1000;

/// How often each gateway process refreshes its presence.
pub(super) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// A heartbeat write that takes longer than this counts as failed.
pub(super) const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(5);
/// A process whose last successful heartbeat began this long ago abandons the
/// driver operations it owns. With [`HEARTBEAT_INTERVAL`] and
/// [`HEARTBEAT_TIMEOUT`] it notices within 75 seconds.
pub(super) const FENCE_AFTER: Duration = Duration::from_mins(1);
/// A pending operation whose owner's presence has not changed for this long
/// is taken over. Exceeds the 75 seconds a process may take to fence itself
/// by more than a Kubernetes client timeout (30s) plus the API server's
/// request timeout (60s).
pub(super) const ORPHAN_AFTER: Duration = Duration::from_mins(4);
/// A pending operation with no recorded owner is taken over after this long.
pub(super) const UNOWNED_AFTER: Duration = Duration::from_mins(15);
/// Presence rows of processes gone for this long are deleted.
const PRESENCE_RETENTION: Duration = Duration::from_hours(24);

fn millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

/// This gateway process's identity as a driver operation owner.
#[derive(Debug)]
pub(super) struct OperationOwner {
    id: String,
    fenced: watch::Sender<bool>,
}

impl OperationOwner {
    pub(super) fn new(replica_id: &str) -> Self {
        Self {
            id: format!("{replica_id}/{}", uuid::Uuid::new_v4()),
            fenced: watch::Sender::new(false),
        }
    }

    pub(super) fn id(&self) -> &str {
        &self.id
    }

    pub(super) fn is_fenced(&self) -> bool {
        *self.fenced.borrow()
    }

    pub(super) fn set_fenced(&self, fenced: bool) {
        self.fenced.send_if_modified(|current| {
            let changed = *current != fenced;
            *current = fenced;
            changed
        });
    }

    /// Resolves once this process may no longer drive operations it owns.
    pub(super) async fn wait_fenced(&self) {
        let mut fenced = self.fenced.subscribe();
        // The sender lives as long as `self`, so the wait only ends on fencing.
        let _ = fenced.wait_for(|fenced| *fenced).await;
    }

    pub(super) async fn heartbeat(&self, store: &Store) -> Result<(), String> {
        store
            .put_if(
                PRESENCE_OBJECT_TYPE,
                &self.id,
                &self.id,
                "",
                b"{}",
                None,
                WriteCondition::Unconditional,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    /// Refresh this process's presence until shutdown. The row is left behind
    /// at shutdown; it simply stops changing.
    pub(super) async fn heartbeat_loop(
        self: Arc<Self>,
        store: Arc<Store>,
        shutdown: watch::Receiver<bool>,
    ) {
        let owner = self.clone();
        self.run_heartbeats(|| owner.heartbeat(&store), shutdown)
            .await;
    }

    /// Fence on elapsed time since the last successful heartbeat began, so a
    /// write that hangs fences as surely as one that fails.
    pub(super) async fn run_heartbeats<F, Fut>(
        &self,
        mut heartbeat: F,
        mut shutdown: watch::Receiver<bool>,
    ) where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<(), String>>,
    {
        let mut last_success = tokio::time::Instant::now();
        loop {
            let started = tokio::time::Instant::now();
            match tokio::time::timeout(HEARTBEAT_TIMEOUT, heartbeat()).await {
                Ok(Ok(())) => {
                    last_success = started;
                    if self.is_fenced() {
                        info!(owner = %self.id, "Driver operation ownership restored");
                    }
                    self.set_fenced(false);
                }
                Ok(Err(error)) => {
                    warn!(owner = %self.id, %error, "Failed to refresh gateway process presence");
                }
                Err(_) => {
                    warn!(owner = %self.id, "Timed out refreshing gateway process presence");
                }
            }
            if last_success.elapsed() >= FENCE_AFTER && !self.is_fenced() {
                warn!(
                    owner = %self.id,
                    "Abandoning owned driver operations; the reconciler will take them over"
                );
                self.set_fenced(true);
            }
            tokio::select! {
                () = tokio::time::sleep(HEARTBEAT_INTERVAL) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        // Settle in-flight operations now rather than leave
                        // them to a takeover once this process is gone.
                        self.set_fenced(true);
                        return;
                    }
                }
            }
        }
    }
}

/// What the takeover sweep has seen, on this process's clock.
#[derive(Debug, Default)]
pub(super) struct Observations {
    /// Per owner: its presence row's version and when that last changed.
    /// `None` while the owner has no row.
    owners: HashMap<String, (Option<(u64, i64)>, Instant)>,
    /// Pending operations with no recorded owner, by sandbox and operation
    /// ID, with when they were first seen.
    unowned: HashMap<(String, String), Instant>,
}

impl ComputeRuntime {
    pub(super) async fn operation_takeover_loop(
        self: Arc<Self>,
        mut cancel: watch::Receiver<bool>,
    ) {
        let mut observations = Observations::default();
        loop {
            if let Err(error) = self
                .take_over_orphaned_operations(&mut observations, Instant::now())
                .await
            {
                warn!(%error, "Driver operation takeover sweep failed");
            }
            tokio::select! {
                () = tokio::time::sleep(HEARTBEAT_INTERVAL) => {}
                _ = cancel.changed() => return,
            }
        }
    }

    pub(super) async fn take_over_orphaned_operations(
        &self,
        observations: &mut Observations,
        now: Instant,
    ) -> Result<(), String> {
        if !self.driver_in_process {
            return Ok(());
        }
        let presence = self.read_presence().await?;
        let mut seen_owners = HashSet::new();
        let mut seen_unowned = HashSet::new();
        let mut offset = 0;
        loop {
            let records = self
                .store
                .list_by_type(Sandbox::object_type(), PAGE_SIZE, offset)
                .await
                .map_err(|error| error.to_string())?;
            let page_len = records.len();
            for record in records {
                let Ok(sandbox) = Sandbox::decode(record.payload.as_slice()) else {
                    continue;
                };
                let Some(provisioning) = sandbox
                    .status
                    .as_ref()
                    .and_then(|status| status.provisioning.as_ref())
                else {
                    continue;
                };
                if !provisioning.driver_operation_pending
                    || sandbox_provisioning_attempt_id(&sandbox).is_none()
                {
                    continue;
                }
                let owner = provisioning.driver_operation_owner.as_str();
                if owner == self.operation_owner.id() {
                    continue;
                }
                let orphaned = if owner.is_empty() {
                    let key = (
                        sandbox.object_id().to_string(),
                        provisioning.driver_operation_id.clone(),
                    );
                    let first_seen = *observations.unowned.entry(key.clone()).or_insert(now);
                    seen_unowned.insert(key);
                    now.saturating_duration_since(first_seen) >= UNOWNED_AFTER
                } else {
                    let version = presence.get(owner).copied();
                    let observed = observations
                        .owners
                        .entry(owner.to_string())
                        .or_insert((version, now));
                    if observed.0 != version {
                        *observed = (version, now);
                    }
                    seen_owners.insert(owner.to_string());
                    now.saturating_duration_since(observed.1) >= ORPHAN_AFTER
                };
                if orphaned && let Err(error) = self.take_over_operation(&sandbox).await {
                    warn!(
                        sandbox_id = %sandbox.object_id(),
                        sandbox_name = %sandbox.object_name(),
                        %error,
                        "Failed to take over abandoned driver operation"
                    );
                }
            }
            if page_len < PAGE_SIZE as usize {
                break;
            }
            offset += u32::try_from(page_len).expect("takeover page length is capped");
        }
        observations
            .owners
            .retain(|owner, _| seen_owners.contains(owner));
        observations
            .unowned
            .retain(|key, _| seen_unowned.contains(key));
        Ok(())
    }

    /// Each owner's presence version (resource version, update time). Deletes
    /// rows untouched for [`PRESENCE_RETENTION`]; that comparison is the only
    /// one made against another process's clock, and a day dwarfs any skew.
    async fn read_presence(&self) -> Result<HashMap<String, (u64, i64)>, String> {
        let now_ms = openshell_core::time::now_ms();
        let mut presence = HashMap::new();
        let mut offset = 0;
        loop {
            let records = self
                .store
                .list_by_type(PRESENCE_OBJECT_TYPE, PAGE_SIZE, offset)
                .await
                .map_err(|error| error.to_string())?;
            let page_len = records.len();
            for record in records {
                if now_ms.saturating_sub(record.updated_at_ms) >= millis(PRESENCE_RETENTION) {
                    // Another sweep or a late heartbeat may win; either is fine.
                    let _ = self
                        .store
                        .delete_if(PRESENCE_OBJECT_TYPE, &record.id, record.resource_version)
                        .await;
                }
                presence.insert(record.id, (record.resource_version, record.updated_at_ms));
            }
            if page_len < PAGE_SIZE as usize {
                break;
            }
            offset += u32::try_from(page_len).expect("presence page length is capped");
        }
        Ok(presence)
    }

    /// Settle an abandoned operation with an unknown outcome. Holds the
    /// lifecycle gate so it cannot interleave with a local lifecycle change.
    async fn take_over_operation(&self, observed: &Sandbox) -> Result<(), String> {
        let sandbox_id = observed.object_id();
        let _lifecycle_guard = self.lifecycle_gates.lock_for(sandbox_id).await;
        let Some(current) = self
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .map_err(|error| error.to_string())?
        else {
            return Ok(());
        };
        if !provisioning_deadline::driver_operation_pending(&current)
            || !provisioning_operation::same_operation(&current, observed)
        {
            return Ok(());
        }
        let abandoned_by = current
            .status
            .as_ref()
            .and_then(|status| status.provisioning.as_ref())
            .map(|record| record.driver_operation_owner.clone())
            .unwrap_or_default();
        let now_ms = openshell_core::time::now_ms();
        let restart = is_automatic_restart_transition(&current);
        let updated = match self
            .store
            .update_message_cas::<Sandbox, _>(
                sandbox_id,
                sandbox_resource_version(&current),
                |sandbox| {
                    if let Some(record) = sandbox
                        .status
                        .as_mut()
                        .and_then(|status| status.provisioning.as_mut())
                    {
                        record.driver_operation_pending = false;
                        // A late commit from the abandoned operation would
                        // carry its ID; a new one makes it stale.
                        record.driver_operation_id = uuid::Uuid::new_v4().to_string();
                        record.driver_operation_owner.clear();
                        // As in settlement: the abandoned operation may have
                        // created compute after any earlier cleanup ran.
                        record.cleanup_completed_time = None;
                    }
                    // A claimed restart (no restart time) is retried now with a
                    // fresh generation. An armed one is already due at its
                    // readiness deadline.
                    if restart
                        && sandbox
                            .status
                            .as_ref()
                            .is_some_and(|status| next_restart_at_ms(status) == 0)
                    {
                        let status = sandbox.status.get_or_insert_with(Default::default);
                        set_next_restart_at_ms(status, now_ms);
                        upsert_ready_condition(
                            &mut sandbox.status,
                            SandboxCondition {
                                r#type: "Ready".to_string(),
                                status: "False".to_string(),
                                reason: "SandboxRestartFailed".to_string(),
                                message: "Sandbox restart was interrupted when its gateway \
                                          process stopped; retrying with a new runtime"
                                    .to_string(),
                                transition_time: None,
                            },
                        );
                    }
                },
            )
            .await
        {
            Ok(updated) => updated,
            // Someone else changed the sandbox; the next sweep re-evaluates it.
            Err(PersistenceError::Conflict { .. }) => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        warn!(
            sandbox_id,
            sandbox_name = %updated.object_name(),
            abandoned_by = %abandoned_by,
            phase = ?SandboxPhase::try_from(updated.phase()).unwrap_or(SandboxPhase::Unknown),
            "Took over a driver operation abandoned by a stopped gateway process"
        );
        emit_reconcile_audit(
            openshell_ocsf::EntityActivityId::Update,
            sandbox_id,
            updated.object_name(),
            format!(
                "sandbox {} driver operation taken over from a stopped gateway process",
                updated.object_name()
            ),
            vec![
                ("operation", serde_json::Value::from("take_over_operation")),
                ("abandoned_by", serde_json::Value::from(abandoned_by)),
            ],
        );
        self.sandbox_index.update_from_sandbox(&updated);
        self.sandbox_watch_bus.notify(sandbox_id);
        self.restart_notify.notify_one();
        Ok(())
    }
}
