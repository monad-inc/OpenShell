// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Restarting an agent after its credentials rotate, without ever leaving it
//! stopped.
//!
//! A restart is a persisted state machine, one per sandbox:
//!
//! - **Requested**: a rotation needs the agent restarted. Nothing is stopped
//!   until the next stage has been saved.
//! - **Stopping**: this controller stops the sandbox, then starts it.
//! - **`AwaitingRunning`**: the start was accepted; it is done when the sandbox
//!   is ready.
//!
//! Every gateway failure is retried with capped backoff. The stage is read
//! from the sandbox's phase on every step, so a reply lost in a crash or a
//! network failure never makes a step repeat wrongly, and a controller
//! restart resumes each restart where it was. A sandbox that someone else
//! stops or deletes, or that fails on its own, is left to them.

use std::sync::Arc;
use std::time::Duration;

use kube::runtime::events::EventType;
use openshell_core::proto::SandboxPhase;
use tracing::{info, warn};

use crate::controller::{Runtime, publish};
use crate::gateway::SandboxRestarter;
use crate::state::{RestartStage, SecretRef};

/// First and longest wait between attempts after a failure. Retried until
/// it succeeds.
const BACKOFF_FIRST: Duration = Duration::from_secs(10);
const BACKOFF_MAX: Duration = Duration::from_mins(5);
/// How often to look again while the sandbox changes phase, and how long a
/// phase may take before each look is reported.
const POLL: Duration = Duration::from_secs(5);
const SLOW: Duration = Duration::from_mins(2);

/// What one look at the sandbox decided.
enum Step {
    /// Moved to the next stage; look again now.
    Advanced,
    /// Waiting for the sandbox to change phase.
    Waiting(&'static str),
    /// A gateway call or a save failed; retry after backoff.
    Failed(String),
    /// The sandbox runs again.
    Done,
    /// The restart ends without this controller starting the sandbox.
    Abandoned {
        type_: EventType,
        reason: &'static str,
        note: String,
    },
}

/// Drive the restart of one sandbox to its end. Started for each new request
/// and, at startup, for each restart a previous run left in progress.
pub(crate) async fn drive(
    restarter: Arc<dyn SandboxRestarter>,
    runtime: Arc<Runtime>,
    secret: SecretRef,
    workspace: String,
    sandbox: String,
) {
    let ctx = &runtime.ctx;
    let mut backoff = BACKOFF_FIRST;
    let mut waiting_since: Option<(&'static str, tokio::time::Instant)> = None;
    loop {
        let Some(stage) = ctx.restart_stage(&workspace, &sandbox).await else {
            return;
        };
        let step = match restarter.phase(&workspace, &sandbox).await {
            Err(err) => Step::Failed(err.to_string()),
            Ok(phase) => {
                step(
                    restarter.as_ref(),
                    &runtime,
                    stage,
                    phase,
                    &workspace,
                    &sandbox,
                )
                .await
            }
        };
        let delay = match step {
            Step::Advanced => {
                backoff = BACKOFF_FIRST;
                waiting_since = None;
                continue;
            }
            Step::Waiting(what) => {
                let since = match waiting_since {
                    Some((previous, since)) if previous == what => since,
                    _ => {
                        let now = tokio::time::Instant::now();
                        waiting_since = Some((what, now));
                        now
                    }
                };
                if since.elapsed() >= SLOW {
                    let note = format!(
                        "Restart of sandbox {workspace}/{sandbox} is waiting: it is still {what}"
                    );
                    publish(
                        &runtime,
                        &secret,
                        EventType::Warning,
                        "AgentRestartPending",
                        note,
                    )
                    .await;
                    waiting_since = Some((what, tokio::time::Instant::now()));
                }
                POLL
            }
            Step::Failed(error) => {
                warn!(
                    secret = %secret,
                    workspace,
                    sandbox,
                    ?stage,
                    retry_in_secs = backoff.as_secs(),
                    error,
                    "agent restart step failed; retrying"
                );
                // No counter or delay in the note, so repeats aggregate into
                // one Event with a count.
                let note = format!(
                    "Restart of sandbox {workspace}/{sandbox} is retrying after a failure: {error}"
                );
                publish(
                    &runtime,
                    &secret,
                    EventType::Warning,
                    "AgentRestartPending",
                    note,
                )
                .await;
                let delay = backoff;
                backoff = (backoff * 2).min(BACKOFF_MAX);
                delay
            }
            Step::Done => {
                let again = ctx.finish_restart(&workspace, &sandbox).await;
                info!(secret = %secret, workspace, sandbox, again, "restarted agent after credential rotation");
                let note = if again {
                    format!(
                        "Restarted sandbox {workspace}/{sandbox}; restarting once more for a later rotation"
                    )
                } else {
                    format!("Restarted sandbox {workspace}/{sandbox} after its credentials rotated")
                };
                publish(&runtime, &secret, EventType::Normal, "AgentRestarted", note).await;
                if !again {
                    return;
                }
                backoff = BACKOFF_FIRST;
                waiting_since = None;
                continue;
            }
            Step::Abandoned {
                type_,
                reason,
                note,
            } => {
                ctx.abandon_restart(&workspace, &sandbox).await;
                info!(secret = %secret, workspace, sandbox, reason, note, "agent restart ended");
                publish(&runtime, &secret, type_, reason, note).await;
                return;
            }
        };
        tokio::time::sleep(delay).await;
    }
}

fn skipped(workspace: &str, sandbox: &str, why: &str) -> Step {
    Step::Abandoned {
        type_: EventType::Normal,
        reason: "AgentRestartSkipped",
        note: format!("Did not restart sandbox {workspace}/{sandbox}: {why}"),
    }
}

fn failed(workspace: &str, sandbox: &str, why: &str) -> Step {
    Step::Abandoned {
        type_: EventType::Warning,
        reason: "AgentRestartFailed",
        note: format!("Restart of sandbox {workspace}/{sandbox} ended: {why}"),
    }
}

async fn step(
    restarter: &dyn SandboxRestarter,
    runtime: &Runtime,
    stage: RestartStage,
    phase: Option<SandboxPhase>,
    workspace: &str,
    sandbox: &str,
) -> Step {
    use SandboxPhase as P;
    let ctx = &runtime.ctx;
    match stage {
        RestartStage::Requested => match phase {
            None | Some(P::Deleting) => skipped(workspace, sandbox, "it was deleted"),
            Some(P::Stopped | P::Stopping | P::Completed) => skipped(
                workspace,
                sandbox,
                "it is not running, and was stopped by someone else",
            ),
            Some(P::Error) => skipped(
                workspace,
                sandbox,
                "it is in Error; it fetches the new values when it next starts",
            ),
            // It may have fetched values from before the rotation; restart it
            // once it runs.
            Some(P::Provisioning | P::Starting) => Step::Waiting("starting"),
            Some(P::Ready | P::Unknown | P::Unspecified) => {
                // Nothing is stopped until this controller has saved that it
                // owns the stop, so it can never forget to start it.
                match ctx
                    .set_restart_stage(workspace, sandbox, RestartStage::Stopping)
                    .await
                {
                    Ok(()) => Step::Advanced,
                    Err(err) => Step::Failed(format!("could not record the restart: {err}")),
                }
            }
        },
        RestartStage::Stopping => match phase {
            None | Some(P::Deleting) => failed(workspace, sandbox, "it was deleted while stopped"),
            Some(P::Stopping) => Step::Waiting("stopping"),
            Some(P::Stopped | P::Completed) => match restarter.start(workspace, sandbox).await {
                Ok(()) => {
                    // A lost save only means a resumed restart sees the
                    // sandbox starting or ready in this stage and stops it
                    // once more: an extra restart, never a stopped agent.
                    if let Err(err) = ctx
                        .set_restart_stage(workspace, sandbox, RestartStage::AwaitingRunning)
                        .await
                    {
                        warn!(workspace, sandbox, error = %err, "could not record the start");
                    }
                    Step::Advanced
                }
                Err(err) => Step::Failed(err.to_string()),
            },
            // The gateway refuses to stop a sandbox that is still starting.
            Some(P::Provisioning | P::Starting) => Step::Waiting("starting"),
            Some(P::Error) => failed(
                workspace,
                sandbox,
                "it is in Error after being stopped; the gateway's own recovery owns it now",
            ),
            Some(P::Ready | P::Unknown | P::Unspecified) => {
                match restarter.stop(workspace, sandbox).await {
                    Ok(()) => Step::Waiting("stopping"),
                    Err(err) => Step::Failed(err.to_string()),
                }
            }
        },
        RestartStage::AwaitingRunning => match phase {
            Some(P::Ready) => Step::Done,
            Some(P::Provisioning | P::Starting | P::Unknown | P::Unspecified) => {
                Step::Waiting("starting")
            }
            None | Some(P::Deleting) => skipped(workspace, sandbox, "it was deleted"),
            Some(P::Stopped | P::Stopping | P::Completed) => skipped(
                workspace,
                sandbox,
                "someone else stopped it after it started",
            ),
            Some(P::Error) => failed(
                workspace,
                sandbox,
                "it is in Error after starting; the gateway's own recovery owns it now",
            ),
        },
    }
}
