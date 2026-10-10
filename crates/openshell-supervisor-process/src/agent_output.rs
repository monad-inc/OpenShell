// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Forward the agent's own stdout and stderr to the gateway as log lines.
//!
//! The supervisor already retains the canonical process's output for SSH
//! attach (see [`crate::main_session`]). This module subscribes to that same
//! retained output, splits it into lines, and pushes each line through the
//! log push channel under a reserved target, so the gateway exports it with
//! `log.source = "agent"` next to the supervisor's own records.
//!
//! Lines are never parsed or rewritten. A harness that writes a JSON event
//! stream exports its whole transcript; a plain-text agent exports its log.
//! The only transformations are the ones a log record forces: a line longer
//! than one record allows is split into ordered fragments, marked so a
//! consumer can rejoin them, and never truncated; and bytes that are not
//! valid UTF-8 become U+FFFD, since a record body is a string.
//!
//! Forwarding is gated by the `agent_output_export_enabled` setting and is
//! off by default. Until the first settings snapshot arrives the forwarder
//! reads nothing; output written meanwhile stays in the supervisor's 1 MiB
//! retained window and is exported once the setting turns out to be on. The
//! forwarder reads from the process's first output event, so anything the
//! window evicted first is reported, not skipped. It also yields to the
//! supervisor's own records: it only enqueues while at least half the push
//! channel is free, so a chatty agent cannot crowd out OCSF events. When it
//! falls behind, the agent is never blocked; the retained window moves on and
//! the skipped span is reported as a `telemetry_gap` line instead of being
//! lost silently. After a gap, the first partial line of each stream is
//! dropped, because the forwarder cannot tell whether its start was skipped.

use std::collections::HashMap;
use std::sync::Arc;

use openshell_core::agent_output::{
    AGENT_STDERR_TARGET, AGENT_STDOUT_TARGET, CHUNK_FINAL_FIELD, CHUNK_INDEX_FIELD,
    CHUNK_TRUNCATED_FIELD,
};
use openshell_core::proto::SandboxLogLine;
use tokio::sync::{mpsc, watch};

use crate::log_push::TELEMETRY_GAP_TARGET;
use crate::main_session::{MainOutput, MainSession};

/// Largest message body one exported record carries.
///
/// Measured after invalid UTF-8 is replaced. Longer lines are split into
/// fragments of at most this many bytes. Sized so a full push batch stays
/// well under the gateway's 1 MiB gRPC message limit.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// How long the forwarder waits before re-checking for free channel space.
const BACKPRESSURE_POLL: std::time::Duration = std::time::Duration::from_millis(5);

/// One exported record cut from the output stream.
#[derive(Debug, PartialEq, Eq)]
struct Frame {
    text: String,
    /// `(index, final)` when the record is a fragment of a split line.
    chunk: Option<(u32, bool)>,
    /// The line's remaining bytes were never read; this empty record closes
    /// the fragments already exported.
    truncated: bool,
}

/// Splits a byte stream into newline-delimited records, fragmenting lines
/// longer than [`MAX_RECORD_BYTES`].
#[derive(Debug, Default)]
struct LineFramer {
    pending: Vec<u8>,
    /// Index of the next fragment when the pending line has already been
    /// split at least once.
    next_chunk: Option<u32>,
    /// Drop bytes up to and including the next newline: the line in progress
    /// lost its beginning or middle, so it cannot be exported faithfully.
    discarding: bool,
}

impl LineFramer {
    fn push(&mut self, mut bytes: &[u8]) -> Vec<Frame> {
        let mut frames = Vec::new();
        if self.discarding {
            let Some(newline) = bytes.iter().position(|&b| b == b'\n') else {
                return frames;
            };
            bytes = &bytes[newline + 1..];
            self.discarding = false;
        }
        while let Some(newline) = bytes.iter().position(|&b| b == b'\n') {
            self.pending.extend_from_slice(&bytes[..newline]);
            bytes = &bytes[newline + 1..];
            if self.pending.last() == Some(&b'\r') {
                self.pending.pop();
            }
            self.split_oversized(&mut frames);
            self.emit_final(&mut frames);
        }
        self.pending.extend_from_slice(bytes);
        self.split_oversized(&mut frames);
        frames
    }

    /// Emit whatever is pending as the end of a line, e.g. when the process
    /// exits without a trailing newline.
    fn finish(&mut self) -> Option<Frame> {
        let mut frames = Vec::new();
        self.emit_final(&mut frames);
        frames.pop()
    }

    /// Abandon the line in progress because output around it was not read.
    /// When `mid_line`, bytes up to the next newline belong to that line and
    /// are dropped too. Returns a closing record when fragments of the line
    /// were already exported, so a consumer rejoining them sees it end.
    fn interrupt(&mut self, mid_line: bool) -> Option<Frame> {
        self.pending.clear();
        self.discarding = mid_line;
        self.next_chunk.take().map(|index| Frame {
            text: String::new(),
            chunk: Some((index, true)),
            truncated: true,
        })
    }

    fn split_oversized(&mut self, frames: &mut Vec<Frame>) {
        // Cheap pre-check: replacement can at most triple the byte count.
        while self.pending.len() * 3 > MAX_RECORD_BYTES
            && let Some(cut) = lossy_cut(&self.pending, MAX_RECORD_BYTES)
        {
            let rest = self.pending.split_off(cut);
            let head = std::mem::replace(&mut self.pending, rest);
            let index = self.next_chunk.unwrap_or(0);
            self.next_chunk = Some(index + 1);
            frames.push(Frame {
                text: String::from_utf8_lossy(&head).into_owned(),
                chunk: Some((index, false)),
                truncated: false,
            });
        }
    }

    fn emit_final(&mut self, frames: &mut Vec<Frame>) {
        let chunk = self.next_chunk.take().map(|index| (index, true));
        let line = std::mem::take(&mut self.pending);
        // A blank line carries nothing; the end of a split line always closes
        // its fragment sequence, even when the remainder is empty.
        if line.is_empty() && chunk.is_none() {
            return;
        }
        frames.push(Frame {
            text: String::from_utf8_lossy(&line).into_owned(),
            chunk,
            truncated: false,
        });
    }
}

/// Where to cut `bytes` so the head, once invalid UTF-8 is replaced with
/// U+FFFD, is at most `max` bytes. `None` when the whole input fits.
///
/// Cuts only between characters or invalid sequences, so a character is never
/// split. A trailing sequence that is merely incomplete (the rest has not been
/// read yet) is sized as a replacement, which only makes the cut earlier.
fn lossy_cut(bytes: &[u8], max: usize) -> Option<usize> {
    const REPLACEMENT_LEN: usize = '\u{FFFD}'.len_utf8();
    let mut out = 0;
    let mut pos = 0;
    for chunk in bytes.utf8_chunks() {
        for (offset, c) in chunk.valid().char_indices() {
            out += c.len_utf8();
            if out > max {
                return Some(pos + offset);
            }
        }
        pos += chunk.valid().len();
        if !chunk.invalid().is_empty() {
            out += REPLACEMENT_LEN;
            if out > max {
                return Some(pos);
            }
            pos += chunk.invalid().len();
        }
    }
    None
}

/// Forwards the main process's output into the log push channel.
struct Forwarder {
    sandbox_id: String,
    tx: mpsc::Sender<SandboxLogLine>,
    /// `None` until the first settings snapshot, then the setting's value.
    enabled: watch::Receiver<Option<bool>>,
    stdout: LineFramer,
    stderr: LineFramer,
}

impl Forwarder {
    fn enabled(&self) -> bool {
        self.enabled.borrow().unwrap_or(false)
    }

    async fn run(mut self, session: Arc<MainSession>) {
        // From the first event, so output evicted before we got here is
        // reported as lag on the first read rather than skipped.
        let mut cursor = session.subscribe_from_start();
        // Hold off reading until the setting is known; the retained window
        // keeps early output for us meanwhile.
        if self.enabled.wait_for(Option::is_some).await.is_err() {
            return;
        }
        loop {
            match cursor.recv().await {
                Ok(MainOutput::Stdout(bytes)) => {
                    if !self.forward(AGENT_STDOUT_TARGET, &bytes).await {
                        return;
                    }
                }
                Ok(MainOutput::Stderr(bytes)) => {
                    if !self.forward(AGENT_STDERR_TARGET, &bytes).await {
                        return;
                    }
                }
                Ok(MainOutput::Exit(_)) => {
                    let enabled = self.enabled();
                    for (target, framer) in [
                        (AGENT_STDOUT_TARGET, &mut self.stdout),
                        (AGENT_STDERR_TARGET, &mut self.stderr),
                    ] {
                        // Disabled: only close a line whose fragments were
                        // already exported.
                        let frame = if enabled {
                            framer.finish()
                        } else {
                            framer.interrupt(false)
                        };
                        if let Some(frame) = frame
                            && !send_yielding(&self.tx, record(&self.sandbox_id, target, frame))
                                .await
                        {
                            return;
                        }
                    }
                    return;
                }
                Err(lagged) => {
                    // The retained window moved past output we had not read.
                    // Whatever line each stream was in is incomplete: close
                    // it and resynchronise on the next newline.
                    // Closing records go out even while disabled, so a line
                    // whose fragments were exported always ends.
                    let closing = [
                        (AGENT_STDOUT_TARGET, self.stdout.interrupt(true)),
                        (AGENT_STDERR_TARGET, self.stderr.interrupt(true)),
                    ];
                    for (target, frame) in closing {
                        if let Some(frame) = frame
                            && !send_yielding(&self.tx, record(&self.sandbox_id, target, frame))
                                .await
                        {
                            return;
                        }
                    }
                    if self.enabled()
                        && !send_yielding(&self.tx, gap_line(&self.sandbox_id, lagged.skipped))
                            .await
                    {
                        return;
                    }
                }
            }
        }
    }

    /// Frame and forward one output read. Returns false once the push
    /// channel has closed.
    async fn forward(&mut self, target: &'static str, bytes: &[u8]) -> bool {
        let enabled = self.enabled();
        let framer = if target == AGENT_STDOUT_TARGET {
            &mut self.stdout
        } else {
            &mut self.stderr
        };
        if !enabled {
            // Export is off: abandon the line in progress. A line that was
            // already being split still gets its closing record.
            let mid_line = !bytes.ends_with(b"\n");
            if let Some(frame) = framer.interrupt(mid_line) {
                return send_yielding(&self.tx, record(&self.sandbox_id, target, frame)).await;
            }
            return !self.tx.is_closed();
        }
        for frame in framer.push(bytes) {
            if !send_yielding(&self.tx, record(&self.sandbox_id, target, frame)).await {
                return false;
            }
        }
        true
    }
}

/// Enqueue `line` once at least half of the push channel is free, leaving the
/// other half for the supervisor's own records. Returns false when the
/// channel has closed.
async fn send_yielding(tx: &mpsc::Sender<SandboxLogLine>, mut line: SandboxLogLine) -> bool {
    let reserve = tx.max_capacity() / 2;
    loop {
        if tx.is_closed() {
            return false;
        }
        if tx.capacity() > reserve {
            match tx.try_send(line) {
                Ok(()) => return true,
                Err(mpsc::error::TrySendError::Closed(_)) => return false,
                Err(mpsc::error::TrySendError::Full(unsent)) => line = unsent,
            }
        }
        tokio::time::sleep(BACKPRESSURE_POLL).await;
    }
}

fn record(sandbox_id: &str, target: &'static str, frame: Frame) -> SandboxLogLine {
    let mut fields = HashMap::new();
    if let Some((index, last)) = frame.chunk {
        fields.insert(CHUNK_INDEX_FIELD.to_string(), index.to_string());
        if last {
            fields.insert(CHUNK_FINAL_FIELD.to_string(), "true".to_string());
        }
    }
    if frame.truncated {
        fields.insert(CHUNK_TRUNCATED_FIELD.to_string(), "true".to_string());
    }
    SandboxLogLine {
        sandbox_id: sandbox_id.to_string(),
        event_time: openshell_core::time::timestamp_from_millis(openshell_core::time::now_ms())
            .ok(),
        level: "INFO".to_string(),
        target: target.to_string(),
        message: frame.text,
        source: "sandbox".to_string(),
        fields,
    }
}

fn gap_line(sandbox_id: &str, skipped_reads: u64) -> SandboxLogLine {
    let mut fields = HashMap::new();
    fields.insert("agent.skipped_reads".to_string(), skipped_reads.to_string());
    SandboxLogLine {
        sandbox_id: sandbox_id.to_string(),
        event_time: openshell_core::time::timestamp_from_millis(openshell_core::time::now_ms())
            .ok(),
        level: "WARN".to_string(),
        target: TELEMETRY_GAP_TARGET.to_string(),
        message: format!(
            "telemetry gap: {skipped_reads} agent output read(s) skipped before export"
        ),
        source: "sandbox".to_string(),
        fields,
    }
}

/// Spawn the agent output forwarder for `session`.
///
/// It runs until the main process exits or the push channel closes. It starts
/// reading once `enabled` holds the first settings snapshot, and forwards only
/// while that value is true.
#[must_use]
pub fn spawn_agent_output_forwarder(
    session: Arc<MainSession>,
    sandbox_id: String,
    tx: mpsc::Sender<SandboxLogLine>,
    enabled: watch::Receiver<Option<bool>>,
) -> tokio::task::JoinHandle<()> {
    let forwarder = Forwarder {
        sandbox_id,
        tx,
        enabled,
        stdout: LineFramer::default(),
        stderr: LineFramer::default(),
    };
    tokio::spawn(forwarder.run(session))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn whole(text: &str) -> Frame {
        Frame {
            text: text.to_string(),
            chunk: None,
            truncated: false,
        }
    }

    #[test]
    fn an_interrupted_split_line_is_closed_and_its_tail_dropped() {
        let mut splitter = LineFramer::default();
        let head = splitter.push("z".repeat(MAX_RECORD_BYTES + 5).as_bytes());
        assert_eq!(head.len(), 1);
        let closing = splitter.interrupt(true).expect("closing record");
        assert_eq!(closing.chunk, Some((1, true)));
        assert!(closing.truncated && closing.text.is_empty());
        // The rest of the interrupted line is dropped, the next line is whole.
        assert_eq!(
            splitter.push(b"tail of lost line\nnext\n"),
            vec![whole("next")]
        );
    }

    #[test]
    fn an_interrupt_at_a_line_boundary_keeps_the_next_line() {
        let mut splitter = LineFramer::default();
        assert_eq!(splitter.interrupt(false), None);
        assert_eq!(splitter.push(b"intact\n"), vec![whole("intact")]);
    }

    #[test]
    fn splits_on_newlines_and_holds_partial_lines() {
        let mut splitter = LineFramer::default();
        assert_eq!(
            splitter.push(b"{\"type\":\"a\"}\n{\"ty"),
            vec![whole("{\"type\":\"a\"}")]
        );
        assert_eq!(
            splitter.push(b"pe\":\"b\"}\r\n"),
            vec![whole("{\"type\":\"b\"}")]
        );
        assert_eq!(splitter.finish(), None);
    }

    #[test]
    fn skips_blank_lines_and_flushes_an_unterminated_tail() {
        let mut splitter = LineFramer::default();
        assert_eq!(splitter.push(b"\n\r\nlast"), vec![]);
        assert_eq!(splitter.finish(), Some(whole("last")));
    }

    #[test]
    fn fragments_long_lines_without_losing_bytes() {
        let mut splitter = LineFramer::default();
        let line = "x".repeat(MAX_RECORD_BYTES * 2 + 10);
        let mut frames = splitter.push(line.as_bytes());
        frames.extend(splitter.push(b"\n"));
        let chunks: Vec<_> = frames.iter().map(|f| f.chunk).collect();
        assert_eq!(
            chunks,
            vec![Some((0, false)), Some((1, false)), Some((2, true))]
        );
        let rejoined: String = frames.into_iter().map(|f| f.text).collect();
        assert_eq!(rejoined, line);
    }

    #[test]
    fn fragment_cuts_land_on_character_boundaries() {
        let mut splitter = LineFramer::default();
        // A 3-byte character straddling the record boundary.
        let mut line = "a".repeat(MAX_RECORD_BYTES - 1);
        line.push('€');
        line.push_str("tail");
        let mut frames = splitter.push(line.as_bytes());
        frames.extend(splitter.finish());
        assert_eq!(frames[0].text.len(), MAX_RECORD_BYTES - 1);
        assert!(frames[1].text.starts_with('€'));
        let rejoined: String = frames.into_iter().map(|f| f.text).collect();
        assert_eq!(rejoined, line);
    }

    #[test]
    fn invalid_utf8_stays_within_the_record_limit_after_replacement() {
        let mut splitter = LineFramer::default();
        let mut frames = splitter.push(&vec![0xFF; MAX_RECORD_BYTES]);
        frames.extend(splitter.push(b"\n"));
        assert!(frames.len() >= 3, "replacement triples the size");
        for frame in &frames {
            assert!(frame.text.len() <= MAX_RECORD_BYTES);
        }
        let replaced: usize = frames.iter().map(|f| f.text.chars().count()).sum();
        assert_eq!(replaced, MAX_RECORD_BYTES, "one U+FFFD per invalid byte");
    }

    #[test]
    fn a_crlf_line_of_exactly_the_record_limit_is_one_record() {
        let mut splitter = LineFramer::default();
        let mut line = "q".repeat(MAX_RECORD_BYTES).into_bytes();
        line.extend_from_slice(b"\r\n");
        assert_eq!(
            splitter.push(&line),
            vec![whole(&"q".repeat(MAX_RECORD_BYTES))]
        );
    }

    #[test]
    fn a_line_ending_exactly_at_the_record_limit_closes_its_fragments() {
        let mut splitter = LineFramer::default();
        let line = "y".repeat(MAX_RECORD_BYTES + 1);
        let mut frames = splitter.push(line.as_bytes());
        frames.extend(splitter.push(b"\n"));
        assert_eq!(frames.last().map(|f| f.chunk), Some(Some((1, true))));
    }

    async fn collect(rx: &mut mpsc::Receiver<SandboxLogLine>, n: usize) -> Vec<SandboxLogLine> {
        let mut lines = Vec::new();
        for _ in 0..n {
            let line = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .expect("forwarded line")
                .expect("channel open");
            lines.push(line);
        }
        lines
    }

    #[tokio::test]
    async fn forwards_stdout_and_stderr_lines_under_agent_targets() {
        let session = MainSession::inert();
        let (tx, mut rx) = mpsc::channel(16);
        let (_enabled, rx_enabled) = watch::channel(Some(true));
        let task =
            spawn_agent_output_forwarder(session.clone(), "sb-1".to_string(), tx, rx_enabled);

        session.publish_for_test(MainOutput::Stdout(Bytes::from_static(
            b"{\"type\":\"result\"}\n",
        )));
        session.publish_for_test(MainOutput::Stderr(Bytes::from_static(b"warming up")));
        session.finish(0, false).await;

        let lines = collect(&mut rx, 2).await;
        task.await.expect("forwarder exits after main process");
        assert_eq!(lines[0].target, AGENT_STDOUT_TARGET);
        assert_eq!(lines[0].message, "{\"type\":\"result\"}");
        assert_eq!(lines[0].sandbox_id, "sb-1");
        assert_eq!(lines[1].target, AGENT_STDERR_TARGET);
        assert_eq!(lines[1].message, "warming up");
    }

    #[tokio::test]
    async fn forwards_nothing_while_disabled() {
        let session = MainSession::inert();
        let (tx, mut rx) = mpsc::channel(16);
        let (enabled, rx_enabled) = watch::channel(Some(false));
        let task =
            spawn_agent_output_forwarder(session.clone(), "sb-1".to_string(), tx, rx_enabled);

        session.publish_for_test(MainOutput::Stdout(Bytes::from_static(b"secret\nhalf a li")));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        enabled.send_replace(Some(true));
        session.publish_for_test(MainOutput::Stdout(Bytes::from_static(b"ne\nvisible\n")));
        session.finish(0, false).await;

        let lines = collect(&mut rx, 1).await;
        task.await.expect("forwarder exits");
        assert_eq!(lines[0].message, "visible");
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn leaves_half_the_channel_for_supervisor_records() {
        let session = MainSession::inert();
        let (tx, mut rx) = mpsc::channel(4);
        let (_enabled, rx_enabled) = watch::channel(Some(true));
        let _task = spawn_agent_output_forwarder(
            session.clone(),
            "sb-1".to_string(),
            tx.clone(),
            rx_enabled,
        );

        session.publish_for_test(MainOutput::Stdout(Bytes::from_static(b"1\n2\n3\n4\n")));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Two lines fill the agent's half; the rest wait for space.
        assert_eq!(tx.capacity(), 2);
        let lines = collect(&mut rx, 4).await;
        let messages: Vec<_> = lines.iter().map(|l| l.message.as_str()).collect();
        assert_eq!(messages, vec!["1", "2", "3", "4"]);
    }

    #[tokio::test]
    async fn exports_output_written_before_the_first_settings_snapshot() {
        let session = MainSession::inert();
        let (tx, mut rx) = mpsc::channel(16);
        let (enabled, rx_enabled) = watch::channel(None);
        let task =
            spawn_agent_output_forwarder(session.clone(), "sb-1".to_string(), tx, rx_enabled);

        session.publish_for_test(MainOutput::Stdout(Bytes::from_static(
            b"{\"type\":\"system\"}\n",
        )));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            rx.try_recv().is_err(),
            "nothing is read before the setting is known"
        );
        enabled.send_replace(Some(true));
        session.finish(0, false).await;

        let lines = collect(&mut rx, 1).await;
        task.await.expect("forwarder exits");
        assert_eq!(lines[0].message, "{\"type\":\"system\"}");
    }

    #[tokio::test]
    async fn output_evicted_before_the_forwarder_started_is_reported_as_a_gap() {
        let session = MainSession::inert();
        // More than the 1 MiB retained window, before the forwarder exists.
        let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
        for _ in 0..20 {
            session.publish_for_test(MainOutput::Stdout(chunk.clone()));
        }
        session.publish_for_test(MainOutput::Stdout(Bytes::from_static(b"\nafter\n")));
        let (tx, mut rx) = mpsc::channel(64);
        let (_enabled, rx_enabled) = watch::channel(Some(true));
        let task =
            spawn_agent_output_forwarder(session.clone(), "sb-1".to_string(), tx, rx_enabled);
        session.finish(0, false).await;
        task.await.expect("forwarder exits");

        let mut lines = Vec::new();
        while let Ok(line) = rx.try_recv() {
            lines.push(line);
        }
        assert_eq!(
            lines[0].target, TELEMETRY_GAP_TARGET,
            "eviction is reported first"
        );
        assert_eq!(lines.last().map(|l| l.message.as_str()), Some("after"));
    }

    #[tokio::test]
    async fn a_split_line_is_closed_even_when_export_is_switched_off() {
        let session = MainSession::inert();
        let (tx, mut rx) = mpsc::channel(16);
        let (enabled, rx_enabled) = watch::channel(Some(true));
        let task =
            spawn_agent_output_forwarder(session.clone(), "sb-1".to_string(), tx, rx_enabled);

        session.publish_for_test(MainOutput::Stdout(Bytes::from(vec![
            b'k';
            MAX_RECORD_BYTES + 1
        ])));
        let first = collect(&mut rx, 1).await;
        assert_eq!(
            first[0].fields.get(CHUNK_INDEX_FIELD).map(String::as_str),
            Some("0")
        );
        enabled.send_replace(Some(false));
        session.finish(0, false).await;
        task.await.expect("forwarder exits");

        let closing = rx.try_recv().expect("closing record");
        assert_eq!(
            closing.fields.get(CHUNK_FINAL_FIELD).map(String::as_str),
            Some("true")
        );
        assert_eq!(
            closing
                .fields
                .get(CHUNK_TRUNCATED_FIELD)
                .map(String::as_str),
            Some("true")
        );
        assert!(closing.message.is_empty());
    }
}
