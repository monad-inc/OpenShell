// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared identifiers for exporting the sandbox agent's own output.
//!
//! When [`crate::settings::AGENT_OUTPUT_EXPORT_ENABLED_KEY`] is on, the
//! supervisor forwards each line the sandbox's main process writes to stdout
//! or stderr as a pushed log line under one of the targets below. The gateway
//! recognises those targets and exports the line with
//! `log.source = "agent"`, so a downstream consumer can tell the agent's own
//! words apart from the supervisor's records.
//!
//! The line is never parsed. Whatever the agent prints, a plain-text log or a
//! harness's JSON event stream, is exported byte for byte as the record body.

/// `log.source` of an exported agent output line.
pub const AGENT_LOG_SOURCE: &str = "agent";

/// Pushed-line target for the agent's stdout.
pub const AGENT_STDOUT_TARGET: &str = "openshell.agent.stdout";

/// Pushed-line target for the agent's stderr.
pub const AGENT_STDERR_TARGET: &str = "openshell.agent.stderr";

/// Field naming the 0-based position of a fragment within a line that was too
/// long for one record. Absent on a line exported whole.
pub const CHUNK_INDEX_FIELD: &str = "agent.chunk.index";

/// Field set to `"true"` on the last fragment of a split line.
pub const CHUNK_FINAL_FIELD: &str = "agent.chunk.final";

/// Field set to `"true"` on an empty final fragment that closes a split line
/// whose remaining bytes were never read (the supervisor fell behind, or
/// export was switched off mid-line).
pub const CHUNK_TRUNCATED_FIELD: &str = "agent.chunk.truncated";

/// Whether a pushed line's target marks it as agent output.
///
/// Only the supervisor sets a pushed line's target, so the agent cannot claim
/// a different source by printing one.
#[must_use]
pub fn is_agent_output_target(target: &str) -> bool {
    target == AGENT_STDOUT_TARGET || target == AGENT_STDERR_TARGET
}

/// Render agent output for display in a terminal or UI.
///
/// Agent text is whatever the sandbox's process printed, including text it
/// read from pages and tools. Control characters (C0, DEL, C1) could drive the
/// operator's terminal, and invisible format characters (bidi overrides,
/// zero-width characters, line and paragraph separators) could make it read
/// differently from what it is, so both are shown as escapes like `\u{1b}`.
/// Printable text, JSON included, is untouched. Display only: the exported
/// record keeps the original bytes.
#[must_use]
pub fn escape_for_display(text: &str) -> std::borrow::Cow<'_, str> {
    fn hidden(c: char) -> bool {
        c.is_control()
            || matches!(
                c,
                '\u{200B}'..='\u{200F}'
                    | '\u{2028}'..='\u{202E}'
                    | '\u{2060}'..='\u{2069}'
                    | '\u{FEFF}'
            )
    }
    if !text.chars().any(hidden) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        if hidden(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_only_the_agent_targets() {
        assert!(is_agent_output_target(AGENT_STDOUT_TARGET));
        assert!(is_agent_output_target(AGENT_STDERR_TARGET));
        assert!(!is_agent_output_target("openshell.agent"));
        assert!(!is_agent_output_target("openshell.agent.stdout.extra"));
        assert!(!is_agent_output_target("telemetry_gap"));
    }

    #[test]
    fn display_escaping_neutralises_controls_and_invisible_formatting() {
        assert_eq!(escape_for_display("{\"a\":1}\ttab"), "{\"a\":1}\\u{9}tab");
        assert_eq!(
            escape_for_display("x\u{1b}]52;c;aGk=\u{7}"),
            "x\\u{1b}]52;c;aGk=\\u{7}"
        );
        assert_eq!(escape_for_display("\u{9b}31m"), "\\u{9b}31m");
        assert_eq!(escape_for_display("abc\u{202e}fed"), "abc\\u{202e}fed");
        assert_eq!(
            escape_for_display("a\u{200b}b\u{2028}c"),
            "a\\u{200b}b\\u{2028}c"
        );
        assert!(matches!(
            escape_for_display("plain € text"),
            std::borrow::Cow::Borrowed(_)
        ));
    }
}
