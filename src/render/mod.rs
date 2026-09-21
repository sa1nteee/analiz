//! Terminal rendering.
//!
//! Every function here is pure: data in, [`String`] out. Nothing touches the
//! network, the filesystem or stdout. That makes the whole presentation layer
//! unit testable, and means the same data can later be rendered as JSON or
//! handed to a UI without rewriting anything.
//!
//! [`interfaces`] renders `netsentry list`, [`capture`] renders a capture run,
//! and failures are rendered by [`error_report`].

pub mod capture;
pub mod interfaces;

pub use capture::{capture_header, capture_summary, packet_line};
pub use interfaces::{format_address, interface_list, netmask_to_prefix_len};

use std::fmt::Write as _;

use crate::error::NetSentryError;

/// Renders a failure as *what happened*, *why*, and *what to do about it*.
///
/// A security tool is only useful if the person running it can tell the
/// difference between "there is nothing to see" and "I could not look", so
/// every failure is reported with its full source chain rather than a single
/// summarised line.
pub fn error_report(error: &NetSentryError) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "error: {error}");

    // Walk the source chain so the driver's own wording is never swallowed.
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        let _ = writeln!(out, "cause: {cause}");
        source = cause.source();
    }

    for (position, hint) in error.hints().iter().enumerate() {
        let label = if position == 0 { "hint: " } else { "      " };
        let _ = writeln!(out, "{label} {hint}");
    }

    out
}

/// Makes driver-supplied text safe to print to a terminal.
///
/// Interface names and descriptions come from the operating system, and on
/// Windows ultimately from the registry. They are not trusted input: a control
/// character or ANSI escape sequence in a description would let whatever wrote
/// that string move the cursor, recolour, or erase parts of our output. For a
/// tool whose job is reporting facts truthfully, that is an output-integrity
/// problem, so control characters are replaced with U+FFFD.
///
/// This lives in the rendering layer, not in the capture layer, because the
/// capture layer has to keep the driver's exact bytes: the interface name is
/// what gets handed back to the driver to open a capture.
///
/// The text is never truncated: hiding part of an interface name would be worse
/// than printing an ugly one.
fn sanitize_display_text(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_report_states_what_why_and_next_step() {
        let report = error_report(&NetSentryError::InterfaceEnumeration {
            source: pcap::Error::PcapError("socket: Operation not permitted".into()),
        });

        assert!(report.starts_with("error: could not enumerate network interfaces\n"));
        assert!(report.contains("cause: "));
        assert!(report.contains("Operation not permitted"));
        assert!(report.contains("hint: "));
        assert!(report.ends_with('\n'));
    }

    #[test]
    fn error_report_indents_continuation_hints() {
        let report = error_report(&NetSentryError::NoInterfacesFound);
        let hint_lines: Vec<&str> = report
            .lines()
            .filter(|line| line.starts_with("hint: ") || line.starts_with("      "))
            .collect();

        assert_eq!(
            hint_lines.len(),
            NetSentryError::NoInterfacesFound.hints().len()
        );
        assert!(hint_lines[0].starts_with("hint: "));
        for line in &hint_lines[1..] {
            assert!(line.starts_with("      "), "unaligned hint: {line:?}");
        }
    }
}
