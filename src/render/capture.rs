//! Rendering a live capture run.

use std::fmt::Write as _;
use std::time::Duration;

use std::path::Path;

use crate::capture::{
    CaptureSettings, CaptureSummary, DriverStats, FileSummary, LinkType, NetworkInterface,
    StopReason, TimeSpan,
};
use crate::render::sanitize_display_text;

/// Renders the banner printed before a capture starts.
pub fn capture_header(
    interface: &NetworkInterface,
    settings: CaptureSettings,
    link_type: &LinkType,
    flow_mode: bool,
) -> String {
    let mut out = String::new();

    let _ = writeln!(
        out,
        "NetSentry {} \u{2014} live capture\n",
        env!("CARGO_PKG_VERSION")
    );

    let name = sanitize_display_text(&interface.name);
    let described = match interface.description.as_deref().map(sanitize_display_text) {
        Some(description) => format!("{name}  ({description})"),
        None => name,
    };
    banner(&mut out, "interface", &described);

    let link = match link_type.description.as_deref().map(sanitize_display_text) {
        Some(description) => format!("{} ({})", link_type.name, description),
        None => link_type.name.clone(),
    };
    banner(&mut out, "link type", &link);
    banner(
        &mut out,
        "snaplen",
        &format!("{} bytes", settings.snaplen()),
    );
    banner(
        &mut out,
        "promiscuous",
        if settings.promiscuous() { "on" } else { "off" },
    );
    banner(
        &mut out,
        "stop after",
        &match settings.count() {
            Some(1) => "1 packet".to_owned(),
            Some(count) => format!("{count} packets"),
            None => "Ctrl+C".to_owned(),
        },
    );
    banner(&mut out, "clock", "UTC");
    banner(
        &mut out,
        "payload",
        "not captured for display \u{2014} metadata only",
    );
    if flow_mode {
        // Flow mode prints nothing per packet, so say up front that the
        // silence is intentional and when the output will arrive.
        banner(
            &mut out,
            "output",
            "conversations, summarised when the capture ends",
        );
    }

    out.push('\n');
    out
}

/// Renders the banner printed before a capture file is analysed.
pub fn file_header(
    path: &Path,
    link_type: &LinkType,
    limit: Option<u64>,
    flow_mode: bool,
) -> String {
    let mut out = String::new();

    let _ = writeln!(
        out,
        "NetSentry {} \u{2014} offline analysis\n",
        env!("CARGO_PKG_VERSION")
    );

    banner(
        &mut out,
        "file",
        &sanitize_display_text(&path.display().to_string()),
    );
    banner(&mut out, "format", "pcap/pcapng (read-only)");

    let link = match link_type.description.as_deref().map(sanitize_display_text) {
        Some(description) => format!("{} ({})", link_type.name, description),
        None => link_type.name.clone(),
    };
    banner(&mut out, "link type", &link);
    banner(
        &mut out,
        "read",
        &match limit {
            Some(1) => "first packet only".to_owned(),
            Some(count) => format!("first {count} packets"),
            None => "whole file".to_owned(),
        },
    );
    banner(&mut out, "clock", "UTC");
    if flow_mode {
        banner(&mut out, "output", "conversations, not individual packets");
    }

    out.push('\n');
    out
}

/// Renders the summary printed once a capture file has been analysed.
///
/// The two kinds of time are labelled apart on purpose. `capture span` is when
/// the traffic happened, taken from the packets; `read in` is how long
/// NetSentry spent reading the file. Reporting the second as though it were the
/// first would be a lie about the evidence.
pub fn file_summary(summary: &FileSummary) -> String {
    let mut out = String::new();
    out.push('\n');

    let _ = writeln!(
        out,
        "[*] Analysis finished ({}).\n",
        stop_reason_phrase(summary.stop_reason)
    );

    let tally = summary.tally;
    summary_row(&mut out, "packets analysed", &tally.packets().to_string());
    summary_row(
        &mut out,
        "captured bytes",
        &tally.captured_bytes().to_string(),
    );
    summary_row(&mut out, "wire bytes", &tally.wire_bytes().to_string());

    out.push('\n');
    render_time_span(&mut out, summary.time_span);
    summary_row(
        &mut out,
        "read in",
        &format!("{} (wall clock)", format_duration(summary.processing_time)),
    );

    if let Some(error) = &summary.read_error {
        out.push('\n');
        let _ = writeln!(out, "    the rest of the file could not be read:");
        let _ = writeln!(out, "      {error}");
        let mut source = std::error::Error::source(error);
        while let Some(cause) = source {
            let _ = writeln!(out, "      cause: {cause}");
            source = cause.source();
        }
    }

    out
}

/// Writes the three rows describing when a capture's packets happened.
fn render_time_span(out: &mut String, span: TimeSpan) {
    match (span.first(), span.last()) {
        (Some(first), Some(last)) => {
            summary_row(out, "first packet", &first.format_datetime());
            summary_row(out, "last packet", &last.format_datetime());
            match span.duration() {
                Some(duration) => summary_row(out, "capture span", &format_duration(duration)),
                None => summary_row(
                    out,
                    "capture span",
                    "unknown \u{2014} the file's timestamps are not in order",
                ),
            }
        }
        _ => {
            summary_row(out, "first packet", "(none)");
            summary_row(out, "last packet", "(none)");
            summary_row(out, "capture span", "(no packets)");
        }
    }
}

/// Renders the warning shown before packets are written to disk.
///
/// Printed every time, without a way to silence it. Writing a capture file is
/// the one thing NetSentry does that creates a lasting copy of other people's
/// traffic, and the person running it should be reminded what that means.
pub fn write_warning(path: &Path) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[!] Writing full packets, payload included, to {}",
        sanitize_display_text(&path.display().to_string())
    );
    let _ = writeln!(
        out,
        "    This file will contain whatever the traffic contained: credentials and"
    );
    let _ = writeln!(
        out,
        "    session tokens from plaintext protocols, hostnames, and your network's"
    );
    let _ = writeln!(
        out,
        "    internal layout. Store and share it accordingly.\n"
    );
    out
}

/// Writes one `[*] label : value` banner line.
fn banner(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "[*] {label:<12}: {value}");
}

/// Renders the summary printed once a capture run is over.
pub fn capture_summary(summary: &CaptureSummary) -> String {
    let mut out = String::new();
    out.push('\n');

    let _ = writeln!(
        out,
        "[*] Capture finished ({}).\n",
        stop_reason_phrase(summary.stop_reason)
    );

    let tally = summary.tally;
    summary_row(&mut out, "packets captured", &tally.packets().to_string());
    summary_row(
        &mut out,
        "captured bytes",
        &tally.captured_bytes().to_string(),
    );
    summary_row(&mut out, "wire bytes", &tally.wire_bytes().to_string());
    summary_row(&mut out, "elapsed", &format_duration(summary.elapsed));
    if let Some(started_at) = summary.started_at {
        summary_row(&mut out, "started at", &started_at.format_datetime());
    }

    out.push('\n');
    match &summary.driver_stats {
        Ok(stats) => {
            let _ = writeln!(out, "    driver statistics");
            summary_row(&mut out, "  received", &stats.received.to_string());
            summary_row(&mut out, "  dropped (buffer)", &stats.dropped.to_string());
            summary_row(
                &mut out,
                "  dropped (interface)",
                &stats.if_dropped.to_string(),
            );
            out.push_str(interface_drop_caveat(stats));
        }
        Err(error) => {
            let _ = writeln!(out, "    driver statistics: unavailable");
            let _ = writeln!(out, "      reason: {error}");
            let mut source = std::error::Error::source(error);
            while let Some(cause) = source {
                let _ = writeln!(out, "      cause:  {cause}");
                source = cause.source();
            }
        }
    }

    out
}

/// The caveat printed under the driver's interface-drop counter.
///
/// libpcap sets this counter to zero on platforms that do not support it and
/// offers no way to tell that apart from "nothing was dropped", so a zero is
/// annotated rather than presented as a fact.
fn interface_drop_caveat(stats: &DriverStats) -> &'static str {
    if stats.if_dropped == 0 {
        "\n    Note: not every driver reports interface-level drops. A zero above\n\
         \x20         can mean \"none\" or \"not reported\".\n"
    } else {
        ""
    }
}

/// Writes one `label : value` summary line.
fn summary_row(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "    {label:<21}: {value}");
}

/// Explains why a capture stopped.
fn stop_reason_phrase(reason: StopReason) -> &'static str {
    match reason {
        StopReason::CountReached => "packet count reached",
        StopReason::Interrupted => "interrupted by user",
        StopReason::SourceEnded => "capture source ended",
        StopReason::OutputClosed => "output closed",
        StopReason::ReadFailed => "could not read any further",
    }
}

/// Formats a duration for humans, keeping millisecond resolution.
fn format_duration(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    let millis = elapsed.subsec_millis();

    if seconds < 60 {
        format!("{seconds}.{millis:03}s")
    } else {
        format!("{}m {:02}.{:03}s", seconds / 60, seconds % 60, millis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetSentryError;
    use crate::capture::{CaptureTally, LinkStatus, PacketTimestamp};

    fn settings() -> CaptureSettings {
        CaptureSettings::new(65_535, true, Some(20)).unwrap_or_default()
    }

    fn link_type() -> LinkType {
        LinkType {
            code: 1,
            name: "EN10MB".into(),
            description: Some("Ethernet".into()),
        }
    }

    fn summary(
        stop_reason: StopReason,
        stats: Result<DriverStats, NetSentryError>,
    ) -> CaptureSummary {
        let mut tally = CaptureTally::default();
        tally.record(64, 1514);
        tally.record(74, 74);

        CaptureSummary {
            tally,
            elapsed: Duration::from_millis(6412),
            started_at: Some(PacketTimestamp::from_parts(1_790_005_351, 104_881)),
            stop_reason,
            driver_stats: stats,
        }
    }

    #[test]
    fn capture_header_states_every_capture_parameter() {
        let interface = NetworkInterface {
            index: 1,
            name: "eth0".into(),
            description: Some("Intel Wi-Fi 6".into()),
            status: LinkStatus::Running,
            attributes: vec![],
            addresses: vec![],
        };
        let header = capture_header(&interface, settings(), &link_type(), false);

        assert!(
            header.contains("interface   : eth0  (Intel Wi-Fi 6)"),
            "{header}"
        );
        assert!(header.contains("link type   : EN10MB (Ethernet)"));
        assert!(header.contains("snaplen     : 65535 bytes"));
        assert!(header.contains("promiscuous : on"));
        assert!(header.contains("stop after  : 20 packets"));
        assert!(header.contains("clock       : UTC"));
        assert!(header.contains("metadata only"));
    }

    #[test]
    fn flow_mode_warns_that_packets_will_not_be_printed() {
        let interface = NetworkInterface {
            index: 1,
            name: "eth0".into(),
            description: None,
            status: LinkStatus::Running,
            attributes: vec![],
            addresses: vec![],
        };
        let header = capture_header(&interface, settings(), &link_type(), true);
        assert!(header.contains("output      : conversations"), "{header}");

        let plain = capture_header(&interface, settings(), &link_type(), false);
        assert!(!plain.contains("output      :"), "{plain}");
    }

    #[test]
    fn capture_header_says_ctrl_c_when_there_is_no_limit() {
        let interface = NetworkInterface {
            index: 1,
            name: "eth0".into(),
            description: None,
            status: LinkStatus::Running,
            attributes: vec![],
            addresses: vec![],
        };
        let unlimited = CaptureSettings::new(1500, false, None).unwrap_or_default();
        let header = capture_header(&interface, unlimited, &link_type(), false);

        assert!(header.contains("stop after  : Ctrl+C"), "{header}");
        assert!(header.contains("promiscuous : off"));
        // No description means no empty parentheses.
        assert!(header.contains("interface   : eth0\n"), "{header}");
    }

    #[test]
    fn capture_summary_reports_totals_and_driver_counters() {
        let rendered = capture_summary(&summary(
            StopReason::CountReached,
            Ok(DriverStats {
                received: 12,
                dropped: 3,
                if_dropped: 1,
            }),
        ));

        assert!(rendered.contains("Capture finished (packet count reached)"));
        assert!(rendered.contains("packets captured     : 2"));
        assert!(rendered.contains("captured bytes       : 138"));
        assert!(rendered.contains("wire bytes           : 1588"));
        assert!(rendered.contains("elapsed              : 6.412s"));
        assert!(rendered.contains("started at           : 2026-09-21 15:42:31.104881 UTC"));
        assert!(rendered.contains("received           : 12"));
        assert!(rendered.contains("dropped (buffer)   : 3"));
        assert!(rendered.contains("dropped (interface): 1"));
        // A non-zero count needs no caveat.
        assert!(!rendered.contains("not reported"));
    }

    #[test]
    fn a_zero_interface_drop_count_is_qualified_rather_than_asserted() {
        let rendered = capture_summary(&summary(
            StopReason::Interrupted,
            Ok(DriverStats {
                received: 2,
                dropped: 0,
                if_dropped: 0,
            }),
        ));

        assert!(rendered.contains("Capture finished (interrupted by user)"));
        assert!(rendered.contains("not every driver reports interface-level drops"));
    }

    #[test]
    fn unavailable_statistics_do_not_cost_the_user_the_summary() {
        let rendered = capture_summary(&summary(
            StopReason::Interrupted,
            Err(NetSentryError::CaptureStatistics {
                source: pcap::Error::PcapError("statistics not supported".into()),
            }),
        ));

        // The totals we computed ourselves are still there ...
        assert!(rendered.contains("packets captured     : 2"));
        // ... and the missing part is named, not faked.
        assert!(rendered.contains("driver statistics: unavailable"));
        assert!(rendered.contains("statistics not supported"));
        assert!(!rendered.contains("received           :"));
    }

    #[test]
    fn every_stop_reason_has_wording() {
        for reason in [
            StopReason::CountReached,
            StopReason::Interrupted,
            StopReason::SourceEnded,
            StopReason::OutputClosed,
        ] {
            assert!(!stop_reason_phrase(reason).is_empty());
        }
    }

    #[test]
    fn durations_stay_readable_past_a_minute() {
        assert_eq!(format_duration(Duration::from_millis(0)), "0.000s");
        assert_eq!(format_duration(Duration::from_millis(7)), "0.007s");
        assert_eq!(format_duration(Duration::from_millis(6412)), "6.412s");
        assert_eq!(format_duration(Duration::from_millis(59_999)), "59.999s");
        assert_eq!(format_duration(Duration::from_millis(60_000)), "1m 00.000s");
        assert_eq!(format_duration(Duration::from_millis(63_120)), "1m 03.120s");
        assert_eq!(format_duration(Duration::from_secs(3671)), "61m 11.000s");
    }
}
