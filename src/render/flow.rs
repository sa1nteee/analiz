//! Rendering the flow table.
//!
//! As everywhere in this layer: data in, [`String`] out. The table arrives
//! already sorted by [`FlowTable::flows_sorted`], so nothing here decides
//! ordering — reproducible output is a property of the tracker, not of the
//! printer.

use std::fmt::Write as _;
use std::time::Duration;

use crate::flow::{Flow, FlowTable, UntrackedCounts};

/// The arrow marking a bidirectional conversation.
const BOTH_WAYS: &str = "\u{2194}";

/// The arrow marking one direction.
const ONE_WAY: &str = "\u{2192}";

/// Renders the whole flow section: a heading, every flow, and a summary.
pub fn flow_table(table: &FlowTable) -> String {
    let mut out = String::new();
    out.push('\n');

    let flows = table.flows_sorted();
    let _ = writeln!(out, "[*] Flows: {}", flows.len());
    if !flows.is_empty() {
        // A and B are not "client" and "server": they are the two endpoints in
        // a fixed order, so that the same conversation is identified the same
        // way no matter which packet arrived first. Saying so beats letting the
        // reader guess.
        let _ = writeln!(
            out,
            "    A is the endpoint on the left of {BOTH_WAYS}, B the one on the right."
        );
        let _ = writeln!(
            out,
            "    The order is fixed by address and port, not by who spoke first."
        );
    }
    out.push('\n');

    if flows.is_empty() {
        let _ = writeln!(out, "    (no TCP or UDP conversations were seen)\n");
    }

    for (position, flow) in flows.iter().enumerate() {
        if position > 0 {
            out.push('\n');
        }
        out.push_str(&flow_entry(flow));
    }

    out.push_str(&untracked_note(table.untracked()));
    if table.is_full() {
        let _ = writeln!(
            out,
            "\n    The flow limit of {} was reached. Raise it with --max-flows.",
            table.max_flows()
        );
    }
    out
}

/// Renders one flow as three lines.
///
/// Three lines rather than a table row because an IPv6 conversation is over 90
/// characters of addresses alone, and a column layout wide enough for that
/// wastes most of its width on the IPv4 case. Wrapping the numbers underneath
/// the endpoints keeps both readable without measuring the terminal.
pub fn flow_entry(flow: &Flow) -> String {
    let mut out = String::new();

    let _ = writeln!(
        out,
        "  {} {} {BOTH_WAYS} {}",
        flow.key.protocol.label(),
        flow.key.a,
        flow.key.b
    );

    let _ = writeln!(
        out,
        "      packets {:<7} bytes {:<10} duration {}",
        flow.total_packets(),
        format_bytes(flow.total_wire_bytes()),
        format_duration(flow.duration())
    );

    let _ = writeln!(
        out,
        "      A{ONE_WAY}B {} / {:<12} B{ONE_WAY}A {} / {}",
        flow.a_to_b.packets,
        format_bytes(flow.a_to_b.wire_bytes),
        flow.b_to_a.packets,
        format_bytes(flow.b_to_a.wire_bytes)
    );

    // Only worth a line when the capture actually truncated something.
    if flow.total_captured_bytes() != flow.total_wire_bytes() {
        let _ = writeln!(
            out,
            "      captured {} of {} on the wire (snapshot length truncated these packets)",
            format_bytes(flow.total_captured_bytes()),
            format_bytes(flow.total_wire_bytes())
        );
    }

    if let Some(facts) = flow.tcp {
        let _ = writeln!(
            out,
            "      TCP A{ONE_WAY}B [{}] syn {} fin {} rst {}   B{ONE_WAY}A [{}] syn {} fin {} rst {}",
            facts.a_to_b.flags_seen,
            facts.a_to_b.syn,
            facts.a_to_b.fin,
            facts.a_to_b.rst,
            facts.b_to_a.flags_seen,
            facts.b_to_a.syn,
            facts.b_to_a.fin,
            facts.b_to_a.rst
        );
    }

    out
}

/// Renders the note about packets that formed no flow.
fn untracked_note(counts: UntrackedCounts) -> String {
    if !counts.any() {
        return String::new();
    }

    let mut reasons = Vec::new();
    let mut add = |count: u64, label: &str| {
        if count > 0 {
            reasons.push(format!("{count} {label}"));
        }
    };
    add(counts.arp, "ARP");
    add(counts.icmp, "ICMP");
    add(counts.later_fragments, "later fragments");
    add(counts.other_protocol, "other IP protocols");
    add(counts.undecoded, "undecoded");
    add(counts.over_flow_limit, "over the flow limit");

    format!(
        "\n    {} packets formed no flow: {}.\n",
        counts.total(),
        reasons.join(", ")
    )
}

/// Formats a byte count for people.
///
/// Decimal units, because network sizes are conventionally decimal and "KB"
/// meaning 1024 is a lie the reader has to know about. Counts below 10 000 are
/// printed exactly: a small flow's size is the kind of number an analyst wants
/// to be able to add up, and rounding it away to save three characters would be
/// a poor trade.
pub fn format_bytes(bytes: u64) -> String {
    const UNIT: f64 = 1000.0;
    const SUFFIXES: [&str; 4] = ["KB", "MB", "GB", "TB"];

    if bytes < 10_000 {
        return format!("{bytes} B");
    }

    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64 / UNIT;
    let mut suffix = SUFFIXES[0];

    for next in SUFFIXES.iter().skip(1) {
        if value < UNIT {
            break;
        }
        value /= UNIT;
        suffix = next;
    }

    format!("{value:.1} {suffix}")
}

/// Formats a flow's duration, or says it could not be worked out.
fn format_duration(duration: Option<Duration>) -> String {
    let Some(duration) = duration else {
        // The timestamps were not points in time; see `Flow::duration`.
        return "unknown".to_owned();
    };

    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{}.{:02}s", seconds, duration.subsec_millis() / 10)
    } else {
        format!(
            "{}m {:02}.{:02}s",
            seconds / 60,
            seconds % 60,
            duration.subsec_millis() / 10
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::PacketMetadata;
    use crate::capture::PacketTimestamp;
    use crate::decode::{DecodedPacket, TransportLayer, UdpHeader};
    use crate::decode::{IpProtocol, Ipv4Header, Ipv6Header, NetworkLayer, TcpFlags, TcpHeader};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn metadata(seconds: i64, micros: i64, caplen: u32, wirelen: u32) -> PacketMetadata {
        PacketMetadata {
            number: 1,
            timestamp: PacketTimestamp::from_parts(seconds, micros),
            caplen,
            wirelen,
        }
    }

    fn ipv4(source: [u8; 4], destination: [u8; 4], protocol: IpProtocol) -> NetworkLayer {
        NetworkLayer::Ipv4(Ipv4Header {
            source: Ipv4Addr::from(source),
            destination: Ipv4Addr::from(destination),
            protocol,
            ttl: 64,
            header_len: 20,
            total_len: 60,
            identification: 0,
            dscp: 0,
            ecn: 0,
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
            checksum: 0,
            options_len: 0,
        })
    }

    fn tcp(source_port: u16, destination_port: u16, flags: u16) -> TransportLayer {
        TransportLayer::Tcp(TcpHeader {
            source_port,
            destination_port,
            sequence: 0,
            acknowledgment: 0,
            header_len: 20,
            flags: TcpFlags(flags),
            window: 0,
            checksum: 0,
            urgent_pointer: 0,
            options_len: 0,
        })
    }

    fn packet(network: NetworkLayer, transport: TransportLayer) -> DecodedPacket {
        DecodedPacket {
            link: None,
            network: Some(network),
            transport: Some(transport),
            stopped: None,
        }
    }

    /// A table holding one TCP conversation with traffic both ways.
    fn one_conversation() -> FlowTable {
        let mut table = FlowTable::default();
        for _ in 0..14 {
            table.record(
                &metadata(100, 0, 300, 300),
                &packet(
                    ipv4([192, 168, 1, 15], [142, 250, 184, 14], IpProtocol::Tcp),
                    tcp(53_122, 443, 0x018),
                ),
            );
        }
        for _ in 0..24 {
            table.record(
                &metadata(102, 740_000, 2_170, 2_170),
                &packet(
                    ipv4([142, 250, 184, 14], [192, 168, 1, 15], IpProtocol::Tcp),
                    tcp(443, 53_122, 0x010),
                ),
            );
        }
        table
    }

    #[test]
    fn a_flow_reads_as_a_conversation_with_both_directions() {
        let table = one_conversation();
        let rendered = flow_table(&table);

        assert!(rendered.contains("[*] Flows: 1"), "{rendered}");
        // The reader is told what A and B mean rather than left to infer it.
        assert!(
            rendered.contains("A is the endpoint on the left"),
            "{rendered}"
        );
        assert!(
            rendered.contains("TCP 142.250.184.14:443 \u{2194} 192.168.1.15:53122"),
            "{rendered}"
        );
        assert!(rendered.contains("packets 38"), "{rendered}");
        assert!(rendered.contains("duration 2.74s"), "{rendered}");
        // The server sent far more than the client, and that asymmetry shows.
        assert!(rendered.contains("A\u{2192}B 24"), "{rendered}");
        assert!(rendered.contains("B\u{2192}A 14"), "{rendered}");
    }

    #[test]
    fn tcp_flag_facts_appear_for_tcp_flows_only() {
        let rendered = flow_table(&one_conversation());
        // A is 142.250.184.14:443 here: the lower-sorted endpoint, which
        // happens to be the server. It sent bare ACKs; the client sent PSH,ACK.
        assert!(rendered.contains("TCP A\u{2192}B [ACK]"), "{rendered}");
        assert!(rendered.contains("B\u{2192}A [PSH,ACK]"), "{rendered}");

        let mut udp = FlowTable::default();
        udp.record(
            &metadata(100, 0, 74, 74),
            &packet(
                ipv4([192, 168, 1, 15], [8, 8, 8, 8], IpProtocol::Udp),
                TransportLayer::Udp(UdpHeader {
                    source_port: 60_432,
                    destination_port: 53,
                    length: 42,
                    checksum: 0,
                    captured_payload_len: 34,
                }),
            ),
        );
        let rendered = flow_table(&udp);
        assert!(rendered.contains("UDP"), "{rendered}");
        assert!(!rendered.contains("syn"), "UDP has no flags: {rendered}");
    }

    #[test]
    fn truncation_is_called_out_only_when_it_happened() {
        let full = flow_table(&one_conversation());
        assert!(!full.contains("snapshot length"), "{full}");

        let mut cut = FlowTable::default();
        cut.record(
            &metadata(100, 0, 64, 1514),
            &packet(
                ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Tcp),
                tcp(5_000, 443, 0x002),
            ),
        );
        let rendered = flow_table(&cut);
        assert!(rendered.contains("snapshot length truncated"), "{rendered}");
        assert!(rendered.contains("64 B of 1514 B"), "{rendered}");
    }

    #[test]
    fn ipv6_endpoints_stay_readable() {
        let mut table = FlowTable::default();
        table.record(
            &metadata(100, 0, 74, 74),
            &packet(
                NetworkLayer::Ipv6(Ipv6Header {
                    source: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                    destination: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
                    next_header: IpProtocol::Tcp,
                    hop_limit: 64,
                    payload_len: 20,
                    traffic_class: 0,
                    flow_label: 0,
                    extension_headers: vec![],
                    non_initial_fragment: false,
                }),
                tcp(53_122, 443, 0x002),
            ),
        );

        let rendered = flow_table(&table);
        assert!(
            rendered.contains("[2001:db8::1]:53122 \u{2194} [2001:db8::2]:443"),
            "{rendered}"
        );
    }

    #[test]
    fn an_empty_table_says_so_plainly() {
        let rendered = flow_table(&FlowTable::default());
        assert!(rendered.contains("[*] Flows: 0"));
        assert!(rendered.contains("no TCP or UDP conversations"));
    }

    #[test]
    fn untracked_packets_are_listed_with_their_reasons() {
        let counts = UntrackedCounts {
            arp: 12,
            icmp: 3,
            later_fragments: 2,
            undecoded: 1,
            other_protocol: 0,
            over_flow_limit: 0,
        };
        let note = untracked_note(counts);

        assert!(note.contains("18 packets formed no flow"), "{note}");
        assert!(note.contains("12 ARP"));
        assert!(note.contains("3 ICMP"));
        assert!(note.contains("2 later fragments"));
        assert!(note.contains("1 undecoded"));
        assert!(
            !note.contains("other IP protocols"),
            "zero counts are omitted"
        );

        assert_eq!(untracked_note(UntrackedCounts::default()), "");
    }

    #[test]
    fn reaching_the_flow_limit_is_announced_with_what_to_do() {
        let mut table = FlowTable::with_limit(1);
        for port in [5_000u16, 5_001] {
            table.record(
                &metadata(100, 0, 60, 60),
                &packet(
                    ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Tcp),
                    tcp(port, 443, 0x002),
                ),
            );
        }

        let rendered = flow_table(&table);
        assert!(
            rendered.contains("flow limit of 1 was reached"),
            "{rendered}"
        );
        assert!(rendered.contains("--max-flows"), "{rendered}");
        assert!(rendered.contains("1 over the flow limit"), "{rendered}");
    }

    #[test]
    fn rendering_is_identical_across_runs() {
        let table = one_conversation();
        assert_eq!(flow_table(&table), flow_table(&table));
    }

    #[test]
    fn byte_counts_stay_exact_while_they_are_small() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(54), "54 B");
        assert_eq!(format_bytes(9_999), "9999 B");
        // Above that, readability wins.
        assert_eq!(format_bytes(10_000), "10.0 KB");
        assert_eq!(format_bytes(56_200), "56.2 KB");
        assert_eq!(format_bytes(1_000_000), "1.0 MB");
        assert_eq!(format_bytes(2_500_000_000), "2.5 GB");
        assert_eq!(format_bytes(u64::MAX), "18446744.1 TB");
    }

    #[test]
    fn durations_read_naturally_at_both_ends_of_the_scale() {
        assert_eq!(format_duration(Some(Duration::ZERO)), "0.00s");
        assert_eq!(
            format_duration(Some(Duration::from_micros(2_740_123))),
            "2.74s"
        );
        assert_eq!(
            format_duration(Some(Duration::from_millis(59_990))),
            "59.99s"
        );
        assert_eq!(format_duration(Some(Duration::from_secs(60))), "1m 00.00s");
        assert_eq!(
            format_duration(Some(Duration::from_secs(3_725))),
            "62m 05.00s"
        );
        assert_eq!(format_duration(None), "unknown");
    }
}
