//! Offline analysis tests, driven by capture files built byte by byte in code.
//!
//! No fixture files are committed. Every capture used here is assembled from a
//! handful of constants, written to a scratch file and deleted afterwards,
//! which keeps the repository free of binary blobs and makes each test say
//! exactly what it is testing. Nothing here touches a network interface or
//! needs privileges.

use std::path::{Path, PathBuf};

use netsentry::capture::{CaptureFile, StopReason};
use netsentry::decode::{LinkLayer, NetworkLayer, TransportLayer, decode};
use netsentry::error::NetSentryError;
use netsentry::flow::{FlowProtocol, FlowTable};

/// A scratch file that deletes itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str, contents: &[u8]) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("netsentry-offline-{}-{name}", std::process::id()));
        std::fs::write(&path, contents).unwrap_or_default();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A classic pcap file header: little-endian, microseconds, snaplen 65535.
fn pcap_header(link_type: u32) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic
    header.extend_from_slice(&2u16.to_le_bytes()); // major
    header.extend_from_slice(&4u16.to_le_bytes()); // minor
    header.extend_from_slice(&0u32.to_le_bytes()); // timezone
    header.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    header.extend_from_slice(&65_535u32.to_le_bytes()); // snaplen
    header.extend_from_slice(&link_type.to_le_bytes());
    header
}

/// A per-packet record header.
fn record_header(seconds: u32, micros: u32, caplen: u32, wirelen: u32) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&seconds.to_le_bytes());
    header.extend_from_slice(&micros.to_le_bytes());
    header.extend_from_slice(&caplen.to_le_bytes());
    header.extend_from_slice(&wirelen.to_le_bytes());
    header
}

/// An Ethernet frame wrapping `payload`.
fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, //
    ];
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// An IPv4 header carrying `protocol`.
fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total = u16::try_from(20 + payload.len()).unwrap_or(u16::MAX);
    let mut header = vec![0x45, 0x00];
    header.extend_from_slice(&total.to_be_bytes());
    header.extend_from_slice(&[0x1c, 0x46, 0x40, 0x00, 0x40, protocol, 0x00, 0x00]);
    header.extend_from_slice(&[192, 168, 1, 15]);
    header.extend_from_slice(&[142, 250, 184, 14]);
    header.extend_from_slice(payload);
    header
}

/// A TCP SYN segment.
fn tcp_syn() -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&53_122u16.to_be_bytes());
    segment.extend_from_slice(&443u16.to_be_bytes());
    segment.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0]);
    segment.extend_from_slice(&[0x50, 0x02, 0xfa, 0xf0, 0, 0, 0, 0]);
    segment
}

/// A UDP datagram with an empty payload.
fn udp() -> Vec<u8> {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&60_432u16.to_be_bytes());
    datagram.extend_from_slice(&53u16.to_be_bytes());
    datagram.extend_from_slice(&8u16.to_be_bytes());
    datagram.extend_from_slice(&[0x12, 0x34]);
    datagram
}

/// A TCP segment with arbitrary ports and flags.
fn tcp(source: u16, destination: u16, flags: u8) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&source.to_be_bytes());
    segment.extend_from_slice(&destination.to_be_bytes());
    segment.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0]);
    segment.push(0x50);
    segment.push(flags);
    segment.extend_from_slice(&[0xfa, 0xf0, 0, 0, 0, 0]);
    segment
}

/// A UDP datagram with arbitrary ports.
fn udp_ports(source: u16, destination: u16) -> Vec<u8> {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&source.to_be_bytes());
    datagram.extend_from_slice(&destination.to_be_bytes());
    datagram.extend_from_slice(&8u16.to_be_bytes());
    datagram.extend_from_slice(&[0x12, 0x34]);
    datagram
}

/// An IPv4 header between two chosen hosts.
fn ipv4_between(source: [u8; 4], destination: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total = u16::try_from(20 + payload.len()).unwrap_or(u16::MAX);
    let mut header = vec![0x45, 0x00];
    header.extend_from_slice(&total.to_be_bytes());
    header.extend_from_slice(&[0x1c, 0x46, 0x40, 0x00, 0x40, protocol, 0x00, 0x00]);
    header.extend_from_slice(&source);
    header.extend_from_slice(&destination);
    header.extend_from_slice(payload);
    header
}

/// Reads a file into a flow table, the way `--flows` does.
fn flows_of(path: &Path, limit: Option<u64>) -> FlowTable {
    let mut file = match CaptureFile::open(path) {
        Ok(file) => file,
        Err(error) => panic!("could not open fixture: {error}"),
    };
    let link = LinkLayer::from_dlt(file.link_type().code);
    let mut table = FlowTable::default();
    let _ = file.run(limit, |metadata, bytes| {
        table.record(metadata, &decode(link, bytes));
        Ok(())
    });
    table
}

/// An ICMP echo reply.
fn icmp_echo_reply() -> Vec<u8> {
    vec![0x00, 0x00, 0xff, 0xff, 0x00, 0x01, 0x00, 0x01]
}

/// An Ethernet/IPv4 ARP request.
fn arp_request() -> Vec<u8> {
    let mut packet = vec![0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01];
    packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet.extend_from_slice(&[192, 168, 1, 15]);
    packet.extend_from_slice(&[0; 6]);
    packet.extend_from_slice(&[192, 168, 1, 1]);
    packet
}

/// Assembles a pcap file from `(seconds, micros, packet)` triples.
fn build_pcap(link_type: u32, packets: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut file = pcap_header(link_type);
    for (seconds, micros, packet) in packets {
        let len = u32::try_from(packet.len()).unwrap_or(0);
        file.extend_from_slice(&record_header(*seconds, *micros, len, len));
        file.extend_from_slice(packet);
    }
    file
}

/// Reads a file and returns every packet's rendered summary.
fn summaries(path: &Path, limit: Option<u64>) -> (Vec<String>, netsentry::capture::FileSummary) {
    let mut file = match CaptureFile::open(path) {
        Ok(file) => file,
        Err(error) => panic!("could not open fixture: {error}"),
    };
    let link = LinkLayer::from_dlt(file.link_type().code);

    let mut lines = Vec::new();
    let summary = file.run(limit, |_, bytes| {
        lines.push(netsentry::render::summary(&decode(link, bytes)));
        Ok(())
    });
    (lines, summary)
}

#[test]
fn reads_a_single_ethernet_tcp_packet() {
    let bytes = build_pcap(
        1,
        &[(
            1_790_005_351,
            123_456,
            ethernet(0x0800, &ipv4(6, &tcp_syn())),
        )],
    );
    let scratch = Scratch::new("one-tcp.pcap", &bytes);

    let mut file = match CaptureFile::open(scratch.path()) {
        Ok(file) => file,
        Err(error) => panic!("{error}"),
    };
    assert_eq!(file.link_type().code, 1);
    assert_eq!(file.link_type().name, "EN10MB");

    let mut seen = Vec::new();
    let summary = file.run(None, |metadata, bytes| {
        seen.push((metadata.number, metadata.caplen, metadata.wirelen));
        let packet = decode(LinkLayer::Ethernet, bytes);
        // The same decoder a live capture uses, producing the same model.
        assert!(matches!(packet.network, Some(NetworkLayer::Ipv4(_))));
        assert!(matches!(packet.transport, Some(TransportLayer::Tcp(_))));
        Ok(())
    });

    assert_eq!(seen, vec![(1, 54, 54)]);
    assert_eq!(summary.tally.packets(), 1);
    assert_eq!(summary.tally.captured_bytes(), 54);
    assert_eq!(summary.tally.wire_bytes(), 54);
    assert_eq!(summary.stop_reason, StopReason::SourceEnded);
    assert!(summary.read_error.is_none());
}

#[test]
fn offline_output_matches_what_the_live_decoder_would_produce() {
    // The point of v0.3: one decoder, one renderer, two sources. The file's
    // bytes go through exactly the path a captured packet goes through.
    let frame = ethernet(0x0800, &ipv4(6, &tcp_syn()));
    let expected = netsentry::render::summary(&decode(LinkLayer::Ethernet, &frame));

    let scratch = Scratch::new(
        "parity.pcap",
        &build_pcap(1, &[(1_790_005_351, 123_456, frame)]),
    );
    let (lines, _) = summaries(scratch.path(), None);

    assert_eq!(lines, vec![expected]);
    assert_eq!(
        lines.first().map(String::as_str),
        Some("192.168.1.15:53122 \u{2192} 142.250.184.14:443 TCP SYN")
    );
}

#[test]
fn reads_a_file_of_several_protocols() {
    let bytes = build_pcap(
        1,
        &[
            (
                1_790_005_351,
                123_456,
                ethernet(0x0800, &ipv4(6, &tcp_syn())),
            ),
            (1_790_005_352, 0, ethernet(0x0800, &ipv4(17, &udp()))),
            (
                1_790_005_353,
                0,
                ethernet(0x0800, &ipv4(1, &icmp_echo_reply())),
            ),
            (1_790_005_355, 999_999, ethernet(0x0806, &arp_request())),
        ],
    );
    let scratch = Scratch::new("mixed.pcap", &bytes);
    let (lines, summary) = summaries(scratch.path(), None);

    assert_eq!(summary.tally.packets(), 4);
    assert!(lines[0].ends_with("TCP SYN"), "{:?}", lines[0]);
    assert!(lines[1].ends_with("UDP len=8"), "{:?}", lines[1]);
    assert!(lines[2].ends_with("ICMP Echo Reply"), "{:?}", lines[2]);
    assert_eq!(lines[3], "ARP Who has 192.168.1.1? Tell 192.168.1.15");
}

#[test]
fn a_packet_truncated_inside_the_file_degrades_the_same_way_as_a_live_one() {
    // The pcap structure is perfectly valid; the packet it contains is not.
    // That must produce the decoder's ordinary graceful degradation, not a
    // file error.
    let full = ethernet(0x0800, &ipv4(6, &tcp_syn()));
    let cut = full.get(..24).unwrap_or_default().to_vec();

    let scratch = Scratch::new("short-packet.pcap", &build_pcap(1, &[(1, 0, cut)]));
    let (lines, summary) = summaries(scratch.path(), None);

    assert_eq!(summary.stop_reason, StopReason::SourceEnded);
    assert!(
        summary.read_error.is_none(),
        "a short packet is not a broken file"
    );
    // The Ethernet header was complete, so its addresses survive; only the
    // IPv4 header above it was cut off.
    assert_eq!(
        lines,
        vec!["00:11:22:33:44:55 \u{2192} aa:bb:cc:dd:ee:ff IPv4 [truncated IPv4]"]
    );

    // Cutting inside the Ethernet header itself degrades one step further.
    let scratch = Scratch::new(
        "shorter-packet.pcap",
        &build_pcap(1, &[(1, 0, full.get(..8).unwrap_or_default().to_vec())]),
    );
    let (lines, summary) = summaries(scratch.path(), None);
    assert!(summary.read_error.is_none());
    assert_eq!(lines, vec!["[truncated Ethernet]"]);
}

#[test]
fn an_unsupported_link_type_is_reported_per_packet_not_refused() {
    // DLT_IEEE802_11. The file is readable; NetSentry simply has no decoder.
    let scratch = Scratch::new(
        "wifi.pcap",
        &build_pcap(105, &[(1_790_005_351, 0, vec![0x08, 0x00, 0x00, 0x00])]),
    );

    let mut file = match CaptureFile::open(scratch.path()) {
        Ok(file) => file,
        Err(error) => panic!("the file itself is fine: {error}"),
    };
    assert_eq!(file.link_type().code, 105);

    let (lines, summary) = summaries(scratch.path(), None);
    assert_eq!(summary.tally.packets(), 1);
    assert_eq!(lines, vec!["[no decoder for link type 105]"]);
    let _ = file.run(None, |_, _| Ok(()));
}

#[test]
fn count_stops_early_and_says_so() {
    let packets: Vec<_> = (0..10)
        .map(|i| (1_790_005_351 + i, 0, ethernet(0x0800, &ipv4(6, &tcp_syn()))))
        .collect();
    let scratch = Scratch::new("ten.pcap", &build_pcap(1, &packets));

    let (lines, summary) = summaries(scratch.path(), Some(3));

    assert_eq!(lines.len(), 3);
    assert_eq!(summary.tally.packets(), 3);
    assert_eq!(summary.stop_reason, StopReason::CountReached);
    // The span covers what was analysed, not what the file holds.
    assert_eq!(
        summary.time_span.last().map(|ts| ts.seconds()),
        Some(1_790_005_353)
    );

    let (all, summary) = summaries(scratch.path(), None);
    assert_eq!(all.len(), 10);
    assert_eq!(summary.stop_reason, StopReason::SourceEnded);
}

#[test]
fn the_summary_reports_the_captures_own_time_span() {
    let scratch = Scratch::new(
        "span.pcap",
        &build_pcap(
            1,
            &[
                (
                    1_790_005_351,
                    123_456,
                    ethernet(0x0800, &ipv4(6, &tcp_syn())),
                ),
                (
                    1_790_005_352,
                    500_000,
                    ethernet(0x0800, &ipv4(6, &tcp_syn())),
                ),
                (
                    1_790_005_355,
                    999_999,
                    ethernet(0x0800, &ipv4(6, &tcp_syn())),
                ),
            ],
        ),
    );
    let (_, summary) = summaries(scratch.path(), None);

    assert_eq!(
        summary
            .time_span
            .first()
            .map(|ts| (ts.seconds(), ts.microseconds())),
        Some((1_790_005_351, 123_456))
    );
    assert_eq!(
        summary
            .time_span
            .last()
            .map(|ts| (ts.seconds(), ts.microseconds())),
        Some((1_790_005_355, 999_999))
    );
    assert_eq!(
        summary.time_span.duration(),
        Some(std::time::Duration::from_micros(4_876_543))
    );
    // Reading three packets from a local file takes nothing like 4.8 seconds:
    // the two clocks must not be confused for one another.
    assert!(summary.processing_time < std::time::Duration::from_secs(1));
}

#[test]
fn an_empty_file_is_rejected_as_a_format_problem() {
    let scratch = Scratch::new("empty.pcap", b"");
    let error = CaptureFile::open(scratch.path()).err();
    assert!(
        matches!(error, Some(NetSentryError::CaptureFileFormat { .. })),
        "got {error:?}"
    );
}

#[test]
fn a_file_that_is_not_a_capture_is_rejected() {
    for (name, contents) in [
        ("text", b"this is not a capture file at all\n".to_vec()),
        ("zeros", vec![0u8; 512]),
        ("ones", vec![0xffu8; 512]),
        ("gzip", vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0]),
    ] {
        let scratch = Scratch::new(name, &contents);
        let error = CaptureFile::open(scratch.path()).err();
        assert!(
            matches!(error, Some(NetSentryError::CaptureFileFormat { .. })),
            "{name} should be refused, got {error:?}"
        );
    }
}

#[test]
fn a_truncated_global_header_is_a_format_problem_not_a_crash() {
    let full = pcap_header(1);
    for length in 0..full.len() {
        let scratch = Scratch::new("cut-header.pcap", full.get(..length).unwrap_or_default());
        let error = CaptureFile::open(scratch.path()).err();
        assert!(
            matches!(error, Some(NetSentryError::CaptureFileFormat { .. })),
            "a {length}-byte header should be refused, got {error:?}"
        );
    }
}

#[test]
fn a_truncated_packet_record_is_a_file_error_not_a_decode_error() {
    // The distinction that matters: the pcap *structure* is damaged here, as
    // opposed to a well-stored packet that is itself short.
    let frame = ethernet(0x0800, &ipv4(6, &tcp_syn()));
    let mut bytes = pcap_header(1);
    let len = u32::try_from(frame.len()).unwrap_or(0);
    bytes.extend_from_slice(&record_header(1_790_005_351, 0, len, len));
    bytes.extend_from_slice(frame.get(..20).unwrap_or_default()); // record cut short

    let scratch = Scratch::new("cut-record.pcap", &bytes);
    let (lines, summary) = summaries(scratch.path(), None);

    assert!(lines.is_empty(), "no complete packet could be read");
    assert_eq!(summary.stop_reason, StopReason::ReadFailed);
    assert!(
        matches!(
            summary.read_error,
            Some(NetSentryError::CaptureFileCorrupt { .. })
        ),
        "got {:?}",
        summary.read_error
    );
}

#[test]
fn packets_before_a_corrupt_tail_are_still_analysed() {
    // A capture whose writer was killed mid-packet. Everything before the
    // damage is real evidence and must not be thrown away.
    let frame = ethernet(0x0800, &ipv4(6, &tcp_syn()));
    let len = u32::try_from(frame.len()).unwrap_or(0);

    let mut bytes = pcap_header(1);
    for seconds in 0..3u32 {
        bytes.extend_from_slice(&record_header(1_790_005_351 + seconds, 0, len, len));
        bytes.extend_from_slice(&frame);
    }
    bytes.extend_from_slice(&record_header(1_790_005_360, 0, len, len));
    bytes.extend_from_slice(&frame[..10]); // and then the disk ran out

    let scratch = Scratch::new("cut-tail.pcap", &bytes);
    let (lines, summary) = summaries(scratch.path(), None);

    assert_eq!(lines.len(), 3, "the intact packets must survive");
    assert_eq!(summary.tally.packets(), 3);
    assert_eq!(summary.stop_reason, StopReason::ReadFailed);
    assert!(summary.read_error.is_some());
}

#[test]
fn an_absurd_packet_length_is_refused_by_the_reader() {
    let mut bytes = pcap_header(1);
    bytes.extend_from_slice(&record_header(1_790_005_351, 0, 0x7fff_ffff, 0x7fff_ffff));
    bytes.extend_from_slice(&ethernet(0x0800, &ipv4(6, &tcp_syn())));

    let scratch = Scratch::new("absurd.pcap", &bytes);
    let (lines, summary) = summaries(scratch.path(), None);

    assert!(lines.is_empty());
    assert_eq!(summary.stop_reason, StopReason::ReadFailed);
    assert_eq!(summary.tally.packets(), 0, "no bytes were invented");
}

#[test]
fn a_capture_with_no_packets_reports_an_empty_span() {
    let scratch = Scratch::new("headers-only.pcap", &pcap_header(1));
    let (lines, summary) = summaries(scratch.path(), None);

    assert!(lines.is_empty());
    assert_eq!(summary.tally.packets(), 0);
    assert_eq!(summary.time_span.first(), None);
    assert_eq!(summary.time_span.duration(), None);
    assert_eq!(summary.stop_reason, StopReason::SourceEnded);
    assert!(summary.read_error.is_none());
}

#[test]
fn reading_a_file_never_modifies_it() {
    let bytes = build_pcap(
        1,
        &[(1_790_005_351, 0, ethernet(0x0800, &ipv4(6, &tcp_syn())))],
    );
    let scratch = Scratch::new("readonly.pcap", &bytes);

    let before = std::fs::read(scratch.path()).unwrap_or_default();
    let (_, summary) = summaries(scratch.path(), None);
    let after = std::fs::read(scratch.path()).unwrap_or_default();

    assert_eq!(summary.tally.packets(), 1);
    assert_eq!(before, after, "offline analysis must be read-only");
}

#[test]
fn no_file_contents_can_bring_the_reader_down() {
    // Every prefix of a valid capture, plus corruptions of it. As with the
    // decoder, the assertion is simply that this returns.
    let valid = build_pcap(
        1,
        &[
            (
                1_790_005_351,
                123_456,
                ethernet(0x0800, &ipv4(6, &tcp_syn())),
            ),
            (1_790_005_352, 0, ethernet(0x0806, &arp_request())),
        ],
    );

    let mut attempts = 0usize;
    for length in 0..=valid.len() {
        let scratch = Scratch::new("sweep-prefix.pcap", valid.get(..length).unwrap_or_default());
        if let Ok(mut file) = CaptureFile::open(scratch.path()) {
            let link = LinkLayer::from_dlt(file.link_type().code);
            let _ = file.run(None, |_, bytes| {
                let _ = decode(link, bytes);
                Ok(())
            });
        }
        attempts += 1;
    }

    for index in 0..valid.len() {
        for replacement in [0x00u8, 0xff] {
            let mut mutated = valid.clone();
            if let Some(slot) = mutated.get_mut(index) {
                *slot = replacement;
            }
            let scratch = Scratch::new("sweep-mutate.pcap", &mutated);
            if let Ok(mut file) = CaptureFile::open(scratch.path()) {
                let link = LinkLayer::from_dlt(file.link_type().code);
                let _ = file.run(None, |_, bytes| {
                    let _ = decode(link, bytes);
                    Ok(())
                });
            }
            attempts += 1;
        }
    }

    assert!(attempts > 300, "only {attempts} files tried");
}

#[test]
fn a_capture_file_becomes_a_flow_table() {
    let client = [192, 168, 1, 15];
    let server = [142, 250, 184, 14];

    // A three-way handshake plus one data segment each way, from a file.
    let bytes = build_pcap(
        1,
        &[
            (
                1_790_005_351,
                0,
                ethernet(
                    0x0800,
                    &ipv4_between(client, server, 6, &tcp(53_122, 443, 0x02)),
                ),
            ),
            (
                1_790_005_351,
                200_000,
                ethernet(
                    0x0800,
                    &ipv4_between(server, client, 6, &tcp(443, 53_122, 0x12)),
                ),
            ),
            (
                1_790_005_351,
                400_000,
                ethernet(
                    0x0800,
                    &ipv4_between(client, server, 6, &tcp(53_122, 443, 0x10)),
                ),
            ),
            (
                1_790_005_353,
                740_000,
                ethernet(
                    0x0800,
                    &ipv4_between(server, client, 6, &tcp(443, 53_122, 0x18)),
                ),
            ),
        ],
    );
    let scratch = Scratch::new("flows-tcp.pcap", &bytes);
    let table = flows_of(scratch.path(), None);

    assert_eq!(table.len(), 1, "one conversation, four packets");
    let flows = table.flows_sorted();
    let flow = flows.first().copied().unwrap_or_else(|| unreachable!());

    assert_eq!(flow.key.protocol, FlowProtocol::Tcp);
    assert_eq!(flow.total_packets(), 4);
    // A is 142.250.184.14:443, the lower-sorted endpoint.
    assert_eq!(flow.key.a.port, 443);
    assert_eq!(flow.key.b.port, 53_122);
    assert_eq!(flow.a_to_b.packets, 2, "server to client");
    assert_eq!(flow.b_to_a.packets, 2, "client to server");
    assert_eq!(
        flow.duration(),
        Some(std::time::Duration::from_micros(2_740_000))
    );

    let facts = flow.tcp.unwrap_or_default();
    assert_eq!(facts.b_to_a.syn, 1, "the client sent one SYN");
    assert_eq!(facts.a_to_b.syn, 1, "the server answered with SYN/ACK");
    assert_eq!(facts.a_to_b.rst, 0);
}

#[test]
fn several_conversations_are_kept_apart_and_ordered() {
    let client = [192, 168, 1, 15];
    let bytes = build_pcap(
        1,
        &[
            (
                1_790_005_353,
                0,
                ethernet(
                    0x0800,
                    &ipv4_between(client, [1, 1, 1, 1], 6, &tcp(5_002, 443, 0x02)),
                ),
            ),
            (
                1_790_005_351,
                0,
                ethernet(
                    0x0800,
                    &ipv4_between(client, [8, 8, 8, 8], 17, &udp_ports(5_000, 53)),
                ),
            ),
            (
                1_790_005_352,
                0,
                ethernet(
                    0x0800,
                    &ipv4_between(client, [1, 1, 1, 1], 6, &tcp(5_001, 443, 0x02)),
                ),
            ),
        ],
    );
    let scratch = Scratch::new("flows-many.pcap", &bytes);
    let table = flows_of(scratch.path(), None);

    assert_eq!(table.len(), 3);
    // Sorted by when each conversation started, not by file order.
    let starts: Vec<i64> = table
        .flows_sorted()
        .iter()
        .map(|flow| flow.first_seen().seconds())
        .collect();
    assert_eq!(starts, vec![1_790_005_351, 1_790_005_352, 1_790_005_353]);

    let protocols: Vec<FlowProtocol> = table
        .flows_sorted()
        .iter()
        .map(|flow| flow.key.protocol)
        .collect();
    assert_eq!(
        protocols,
        vec![FlowProtocol::Udp, FlowProtocol::Tcp, FlowProtocol::Tcp]
    );
}

#[test]
fn arp_and_icmp_in_a_file_are_counted_but_form_no_flows() {
    let bytes = build_pcap(
        1,
        &[
            (1_790_005_351, 0, ethernet(0x0806, &arp_request())),
            (
                1_790_005_352,
                0,
                ethernet(0x0800, &ipv4(1, &icmp_echo_reply())),
            ),
            (1_790_005_353, 0, ethernet(0x0800, &ipv4(6, &tcp_syn()))),
        ],
    );
    let scratch = Scratch::new("flows-mixed.pcap", &bytes);
    let table = flows_of(scratch.path(), None);

    assert_eq!(table.len(), 1, "only the TCP packet is a conversation");
    let counts = table.untracked();
    assert_eq!(counts.arp, 1);
    assert_eq!(counts.icmp, 1);
    assert_eq!(counts.total(), 2);
}

#[test]
fn a_later_fragment_in_a_file_does_not_invent_a_flow() {
    // A fragment at offset 185 carries no ports. Its first bytes are the middle
    // of someone else's payload and must not be read as a TCP header.
    let mut fragment = ipv4_between([192, 168, 1, 15], [1, 1, 1, 1], 6, &[0xaa; 8]);
    fragment[6] = 0x20; // more fragments ...
    fragment[7] = 0xb9; // ... at offset 185

    let bytes = build_pcap(1, &[(1_790_005_351, 0, ethernet(0x0800, &fragment))]);
    let scratch = Scratch::new("flows-fragment.pcap", &bytes);
    let table = flows_of(scratch.path(), None);

    assert!(table.is_empty());
    assert_eq!(table.untracked().later_fragments, 1);
}

#[test]
fn the_flow_table_survives_a_corrupt_file_tail() {
    let frame = ethernet(0x0800, &ipv4(6, &tcp_syn()));
    let len = u32::try_from(frame.len()).unwrap_or(0);

    let mut bytes = pcap_header(1);
    for seconds in 0..3u32 {
        bytes.extend_from_slice(&record_header(1_790_005_351 + seconds, 0, len, len));
        bytes.extend_from_slice(&frame);
    }
    bytes.extend_from_slice(&record_header(1_790_005_360, 0, len, len));
    bytes.extend_from_slice(&frame[..10]);

    let scratch = Scratch::new("flows-cut.pcap", &bytes);
    let table = flows_of(scratch.path(), None);

    assert_eq!(table.len(), 1);
    assert_eq!(
        table
            .flows_sorted()
            .first()
            .map(|flow| flow.total_packets()),
        Some(3),
        "the packets before the damage still count"
    );
}

#[test]
fn count_limits_what_the_flow_table_sees() {
    let client = [192, 168, 1, 15];
    let packets: Vec<_> = (0..6u16)
        .map(|index| {
            (
                1_790_005_351 + u32::from(index),
                0,
                ethernet(
                    0x0800,
                    &ipv4_between(client, [1, 1, 1, 1], 6, &tcp(5_000 + index, 443, 0x02)),
                ),
            )
        })
        .collect();
    let scratch = Scratch::new("flows-count.pcap", &build_pcap(1, &packets));

    assert_eq!(flows_of(scratch.path(), None).len(), 6);
    assert_eq!(flows_of(scratch.path(), Some(2)).len(), 2);
}

#[test]
fn flow_output_is_byte_identical_between_runs() {
    let client = [192, 168, 1, 15];
    let packets: Vec<_> = (0..20u16)
        .map(|index| {
            (
                1_790_005_351,
                u32::from(index),
                ethernet(
                    0x0800,
                    &ipv4_between(client, [1, 1, 1, 1], 6, &tcp(5_000 + index, 443, 0x02)),
                ),
            )
        })
        .collect();
    let scratch = Scratch::new("flows-stable.pcap", &build_pcap(1, &packets));

    // Twenty flows all starting within the same second, so the tie-break is
    // doing the work. Hash order would differ between runs of the process.
    let first = netsentry::render::flow_table(&flows_of(scratch.path(), None));
    let second = netsentry::render::flow_table(&flows_of(scratch.path(), None));
    assert_eq!(first, second);
    assert!(first.contains("[*] Flows: 20"));
}
