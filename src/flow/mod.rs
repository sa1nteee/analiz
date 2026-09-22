//! Flow tracking: grouping packets into the conversations they belong to.
//!
//! A capture of a few minutes is tens of thousands of packets and perhaps a few
//! dozen conversations. The packet list says what happened; the flow table says
//! *who was talking to whom*, which is the question most security analysis
//! actually starts from.
//!
//! # Where this sits
//!
//! ```text
//! capture / file  ─→  decode  ─→  flow tracking  ─→  render
//! ```
//!
//! The tracker takes [`DecodedPacket`] and [`PacketMetadata`] — never raw
//! bytes. It computes no offsets and parses no headers; the decoder stays the
//! single source of truth about what a packet contains. That also means the
//! whole layer is testable by constructing decoded packets directly, with no
//! network and no capture file.
//!
//! # What gets a flow, and what does not
//!
//! Only TCP and UDP. Both have ports, and a port pair is what makes two
//! endpoints a *conversation* rather than just two hosts that exchanged
//! something.
//!
//! ICMP has no ports. An ICMP flow would have to be keyed on host pairs alone,
//! which mixes unrelated things together — an echo request, a "host
//! unreachable" about some third connection, and a traceroute probe would all
//! land in one bucket and none of them is a conversation with the others.
//! Worse, most interesting ICMP messages *quote* a different packet, so the
//! conversation they concern is not the one their own headers describe.
//! Handling that properly means correlating the quoted header with an existing
//! flow, which is real work and belongs where it is useful — with the detection
//! rules of v0.7, not here.
//!
//! ARP is not IP at all: it has no addresses of the kind a flow is keyed on.
//!
//! Neither is dropped from the packet view; both still decode and print exactly
//! as before. They are counted in [`UntrackedCounts`] so the summary can say
//! what it left out rather than quietly narrowing the picture.

pub mod key;
pub mod stats;

pub use key::{Direction, Endpoint, FlowKey, FlowProtocol};
pub use stats::{DirectionStats, Flow, TcpDirectionFacts, TcpFacts};

use std::collections::HashMap;

use crate::capture::PacketMetadata;
use crate::decode::{DecodeStop, DecodedPacket, NetworkLayer, TransportLayer};

/// How many flows to track before refusing to start new ones.
///
/// A flow costs roughly 200 bytes plus hash-table overhead, so this bounds the
/// table at somewhere under 50 MB. That is generous for real traffic — a busy
/// office network produces tens of thousands of flows in an hour — while still
/// being a bound, which matters because the input is attacker-controlled: a
/// crafted capture can name a million distinct endpoints as cheaply as one.
///
/// Raise it with `--max-flows` when a real capture needs more.
pub const DEFAULT_MAX_FLOWS: usize = 100_000;

/// Why a packet could not be put into a flow.
///
/// Every one of these is a normal thing to see in a capture, not an error.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UntrackedCounts {
    /// ARP packets, which have no IP layer to key a flow on.
    pub arp: u64,
    /// ICMP and ICMPv6 messages, which have no ports.
    pub icmp: u64,
    /// Fragments other than the first, whose ports are in another packet.
    pub later_fragments: u64,
    /// Packets whose headers did not decode far enough to identify a flow.
    pub undecoded: u64,
    /// Packets carrying an IP protocol NetSentry forms no flows for.
    pub other_protocol: u64,
    /// Packets that would have started a new flow after the limit was reached.
    pub over_flow_limit: u64,
}

impl UntrackedCounts {
    /// How many packets were left out of the flow table altogether.
    pub fn total(self) -> u64 {
        self.arp
            .saturating_add(self.icmp)
            .saturating_add(self.later_fragments)
            .saturating_add(self.undecoded)
            .saturating_add(self.other_protocol)
            .saturating_add(self.over_flow_limit)
    }

    /// Whether anything at all was left out.
    pub fn any(self) -> bool {
        self.total() > 0
    }
}

/// What happened to one packet offered to the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// The packet was counted into a flow.
    Tracked,
    /// The packet belongs to no flow NetSentry forms.
    Untracked,
    /// The packet would have needed a new flow, and the limit was reached.
    OverLimit,
}

/// The set of conversations seen so far.
///
/// # Why a `HashMap`
///
/// Every packet does exactly one lookup here, so the per-packet cost is what
/// matters, and hashing is constant where a `BTreeMap` would be logarithmic in
/// the number of flows. The price is that iteration order is unspecified, which
/// would make output differ between runs — so the table is sorted once, at the
/// end, by [`FlowTable::flows_sorted`]. Paying `O(n log n)` once beats paying
/// `O(log n)` per packet on a capture with far more packets than flows.
#[derive(Debug)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    max_flows: usize,
    untracked: UntrackedCounts,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::with_limit(DEFAULT_MAX_FLOWS)
    }
}

impl FlowTable {
    /// Creates a table that will track at most `max_flows` conversations.
    pub fn with_limit(max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows,
            untracked: UntrackedCounts::default(),
        }
    }

    /// Folds one decoded packet into the table.
    ///
    /// Never fails. A packet that belongs to no flow, or that arrives after the
    /// limit is reached, is counted and the analysis continues — losing the
    /// rest of a capture because one packet did not fit would be a far worse
    /// outcome than an incomplete flow table that says so.
    pub fn record(&mut self, metadata: &PacketMetadata, packet: &DecodedPacket) -> RecordOutcome {
        let Some((key, direction)) = FlowKey::from_packet(packet) else {
            self.untracked_reason(packet);
            return RecordOutcome::Untracked;
        };

        // Looking the key up before deciding about the limit means an existing
        // flow keeps being counted even once the table is full. Only *new*
        // conversations are refused.
        if !self.flows.contains_key(&key) && self.flows.len() >= self.max_flows {
            self.untracked.over_flow_limit = self.untracked.over_flow_limit.saturating_add(1);
            return RecordOutcome::OverLimit;
        }

        self.flows
            .entry(key)
            .or_insert_with(|| Flow::new(key, metadata.timestamp))
            .record(
                direction,
                metadata.timestamp,
                metadata.caplen,
                metadata.wirelen,
                packet.transport.as_ref(),
            );

        RecordOutcome::Tracked
    }

    /// Works out why a packet formed no flow, and counts it.
    fn untracked_reason(&mut self, packet: &DecodedPacket) {
        let counter = match (&packet.network, &packet.transport, &packet.stopped) {
            (Some(NetworkLayer::Arp(_)), _, _) => &mut self.untracked.arp,
            (_, Some(TransportLayer::Icmp(_)), _) => &mut self.untracked.icmp,
            (Some(_), None, Some(DecodeStop::NonInitialFragment)) => {
                &mut self.untracked.later_fragments
            }
            (Some(_), None, Some(DecodeStop::UnsupportedProtocol(_))) => {
                &mut self.untracked.other_protocol
            }
            _ => &mut self.untracked.undecoded,
        };
        *counter = counter.saturating_add(1);
    }

    /// How many conversations are being tracked.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Whether no conversation has been seen.
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// The limit this table was built with.
    pub fn max_flows(&self) -> usize {
        self.max_flows
    }

    /// Whether the table has stopped accepting new conversations.
    pub fn is_full(&self) -> bool {
        self.flows.len() >= self.max_flows
    }

    /// What was left out, and why.
    pub fn untracked(&self) -> UntrackedCounts {
        self.untracked
    }

    /// Every flow, in a stable order.
    ///
    /// Sorted by when the conversation started, then by protocol and endpoints.
    /// The tie-breaks matter: without them two flows stamped at the same
    /// microsecond would come out in hash order, and the same capture would
    /// print differently between runs. Forensic output has to be reproducible.
    pub fn flows_sorted(&self) -> Vec<&Flow> {
        let mut flows: Vec<&Flow> = self.flows.values().collect();
        flows.sort_by(|left, right| {
            left.first_seen()
                .cmp(&right.first_seen())
                .then_with(|| left.key.cmp(&right.key))
        });
        flows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::PacketTimestamp;
    use crate::decode::{
        ArpOperation, ArpPacket, EtherType, IcmpFamily, IcmpMessage, IpProtocol, Ipv4Header,
        Ipv6Header, Layer, TcpFlags, TcpHeader, UdpHeader,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn metadata(number: u64, seconds: i64, caplen: u32, wirelen: u32) -> PacketMetadata {
        PacketMetadata {
            number,
            timestamp: PacketTimestamp::from_parts(seconds, 0),
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

    fn ipv6(source: u16, destination: u16) -> NetworkLayer {
        NetworkLayer::Ipv6(Ipv6Header {
            source: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, source),
            destination: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, destination),
            next_header: IpProtocol::Tcp,
            hop_limit: 64,
            payload_len: 20,
            traffic_class: 0,
            flow_label: 0,
            extension_headers: vec![],
            non_initial_fragment: false,
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

    fn udp(source_port: u16, destination_port: u16) -> TransportLayer {
        TransportLayer::Udp(UdpHeader {
            source_port,
            destination_port,
            length: 42,
            checksum: 0,
            captured_payload_len: 34,
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

    #[test]
    fn a_tcp_packet_creates_a_flow() {
        let mut table = FlowTable::default();
        let outcome = table.record(
            &metadata(1, 100, 74, 74),
            &packet(
                ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Tcp),
                tcp(53_122, 443, 0x002),
            ),
        );

        assert_eq!(outcome, RecordOutcome::Tracked);
        assert_eq!(table.len(), 1);
        let flows = table.flows_sorted();
        let flow = flows.first().copied().unwrap_or_else(|| unreachable!());
        assert_eq!(flow.key.protocol, FlowProtocol::Tcp);
        assert_eq!(flow.total_packets(), 1);
    }

    #[test]
    fn a_udp_packet_creates_a_flow() {
        let mut table = FlowTable::default();
        table.record(
            &metadata(1, 100, 74, 74),
            &packet(
                ipv4([192, 168, 1, 15], [8, 8, 8, 8], IpProtocol::Udp),
                udp(60_432, 53),
            ),
        );

        assert_eq!(table.len(), 1);
        assert_eq!(
            table.flows_sorted().first().map(|flow| flow.key.protocol),
            Some(FlowProtocol::Udp)
        );
    }

    #[test]
    fn the_reverse_packet_joins_the_same_flow() {
        for (forward, back) in [
            (tcp(53_122, 443, 0x002), tcp(443, 53_122, 0x012)),
            (udp(60_432, 53), udp(53, 60_432)),
        ] {
            let mut table = FlowTable::default();
            let protocol = match forward {
                TransportLayer::Tcp(_) => IpProtocol::Tcp,
                _ => IpProtocol::Udp,
            };

            table.record(
                &metadata(1, 100, 74, 74),
                &packet(ipv4([192, 168, 1, 15], [1, 1, 1, 1], protocol), forward),
            );
            table.record(
                &metadata(2, 101, 1500, 1500),
                &packet(ipv4([1, 1, 1, 1], [192, 168, 1, 15], protocol), back),
            );

            assert_eq!(table.len(), 1, "one conversation, not two");
            let flows = table.flows_sorted();
            let flow = flows.first().copied().unwrap_or_else(|| unreachable!());
            assert_eq!(flow.total_packets(), 2);
            assert_eq!(flow.a_to_b.packets, 1);
            assert_eq!(flow.b_to_a.packets, 1);
        }
    }

    #[test]
    fn arrival_order_does_not_change_the_table() {
        let forward = packet(
            ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Tcp),
            tcp(53_122, 443, 0x002),
        );
        let back = packet(
            ipv4([1, 1, 1, 1], [192, 168, 1, 15], IpProtocol::Tcp),
            tcp(443, 53_122, 0x012),
        );

        let mut one_way = FlowTable::default();
        one_way.record(&metadata(1, 100, 74, 74), &forward);
        one_way.record(&metadata(2, 101, 60, 60), &back);

        let mut other_way = FlowTable::default();
        other_way.record(&metadata(1, 101, 60, 60), &back);
        other_way.record(&metadata(2, 100, 74, 74), &forward);

        let left = one_way.flows_sorted();
        let right = other_way.flows_sorted();
        assert_eq!(left.len(), right.len());
        assert_eq!(
            left.first().map(|flow| flow.key),
            right.first().map(|f| f.key)
        );
        // Both saw one packet each way, whichever order they arrived in.
        assert_eq!(
            left.first()
                .map(|flow| (flow.a_to_b.packets, flow.b_to_a.packets)),
            right
                .first()
                .map(|flow| (flow.a_to_b.packets, flow.b_to_a.packets))
        );
    }

    #[test]
    fn different_ports_and_protocols_are_different_flows() {
        let mut table = FlowTable::default();
        let client = [192, 168, 1, 15];
        let server = [1, 1, 1, 1];

        table.record(
            &metadata(1, 100, 60, 60),
            &packet(
                ipv4(client, server, IpProtocol::Tcp),
                tcp(5_000, 443, 0x002),
            ),
        );
        table.record(
            &metadata(2, 100, 60, 60),
            &packet(
                ipv4(client, server, IpProtocol::Tcp),
                tcp(5_001, 443, 0x002),
            ),
        );
        table.record(
            &metadata(3, 100, 60, 60),
            &packet(ipv4(client, server, IpProtocol::Udp), udp(5_000, 443)),
        );

        assert_eq!(table.len(), 3);
    }

    #[test]
    fn ipv4_and_ipv6_conversations_stay_apart() {
        let mut table = FlowTable::default();
        table.record(
            &metadata(1, 100, 60, 60),
            &packet(
                ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Tcp),
                tcp(5_000, 443, 0x002),
            ),
        );
        table.record(
            &metadata(2, 100, 60, 60),
            &packet(ipv6(1, 2), tcp(5_000, 443, 0x002)),
        );

        assert_eq!(table.len(), 2);
    }

    #[test]
    fn directional_byte_counters_keep_caplen_and_wirelen_apart() {
        let mut table = FlowTable::default();
        // A capture with a small snapshot length.
        table.record(
            &metadata(1, 100, 64, 1514),
            &packet(
                ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Tcp),
                tcp(53_122, 443, 0x002),
            ),
        );
        table.record(
            &metadata(2, 101, 64, 590),
            &packet(
                ipv4([1, 1, 1, 1], [192, 168, 1, 15], IpProtocol::Tcp),
                tcp(443, 53_122, 0x012),
            ),
        );

        let flows = table.flows_sorted();
        let flow = flows.first().copied().unwrap_or_else(|| unreachable!());
        assert_eq!(flow.total_captured_bytes(), 128);
        assert_eq!(flow.total_wire_bytes(), 2104);
    }

    #[test]
    fn arp_icmp_and_later_fragments_are_counted_but_not_tracked() {
        let mut table = FlowTable::default();

        let arp = DecodedPacket {
            network: Some(NetworkLayer::Arp(ArpPacket {
                operation: ArpOperation::Request,
                hardware_type: 1,
                protocol_type: EtherType::Ipv4,
                addresses: None,
            })),
            ..DecodedPacket::default()
        };
        let icmp = packet(
            ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Icmp),
            TransportLayer::Icmp(IcmpMessage {
                family: IcmpFamily::V4,
                message_type: 8,
                code: 0,
                checksum: 0,
            }),
        );
        let fragment = DecodedPacket {
            network: Some(ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Tcp)),
            transport: None,
            stopped: Some(DecodeStop::NonInitialFragment),
            ..DecodedPacket::default()
        };
        let truncated = DecodedPacket {
            stopped: Some(DecodeStop::Truncated {
                layer: Layer::Network,
                protocol: "IPv4",
            }),
            ..DecodedPacket::default()
        };
        let gre = DecodedPacket {
            network: Some(ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Other(47))),
            transport: None,
            stopped: Some(DecodeStop::UnsupportedProtocol(IpProtocol::Other(47))),
            ..DecodedPacket::default()
        };

        for (index, decoded) in [arp, icmp, fragment, truncated, gre].iter().enumerate() {
            let outcome = table.record(&metadata(index as u64 + 1, 100, 60, 60), decoded);
            assert_eq!(outcome, RecordOutcome::Untracked);
        }

        assert!(table.is_empty(), "none of these form a conversation");
        let counts = table.untracked();
        assert_eq!(counts.arp, 1);
        assert_eq!(counts.icmp, 1);
        assert_eq!(counts.later_fragments, 1);
        assert_eq!(counts.undecoded, 1);
        assert_eq!(counts.other_protocol, 1);
        assert_eq!(counts.total(), 5);
        assert!(counts.any());
    }

    #[test]
    fn the_flow_limit_refuses_new_flows_without_losing_old_ones() {
        let mut table = FlowTable::with_limit(2);

        for port in [5_000u16, 5_001, 5_002, 5_003] {
            table.record(
                &metadata(1, 100, 60, 60),
                &packet(
                    ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Tcp),
                    tcp(port, 443, 0x002),
                ),
            );
        }

        assert_eq!(table.len(), 2, "the limit held");
        assert!(table.is_full());
        assert_eq!(table.untracked().over_flow_limit, 2);

        // An already-tracked conversation keeps being counted even when full.
        let outcome = table.record(
            &metadata(2, 101, 1500, 1500),
            &packet(
                ipv4([1, 1, 1, 1], [192, 168, 1, 15], IpProtocol::Tcp),
                tcp(443, 5_000, 0x012),
            ),
        );
        assert_eq!(outcome, RecordOutcome::Tracked);
        assert_eq!(table.len(), 2);
        let total: u64 = table.flows_sorted().iter().map(|f| f.total_packets()).sum();
        assert_eq!(total, 3, "one flow gained its reply packet");
    }

    #[test]
    fn flows_come_out_in_a_stable_order() {
        let mut table = FlowTable::default();
        // Deliberately inserted out of chronological order.
        for (seconds, port) in [(300i64, 5_002u16), (100, 5_000), (200, 5_001)] {
            table.record(
                &metadata(1, seconds, 60, 60),
                &packet(
                    ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Tcp),
                    tcp(port, 443, 0x002),
                ),
            );
        }

        let order: Vec<i64> = table
            .flows_sorted()
            .iter()
            .map(|flow| flow.first_seen().seconds())
            .collect();
        assert_eq!(order, vec![100, 200, 300], "sorted by when they started");

        // And repeated calls agree, which hash order would not guarantee.
        let first: Vec<FlowKey> = table.flows_sorted().iter().map(|f| f.key).collect();
        let second: Vec<FlowKey> = table.flows_sorted().iter().map(|f| f.key).collect();
        assert_eq!(first, second);
    }

    #[test]
    fn flows_starting_at_the_same_instant_still_have_a_fixed_order() {
        let mut table = FlowTable::default();
        for port in [5_003u16, 5_001, 5_002] {
            table.record(
                &metadata(1, 100, 60, 60),
                &packet(
                    ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Tcp),
                    tcp(port, 443, 0x002),
                ),
            );
        }

        let ports: Vec<u16> = table
            .flows_sorted()
            .iter()
            .map(|flow| flow.key.b.port)
            .collect();
        assert_eq!(ports, vec![5_001, 5_002, 5_003], "tie-broken by endpoint");
    }

    #[test]
    fn out_of_order_timestamps_do_not_produce_a_backwards_duration() {
        let mut table = FlowTable::default();
        let forward = packet(
            ipv4([192, 168, 1, 15], [1, 1, 1, 1], IpProtocol::Tcp),
            tcp(53_122, 443, 0x002),
        );

        table.record(&metadata(1, 500, 60, 60), &forward);
        table.record(&metadata(2, 100, 60, 60), &forward);
        table.record(&metadata(3, 300, 60, 60), &forward);

        let flows = table.flows_sorted();
        let flow = flows.first().copied().unwrap_or_else(|| unreachable!());
        assert_eq!(flow.first_seen().seconds(), 100);
        assert_eq!(flow.last_seen().seconds(), 500);
        assert_eq!(flow.duration(), Some(std::time::Duration::from_secs(400)));
    }

    #[test]
    fn an_empty_table_reports_nothing_rather_than_guessing() {
        let table = FlowTable::default();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert!(table.flows_sorted().is_empty());
        assert!(!table.untracked().any());
        assert_eq!(table.max_flows(), DEFAULT_MAX_FLOWS);
        assert!(!table.is_full());
    }
}
