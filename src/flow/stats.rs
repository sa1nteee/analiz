//! What a flow accumulates as its packets go by.

use std::time::Duration;

use crate::capture::PacketTimestamp;
use crate::decode::{TcpFlags, TransportLayer};
use crate::flow::key::{Direction, FlowKey};

/// Counters for one direction of a flow.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DirectionStats {
    /// Packets seen travelling this way.
    pub packets: u64,
    /// Bytes of those packets that the capture actually kept.
    pub captured_bytes: u64,
    /// Bytes those packets occupied on the wire.
    ///
    /// Larger than `captured_bytes` when the capture's snapshot length
    /// truncated them. Kept separate so that "how much data moved" and "how
    /// much data we have" stay distinguishable.
    pub wire_bytes: u64,
}

impl DirectionStats {
    /// Adds one packet.
    ///
    /// Saturating throughout: the lengths come from a capture file, which is
    /// attacker-controlled input. A counter that stops climbing is wrong; a
    /// tool that aborts mid-analysis because a counter wrapped is worse.
    fn record(&mut self, caplen: u32, wirelen: u32) {
        self.packets = self.packets.saturating_add(1);
        self.captured_bytes = self.captured_bytes.saturating_add(u64::from(caplen));
        self.wire_bytes = self.wire_bytes.saturating_add(u64::from(wirelen));
    }
}

/// Cheap TCP facts for one direction of a flow.
///
/// These are counters and a bitwise OR, not a state machine. Knowing that one
/// side sent forty SYNs and the other sent no SYN/ACKs is the kind of thing
/// v0.7 will ask about; working out what state the connection was in is not
/// something this version attempts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TcpDirectionFacts {
    /// Every flag bit seen in this direction, OR-ed together.
    pub flags_seen: TcpFlags,
    /// Segments with SYN set.
    pub syn: u64,
    /// Segments with FIN set.
    pub fin: u64,
    /// Segments with RST set.
    pub rst: u64,
}

impl TcpDirectionFacts {
    /// Folds one segment's flags in.
    fn record(&mut self, flags: TcpFlags) {
        self.flags_seen = TcpFlags(self.flags_seen.0 | flags.0);
        if flags.has_syn() {
            self.syn = self.syn.saturating_add(1);
        }
        if flags.has_fin() {
            self.fin = self.fin.saturating_add(1);
        }
        if flags.is_reset() {
            self.rst = self.rst.saturating_add(1);
        }
    }
}

/// TCP facts for both directions of a flow.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TcpFacts {
    /// Facts about packets from A to B.
    pub a_to_b: TcpDirectionFacts,
    /// Facts about packets from B to A.
    pub b_to_a: TcpDirectionFacts,
}

/// One tracked conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    /// Which conversation this is.
    pub key: FlowKey,
    /// The earliest timestamp seen on any of its packets.
    first_seen: PacketTimestamp,
    /// The latest timestamp seen on any of its packets.
    last_seen: PacketTimestamp,
    /// Counters for packets from A to B.
    pub a_to_b: DirectionStats,
    /// Counters for packets from B to A.
    pub b_to_a: DirectionStats,
    /// TCP facts, when this is a TCP flow.
    pub tcp: Option<TcpFacts>,
}

impl Flow {
    /// Starts a flow from its first packet.
    pub fn new(key: FlowKey, timestamp: PacketTimestamp) -> Self {
        Self {
            key,
            first_seen: timestamp,
            last_seen: timestamp,
            a_to_b: DirectionStats::default(),
            b_to_a: DirectionStats::default(),
            tcp: None,
        }
    }

    /// Folds one packet into the flow.
    pub fn record(
        &mut self,
        direction: Direction,
        timestamp: PacketTimestamp,
        caplen: u32,
        wirelen: u32,
        transport: Option<&TransportLayer>,
    ) {
        // Minimum and maximum, not first and last arrival. Capture files are
        // not required to be in timestamp order and real ones sometimes are
        // not, so taking the ends of the range keeps the duration from going
        // backwards.
        self.first_seen = self.first_seen.min(timestamp);
        self.last_seen = self.last_seen.max(timestamp);

        match direction {
            Direction::AtoB => self.a_to_b.record(caplen, wirelen),
            Direction::BtoA => self.b_to_a.record(caplen, wirelen),
        }

        if let Some(TransportLayer::Tcp(segment)) = transport {
            let facts = self.tcp.get_or_insert_with(TcpFacts::default);
            match direction {
                Direction::AtoB => facts.a_to_b.record(segment.flags),
                Direction::BtoA => facts.b_to_a.record(segment.flags),
            }
        }
    }

    /// The earliest timestamp seen on this flow.
    pub fn first_seen(&self) -> PacketTimestamp {
        self.first_seen
    }

    /// The latest timestamp seen on this flow.
    pub fn last_seen(&self) -> PacketTimestamp {
        self.last_seen
    }

    /// How long the conversation lasted.
    ///
    /// Returns [`None`] when either end is a timestamp that is not a point in
    /// time, rather than producing a duration from nonsense.
    pub fn duration(&self) -> Option<Duration> {
        let micros = self.last_seen.micros_since_epoch()? - self.first_seen.micros_since_epoch()?;
        u64::try_from(micros).ok().map(Duration::from_micros)
    }

    /// Packets in both directions.
    pub fn total_packets(&self) -> u64 {
        self.a_to_b.packets.saturating_add(self.b_to_a.packets)
    }

    /// Captured bytes in both directions.
    pub fn total_captured_bytes(&self) -> u64 {
        self.a_to_b
            .captured_bytes
            .saturating_add(self.b_to_a.captured_bytes)
    }

    /// Wire bytes in both directions.
    pub fn total_wire_bytes(&self) -> u64 {
        self.a_to_b
            .wire_bytes
            .saturating_add(self.b_to_a.wire_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{TcpHeader, TransportLayer};
    use crate::flow::key::{Endpoint, FlowProtocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn endpoint(last: u8, port: u16) -> Endpoint {
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)), port)
    }

    fn key() -> FlowKey {
        FlowKey::canonical(FlowProtocol::Tcp, endpoint(1, 5_000), endpoint(2, 443)).0
    }

    fn ts(seconds: i64, micros: i64) -> PacketTimestamp {
        PacketTimestamp::from_parts(seconds, micros)
    }

    fn tcp(flags: u16) -> TransportLayer {
        TransportLayer::Tcp(TcpHeader {
            source_port: 5_000,
            destination_port: 443,
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

    #[test]
    fn packets_are_counted_in_the_direction_they_travelled() {
        let mut flow = Flow::new(key(), ts(100, 0));
        flow.record(Direction::AtoB, ts(100, 0), 74, 74, None);
        flow.record(Direction::AtoB, ts(101, 0), 66, 66, None);
        flow.record(Direction::BtoA, ts(102, 0), 1500, 1500, None);

        assert_eq!(flow.a_to_b.packets, 2);
        assert_eq!(flow.b_to_a.packets, 1);
        assert_eq!(flow.total_packets(), 3);
    }

    #[test]
    fn captured_and_wire_bytes_are_counted_separately() {
        let mut flow = Flow::new(key(), ts(100, 0));
        // A capture with a small snapshot length: 64 bytes kept of a 1514-byte
        // frame.
        flow.record(Direction::AtoB, ts(100, 0), 64, 1514, None);
        flow.record(Direction::BtoA, ts(101, 0), 64, 590, None);

        assert_eq!(flow.a_to_b.captured_bytes, 64);
        assert_eq!(flow.a_to_b.wire_bytes, 1514);
        assert_eq!(flow.total_captured_bytes(), 128);
        assert_eq!(flow.total_wire_bytes(), 2104);
    }

    #[test]
    fn byte_counters_saturate_rather_than_wrapping() {
        let mut flow = Flow::new(key(), ts(0, 0));
        flow.a_to_b = DirectionStats {
            packets: u64::MAX,
            captured_bytes: u64::MAX,
            wire_bytes: u64::MAX - 1,
        };
        flow.record(Direction::AtoB, ts(0, 0), u32::MAX, u32::MAX, None);

        assert_eq!(flow.a_to_b.packets, u64::MAX);
        assert_eq!(flow.a_to_b.wire_bytes, u64::MAX);
        assert_eq!(flow.total_packets(), u64::MAX);
    }

    #[test]
    fn first_and_last_seen_are_the_extremes_not_the_arrival_order() {
        let mut flow = Flow::new(key(), ts(500, 0));
        // Deliberately out of order, as a merged or clock-adjusted capture is.
        flow.record(Direction::AtoB, ts(500, 0), 60, 60, None);
        flow.record(Direction::AtoB, ts(100, 0), 60, 60, None);
        flow.record(Direction::BtoA, ts(900, 0), 60, 60, None);
        flow.record(Direction::AtoB, ts(300, 0), 60, 60, None);

        assert_eq!(flow.first_seen(), ts(100, 0));
        assert_eq!(flow.last_seen(), ts(900, 0));
        assert_eq!(flow.duration(), Some(Duration::from_secs(800)));
    }

    #[test]
    fn a_single_packet_flow_lasts_no_time() {
        let mut flow = Flow::new(key(), ts(100, 123_456));
        flow.record(Direction::AtoB, ts(100, 123_456), 60, 60, None);

        assert_eq!(flow.duration(), Some(Duration::ZERO));
        assert_eq!(flow.first_seen(), flow.last_seen());
    }

    #[test]
    fn duration_keeps_microsecond_resolution() {
        let mut flow = Flow::new(key(), ts(100, 250_000));
        flow.record(Direction::AtoB, ts(100, 250_000), 60, 60, None);
        flow.record(Direction::BtoA, ts(102, 990_123), 60, 60, None);

        assert_eq!(flow.duration(), Some(Duration::from_micros(2_740_123)));
    }

    #[test]
    fn a_malformed_timestamp_yields_no_duration_rather_than_a_wrong_one() {
        let mut flow = Flow::new(key(), ts(100, 0));
        flow.record(Direction::AtoB, ts(100, -1), 60, 60, None);

        assert_eq!(flow.duration(), None);
        // The packet was still counted: a bad clock is not a reason to lose it.
        assert_eq!(flow.total_packets(), 1);
    }

    #[test]
    fn tcp_flags_accumulate_per_direction() {
        let mut flow = Flow::new(key(), ts(100, 0));
        flow.record(Direction::AtoB, ts(100, 0), 60, 60, Some(&tcp(0x002))); // SYN
        flow.record(Direction::BtoA, ts(101, 0), 60, 60, Some(&tcp(0x012))); // SYN,ACK
        flow.record(Direction::AtoB, ts(102, 0), 60, 60, Some(&tcp(0x010))); // ACK
        flow.record(Direction::AtoB, ts(103, 0), 60, 60, Some(&tcp(0x011))); // FIN,ACK
        flow.record(Direction::BtoA, ts(104, 0), 60, 60, Some(&tcp(0x004))); // RST

        let facts = flow.tcp.unwrap_or_default();
        assert_eq!(facts.a_to_b.syn, 1);
        assert_eq!(facts.a_to_b.fin, 1);
        assert_eq!(facts.a_to_b.rst, 0);
        assert_eq!(facts.b_to_a.syn, 1);
        assert_eq!(facts.b_to_a.rst, 1);
        // Every bit either side ever set, OR-ed together.
        assert_eq!(facts.a_to_b.flags_seen.to_string(), "SYN,FIN,ACK");
        assert_eq!(facts.b_to_a.flags_seen.to_string(), "SYN,RST,ACK");
    }

    #[test]
    fn a_udp_flow_carries_no_tcp_facts() {
        let mut flow = Flow::new(key(), ts(100, 0));
        flow.record(Direction::AtoB, ts(100, 0), 60, 60, None);
        assert_eq!(flow.tcp, None);
    }
}
