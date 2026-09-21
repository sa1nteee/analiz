//! Primitive protocol values.
//!
//! These are the small, reusable pieces the packet headers are built from: a
//! MAC address, an EtherType, an IP protocol number, a set of TCP flags. They
//! are separate types rather than bare integers so that a port number can never
//! be mistaken for a protocol number, and so each one owns its own formatting.
//!
//! Every enum here keeps an `Other(..)` variant carrying the raw value. A
//! protocol number NetSentry has never heard of is still a fact worth
//! reporting; discarding it would be the parser lying about what was on the
//! wire.

use std::fmt;

/// A 48-bit link-layer (MAC) address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// The broadcast address `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);

    /// The all-zero address, used by ARP to mean "unknown".
    pub const UNSPECIFIED: Self = Self([0x00; 6]);

    /// Whether this is the link-layer broadcast address.
    pub fn is_broadcast(self) -> bool {
        self == Self::BROADCAST
    }

    /// Whether the multicast bit (the low bit of the first octet) is set.
    pub fn is_multicast(self) -> bool {
        self.0.first().is_some_and(|first| first & 0x01 != 0)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// The protocol carried by an Ethernet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    /// IPv4 (`0x0800`).
    Ipv4,
    /// ARP (`0x0806`).
    Arp,
    /// IPv6 (`0x86dd`).
    Ipv6,
    /// 802.1Q VLAN tag (`0x8100`).
    Vlan,
    /// 802.1ad service VLAN tag (`0x88a8`).
    VlanQinQ,
    /// A value below `0x0600`, which in IEEE 802.3 is a length, not a type.
    Length(u16),
    /// Anything else, kept as reported.
    Other(u16),
}

impl EtherType {
    /// Values below this are an 802.3 length field rather than a type.
    const MIN_ETHER_TYPE: u16 = 0x0600;

    /// Classifies a raw EtherType field.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86dd => Self::Ipv6,
            0x8100 => Self::Vlan,
            0x88a8 => Self::VlanQinQ,
            other if other < Self::MIN_ETHER_TYPE => Self::Length(other),
            other => Self::Other(other),
        }
    }

    /// The raw value as it appeared on the wire.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Ipv4 => 0x0800,
            Self::Arp => 0x0806,
            Self::Ipv6 => 0x86dd,
            Self::Vlan => 0x8100,
            Self::VlanQinQ => 0x88a8,
            Self::Length(value) | Self::Other(value) => value,
        }
    }

    /// Whether this tag introduces another VLAN tag.
    pub fn is_vlan(self) -> bool {
        matches!(self, Self::Vlan | Self::VlanQinQ)
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4 => f.write_str("IPv4"),
            Self::Arp => f.write_str("ARP"),
            Self::Ipv6 => f.write_str("IPv6"),
            Self::Vlan => f.write_str("802.1Q"),
            Self::VlanQinQ => f.write_str("802.1ad"),
            Self::Length(value) => write!(f, "802.3 length {value}"),
            Self::Other(value) => write!(f, "EtherType 0x{value:04x}"),
        }
    }
}

/// An IP protocol number, from IPv4's `protocol` or IPv6's `next header`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    /// IPv6 Hop-by-Hop options (0).
    HopByHop,
    /// ICMP for IPv4 (1).
    Icmp,
    /// TCP (6).
    Tcp,
    /// UDP (17).
    Udp,
    /// IPv6 routing header (43).
    Ipv6Route,
    /// IPv6 fragment header (44).
    Ipv6Fragment,
    /// Encapsulating Security Payload (50).
    Esp,
    /// Authentication Header (51).
    AuthHeader,
    /// ICMP for IPv6 (58).
    Icmpv6,
    /// "No next header" (59).
    NoNextHeader,
    /// IPv6 destination options (60).
    Ipv6DestOpts,
    /// Mobility header (135).
    Mobility,
    /// Anything else, kept as reported.
    Other(u8),
}

impl IpProtocol {
    /// Classifies a raw protocol number.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::HopByHop,
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            43 => Self::Ipv6Route,
            44 => Self::Ipv6Fragment,
            50 => Self::Esp,
            51 => Self::AuthHeader,
            58 => Self::Icmpv6,
            59 => Self::NoNextHeader,
            60 => Self::Ipv6DestOpts,
            135 => Self::Mobility,
            other => Self::Other(other),
        }
    }

    /// The raw value as it appeared on the wire.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::HopByHop => 0,
            Self::Icmp => 1,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Ipv6Route => 43,
            Self::Ipv6Fragment => 44,
            Self::Esp => 50,
            Self::AuthHeader => 51,
            Self::Icmpv6 => 58,
            Self::NoNextHeader => 59,
            Self::Ipv6DestOpts => 60,
            Self::Mobility => 135,
            Self::Other(value) => value,
        }
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HopByHop => f.write_str("Hop-by-Hop"),
            Self::Icmp => f.write_str("ICMP"),
            Self::Tcp => f.write_str("TCP"),
            Self::Udp => f.write_str("UDP"),
            Self::Ipv6Route => f.write_str("IPv6-Route"),
            Self::Ipv6Fragment => f.write_str("IPv6-Frag"),
            Self::Esp => f.write_str("ESP"),
            Self::AuthHeader => f.write_str("AH"),
            Self::Icmpv6 => f.write_str("ICMPv6"),
            Self::NoNextHeader => f.write_str("no-next-header"),
            Self::Ipv6DestOpts => f.write_str("IPv6-DestOpts"),
            Self::Mobility => f.write_str("Mobility"),
            Self::Other(value) => write!(f, "IP protocol {value}"),
        }
    }
}

/// The TCP control bits.
///
/// Stored as the raw field rather than nine booleans so that reserved and
/// future bits survive, and so the value can be compared cheaply by later
/// analysis (a flow tracker cares about exact flag combinations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u16);

impl TcpFlags {
    const FIN: u16 = 0x001;
    const SYN: u16 = 0x002;
    const RST: u16 = 0x004;
    const PSH: u16 = 0x008;
    const ACK: u16 = 0x010;
    const URG: u16 = 0x020;
    const ECE: u16 = 0x040;
    const CWR: u16 = 0x080;
    const NS: u16 = 0x100;

    /// Flag names in the order they are conventionally written, so that a
    /// SYN/ACK reads `SYN,ACK` rather than `ACK,SYN`.
    const NAMES: [(u16, &'static str); 9] = [
        (Self::SYN, "SYN"),
        (Self::FIN, "FIN"),
        (Self::RST, "RST"),
        (Self::PSH, "PSH"),
        (Self::ACK, "ACK"),
        (Self::URG, "URG"),
        (Self::ECE, "ECE"),
        (Self::CWR, "CWR"),
        (Self::NS, "NS"),
    ];

    /// Whether a given flag is set.
    fn has(self, flag: u16) -> bool {
        self.0 & flag != 0
    }

    /// SYN without ACK: a connection attempt.
    pub fn is_syn(self) -> bool {
        self.has(Self::SYN) && !self.has(Self::ACK)
    }

    /// SYN with ACK: a connection being accepted.
    pub fn is_syn_ack(self) -> bool {
        self.has(Self::SYN) && self.has(Self::ACK)
    }

    /// RST: a connection being refused or torn down.
    pub fn is_reset(self) -> bool {
        self.has(Self::RST)
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (bit, name) in Self::NAMES {
            if self.has(bit) {
                if !first {
                    f.write_str(",")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            // No bits set at all: say so rather than printing nothing.
            f.write_str("none")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_addresses_print_in_the_conventional_form() {
        let mac = MacAddress([0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc]);
        assert_eq!(mac.to_string(), "00:11:22:aa:bb:cc");
        assert_eq!(MacAddress::BROADCAST.to_string(), "ff:ff:ff:ff:ff:ff");
    }

    #[test]
    fn broadcast_and_multicast_are_recognised() {
        assert!(MacAddress::BROADCAST.is_broadcast());
        assert!(MacAddress::BROADCAST.is_multicast());
        // IPv4 multicast MACs start 01:00:5e.
        assert!(MacAddress([0x01, 0x00, 0x5e, 0, 0, 1]).is_multicast());
        assert!(!MacAddress([0x00, 0x11, 0x22, 0, 0, 1]).is_multicast());
        assert!(!MacAddress::UNSPECIFIED.is_broadcast());
    }

    #[test]
    fn ether_types_round_trip_through_their_raw_value() {
        for raw in [
            0x0800, 0x0806, 0x86dd, 0x8100, 0x88a8, 0x88cc, 0x0001, 0x05dc,
        ] {
            assert_eq!(EtherType::from_u16(raw).as_u16(), raw, "raw {raw:#06x}");
        }
    }

    #[test]
    fn small_ether_type_values_are_lengths_not_types() {
        // In IEEE 802.3 a value of 1500 or below is a payload length.
        assert_eq!(EtherType::from_u16(0x05dc), EtherType::Length(1500));
        assert_eq!(EtherType::from_u16(0x05ff), EtherType::Length(0x05ff));
        assert_eq!(EtherType::from_u16(0x0600), EtherType::Other(0x0600));
    }

    #[test]
    fn unknown_ether_types_keep_their_value_and_print_it() {
        // LLDP, which NetSentry does not decode.
        let lldp = EtherType::from_u16(0x88cc);
        assert_eq!(lldp, EtherType::Other(0x88cc));
        assert_eq!(lldp.to_string(), "EtherType 0x88cc");
    }

    #[test]
    fn vlan_tags_are_flagged_as_such() {
        assert!(EtherType::Vlan.is_vlan());
        assert!(EtherType::VlanQinQ.is_vlan());
        assert!(!EtherType::Ipv4.is_vlan());
    }

    #[test]
    fn ip_protocols_round_trip_and_name_themselves() {
        for raw in [0u8, 1, 6, 17, 43, 44, 50, 51, 58, 59, 60, 135, 200, 255] {
            assert_eq!(IpProtocol::from_u8(raw).as_u8(), raw, "raw {raw}");
        }
        assert_eq!(IpProtocol::from_u8(6).to_string(), "TCP");
        assert_eq!(IpProtocol::from_u8(200).to_string(), "IP protocol 200");
    }

    #[test]
    fn tcp_flags_are_written_the_way_people_read_them() {
        assert_eq!(TcpFlags(0x002).to_string(), "SYN");
        assert_eq!(TcpFlags(0x012).to_string(), "SYN,ACK");
        assert_eq!(TcpFlags(0x011).to_string(), "FIN,ACK");
        assert_eq!(TcpFlags(0x004).to_string(), "RST");
        assert_eq!(TcpFlags(0x018).to_string(), "PSH,ACK");
        assert_eq!(TcpFlags(0x000).to_string(), "none");
    }

    #[test]
    fn tcp_flag_predicates_distinguish_handshake_stages() {
        assert!(TcpFlags(0x002).is_syn());
        assert!(!TcpFlags(0x012).is_syn(), "SYN/ACK is not a bare SYN");
        assert!(TcpFlags(0x012).is_syn_ack());
        assert!(TcpFlags(0x014).is_reset());
        assert!(!TcpFlags(0x010).is_syn());
    }

    #[test]
    fn reserved_tcp_bits_are_not_silently_dropped() {
        // The NS bit plus an unassigned reserved bit.
        let flags = TcpFlags(0x102);
        assert_eq!(flags.0, 0x102);
        assert_eq!(flags.to_string(), "SYN,NS");
    }
}
