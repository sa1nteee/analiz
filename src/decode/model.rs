//! The decoded packet domain model.
//!
//! These types are NetSentry's own vocabulary for "what was on the wire". They
//! are deliberately richer than the terminal summary needs, because v0.4's flow
//! tracking and v0.7's detection rules will read them, and a field thrown away
//! here is a field those layers can never get back.
//!
//! Packet *payload* is the exception: it is not stored. Headers describe who
//! was talking; payload is what they said, and nothing in this version needs
//! that.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::decode::types::{EtherType, IpProtocol, MacAddress, TcpFlags};

/// Everything the decoder understood about one captured packet.
///
/// Layers are independently optional: a packet can have a link header and
/// nothing else (an unsupported EtherType), or a network header and no
/// transport header (a non-initial fragment). [`DecodedPacket::stopped`] says
/// why the chain ended where it did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DecodedPacket {
    /// The link-layer frame, when the link type was supported.
    pub link: Option<LinkFrame>,
    /// The network-layer header, when one was found and readable.
    pub network: Option<NetworkLayer>,
    /// The transport-layer header, when one was found and readable.
    pub transport: Option<TransportLayer>,
    /// Why decoding stopped, if it stopped before running out of layers.
    pub stopped: Option<DecodeStop>,
}

impl DecodedPacket {
    /// A packet that could not be decoded at all.
    pub fn stopped_at(stop: DecodeStop) -> Self {
        Self {
            stopped: Some(stop),
            ..Self::default()
        }
    }

    /// Whether decoding ended early for any reason.
    pub fn is_incomplete(&self) -> bool {
        self.stopped.is_some()
    }
}

/// Which protocol layer a decoder was working on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Ethernet, Linux SLL, VLAN tags.
    Link,
    /// IPv4, IPv6, ARP.
    Network,
    /// TCP, UDP, ICMP.
    Transport,
}

impl Layer {
    /// A short lowercase name for messages.
    pub fn label(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Network => "network",
            Self::Transport => "transport",
        }
    }
}

/// Why the decoder stopped before reaching the end of the protocol stack.
///
/// Every variant is a *result*, not a failure of the program: the packet is
/// reported as far as it was understood and the capture continues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeStop {
    /// The capture's link type has no decoder.
    UnsupportedLinkType {
        /// The `DLT_*` value reported by the capture driver.
        dlt: i32,
    },
    /// The packet ended in the middle of a header.
    Truncated {
        /// Where the packet ran out.
        layer: Layer,
        /// What was being read, for the user's benefit.
        protocol: &'static str,
    },
    /// A header was complete but its contents contradict themselves.
    Malformed {
        /// Where the contradiction was found.
        layer: Layer,
        /// What was being read.
        protocol: &'static str,
        /// What did not add up.
        reason: &'static str,
    },
    /// The link layer carried something NetSentry does not decode.
    UnsupportedEtherType(EtherType),
    /// The network layer carried something NetSentry does not decode.
    UnsupportedProtocol(IpProtocol),
    /// A non-initial IP fragment: the transport header is in an earlier packet,
    /// so there is nothing here to parse.
    NonInitialFragment,
    /// An IPv6 extension header chain that could not be followed safely.
    UnsupportedExtensionHeader(IpProtocol),
}

/// The link-layer frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkFrame {
    /// An Ethernet II frame.
    Ethernet(EthernetFrame),
    /// A Linux "cooked capture" pseudo-header.
    LinuxSll(LinuxSllFrame),
}

/// An Ethernet II frame header, with any VLAN tags that followed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    /// Where the frame came from.
    pub source: MacAddress,
    /// Where the frame was addressed.
    pub destination: MacAddress,
    /// The protocol of the payload, after any VLAN tags were stripped.
    pub ether_type: EtherType,
    /// VLAN tags, outermost first. Empty on an untagged frame.
    pub vlan_tags: Vec<VlanTag>,
}

/// An IEEE 802.1Q VLAN tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanTag {
    /// The tag protocol the tag was introduced by (`0x8100` or `0x88a8`).
    pub tag_protocol: EtherType,
    /// Priority code point: the 802.1p class of service, 0-7.
    pub priority: u8,
    /// Drop eligible indicator.
    pub drop_eligible: bool,
    /// VLAN identifier, 0-4095.
    pub id: u16,
}

/// A Linux SLL / SLL2 "cooked capture" header.
///
/// This pseudo-header replaces the real link header when capturing on the
/// `any` device, where frames from different link types are mixed together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSllFrame {
    /// Whether this is SLL (version 1) or SLL2.
    pub version: SllVersion,
    /// How the packet reached this host.
    pub packet_type: SllPacketType,
    /// The `ARPHRD_*` value describing the real link layer.
    pub arphrd_type: u16,
    /// The source link-layer address, as much of it as was reported.
    pub source_address: Vec<u8>,
    /// The protocol of the payload.
    pub protocol: EtherType,
}

/// Which Linux cooked-capture header version was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SllVersion {
    /// `DLT_LINUX_SLL` (113), a 16-byte header.
    V1,
    /// `DLT_LINUX_SLL2` (276), a 20-byte header.
    V2,
}

/// How a packet reached the capturing host, per Linux's `PACKET_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SllPacketType {
    /// Addressed to us.
    Host,
    /// A link-layer broadcast.
    Broadcast,
    /// A link-layer multicast.
    Multicast,
    /// Addressed to another host, seen because the interface is promiscuous.
    OtherHost,
    /// Sent by this host.
    Outgoing,
    /// Anything else, kept as reported.
    Other(u16),
}

impl SllPacketType {
    /// Classifies a raw `PACKET_*` value.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0 => Self::Host,
            1 => Self::Broadcast,
            2 => Self::Multicast,
            3 => Self::OtherHost,
            4 => Self::Outgoing,
            other => Self::Other(other),
        }
    }
}

/// The network-layer header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkLayer {
    /// An IPv4 header.
    Ipv4(Ipv4Header),
    /// An IPv6 header, with any extension headers that were walked.
    Ipv6(Ipv6Header),
    /// An ARP packet, which has no transport layer above it.
    Arp(ArpPacket),
}

/// An IPv4 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    /// Sender address.
    pub source: Ipv4Addr,
    /// Recipient address.
    pub destination: Ipv4Addr,
    /// The protocol of the payload.
    pub protocol: IpProtocol,
    /// Time to live: how many more routers may forward this packet.
    pub ttl: u8,
    /// Header length in bytes, including options. Always a multiple of 4.
    pub header_len: u8,
    /// Total packet length in bytes, as the sender declared it.
    pub total_len: u16,
    /// Identification field, used to reassemble fragments.
    pub identification: u16,
    /// Differentiated services code point.
    pub dscp: u8,
    /// Explicit congestion notification bits.
    pub ecn: u8,
    /// The "don't fragment" flag.
    pub dont_fragment: bool,
    /// The "more fragments" flag.
    pub more_fragments: bool,
    /// This fragment's offset within the original packet, in 8-byte units.
    pub fragment_offset: u16,
    /// Header checksum as it appeared. Not verified by NetSentry.
    pub checksum: u16,
    /// Length of the options that followed the fixed 20-byte header.
    pub options_len: u8,
}

impl Ipv4Header {
    /// Whether this packet is a piece of a larger one.
    pub fn is_fragment(&self) -> bool {
        self.more_fragments || self.fragment_offset > 0
    }

    /// Whether the transport header is missing because it was in an earlier
    /// fragment.
    pub fn is_non_initial_fragment(&self) -> bool {
        self.fragment_offset > 0
    }
}

/// An IPv6 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Header {
    /// Sender address.
    pub source: Ipv6Addr,
    /// Recipient address.
    pub destination: Ipv6Addr,
    /// The protocol after any extension headers were followed.
    pub next_header: IpProtocol,
    /// Hop limit: IPv6's name for TTL.
    pub hop_limit: u8,
    /// Payload length in bytes, as the sender declared it. Includes extension
    /// headers.
    pub payload_len: u16,
    /// Traffic class, IPv6's equivalent of DSCP plus ECN.
    pub traffic_class: u8,
    /// Flow label, used to group packets belonging to one stream.
    pub flow_label: u32,
    /// Extension headers walked, in the order they appeared.
    pub extension_headers: Vec<IpProtocol>,
    /// Whether a fragment header said this is not the first fragment.
    pub non_initial_fragment: bool,
}

/// An ARP packet.
///
/// Only the Ethernet/IPv4 form carries addresses; any other hardware or
/// protocol combination is reported by its numbers alone rather than
/// misinterpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket {
    /// What the sender is asking for or announcing.
    pub operation: ArpOperation,
    /// Hardware type, `1` for Ethernet.
    pub hardware_type: u16,
    /// Protocol type, `0x0800` for IPv4.
    pub protocol_type: EtherType,
    /// The addresses, when this is an Ethernet/IPv4 ARP packet.
    pub addresses: Option<ArpAddresses>,
}

/// The address quartet of an Ethernet/IPv4 ARP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpAddresses {
    /// The sender's MAC address.
    pub sender_mac: MacAddress,
    /// The sender's IPv4 address.
    pub sender_ip: Ipv4Addr,
    /// The target's MAC address; all-zero in a request.
    pub target_mac: MacAddress,
    /// The IPv4 address being asked about.
    pub target_ip: Ipv4Addr,
}

/// What an ARP packet is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    /// "Who has this IP?"
    Request,
    /// "I have this IP."
    Reply,
    /// Anything else, kept as reported.
    Other(u16),
}

impl ArpOperation {
    /// Classifies a raw operation code.
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::Request,
            2 => Self::Reply,
            other => Self::Other(other),
        }
    }
}

/// The transport-layer header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportLayer {
    /// A TCP header.
    Tcp(TcpHeader),
    /// A UDP header.
    Udp(UdpHeader),
    /// An ICMP or ICMPv6 message.
    Icmp(IcmpMessage),
}

/// A TCP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    /// Sender's port.
    pub source_port: u16,
    /// Recipient's port.
    pub destination_port: u16,
    /// Sequence number of the first byte of this segment.
    pub sequence: u32,
    /// The next sequence number the sender expects to receive.
    pub acknowledgment: u32,
    /// Header length in bytes, including options. Always a multiple of 4.
    pub header_len: u8,
    /// The control bits.
    pub flags: TcpFlags,
    /// How many more bytes the sender is willing to receive.
    pub window: u16,
    /// Checksum as it appeared. Not verified by NetSentry.
    pub checksum: u16,
    /// Urgent pointer.
    pub urgent_pointer: u16,
    /// Length of the options that followed the fixed 20-byte header.
    ///
    /// The options themselves are not parsed in this version; only their length
    /// matters, because it decides where the payload starts.
    pub options_len: u8,
}

/// A UDP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    /// Sender's port.
    pub source_port: u16,
    /// Recipient's port.
    pub destination_port: u16,
    /// Datagram length in bytes, including this 8-byte header, as declared.
    pub length: u16,
    /// Checksum as it appeared. Not verified by NetSentry.
    pub checksum: u16,
    /// Payload bytes actually present after the header.
    ///
    /// This can be smaller than `length` implies when the capture's snapshot
    /// length truncated the packet, and larger is a contradiction worth seeing.
    pub captured_payload_len: u16,
}

impl UdpHeader {
    /// The payload length the header claims, if the header is self-consistent.
    pub fn declared_payload_len(self) -> Option<u16> {
        self.length.checked_sub(Self::HEADER_LEN)
    }

    /// Size of a UDP header in bytes.
    pub const HEADER_LEN: u16 = 8;
}

/// An ICMP or ICMPv6 message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpMessage {
    /// Whether this is ICMP for IPv4 or ICMPv6.
    pub family: IcmpFamily,
    /// The message type.
    pub message_type: u8,
    /// The message code, whose meaning depends on the type.
    pub code: u8,
    /// Checksum as it appeared. Not verified by NetSentry.
    pub checksum: u16,
}

impl IcmpMessage {
    /// A human-readable name for this type and code, when one is known.
    ///
    /// Only the common messages are named. An unnamed message still reports its
    /// numbers, which is what matters.
    pub fn description(self) -> Option<&'static str> {
        match self.family {
            IcmpFamily::V4 => match self.message_type {
                0 => Some("Echo Reply"),
                3 => Some("Destination Unreachable"),
                5 => Some("Redirect"),
                8 => Some("Echo Request"),
                11 => Some("Time Exceeded"),
                12 => Some("Parameter Problem"),
                13 => Some("Timestamp Request"),
                14 => Some("Timestamp Reply"),
                _ => None,
            },
            IcmpFamily::V6 => match self.message_type {
                1 => Some("Destination Unreachable"),
                2 => Some("Packet Too Big"),
                3 => Some("Time Exceeded"),
                4 => Some("Parameter Problem"),
                128 => Some("Echo Request"),
                129 => Some("Echo Reply"),
                133 => Some("Router Solicitation"),
                134 => Some("Router Advertisement"),
                135 => Some("Neighbor Solicitation"),
                136 => Some("Neighbor Advertisement"),
                137 => Some("Redirect"),
                _ => None,
            },
        }
    }
}

/// Which ICMP an [`IcmpMessage`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpFamily {
    /// ICMP for IPv4.
    V4,
    /// ICMPv6.
    V6,
}

impl IcmpFamily {
    /// The protocol's usual name.
    pub fn label(self) -> &'static str {
        match self {
            Self::V4 => "ICMP",
            Self::V6 => "ICMPv6",
        }
    }
}
