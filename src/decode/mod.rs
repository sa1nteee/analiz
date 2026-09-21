//! Packet decoding.
//!
//! # What this layer is
//!
//! One pure function: [`decode`] takes a link type and a slice of bytes and
//! returns what it understood. It knows nothing about libpcap, about which
//! interface the bytes came from, or about where the answer will be printed,
//! and it holds no state between calls. That makes it testable against
//! hand-built byte arrays with no network, no privileges and no capture, and it
//! makes it a ready-made `cargo-fuzz` target: the whole interface is
//! `(link, &[u8]) -> DecodedPacket`, with no failure mode other than a value.
//!
//! # Handling hostile input
//!
//! Every byte reaching this layer came off a network and is untrusted. Three
//! things keep that safe:
//!
//! * `unsafe_code = "forbid"` on the crate, so no length mistake here can ever
//!   become a memory-safety bug. The compiler enforces this; it is not a
//!   promise made in a comment.
//! * [`bytes::ByteReader`], through which every read goes. There is no indexing
//!   anywhere in this module, so there is nothing to get wrong.
//! * Bounded loops. VLAN tag stacks and IPv6 extension header chains are both
//!   attacker-controlled, and both are capped.
//!
//! A malformed packet therefore produces a *result* — a [`DecodedPacket`] whose
//! [`stopped`](DecodedPacket::stopped) field says how far decoding got — never
//! a panic, and never a stopped capture.
//!
//! # What it deliberately does not do
//!
//! Payload is not stored, checksums are not verified, and nothing above the
//! transport header is parsed. Where a header cannot be located with certainty
//! — a non-initial fragment, an unfollowable extension header chain — decoding
//! stops and says so, rather than reading bytes at a guessed offset.

pub mod bytes;
pub mod link;
pub mod model;
pub mod net;
pub mod transport;
pub mod types;

pub use model::{
    ArpAddresses, ArpOperation, ArpPacket, DecodeStop, DecodedPacket, EthernetFrame, IcmpFamily,
    IcmpMessage, Ipv4Header, Ipv6Header, Layer, LinkFrame, LinuxSllFrame, NetworkLayer,
    SllPacketType, SllVersion, TcpHeader, TransportLayer, UdpHeader, VlanTag,
};
pub use types::{EtherType, IpProtocol, MacAddress, TcpFlags};

use crate::decode::link::LinkResult;
use crate::decode::net::NetworkResult;

/// The link-layer format of a capture, as far as decoding is concerned.
///
/// This is a separate type from the capture layer's `LinkType` on purpose: the
/// decoder must not depend on the capture layer, and it needs no name or
/// description, only enough to pick a parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkLayer {
    /// `DLT_EN10MB` (1): Ethernet II, by far the common case.
    Ethernet,
    /// `DLT_LINUX_SLL` (113): Linux cooked capture, used by the `any` device.
    LinuxSll,
    /// `DLT_LINUX_SLL2` (276): the newer cooked-capture header.
    LinuxSll2,
    /// A link type NetSentry has no decoder for.
    Unsupported(i32),
}

impl LinkLayer {
    /// Classifies a `DLT_*` value from the capture driver.
    pub fn from_dlt(dlt: i32) -> Self {
        match dlt {
            1 => Self::Ethernet,
            113 => Self::LinuxSll,
            276 => Self::LinuxSll2,
            other => Self::Unsupported(other),
        }
    }

    /// The `DLT_*` value this corresponds to.
    pub fn as_dlt(self) -> i32 {
        match self {
            Self::Ethernet => 1,
            Self::LinuxSll => 113,
            Self::LinuxSll2 => 276,
            Self::Unsupported(dlt) => dlt,
        }
    }
}

/// Decodes one captured packet.
///
/// Never fails and never panics: an undecodable packet comes back as a
/// [`DecodedPacket`] carrying whatever was understood plus a
/// [`DecodeStop`] explaining where decoding ended.
pub fn decode(link: LinkLayer, bytes: &[u8]) -> DecodedPacket {
    let link_result = match link {
        LinkLayer::Ethernet => link::decode_ethernet(bytes),
        LinkLayer::LinuxSll => link::decode_linux_sll(bytes),
        LinkLayer::LinuxSll2 => link::decode_linux_sll2(bytes),
        LinkLayer::Unsupported(dlt) => {
            return DecodedPacket::stopped_at(DecodeStop::UnsupportedLinkType { dlt });
        }
    };

    match link_result {
        Ok(result) => decode_above_link(result),
        Err(stop) => DecodedPacket::stopped_at(stop),
    }
}

/// Continues from a decoded link frame into the network layer.
fn decode_above_link(link: LinkResult<'_>) -> DecodedPacket {
    let mut packet = DecodedPacket {
        link: Some(link.frame),
        ..DecodedPacket::default()
    };

    let network_result = match link.payload_type {
        EtherType::Ipv4 => net::decode_ipv4(link.payload),
        EtherType::Ipv6 => net::decode_ipv6(link.payload),
        EtherType::Arp => net::decode_arp(link.payload),
        other => {
            packet.stopped = Some(DecodeStop::UnsupportedEtherType(other));
            return packet;
        }
    };

    match network_result {
        Ok(result) => decode_above_network(packet, result),
        Err(stop) => {
            packet.stopped = Some(stop);
            packet
        }
    }
}

/// Continues from a decoded network header into the transport layer.
fn decode_above_network(mut packet: DecodedPacket, network: NetworkResult<'_>) -> DecodedPacket {
    packet.network = Some(network.layer);

    let Some(protocol) = network.payload_protocol else {
        packet.stopped = network.stopped;
        return packet;
    };

    let transport_result = match protocol {
        IpProtocol::Tcp => transport::decode_tcp(network.payload),
        IpProtocol::Udp => transport::decode_udp(network.payload),
        IpProtocol::Icmp => transport::decode_icmp(network.payload, IcmpFamily::V4),
        IpProtocol::Icmpv6 => transport::decode_icmp(network.payload, IcmpFamily::V6),
        other => {
            packet.stopped = Some(DecodeStop::UnsupportedProtocol(other));
            return packet;
        }
    };

    match transport_result {
        Ok(layer) => packet.transport = Some(layer),
        Err(stop) => packet.stopped = Some(stop),
    }
    packet
}
