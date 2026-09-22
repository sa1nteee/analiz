//! Identifying which conversation a packet belongs to.
//!
//! A flow is one conversation between two endpoints. The hard part is that the
//! same conversation arrives as packets going both ways, and the tool must not
//! report those as two separate things — so the identity of a flow has to be
//! independent of which direction a packet happened to be travelling, and of
//! which packet arrived first.

use std::fmt;
use std::net::IpAddr;

use crate::decode::{DecodedPacket, NetworkLayer, TransportLayer};

/// One end of a conversation.
///
/// Ordered so that a pair of endpoints has a canonical order. The derived
/// ordering compares the address first and the port second, and [`IpAddr`]'s
/// own ordering puts every IPv4 address before every IPv6 one — so an IPv4 and
/// an IPv6 endpoint can never compare equal, even when the IPv6 address is the
/// `::ffff:` mapped form of the IPv4 one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    /// The host's address.
    pub address: IpAddr,
    /// The transport port.
    pub port: u16,
}

impl Endpoint {
    /// Builds an endpoint.
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self { address, port }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.address {
            // An IPv6 address contains colons, so the port needs brackets
            // around the address to stay readable — the same convention URLs
            // use.
            IpAddr::V6(address) => write!(f, "[{address}]:{}", self.port),
            IpAddr::V4(address) => write!(f, "{address}:{}", self.port),
        }
    }
}

/// The transport protocols NetSentry forms flows for.
///
/// Deliberately not [`crate::decode::IpProtocol`]: that type can hold any
/// protocol number, and a flow can only exist for one with ports. Using a
/// narrower type means an ICMP flow cannot be constructed by mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlowProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl FlowProtocol {
    /// The protocol's usual name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

/// Which way along a flow a packet was travelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From endpoint A towards endpoint B.
    AtoB,
    /// From endpoint B towards endpoint A.
    BtoA,
}

/// The identity of one bidirectional conversation.
///
/// # Why the endpoints are sorted
///
/// The 5-tuple that identifies a flow — two addresses, two ports, a protocol —
/// describes one *direction*. Storing it as it arrives would file
/// `10.0.0.1:5000 → 1.1.1.1:443` and `1.1.1.1:443 → 10.0.0.1:5000` as two
/// unrelated conversations, which is exactly the opposite of what a flow is
/// for.
///
/// So the two endpoints are put in a fixed order, and the smaller one is always
/// A. That makes the key a property of the conversation rather than of the
/// packet that happened to be seen first: the same packets in any order produce
/// the same key, and the same A and B. Which direction a given packet was
/// going is not thrown away — it comes back from [`FlowKey::from_packet`]
/// alongside the key, and is what the directional counters are keyed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    /// The transport protocol.
    pub protocol: FlowProtocol,
    /// The lower-ordered endpoint.
    pub a: Endpoint,
    /// The higher-ordered endpoint.
    pub b: Endpoint,
}

impl FlowKey {
    /// Builds the canonical key for a packet travelling `source` to
    /// `destination`, together with which direction that is.
    pub fn canonical(
        protocol: FlowProtocol,
        source: Endpoint,
        destination: Endpoint,
    ) -> (Self, Direction) {
        if source <= destination {
            (
                Self {
                    protocol,
                    a: source,
                    b: destination,
                },
                Direction::AtoB,
            )
        } else {
            (
                Self {
                    protocol,
                    a: destination,
                    b: source,
                },
                Direction::BtoA,
            )
        }
    }

    /// Works out which flow a decoded packet belongs to.
    ///
    /// Returns [`None`] when the packet is not part of a trackable
    /// conversation. That covers more cases than it might seem, and all of them
    /// are deliberate rather than oversights:
    ///
    /// * **ARP** has no IP layer, so there is nothing to key on.
    /// * **ICMP** has no ports; see [`crate::flow`] for why it gets no flow.
    /// * **A non-initial fragment** carries no transport header, so its ports
    ///   are in a different packet. The decoder already refuses to invent them,
    ///   and this refuses to invent a flow from them.
    /// * **A truncated packet** whose transport header did not decode.
    ///
    /// The reason is not returned here; [`crate::flow::FlowTable`] works it out
    /// from the packet so that it can be counted.
    pub fn from_packet(packet: &DecodedPacket) -> Option<(Self, Direction)> {
        let (source_address, destination_address) = match packet.network.as_ref()? {
            NetworkLayer::Ipv4(header) => {
                (IpAddr::V4(header.source), IpAddr::V4(header.destination))
            }
            NetworkLayer::Ipv6(header) => {
                (IpAddr::V6(header.source), IpAddr::V6(header.destination))
            }
            NetworkLayer::Arp(_) => return None,
        };

        let (protocol, source_port, destination_port) = match packet.transport.as_ref()? {
            TransportLayer::Tcp(segment) => (
                FlowProtocol::Tcp,
                segment.source_port,
                segment.destination_port,
            ),
            TransportLayer::Udp(datagram) => (
                FlowProtocol::Udp,
                datagram.source_port,
                datagram.destination_port,
            ),
            TransportLayer::Icmp(_) => return None,
        };

        Some(Self::canonical(
            protocol,
            Endpoint::new(source_address, source_port),
            Endpoint::new(destination_address, destination_port),
        ))
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} \u{2194} {}",
            self.protocol.label(),
            self.a,
            self.b
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> Endpoint {
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    fn v6(last: u16, port: u16) -> Endpoint {
        Endpoint::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last)),
            port,
        )
    }

    #[test]
    fn both_directions_of_one_conversation_share_a_key() {
        let client = v4(192, 168, 1, 15, 53_122);
        let server = v4(142, 250, 184, 14, 443);

        let (outbound, out_direction) = FlowKey::canonical(FlowProtocol::Tcp, client, server);
        let (inbound, in_direction) = FlowKey::canonical(FlowProtocol::Tcp, server, client);

        assert_eq!(outbound, inbound, "one conversation, one key");
        assert_ne!(
            out_direction, in_direction,
            "but the two packets went opposite ways"
        );
    }

    #[test]
    fn the_key_does_not_depend_on_which_packet_arrived_first() {
        let one = v4(10, 0, 0, 1, 5_000);
        let other = v4(1, 1, 1, 1, 443);

        // Whichever way round the first packet was seen, A and B come out the
        // same, so two runs over the same capture agree.
        let (first, _) = FlowKey::canonical(FlowProtocol::Udp, one, other);
        let (second, _) = FlowKey::canonical(FlowProtocol::Udp, other, one);

        assert_eq!(first, second);
        assert_eq!(first.a, other, "the lower endpoint is always A");
        assert_eq!(first.b, one);
    }

    #[test]
    fn direction_reports_which_way_the_packet_actually_went() {
        let low = v4(1, 1, 1, 1, 443);
        let high = v4(10, 0, 0, 1, 5_000);

        assert_eq!(
            FlowKey::canonical(FlowProtocol::Tcp, low, high).1,
            Direction::AtoB
        );
        assert_eq!(
            FlowKey::canonical(FlowProtocol::Tcp, high, low).1,
            Direction::BtoA
        );
    }

    #[test]
    fn a_host_talking_to_itself_is_still_deterministic() {
        let endpoint = v4(127, 0, 0, 1, 5_000);
        let (key, direction) = FlowKey::canonical(FlowProtocol::Tcp, endpoint, endpoint);

        assert_eq!(key.a, key.b);
        assert_eq!(direction, Direction::AtoB);
    }

    #[test]
    fn different_ports_are_different_flows() {
        let client_a = v4(10, 0, 0, 1, 5_000);
        let client_b = v4(10, 0, 0, 1, 5_001);
        let server = v4(1, 1, 1, 1, 443);

        let (first, _) = FlowKey::canonical(FlowProtocol::Tcp, client_a, server);
        let (second, _) = FlowKey::canonical(FlowProtocol::Tcp, client_b, server);
        assert_ne!(first, second);
    }

    #[test]
    fn different_protocols_are_different_flows() {
        let client = v4(10, 0, 0, 1, 5_000);
        let server = v4(1, 1, 1, 1, 53);

        let (tcp, _) = FlowKey::canonical(FlowProtocol::Tcp, client, server);
        let (udp, _) = FlowKey::canonical(FlowProtocol::Udp, client, server);
        assert_ne!(tcp, udp, "same hosts and ports, different conversations");
    }

    #[test]
    fn ipv4_and_ipv6_endpoints_never_collide() {
        let four = v4(1, 2, 3, 4, 443);
        let six = v6(1, 443);
        assert_ne!(four, six);

        // Not even the IPv4-mapped form of the same address.
        let mapped = Endpoint::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304)),
            443,
        );
        assert_ne!(four, mapped);

        let (v4_flow, _) = FlowKey::canonical(FlowProtocol::Tcp, four, v4(5, 6, 7, 8, 80));
        let (v6_flow, _) = FlowKey::canonical(FlowProtocol::Tcp, six, v6(2, 80));
        assert_ne!(v4_flow, v6_flow);
    }

    #[test]
    fn ipv6_flows_are_canonical_too() {
        let one = v6(1, 5_000);
        let other = v6(2, 443);

        let (forward, forward_direction) = FlowKey::canonical(FlowProtocol::Tcp, one, other);
        let (back, back_direction) = FlowKey::canonical(FlowProtocol::Tcp, other, one);

        assert_eq!(forward, back);
        assert_eq!(forward.a, one, "2001:db8::1 sorts below 2001:db8::2");
        assert_eq!(forward_direction, Direction::AtoB);
        assert_eq!(back_direction, Direction::BtoA);
    }

    #[test]
    fn endpoints_print_readably_for_both_address_families() {
        assert_eq!(
            v4(192, 168, 1, 15, 53_122).to_string(),
            "192.168.1.15:53122"
        );
        assert_eq!(v6(1, 443).to_string(), "[2001:db8::1]:443");
    }

    #[test]
    fn a_flow_key_prints_as_a_two_way_conversation() {
        let (key, _) = FlowKey::canonical(
            FlowProtocol::Tcp,
            v4(192, 168, 1, 15, 53_122),
            v4(142, 250, 184, 14, 443),
        );
        assert_eq!(
            key.to_string(),
            "TCP 142.250.184.14:443 \u{2194} 192.168.1.15:53122"
        );
    }
}
