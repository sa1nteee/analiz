//! Rendering a decoded packet as one line of terminal output.
//!
//! This module contains no decoding logic whatsoever: it reads an already
//! decoded [`DecodedPacket`] and turns it into text. That separation is what
//! lets the decoder be tested against byte arrays and the renderer be tested
//! against hand-built models, neither needing the other to be correct.

use std::fmt::Write as _;

use crate::capture::PacketMetadata;
use crate::decode::{
    ArpOperation, ArpPacket, DecodeStop, DecodedPacket, EtherType, IcmpMessage, LinkFrame,
    NetworkLayer, TcpHeader, TransportLayer, UdpHeader,
};

/// The arrow between a source and a destination.
const ARROW: &str = "\u{2192}";

/// Renders one captured packet as a single line, without a trailing newline.
pub fn packet_line(metadata: &PacketMetadata, packet: &DecodedPacket) -> String {
    format!(
        "{:>6}  {}  {}",
        metadata.number,
        metadata.timestamp.format_time_of_day(),
        summary(packet)
    )
}

/// Describes a decoded packet in as much detail as was understood.
///
/// The rule throughout is that a packet is described by the deepest layer that
/// decoded, and that a layer which did not decode is *named* rather than
/// silently omitted.
pub fn summary(packet: &DecodedPacket) -> String {
    match (&packet.network, &packet.transport) {
        (Some(NetworkLayer::Arp(arp)), _) => arp_summary(arp),
        (Some(network), Some(transport)) => {
            format!(
                "{} {}",
                endpoints(network, transport),
                transport_detail(transport)
            )
        }
        (Some(network), None) => format!("{} {}", addresses(network), network_only_detail(packet)),
        (None, _) => link_only_summary(packet),
    }
}

/// `source:port -> destination:port`, or bare addresses for protocols without
/// ports.
fn endpoints(network: &NetworkLayer, transport: &TransportLayer) -> String {
    let (source, destination) = address_pair(network);
    match transport {
        TransportLayer::Tcp(TcpHeader {
            source_port,
            destination_port,
            ..
        })
        | TransportLayer::Udp(UdpHeader {
            source_port,
            destination_port,
            ..
        }) => format!("{source}:{source_port} {ARROW} {destination}:{destination_port}"),
        TransportLayer::Icmp(_) => format!("{source} {ARROW} {destination}"),
    }
}

/// `source -> destination` with no ports.
fn addresses(network: &NetworkLayer) -> String {
    let (source, destination) = address_pair(network);
    format!("{source} {ARROW} {destination}")
}

/// The two addresses of a network header, as text.
fn address_pair(network: &NetworkLayer) -> (String, String) {
    match network {
        NetworkLayer::Ipv4(header) => (header.source.to_string(), header.destination.to_string()),
        NetworkLayer::Ipv6(header) => (header.source.to_string(), header.destination.to_string()),
        // ARP is rendered by `arp_summary`; this keeps the function total.
        NetworkLayer::Arp(_) => ("ARP".to_owned(), "ARP".to_owned()),
    }
}

/// The protocol-specific tail of the line.
fn transport_detail(transport: &TransportLayer) -> String {
    match transport {
        TransportLayer::Tcp(segment) => format!("TCP {}", segment.flags),
        TransportLayer::Udp(datagram) => format!("UDP len={}", datagram.length),
        TransportLayer::Icmp(message) => icmp_detail(message),
    }
}

/// `ICMP Echo Reply`, or `ICMP type 99 code 7` when the type has no name.
fn icmp_detail(message: &IcmpMessage) -> String {
    let family = message.family.label();
    match message.description() {
        Some(description) => format!("{family} {description}"),
        None => format!(
            "{family} type {} code {}",
            message.message_type, message.code
        ),
    }
}

/// What to say when a network header decoded but nothing above it did.
fn network_only_detail(packet: &DecodedPacket) -> String {
    let protocol = match &packet.network {
        Some(NetworkLayer::Ipv4(header)) => header.protocol.to_string(),
        Some(NetworkLayer::Ipv6(header)) => header.next_header.to_string(),
        _ => "IP".to_owned(),
    };

    match &packet.stopped {
        Some(DecodeStop::NonInitialFragment) => format!("{protocol} [later fragment]"),
        Some(DecodeStop::Truncated { protocol: cut, .. }) => {
            format!("{protocol} [truncated {cut}]")
        }
        Some(DecodeStop::Malformed {
            protocol: bad,
            reason,
            ..
        }) => {
            format!("{protocol} [malformed {bad}: {reason}]")
        }
        Some(DecodeStop::UnsupportedExtensionHeader(header)) => {
            format!("{protocol} [unfollowable {header} header]")
        }
        _ => protocol,
    }
}

/// `who has X? tell Y` and `X is at Y`, the way ARP is conventionally read.
fn arp_summary(arp: &ArpPacket) -> String {
    let Some(addresses) = arp.addresses else {
        // A hardware or protocol type we do not decode: report the numbers.
        return format!(
            "ARP operation {} hardware type {}",
            match arp.operation {
                ArpOperation::Request => "request".to_owned(),
                ArpOperation::Reply => "reply".to_owned(),
                ArpOperation::Other(code) => code.to_string(),
            },
            arp.hardware_type
        );
    };

    match arp.operation {
        ArpOperation::Request => format!(
            "ARP Who has {}? Tell {}",
            addresses.target_ip, addresses.sender_ip
        ),
        ArpOperation::Reply => {
            format!("ARP {} is at {}", addresses.sender_ip, addresses.sender_mac)
        }
        ArpOperation::Other(code) => format!(
            "ARP operation {code} {} {ARROW} {}",
            addresses.sender_ip, addresses.target_ip
        ),
    }
}

/// What to say when nothing above the link layer decoded.
fn link_only_summary(packet: &DecodedPacket) -> String {
    let Some(link) = &packet.link else {
        // Not even a link header: all we have is the reason.
        return stop_summary(packet.stopped.as_ref());
    };

    let mut line = String::new();
    match link {
        LinkFrame::Ethernet(frame) => {
            let _ = write!(line, "{} {ARROW} {}", frame.source, frame.destination);
            for tag in &frame.vlan_tags {
                let _ = write!(line, " vlan={}", tag.id);
            }
            let _ = write!(line, " {}", describe_ether_type(frame.ether_type));
        }
        LinkFrame::LinuxSll(frame) => {
            let _ = write!(line, "SLL {}", describe_ether_type(frame.protocol));
        }
    }

    if let Some(detail) = stop_detail(packet.stopped.as_ref()) {
        let _ = write!(line, " [{detail}]");
    }
    line
}

/// How to name an EtherType that had no decoder.
fn describe_ether_type(ether_type: EtherType) -> String {
    match ether_type {
        EtherType::Other(value) => format!("EtherType 0x{value:04x}"),
        other => other.to_string(),
    }
}

/// A bracketed note about why decoding stopped, when it adds anything.
fn stop_detail(stop: Option<&DecodeStop>) -> Option<String> {
    match stop? {
        DecodeStop::Truncated { protocol, .. } => Some(format!("truncated {protocol}")),
        DecodeStop::Malformed {
            protocol, reason, ..
        } => Some(format!("malformed {protocol}: {reason}")),
        DecodeStop::UnsupportedLinkType { dlt } => Some(format!("no decoder for link type {dlt}")),
        DecodeStop::NonInitialFragment => Some("later fragment".to_owned()),
        DecodeStop::UnsupportedExtensionHeader(header) => {
            Some(format!("unfollowable {header} header"))
        }
        // The EtherType and protocol are already printed alongside.
        DecodeStop::UnsupportedEtherType(_) | DecodeStop::UnsupportedProtocol(_) => None,
    }
}

/// A standalone description of why nothing decoded at all.
fn stop_summary(stop: Option<&DecodeStop>) -> String {
    match stop_detail(stop) {
        Some(detail) => format!("[{detail}]"),
        None => "[undecoded packet]".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::PacketTimestamp;
    use crate::decode::{
        ArpAddresses, DecodeStop, EthernetFrame, IcmpFamily, Ipv4Header, Ipv6Header, Layer,
        LinuxSllFrame, MacAddress, SllPacketType, SllVersion, TcpFlags, VlanTag,
    };
    use crate::decode::{IpProtocol, LinkLayer, decode};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn metadata() -> PacketMetadata {
        PacketMetadata {
            number: 1,
            timestamp: PacketTimestamp::from_parts(1_790_005_351, 123_456),
            caplen: 74,
            wirelen: 74,
        }
    }

    fn ipv4(protocol: IpProtocol) -> NetworkLayer {
        NetworkLayer::Ipv4(Ipv4Header {
            source: Ipv4Addr::new(192, 168, 1, 15),
            destination: Ipv4Addr::new(142, 250, 184, 14),
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
            window: 64240,
            checksum: 0,
            urgent_pointer: 0,
            options_len: 0,
        })
    }

    fn packet(network: Option<NetworkLayer>, transport: Option<TransportLayer>) -> DecodedPacket {
        DecodedPacket {
            link: Some(LinkFrame::Ethernet(EthernetFrame {
                source: MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                destination: MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                ether_type: EtherType::Ipv4,
                vlan_tags: vec![],
            })),
            network,
            transport,
            stopped: None,
        }
    }

    #[test]
    fn renders_a_tcp_segment_the_way_the_examples_read() {
        let decoded = packet(Some(ipv4(IpProtocol::Tcp)), Some(tcp(53122, 443, 0x002)));
        assert_eq!(
            summary(&decoded),
            "192.168.1.15:53122 \u{2192} 142.250.184.14:443 TCP SYN"
        );

        let line = packet_line(&metadata(), &decoded);
        assert_eq!(
            line,
            "     1  15:42:31.123456  192.168.1.15:53122 \u{2192} 142.250.184.14:443 TCP SYN"
        );
    }

    #[test]
    fn renders_a_udp_datagram_with_its_declared_length() {
        let decoded = packet(
            Some(ipv4(IpProtocol::Udp)),
            Some(TransportLayer::Udp(UdpHeader {
                source_port: 60432,
                destination_port: 53,
                length: 42,
                checksum: 0,
                captured_payload_len: 34,
            })),
        );
        assert!(summary(&decoded).ends_with(":60432 \u{2192} 142.250.184.14:53 UDP len=42"));
    }

    #[test]
    fn renders_icmp_without_ports_and_with_its_name() {
        let decoded = packet(
            Some(ipv4(IpProtocol::Icmp)),
            Some(TransportLayer::Icmp(IcmpMessage {
                family: IcmpFamily::V4,
                message_type: 0,
                code: 0,
                checksum: 0,
            })),
        );
        assert_eq!(
            summary(&decoded),
            "192.168.1.15 \u{2192} 142.250.184.14 ICMP Echo Reply"
        );
    }

    #[test]
    fn an_unnamed_icmp_type_is_shown_by_its_numbers() {
        let decoded = packet(
            Some(ipv4(IpProtocol::Icmp)),
            Some(TransportLayer::Icmp(IcmpMessage {
                family: IcmpFamily::V4,
                message_type: 99,
                code: 7,
                checksum: 0,
            })),
        );
        assert!(summary(&decoded).ends_with("ICMP type 99 code 7"));
    }

    #[test]
    fn renders_arp_requests_and_replies_in_their_conventional_wording() {
        let addresses = ArpAddresses {
            sender_mac: MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            sender_ip: Ipv4Addr::new(192, 168, 1, 15),
            target_mac: MacAddress::UNSPECIFIED,
            target_ip: Ipv4Addr::new(192, 168, 1, 1),
        };

        let request = packet(
            Some(NetworkLayer::Arp(ArpPacket {
                operation: ArpOperation::Request,
                hardware_type: 1,
                protocol_type: EtherType::Ipv4,
                addresses: Some(addresses),
            })),
            None,
        );
        assert_eq!(
            summary(&request),
            "ARP Who has 192.168.1.1? Tell 192.168.1.15"
        );

        let reply = packet(
            Some(NetworkLayer::Arp(ArpPacket {
                operation: ArpOperation::Reply,
                hardware_type: 1,
                protocol_type: EtherType::Ipv4,
                addresses: Some(ArpAddresses {
                    sender_ip: Ipv4Addr::new(192, 168, 1, 1),
                    sender_mac: MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                    ..addresses
                }),
            })),
            None,
        );
        assert_eq!(summary(&reply), "ARP 192.168.1.1 is at aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn renders_ipv6_addresses() {
        let decoded = packet(
            Some(NetworkLayer::Ipv6(Ipv6Header {
                source: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                destination: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
                next_header: IpProtocol::Tcp,
                hop_limit: 64,
                payload_len: 20,
                traffic_class: 0,
                flow_label: 0,
                extension_headers: vec![],
                non_initial_fragment: false,
            })),
            Some(tcp(443, 53122, 0x012)),
        );
        assert_eq!(
            summary(&decoded),
            "2001:db8::1:443 \u{2192} 2001:db8::2:53122 TCP SYN,ACK"
        );
    }

    #[test]
    fn an_unknown_ether_type_falls_back_to_the_link_header() {
        let decoded = DecodedPacket {
            link: Some(LinkFrame::Ethernet(EthernetFrame {
                source: MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                destination: MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                ether_type: EtherType::Other(0x88cc),
                vlan_tags: vec![],
            })),
            network: None,
            transport: None,
            stopped: Some(DecodeStop::UnsupportedEtherType(EtherType::Other(0x88cc))),
        };
        assert_eq!(
            summary(&decoded),
            "00:11:22:33:44:55 \u{2192} aa:bb:cc:dd:ee:ff EtherType 0x88cc"
        );
    }

    #[test]
    fn vlan_ids_are_shown_on_the_link_fallback_line() {
        let decoded = DecodedPacket {
            link: Some(LinkFrame::Ethernet(EthernetFrame {
                source: MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                destination: MacAddress::BROADCAST,
                ether_type: EtherType::Other(0x88cc),
                vlan_tags: vec![VlanTag {
                    tag_protocol: EtherType::Vlan,
                    priority: 0,
                    drop_eligible: false,
                    id: 100,
                }],
            })),
            network: None,
            transport: None,
            stopped: Some(DecodeStop::UnsupportedEtherType(EtherType::Other(0x88cc))),
        };
        assert!(summary(&decoded).contains("vlan=100"));
    }

    #[test]
    fn a_truncated_packet_says_so_rather_than_showing_nothing() {
        let decoded = DecodedPacket {
            link: None,
            network: None,
            transport: None,
            stopped: Some(DecodeStop::Truncated {
                layer: Layer::Network,
                protocol: "IPv4",
            }),
        };
        assert_eq!(summary(&decoded), "[truncated IPv4]");
    }

    #[test]
    fn a_truncated_transport_header_keeps_the_addresses_that_did_decode() {
        let decoded = DecodedPacket {
            stopped: Some(DecodeStop::Truncated {
                layer: Layer::Transport,
                protocol: "TCP",
            }),
            ..packet(Some(ipv4(IpProtocol::Tcp)), None)
        };
        assert_eq!(
            summary(&decoded),
            "192.168.1.15 \u{2192} 142.250.184.14 TCP [truncated TCP]"
        );
    }

    #[test]
    fn a_later_fragment_is_labelled_as_one() {
        let decoded = DecodedPacket {
            stopped: Some(DecodeStop::NonInitialFragment),
            ..packet(Some(ipv4(IpProtocol::Tcp)), None)
        };
        assert!(summary(&decoded).ends_with("TCP [later fragment]"));
    }

    #[test]
    fn an_unsupported_link_type_is_reported_on_its_own() {
        let decoded = DecodedPacket::stopped_at(DecodeStop::UnsupportedLinkType { dlt: 105 });
        assert_eq!(summary(&decoded), "[no decoder for link type 105]");
    }

    #[test]
    fn a_linux_cooked_frame_without_a_decodable_payload_still_renders() {
        let decoded = DecodedPacket {
            link: Some(LinkFrame::LinuxSll(LinuxSllFrame {
                version: SllVersion::V1,
                packet_type: SllPacketType::Host,
                arphrd_type: 1,
                source_address: vec![],
                protocol: EtherType::Other(0x4321),
            })),
            network: None,
            transport: None,
            stopped: Some(DecodeStop::UnsupportedEtherType(EtherType::Other(0x4321))),
        };
        assert_eq!(summary(&decoded), "SLL EtherType 0x4321");
    }

    #[test]
    fn an_unsupported_ip_protocol_names_the_protocol() {
        let decoded = DecodedPacket {
            stopped: Some(DecodeStop::UnsupportedProtocol(IpProtocol::Other(47))),
            ..packet(Some(ipv4(IpProtocol::Other(47))), None)
        };
        assert_eq!(
            summary(&decoded),
            "192.168.1.15 \u{2192} 142.250.184.14 IP protocol 47"
        );
    }

    #[test]
    fn packet_line_survives_an_unconvertible_timestamp() {
        let broken = PacketMetadata {
            timestamp: PacketTimestamp::from_parts(i64::MAX, -5),
            ..metadata()
        };
        let decoded = packet(Some(ipv4(IpProtocol::Tcp)), Some(tcp(53122, 443, 0x002)));

        let line = packet_line(&broken, &decoded);
        // The timestamp degrades to its raw form; the packet is still described.
        assert!(line.contains("raw"), "{line}");
        assert!(line.contains("TCP SYN"), "{line}");
    }

    #[test]
    fn no_decoded_packet_can_make_the_renderer_panic() {
        // Feed the renderer the output of the decoder for a wide range of junk.
        // Rendering is the last step before the terminal; it must be as
        // unfailing as the decoding that precedes it.
        let mut rendered = 0usize;
        for link in [
            LinkLayer::Ethernet,
            LinkLayer::LinuxSll,
            LinkLayer::Unsupported(9),
        ] {
            for length in 0..64usize {
                for fill in [0x00u8, 0xff, 0x45, 0x60, 0x81] {
                    let bytes = vec![fill; length];
                    let decoded = decode(link, &bytes);
                    let line = packet_line(&metadata(), &decoded);
                    assert!(!line.is_empty());
                    rendered += 1;
                }
            }
        }
        assert!(rendered > 900, "only {rendered} renders");
    }
}
