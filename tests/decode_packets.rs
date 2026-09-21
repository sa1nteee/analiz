//! End-to-end decoding tests, driven entirely by hand-built byte arrays.
//!
//! These exercise the public API the way the capture loop does — one link type
//! and one slice of bytes — with no network, no privileges and no capture.
//!
//! The last test in this file is the important one: it feeds every prefix and
//! every single-byte mutation of every fixture to the decoder and asserts only
//! that the process survives. A packet decoder's first duty is to stay standing.

use netsentry::decode::{
    ArpOperation, DecodeStop, EtherType, IcmpFamily, IpProtocol, Layer, LinkFrame, LinkLayer,
    NetworkLayer, TransportLayer, decode,
};

/// Builds an Ethernet header in front of a payload.
fn ethernet(ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // destination
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // source
    ];
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// An IPv4 header carrying `protocol`, with a correct total length.
fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = u16::try_from(20 + payload.len()).unwrap_or(u16::MAX);
    let mut header = vec![0x45, 0x00];
    header.extend_from_slice(&total_len.to_be_bytes());
    header.extend_from_slice(&[
        0x1c, 0x46, // identification
        0x40, 0x00,     // don't fragment
        0x40,     // TTL 64
        protocol, //
        0x00, 0x00, // checksum
        192, 168, 1, 15, //
        142, 250, 184, 14,
    ]);
    header.extend_from_slice(payload);
    header
}

/// An IPv6 header carrying `next_header`.
fn ipv6(next_header: u8, payload: &[u8]) -> Vec<u8> {
    let payload_len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    let mut header = vec![0x60, 0x00, 0x00, 0x00];
    header.extend_from_slice(&payload_len.to_be_bytes());
    header.push(next_header);
    header.push(0x40);
    header.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    header.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    header.extend_from_slice(payload);
    header
}

/// A TCP header with the given flags.
fn tcp(source: u16, destination: u16, flags: u8) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&source.to_be_bytes());
    header.extend_from_slice(&destination.to_be_bytes());
    header.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // sequence
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // acknowledgment
    header.push(0x50); // data offset 5
    header.push(flags);
    header.extend_from_slice(&[0xfa, 0xf0, 0x00, 0x00, 0x00, 0x00]);
    header
}

/// A UDP header plus `payload_len` bytes of payload.
fn udp(source: u16, destination: u16, payload_len: usize) -> Vec<u8> {
    let length = u16::try_from(8 + payload_len).unwrap_or(u16::MAX);
    let mut header = Vec::new();
    header.extend_from_slice(&source.to_be_bytes());
    header.extend_from_slice(&destination.to_be_bytes());
    header.extend_from_slice(&length.to_be_bytes());
    header.extend_from_slice(&[0x12, 0x34]);
    header.extend(std::iter::repeat_n(0u8, payload_len));
    header
}

/// An Ethernet/IPv4 ARP packet.
fn arp(operation: u16, target_mac: [u8; 6]) -> Vec<u8> {
    let mut packet = vec![0x00, 0x01, 0x08, 0x00, 0x06, 0x04];
    packet.extend_from_slice(&operation.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet.extend_from_slice(&[192, 168, 1, 15]);
    packet.extend_from_slice(&target_mac);
    packet.extend_from_slice(&[192, 168, 1, 1]);
    packet
}

/// Every fixture used below, so the robustness sweep can reuse them.
fn fixtures() -> Vec<(&'static str, LinkLayer, Vec<u8>)> {
    vec![
        (
            "ethernet/ipv4/tcp",
            LinkLayer::Ethernet,
            ethernet(0x0800, &ipv4(6, &tcp(53122, 443, 0x02))),
        ),
        (
            "ethernet/ipv4/udp",
            LinkLayer::Ethernet,
            ethernet(0x0800, &ipv4(17, &udp(60432, 53, 34))),
        ),
        (
            "ethernet/ipv4/icmp",
            LinkLayer::Ethernet,
            ethernet(0x0800, &ipv4(1, &[0x00, 0x00, 0xff, 0xff, 0, 1, 0, 1])),
        ),
        (
            "ethernet/ipv6/tcp",
            LinkLayer::Ethernet,
            ethernet(0x86dd, &ipv6(6, &tcp(443, 53122, 0x12))),
        ),
        (
            "ethernet/ipv6/icmpv6",
            LinkLayer::Ethernet,
            ethernet(0x86dd, &ipv6(58, &[0x80, 0x00, 0x00, 0x00])),
        ),
        (
            "ethernet/arp",
            LinkLayer::Ethernet,
            ethernet(0x0806, &arp(1, [0; 6])),
        ),
        (
            "ethernet/lldp",
            LinkLayer::Ethernet,
            ethernet(0x88cc, &[0x02, 0x07, 0x04]),
        ),
        ("ethernet/vlan/ipv4/tcp", LinkLayer::Ethernet, {
            let mut inner = vec![0xa0, 0x64, 0x08, 0x00];
            inner.extend_from_slice(&ipv4(6, &tcp(80, 12345, 0x10)));
            ethernet(0x8100, &inner)
        }),
        ("linux-sll/ipv4/udp", LinkLayer::LinuxSll, {
            let mut frame = vec![
                0x00, 0x00, 0x00, 0x01, 0x00, 0x06, //
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, //
                0x08, 0x00,
            ];
            frame.extend_from_slice(&ipv4(17, &udp(1234, 53, 20)));
            frame
        }),
    ]
}

/// Looks a fixture up by name.
fn fixture(name: &str) -> Vec<u8> {
    fixtures()
        .into_iter()
        .find(|(fixture_name, _, _)| *fixture_name == name)
        .map(|(_, _, bytes)| bytes)
        .unwrap_or_default()
}

#[test]
fn decodes_a_tcp_syn_end_to_end() {
    let packet = decode(LinkLayer::Ethernet, &fixture("ethernet/ipv4/tcp"));

    assert!(!packet.is_incomplete(), "stopped at {:?}", packet.stopped);

    let Some(LinkFrame::Ethernet(ethernet)) = packet.link else {
        panic!("expected an Ethernet frame");
    };
    assert_eq!(ethernet.source.to_string(), "00:11:22:33:44:55");
    assert_eq!(ethernet.ether_type, EtherType::Ipv4);

    let Some(NetworkLayer::Ipv4(ip)) = packet.network else {
        panic!("expected IPv4");
    };
    assert_eq!(ip.source.to_string(), "192.168.1.15");
    assert_eq!(ip.destination.to_string(), "142.250.184.14");
    assert_eq!(ip.protocol, IpProtocol::Tcp);
    assert_eq!(ip.ttl, 64);

    let Some(TransportLayer::Tcp(segment)) = packet.transport else {
        panic!("expected TCP");
    };
    assert_eq!(segment.source_port, 53122);
    assert_eq!(segment.destination_port, 443);
    assert_eq!(segment.flags.to_string(), "SYN");
}

#[test]
fn decodes_a_udp_datagram_end_to_end() {
    let packet = decode(LinkLayer::Ethernet, &fixture("ethernet/ipv4/udp"));

    assert!(!packet.is_incomplete());
    let Some(TransportLayer::Udp(datagram)) = packet.transport else {
        panic!("expected UDP");
    };
    assert_eq!(datagram.source_port, 60432);
    assert_eq!(datagram.destination_port, 53);
    assert_eq!(datagram.length, 42);
}

#[test]
fn decodes_an_icmp_echo_reply_end_to_end() {
    let packet = decode(LinkLayer::Ethernet, &fixture("ethernet/ipv4/icmp"));

    assert!(!packet.is_incomplete());
    let Some(TransportLayer::Icmp(message)) = packet.transport else {
        panic!("expected ICMP");
    };
    assert_eq!(message.family, IcmpFamily::V4);
    assert_eq!(message.description(), Some("Echo Reply"));
}

#[test]
fn decodes_ipv6_and_icmpv6_end_to_end() {
    let packet = decode(LinkLayer::Ethernet, &fixture("ethernet/ipv6/tcp"));
    let Some(NetworkLayer::Ipv6(ip)) = packet.network else {
        panic!("expected IPv6");
    };
    assert_eq!(ip.source.to_string(), "2001:db8::1");
    assert_eq!(ip.hop_limit, 64);
    let Some(TransportLayer::Tcp(segment)) = packet.transport else {
        panic!("expected TCP");
    };
    assert_eq!(segment.flags.to_string(), "SYN,ACK");

    let packet = decode(LinkLayer::Ethernet, &fixture("ethernet/ipv6/icmpv6"));
    let Some(TransportLayer::Icmp(message)) = packet.transport else {
        panic!("expected ICMPv6");
    };
    assert_eq!(message.family, IcmpFamily::V6);
    assert_eq!(message.description(), Some("Echo Request"));
}

#[test]
fn decodes_arp_requests_and_replies_end_to_end() {
    let reply_bytes = ethernet(0x0806, &arp(2, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    let request = decode(LinkLayer::Ethernet, &fixture("ethernet/arp"));
    let Some(NetworkLayer::Arp(arp)) = request.network else {
        panic!("expected ARP");
    };
    assert_eq!(arp.operation, ArpOperation::Request);
    assert_eq!(
        arp.addresses.map(|a| a.target_ip.to_string()),
        Some("192.168.1.1".to_owned())
    );
    assert!(request.transport.is_none(), "ARP has no transport layer");

    let reply = decode(LinkLayer::Ethernet, &reply_bytes);
    let Some(NetworkLayer::Arp(arp)) = reply.network else {
        panic!("expected ARP");
    };
    assert_eq!(arp.operation, ArpOperation::Reply);
    assert_eq!(
        arp.addresses.map(|a| a.sender_mac.to_string()),
        Some("00:11:22:33:44:55".to_owned())
    );
}

#[test]
fn decodes_a_vlan_tagged_packet_end_to_end() {
    let packet = decode(LinkLayer::Ethernet, &fixture("ethernet/vlan/ipv4/tcp"));

    let Some(LinkFrame::Ethernet(ethernet)) = &packet.link else {
        panic!("expected an Ethernet frame");
    };
    assert_eq!(ethernet.vlan_tags.len(), 1);
    assert_eq!(ethernet.vlan_tags.first().map(|tag| tag.id), Some(100));
    // The tag must not have displaced the IP header.
    assert!(matches!(packet.network, Some(NetworkLayer::Ipv4(_))));
    assert!(matches!(packet.transport, Some(TransportLayer::Tcp(_))));
}

#[test]
fn decodes_a_linux_cooked_capture_end_to_end() {
    let packet = decode(LinkLayer::LinuxSll, &fixture("linux-sll/ipv4/udp"));

    assert!(matches!(packet.link, Some(LinkFrame::LinuxSll(_))));
    assert!(matches!(packet.network, Some(NetworkLayer::Ipv4(_))));
    let Some(TransportLayer::Udp(datagram)) = packet.transport else {
        panic!("expected UDP");
    };
    assert_eq!(datagram.destination_port, 53);
}

#[test]
fn an_unsupported_link_type_is_a_result_not_a_failure() {
    // DLT_IEEE802_11 (105), which NetSentry has no decoder for.
    let packet = decode(LinkLayer::from_dlt(105), &[0x08, 0x00, 0x00, 0x00]);

    assert_eq!(
        packet.stopped,
        Some(DecodeStop::UnsupportedLinkType { dlt: 105 })
    );
    assert!(packet.link.is_none());
    assert!(packet.network.is_none());
}

#[test]
fn an_unknown_ether_type_still_yields_the_link_header() {
    let packet = decode(LinkLayer::Ethernet, &fixture("ethernet/lldp"));

    let Some(LinkFrame::Ethernet(ethernet)) = &packet.link else {
        panic!("the Ethernet header is readable even so");
    };
    assert_eq!(ethernet.ether_type, EtherType::Other(0x88cc));
    assert_eq!(
        packet.stopped,
        Some(DecodeStop::UnsupportedEtherType(EtherType::Other(0x88cc)))
    );
    assert!(packet.network.is_none());
}

#[test]
fn an_unsupported_ip_protocol_still_yields_the_ip_header() {
    // GRE (47), which NetSentry does not decode.
    let bytes = ethernet(0x0800, &ipv4(47, &[0u8; 8]));
    let packet = decode(LinkLayer::Ethernet, &bytes);

    assert!(matches!(packet.network, Some(NetworkLayer::Ipv4(_))));
    assert_eq!(
        packet.stopped,
        Some(DecodeStop::UnsupportedProtocol(IpProtocol::Other(47)))
    );
    assert!(packet.transport.is_none());
}

#[test]
fn a_truncated_packet_reports_how_far_it_got() {
    let full = fixture("ethernet/ipv4/tcp");

    // Cut inside the IPv4 header: the link layer survives, the network layer
    // does not.
    let cut = full.get(..24).unwrap_or(&[]);
    let packet = decode(LinkLayer::Ethernet, cut);

    assert!(packet.link.is_some(), "the Ethernet header was complete");
    assert!(packet.network.is_none());
    assert_eq!(
        packet.stopped,
        Some(DecodeStop::Truncated {
            layer: Layer::Network,
            protocol: "IPv4"
        })
    );

    // Cut inside the TCP header: both headers below it survive.
    let cut = full.get(..40).unwrap_or(&[]);
    let packet = decode(LinkLayer::Ethernet, cut);
    assert!(packet.link.is_some());
    assert!(packet.network.is_some());
    assert!(packet.transport.is_none());
    assert!(matches!(
        packet.stopped,
        Some(DecodeStop::Truncated {
            layer: Layer::Transport,
            ..
        })
    ));
}

#[test]
fn link_layers_map_to_and_from_their_dlt_values() {
    for (dlt, expected) in [
        (1, LinkLayer::Ethernet),
        (113, LinkLayer::LinuxSll),
        (276, LinkLayer::LinuxSll2),
        (105, LinkLayer::Unsupported(105)),
        (-1, LinkLayer::Unsupported(-1)),
    ] {
        assert_eq!(LinkLayer::from_dlt(dlt), expected);
        assert_eq!(expected.as_dlt(), dlt);
    }
}

#[test]
fn no_input_at_all_can_bring_the_decoder_down() {
    // Every prefix of every fixture, plus every single-byte corruption of it.
    // The assertion is simply that this function returns: a decoder that
    // panics on a crafted packet is a denial-of-service bug in a tool whose
    // whole job is reading crafted packets.
    let link_layers = [
        LinkLayer::Ethernet,
        LinkLayer::LinuxSll,
        LinkLayer::LinuxSll2,
        LinkLayer::Unsupported(999),
    ];

    let mut decoded = 0usize;

    for (_, _, bytes) in fixtures() {
        for link in link_layers {
            // Truncation: every possible short read.
            for length in 0..=bytes.len() {
                let prefix = bytes.get(..length).unwrap_or(&[]);
                let _ = decode(link, prefix);
                decoded += 1;
            }

            // Corruption: flip each byte to three awkward values in turn.
            for index in 0..bytes.len() {
                for replacement in [0x00u8, 0xff, 0x45] {
                    let mut mutated = bytes.clone();
                    if let Some(slot) = mutated.get_mut(index) {
                        *slot = replacement;
                    }
                    let _ = decode(link, &mutated);
                    decoded += 1;
                }
            }
        }
    }

    // Degenerate inputs.
    for link in link_layers {
        let _ = decode(link, &[]);
        let _ = decode(link, &[0x00]);
        let _ = decode(link, &vec![0xff; 4096]);
        decoded += 3;
    }

    // The exact number only matters as a guard against the sweep silently
    // shrinking to nothing if a fixture is removed.
    assert!(
        decoded > 5_000,
        "the sweep covered only {decoded} inputs, which is too few to mean much"
    );
    println!("decoder survived {decoded} malformed or truncated inputs");
}
