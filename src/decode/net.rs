//! Network-layer decoding: IPv4, IPv6 and ARP.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::decode::bytes::ByteReader;
use crate::decode::model::{
    ArpAddresses, ArpOperation, ArpPacket, DecodeStop, Ipv4Header, Ipv6Header, Layer, NetworkLayer,
};
use crate::decode::types::{EtherType, IpProtocol, MacAddress};

/// Length of an IPv4 header without options.
const IPV4_MIN_HEADER_LEN: u8 = 20;

/// Length of the fixed IPv6 header.
const IPV6_HEADER_LEN: usize = 40;

/// How many IPv6 extension headers to follow before giving up.
///
/// A real packet has one or two. A bound is required because the chain is
/// attacker-controlled: without it, a crafted packet could keep the decoder
/// walking a chain of its choosing.
const MAX_EXTENSION_HEADERS: usize = 8;

/// What a network-layer decoder produced.
pub struct NetworkResult<'a> {
    /// The decoded header.
    pub layer: NetworkLayer,
    /// The protocol of the payload, or [`None`] when there is nothing above
    /// this layer to decode.
    pub payload_protocol: Option<IpProtocol>,
    /// The bytes after the header.
    pub payload: &'a [u8],
    /// Why there is no transport layer to decode, when that is the case.
    pub stopped: Option<DecodeStop>,
}

/// Decodes an IPv4 header, honouring its variable header length.
///
/// # Errors
///
/// [`DecodeStop::Truncated`] if the header is incomplete, or
/// [`DecodeStop::Malformed`] if its own fields contradict each other.
pub fn decode_ipv4(bytes: &[u8]) -> Result<NetworkResult<'_>, DecodeStop> {
    let mut reader = ByteReader::new(bytes);

    let version_ihl = reader.u8().ok_or(truncated("IPv4"))?;
    let version = version_ihl >> 4;
    let ihl = version_ihl & 0x0f;

    if version != 4 {
        return Err(malformed("IPv4", "version field is not 4"));
    }
    // The header length is given in 32-bit words and must cover the fixed part.
    let header_len = ihl.saturating_mul(4);
    if header_len < IPV4_MIN_HEADER_LEN {
        return Err(malformed(
            "IPv4",
            "header length is below the 20-byte minimum",
        ));
    }

    let dscp_ecn = reader.u8().ok_or(truncated("IPv4"))?;
    let total_len = reader.u16().ok_or(truncated("IPv4"))?;
    let identification = reader.u16().ok_or(truncated("IPv4"))?;
    let flags_fragment = reader.u16().ok_or(truncated("IPv4"))?;
    let ttl = reader.u8().ok_or(truncated("IPv4"))?;
    let protocol = IpProtocol::from_u8(reader.u8().ok_or(truncated("IPv4"))?);
    let checksum = reader.u16().ok_or(truncated("IPv4"))?;
    let source = Ipv4Addr::from(reader.array::<4>().ok_or(truncated("IPv4"))?);
    let destination = Ipv4Addr::from(reader.array::<4>().ok_or(truncated("IPv4"))?);

    // Options sit between the fixed header and the payload. Skipping exactly
    // this many bytes is what keeps the transport header at the right offset.
    let options_len = header_len.saturating_sub(IPV4_MIN_HEADER_LEN);
    reader
        .skip(usize::from(options_len))
        .ok_or(truncated("IPv4 options"))?;

    let header = Ipv4Header {
        source,
        destination,
        protocol,
        ttl,
        header_len,
        total_len,
        identification,
        dscp: dscp_ecn >> 2,
        ecn: dscp_ecn & 0x03,
        // Bit 15 is reserved, 14 is "don't fragment", 13 is "more fragments".
        dont_fragment: flags_fragment & 0x4000 != 0,
        more_fragments: flags_fragment & 0x2000 != 0,
        fragment_offset: flags_fragment & 0x1fff,
        checksum,
        options_len,
    };

    if total_len != 0 && total_len < u16::from(header_len) {
        return Err(malformed("IPv4", "total length is shorter than the header"));
    }

    // A fragment other than the first carries no transport header: it is a
    // slice out of the middle of one. Parsing its first bytes as TCP would
    // invent a header that was never sent.
    let non_initial = header.is_non_initial_fragment();

    Ok(NetworkResult {
        payload_protocol: (!non_initial).then_some(protocol),
        stopped: non_initial.then_some(DecodeStop::NonInitialFragment),
        layer: NetworkLayer::Ipv4(header),
        payload: reader.rest(),
    })
}

/// Decodes an IPv6 header and walks its extension header chain.
///
/// # Errors
///
/// [`DecodeStop::Truncated`] if the header is incomplete, or
/// [`DecodeStop::Malformed`] if the version field is not 6.
pub fn decode_ipv6(bytes: &[u8]) -> Result<NetworkResult<'_>, DecodeStop> {
    let mut reader = ByteReader::new(bytes);

    // The first word packs version (4 bits), traffic class (8) and flow label
    // (20) together.
    let first_word = reader.u32().ok_or(truncated("IPv6"))?;
    if first_word >> 28 != 6 {
        return Err(malformed("IPv6", "version field is not 6"));
    }

    let payload_len = reader.u16().ok_or(truncated("IPv6"))?;
    let first_next_header = IpProtocol::from_u8(reader.u8().ok_or(truncated("IPv6"))?);
    let hop_limit = reader.u8().ok_or(truncated("IPv6"))?;
    let source = Ipv6Addr::from(reader.array::<16>().ok_or(truncated("IPv6"))?);
    let destination = Ipv6Addr::from(reader.array::<16>().ok_or(truncated("IPv6"))?);

    debug_assert_eq!(reader.position(), IPV6_HEADER_LEN);

    let chain = walk_extension_headers(&mut reader, first_next_header);

    let header = Ipv6Header {
        source,
        destination,
        next_header: chain.final_protocol,
        hop_limit,
        payload_len,
        traffic_class: u8::try_from((first_word >> 20) & 0xff).unwrap_or(0),
        flow_label: first_word & 0x000f_ffff,
        extension_headers: chain.walked,
        non_initial_fragment: chain.non_initial_fragment,
    };

    Ok(NetworkResult {
        payload_protocol: chain.stopped.is_none().then_some(chain.final_protocol),
        stopped: chain.stopped,
        layer: NetworkLayer::Ipv6(header),
        payload: reader.rest(),
    })
}

/// The outcome of following an IPv6 extension header chain.
struct ExtensionChain {
    /// Extension headers successfully walked, in order.
    walked: Vec<IpProtocol>,
    /// The protocol the chain ended on.
    final_protocol: IpProtocol,
    /// Why the walk stopped short, if it did.
    stopped: Option<DecodeStop>,
    /// Whether a fragment header said this is not the first fragment.
    non_initial_fragment: bool,
}

/// Follows the IPv6 extension header chain to the transport header.
///
/// Extension headers all begin with a next-header byte, but they do *not* share
/// one length encoding, which is why each kind is handled explicitly:
///
/// * Hop-by-Hop, Routing, Destination Options and Mobility give their length in
///   8-octet units, not counting the first 8 octets.
/// * A Fragment header is always exactly 8 bytes.
/// * An Authentication Header gives its length in 4-octet units, minus 2.
///
/// Anything else — ESP's encrypted payload, an unknown number — ends the walk
/// with [`DecodeStop::UnsupportedExtensionHeader`]. Guessing a length would put
/// the transport decoder at an offset chosen by whoever sent the packet.
fn walk_extension_headers(reader: &mut ByteReader<'_>, first: IpProtocol) -> ExtensionChain {
    let mut walked = Vec::new();
    let mut protocol = first;
    let mut non_initial_fragment = false;

    for _ in 0..MAX_EXTENSION_HEADERS {
        let length_in_bytes = match protocol {
            IpProtocol::HopByHop
            | IpProtocol::Ipv6Route
            | IpProtocol::Ipv6DestOpts
            | IpProtocol::Mobility => {
                let Some(extra_units) = peek_ext_len(reader) else {
                    return ExtensionChain {
                        walked,
                        final_protocol: protocol,
                        stopped: Some(truncated("IPv6 extension header")),
                        non_initial_fragment,
                    };
                };
                (usize::from(extra_units) + 1) * 8
            }
            IpProtocol::Ipv6Fragment => 8,
            IpProtocol::AuthHeader => {
                let Some(units) = peek_ext_len(reader) else {
                    return ExtensionChain {
                        walked,
                        final_protocol: protocol,
                        stopped: Some(truncated("IPv6 authentication header")),
                        non_initial_fragment,
                    };
                };
                (usize::from(units) + 2) * 4
            }
            // Not an extension header: the chain ends here, normally.
            _ => {
                return ExtensionChain {
                    walked,
                    final_protocol: protocol,
                    stopped: None,
                    non_initial_fragment,
                };
            }
        };

        let Some(block) = reader.take(length_in_bytes) else {
            return ExtensionChain {
                walked,
                final_protocol: protocol,
                stopped: Some(truncated("IPv6 extension header")),
                non_initial_fragment,
            };
        };

        // A fragment header's offset lives in bytes 2-3 of the block.
        if protocol == IpProtocol::Ipv6Fragment {
            let offset_field = block
                .get(2..4)
                .and_then(|pair| <[u8; 2]>::try_from(pair).ok())
                .map(u16::from_be_bytes)
                .unwrap_or(0);
            if offset_field & 0xfff8 != 0 {
                non_initial_fragment = true;
            }
        }

        walked.push(protocol);
        protocol = match block.first() {
            Some(&next) => IpProtocol::from_u8(next),
            None => {
                return ExtensionChain {
                    walked,
                    final_protocol: protocol,
                    stopped: Some(truncated("IPv6 extension header")),
                    non_initial_fragment,
                };
            }
        };

        if non_initial_fragment {
            return ExtensionChain {
                walked,
                final_protocol: protocol,
                stopped: Some(DecodeStop::NonInitialFragment),
                non_initial_fragment,
            };
        }
    }

    ExtensionChain {
        walked,
        final_protocol: protocol,
        stopped: Some(DecodeStop::UnsupportedExtensionHeader(protocol)),
        non_initial_fragment,
    }
}

/// Reads an extension header's length byte without consuming the header.
fn peek_ext_len(reader: &ByteReader<'_>) -> Option<u8> {
    let mut probe = reader.clone();
    probe.u8()?; // next header
    probe.u8() // header extension length
}

/// Decodes an ARP packet.
///
/// Only the Ethernet/IPv4 combination carries addresses NetSentry understands.
/// Any other hardware or protocol type is reported by its numbers rather than
/// read as if it were Ethernet/IPv4.
///
/// # Errors
///
/// [`DecodeStop::Truncated`] if the packet is incomplete.
pub fn decode_arp(bytes: &[u8]) -> Result<NetworkResult<'_>, DecodeStop> {
    let mut reader = ByteReader::new(bytes);

    let hardware_type = reader.u16().ok_or(arp_truncated())?;
    let protocol_type = EtherType::from_u16(reader.u16().ok_or(arp_truncated())?);
    let hardware_len = reader.u8().ok_or(arp_truncated())?;
    let protocol_len = reader.u8().ok_or(arp_truncated())?;
    let operation = ArpOperation::from_u16(reader.u16().ok_or(arp_truncated())?);

    let is_ethernet_ipv4 = hardware_type == 1
        && protocol_type == EtherType::Ipv4
        && hardware_len == 6
        && protocol_len == 4;

    let addresses = if is_ethernet_ipv4 {
        Some(ArpAddresses {
            sender_mac: MacAddress(reader.array::<6>().ok_or(arp_truncated())?),
            sender_ip: Ipv4Addr::from(reader.array::<4>().ok_or(arp_truncated())?),
            target_mac: MacAddress(reader.array::<6>().ok_or(arp_truncated())?),
            target_ip: Ipv4Addr::from(reader.array::<4>().ok_or(arp_truncated())?),
        })
    } else {
        None
    };

    Ok(NetworkResult {
        layer: NetworkLayer::Arp(ArpPacket {
            operation,
            hardware_type,
            protocol_type,
            addresses,
        }),
        // ARP is the whole packet; nothing rides on top of it.
        payload_protocol: None,
        payload: &[],
        stopped: None,
    })
}

/// Builds a truncation result for this layer.
fn truncated(protocol: &'static str) -> DecodeStop {
    DecodeStop::Truncated {
        layer: Layer::Network,
        protocol,
    }
}

/// Builds a truncation result for ARP.
fn arp_truncated() -> DecodeStop {
    truncated("ARP")
}

/// Builds a malformed-header result for this layer.
fn malformed(protocol: &'static str, reason: &'static str) -> DecodeStop {
    DecodeStop::Malformed {
        layer: Layer::Network,
        protocol,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 20-byte IPv4 header for a TCP packet, with no options.
    fn ipv4_tcp() -> Vec<u8> {
        vec![
            0x45, // version 4, IHL 5 (20 bytes)
            0x00, // DSCP 0, ECN 0
            0x00, 0x3c, // total length 60
            0x1c, 0x46, // identification
            0x40, 0x00, // don't fragment, offset 0
            0x40, // TTL 64
            0x06, // protocol: TCP
            0xb1, 0xe6, // checksum
            192, 168, 1, 15, // source
            142, 250, 184, 14, // destination
        ]
    }

    #[test]
    fn decodes_a_plain_ipv4_header() {
        let mut packet = ipv4_tcp();
        packet.extend_from_slice(&[0xde, 0xad]);

        let Ok(result) = decode_ipv4(&packet) else {
            panic!("a well-formed header must decode");
        };
        let NetworkLayer::Ipv4(header) = result.layer else {
            panic!("expected IPv4");
        };

        assert_eq!(header.source, Ipv4Addr::new(192, 168, 1, 15));
        assert_eq!(header.destination, Ipv4Addr::new(142, 250, 184, 14));
        assert_eq!(header.protocol, IpProtocol::Tcp);
        assert_eq!(header.ttl, 64);
        assert_eq!(header.header_len, 20);
        assert_eq!(header.total_len, 60);
        assert_eq!(header.identification, 0x1c46);
        assert_eq!(header.options_len, 0);
        assert!(header.dont_fragment);
        assert!(!header.more_fragments);
        assert_eq!(header.fragment_offset, 0);
        assert!(!header.is_fragment());
        assert_eq!(result.payload, &[0xde, 0xad]);
        assert_eq!(result.payload_protocol, Some(IpProtocol::Tcp));
    }

    #[test]
    fn ipv4_options_move_the_payload_to_the_right_offset() {
        let mut packet = ipv4_tcp();
        packet[0] = 0x47; // IHL 7 => 28-byte header, 8 bytes of options
        // Eight bytes of options, then the payload.
        packet.extend_from_slice(&[0x01; 8]);
        packet.extend_from_slice(&[0xaa, 0xbb]);

        let Ok(result) = decode_ipv4(&packet) else {
            panic!("options are not a failure");
        };
        let NetworkLayer::Ipv4(header) = result.layer else {
            panic!("expected IPv4");
        };

        assert_eq!(header.header_len, 28);
        assert_eq!(header.options_len, 8);
        // The options must be skipped, not handed on as payload.
        assert_eq!(result.payload, &[0xaa, 0xbb]);
    }

    #[test]
    fn options_that_run_past_the_captured_bytes_are_reported() {
        let mut packet = ipv4_tcp();
        packet[0] = 0x4f; // IHL 15 => 60-byte header, 40 bytes of options ...
        // ... but none of them are present.

        assert!(matches!(
            decode_ipv4(&packet),
            Err(DecodeStop::Truncated { .. })
        ));
    }

    #[test]
    fn a_wrong_version_or_short_ihl_is_malformed_not_guessed() {
        let mut wrong_version = ipv4_tcp();
        wrong_version[0] = 0x65; // version 6 in an IPv4 slot
        assert!(matches!(
            decode_ipv4(&wrong_version),
            Err(DecodeStop::Malformed { .. })
        ));

        let mut short_ihl = ipv4_tcp();
        short_ihl[0] = 0x44; // IHL 4 => 16 bytes, below the minimum
        assert!(matches!(
            decode_ipv4(&short_ihl),
            Err(DecodeStop::Malformed { .. })
        ));
    }

    #[test]
    fn a_total_length_shorter_than_the_header_is_malformed() {
        let mut packet = ipv4_tcp();
        packet[2] = 0x00;
        packet[3] = 0x0a; // total length 10, less than the 20-byte header

        assert!(matches!(
            decode_ipv4(&packet),
            Err(DecodeStop::Malformed { .. })
        ));
    }

    #[test]
    fn a_first_fragment_still_carries_its_transport_header() {
        let mut packet = ipv4_tcp();
        packet[6] = 0x20; // more fragments, offset 0
        packet[7] = 0x00;
        packet.extend_from_slice(&[0xaa]);

        let Ok(result) = decode_ipv4(&packet) else {
            panic!("a first fragment is well-formed");
        };
        let NetworkLayer::Ipv4(header) = result.layer else {
            panic!("expected IPv4");
        };

        assert!(header.is_fragment());
        assert!(!header.is_non_initial_fragment());
        assert!(header.more_fragments);
        // The transport header really is here, so decoding may continue.
        assert_eq!(result.payload_protocol, Some(IpProtocol::Tcp));
        assert_eq!(result.stopped, None);
    }

    #[test]
    fn a_later_fragment_is_not_parsed_as_if_it_had_a_transport_header() {
        let mut packet = ipv4_tcp();
        packet[6] = 0x20; // more fragments ...
        packet[7] = 0xb9; // ... at offset 185, so this is not the first
        packet.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);

        let Ok(result) = decode_ipv4(&packet) else {
            panic!("a later fragment is still a valid IPv4 header");
        };
        let NetworkLayer::Ipv4(header) = result.layer else {
            panic!("expected IPv4");
        };

        assert!(header.is_non_initial_fragment());
        assert_eq!(header.fragment_offset, 185);
        // These bytes are the middle of someone else's payload. Reading them
        // as a TCP header would invent a header that was never sent.
        assert_eq!(result.payload_protocol, None);
        assert_eq!(result.stopped, Some(DecodeStop::NonInitialFragment));
    }

    #[test]
    fn every_truncation_of_an_ipv4_header_is_reported() {
        let packet = ipv4_tcp();
        for length in 0..packet.len() {
            let prefix = packet.get(..length).unwrap_or(&[]);
            let outcome = decode_ipv4(prefix);
            assert!(
                outcome.is_err(),
                "a {length}-byte IPv4 header must not decode"
            );
        }
        assert!(decode_ipv4(&packet).is_ok());
    }

    /// A 40-byte IPv6 header for a TCP packet.
    fn ipv6_tcp() -> Vec<u8> {
        let mut packet = vec![
            0x60, 0x00, 0x00, 0x00, // version 6, traffic class 0, flow label 0
            0x00, 0x14, // payload length 20
            0x06, // next header: TCP
            0x40, // hop limit 64
        ];
        // 2001:db8::1 -> 2001:db8::2
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        packet.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ]);
        packet
    }

    #[test]
    fn decodes_a_plain_ipv6_header() {
        let mut packet = ipv6_tcp();
        packet.extend_from_slice(&[0xaa, 0xbb]);

        let Ok(result) = decode_ipv6(&packet) else {
            panic!("a well-formed header must decode");
        };
        let NetworkLayer::Ipv6(header) = result.layer else {
            panic!("expected IPv6");
        };

        assert_eq!(header.source.to_string(), "2001:db8::1");
        assert_eq!(header.destination.to_string(), "2001:db8::2");
        assert_eq!(header.next_header, IpProtocol::Tcp);
        assert_eq!(header.hop_limit, 64);
        assert_eq!(header.payload_len, 20);
        assert!(header.extension_headers.is_empty());
        assert_eq!(result.payload, &[0xaa, 0xbb]);
        assert_eq!(result.payload_protocol, Some(IpProtocol::Tcp));
    }

    #[test]
    fn traffic_class_and_flow_label_are_unpacked_correctly() {
        let mut packet = ipv6_tcp();
        // version 6, traffic class 0x88, flow label 0x12345
        packet[0] = 0x68;
        packet[1] = 0x81;
        packet[2] = 0x23;
        packet[3] = 0x45;

        let Ok(result) = decode_ipv6(&packet) else {
            panic!("must decode");
        };
        let NetworkLayer::Ipv6(header) = result.layer else {
            panic!("expected IPv6");
        };
        assert_eq!(header.traffic_class, 0x88);
        assert_eq!(header.flow_label, 0x12345);
    }

    #[test]
    fn a_wrong_ipv6_version_is_malformed() {
        let mut packet = ipv6_tcp();
        packet[0] = 0x40; // version 4 in an IPv6 slot
        assert!(matches!(
            decode_ipv6(&packet),
            Err(DecodeStop::Malformed { .. })
        ));
    }

    #[test]
    fn walks_an_ipv6_extension_header_chain_to_the_transport_header() {
        let mut packet = ipv6_tcp();
        packet[6] = 0x00; // next header: Hop-by-Hop
        // Hop-by-Hop: next header TCP, length 0 => 8 bytes total.
        packet.extend_from_slice(&[0x06, 0x00, 0, 0, 0, 0, 0, 0]);
        packet.extend_from_slice(&[0xaa, 0xbb]);

        let Ok(result) = decode_ipv6(&packet) else {
            panic!("a chain of known headers must be walked");
        };
        let NetworkLayer::Ipv6(header) = result.layer else {
            panic!("expected IPv6");
        };

        assert_eq!(header.extension_headers, vec![IpProtocol::HopByHop]);
        assert_eq!(header.next_header, IpProtocol::Tcp);
        // The payload starts after the extension header, not after byte 40.
        assert_eq!(result.payload, &[0xaa, 0xbb]);
    }

    #[test]
    fn walks_a_longer_extension_header_chain() {
        let mut packet = ipv6_tcp();
        packet[6] = 0x00; // Hop-by-Hop ...
        // ... then Destination Options (60), 16 bytes long ...
        packet.extend_from_slice(&[0x3c, 0x00, 0, 0, 0, 0, 0, 0]);
        // ... then TCP.
        packet.extend_from_slice(&[0x06, 0x01, 0, 0, 0, 0, 0, 0]);
        packet.extend_from_slice(&[0u8; 8]);
        packet.push(0xaa);

        let Ok(result) = decode_ipv6(&packet) else {
            panic!("must decode");
        };
        let NetworkLayer::Ipv6(header) = result.layer else {
            panic!("expected IPv6");
        };
        assert_eq!(
            header.extension_headers,
            vec![IpProtocol::HopByHop, IpProtocol::Ipv6DestOpts]
        );
        assert_eq!(header.next_header, IpProtocol::Tcp);
        assert_eq!(result.payload, &[0xaa]);
    }

    #[test]
    fn an_encrypted_payload_ends_the_walk_rather_than_being_guessed_at() {
        let mut packet = ipv6_tcp();
        packet[6] = 0x32; // ESP: the rest is encrypted
        packet.extend_from_slice(&[0xaa; 16]);

        let Ok(result) = decode_ipv6(&packet) else {
            panic!("the IPv6 header itself is fine");
        };
        // ESP is not an extension header we can step over, so decoding stops
        // rather than reading ciphertext as a TCP header.
        assert_eq!(result.payload_protocol, Some(IpProtocol::Esp));
    }

    #[test]
    fn an_extension_chain_that_runs_off_the_packet_is_reported() {
        let mut packet = ipv6_tcp();
        packet[6] = 0x00; // Hop-by-Hop claiming 48 bytes ...
        packet.extend_from_slice(&[0x06, 0x05]); // ... but nothing follows

        let Ok(result) = decode_ipv6(&packet) else {
            panic!("the fixed header decoded fine");
        };
        assert!(matches!(result.stopped, Some(DecodeStop::Truncated { .. })));
        assert_eq!(result.payload_protocol, None);
    }

    #[test]
    fn an_endless_extension_chain_is_bounded() {
        let mut packet = ipv6_tcp();
        packet[6] = 0x00;
        // Sixty Hop-by-Hop headers, each pointing at another one.
        for _ in 0..60 {
            packet.extend_from_slice(&[0x00, 0x00, 0, 0, 0, 0, 0, 0]);
        }

        let Ok(result) = decode_ipv6(&packet) else {
            panic!("must not fail outright");
        };
        let NetworkLayer::Ipv6(header) = &result.layer else {
            panic!("expected IPv6");
        };
        assert_eq!(header.extension_headers.len(), MAX_EXTENSION_HEADERS);
        assert!(matches!(
            result.stopped,
            Some(DecodeStop::UnsupportedExtensionHeader(_))
        ));
    }

    #[test]
    fn a_later_ipv6_fragment_is_not_parsed_as_transport() {
        let mut packet = ipv6_tcp();
        packet[6] = 0x2c; // next header: Fragment
        // Fragment header: next TCP, reserved, offset 185 (<<3 = 0x05c8), id.
        packet.extend_from_slice(&[0x06, 0x00, 0x05, 0xc8, 0, 0, 0, 1]);
        packet.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);

        let Ok(result) = decode_ipv6(&packet) else {
            panic!("the header chain is well formed");
        };
        let NetworkLayer::Ipv6(header) = &result.layer else {
            panic!("expected IPv6");
        };

        assert!(header.non_initial_fragment);
        assert_eq!(result.payload_protocol, None);
        assert_eq!(result.stopped, Some(DecodeStop::NonInitialFragment));
    }

    #[test]
    fn every_truncation_of_an_ipv6_header_is_reported() {
        let packet = ipv6_tcp();
        for length in 0..IPV6_HEADER_LEN {
            let prefix = packet.get(..length).unwrap_or(&[]);
            assert!(
                decode_ipv6(prefix).is_err(),
                "a {length}-byte IPv6 header must not decode"
            );
        }
        assert!(decode_ipv6(&packet).is_ok());
    }

    /// An Ethernet/IPv4 ARP request: who has 192.168.1.1?
    fn arp_request() -> Vec<u8> {
        vec![
            0x00, 0x01, // hardware type: Ethernet
            0x08, 0x00, // protocol type: IPv4
            0x06, // hardware address length
            0x04, // protocol address length
            0x00, 0x01, // operation: request
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // sender MAC
            192, 168, 1, 15, // sender IP
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC: unknown
            192, 168, 1, 1, // target IP
        ]
    }

    #[test]
    fn decodes_an_arp_request() {
        let packet = arp_request();
        let Ok(result) = decode_arp(&packet) else {
            panic!("a well-formed request must decode");
        };
        let NetworkLayer::Arp(arp) = result.layer else {
            panic!("expected ARP");
        };

        assert_eq!(arp.operation, ArpOperation::Request);
        assert_eq!(arp.hardware_type, 1);
        assert_eq!(arp.protocol_type, EtherType::Ipv4);

        let addresses = arp.addresses.unwrap_or(ArpAddresses {
            sender_mac: MacAddress::UNSPECIFIED,
            sender_ip: Ipv4Addr::UNSPECIFIED,
            target_mac: MacAddress::UNSPECIFIED,
            target_ip: Ipv4Addr::UNSPECIFIED,
        });
        assert_eq!(addresses.sender_ip, Ipv4Addr::new(192, 168, 1, 15));
        assert_eq!(addresses.target_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addresses.sender_mac.to_string(), "00:11:22:33:44:55");
        assert_eq!(addresses.target_mac, MacAddress::UNSPECIFIED);
        // Nothing rides on top of ARP.
        assert_eq!(result.payload_protocol, None);
    }

    #[test]
    fn decodes_an_arp_reply() {
        let mut packet = arp_request();
        packet[7] = 0x02; // operation: reply
        packet.splice(18..24, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let Ok(result) = decode_arp(&packet) else {
            panic!("a well-formed reply must decode");
        };
        let NetworkLayer::Arp(arp) = result.layer else {
            panic!("expected ARP");
        };
        assert_eq!(arp.operation, ArpOperation::Reply);
        assert_eq!(
            arp.addresses.map(|a| a.target_mac.to_string()),
            Some("aa:bb:cc:dd:ee:ff".to_owned())
        );
    }

    #[test]
    fn a_non_ethernet_arp_packet_is_reported_without_inventing_addresses() {
        let mut packet = arp_request();
        packet[1] = 0x06; // hardware type: IEEE 802 networks, not Ethernet

        let Ok(result) = decode_arp(&packet) else {
            panic!("the fixed part still decodes");
        };
        let NetworkLayer::Arp(arp) = result.layer else {
            panic!("expected ARP");
        };
        assert_eq!(arp.hardware_type, 6);
        assert_eq!(
            arp.addresses, None,
            "addresses of an unknown layout must not be read as Ethernet/IPv4"
        );
        assert_eq!(arp.operation, ArpOperation::Request);
    }

    #[test]
    fn an_unknown_arp_operation_keeps_its_number() {
        let mut packet = arp_request();
        packet[7] = 0x09; // InARP reply
        let Ok(result) = decode_arp(&packet) else {
            panic!("must decode");
        };
        let NetworkLayer::Arp(arp) = result.layer else {
            panic!("expected ARP");
        };
        assert_eq!(arp.operation, ArpOperation::Other(9));
    }

    #[test]
    fn every_truncation_of_an_arp_packet_is_reported() {
        let packet = arp_request();
        for length in 0..packet.len() {
            let prefix = packet.get(..length).unwrap_or(&[]);
            let outcome = decode_arp(prefix);
            // The first 8 bytes are the fixed part; a packet shorter than the
            // full 28 bytes cannot yield Ethernet/IPv4 addresses.
            if length < 8 {
                assert!(outcome.is_err(), "{length} bytes is not an ARP packet");
            } else if let Ok(result) = outcome {
                let NetworkLayer::Arp(arp) = result.layer else {
                    panic!("expected ARP");
                };
                assert!(
                    arp.addresses.is_none() || length == packet.len(),
                    "{length} bytes must not yield complete addresses"
                );
            }
        }
    }
}
