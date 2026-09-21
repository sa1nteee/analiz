//! Link-layer decoding: Ethernet II, 802.1Q VLAN tags and Linux cooked capture.

use crate::decode::bytes::ByteReader;
use crate::decode::model::{
    DecodeStop, EthernetFrame, Layer, LinkFrame, LinuxSllFrame, SllPacketType, SllVersion, VlanTag,
};
use crate::decode::types::{EtherType, MacAddress};

/// Length of the fixed Ethernet II header in bytes.
const ETHERNET_HEADER_LEN: usize = 14;

/// How many stacked VLAN tags to follow.
///
/// Two covers 802.1ad QinQ, which is as deep as tagging goes in practice. A
/// bound is required rather than merely tidy: without one, a frame claiming to
/// be VLAN-tagged all the way down would keep the decoder looping over
/// attacker-chosen data.
const MAX_VLAN_TAGS: usize = 2;

/// What a link-layer decoder produced.
pub struct LinkResult<'a> {
    /// The decoded frame.
    pub frame: LinkFrame,
    /// The protocol of the payload.
    pub payload_type: EtherType,
    /// The bytes after the link header.
    pub payload: &'a [u8],
}

/// Decodes an Ethernet II frame, following any VLAN tags.
///
/// # Errors
///
/// [`DecodeStop::Truncated`] if the frame ends inside a header.
pub fn decode_ethernet(bytes: &[u8]) -> Result<LinkResult<'_>, DecodeStop> {
    let mut reader = ByteReader::new(bytes);

    let destination = MacAddress(reader.array::<6>().ok_or(truncated("Ethernet"))?);
    let source = MacAddress(reader.array::<6>().ok_or(truncated("Ethernet"))?);
    let mut ether_type = EtherType::from_u16(reader.u16().ok_or(truncated("Ethernet"))?);

    debug_assert_eq!(reader.position(), ETHERNET_HEADER_LEN);

    let mut vlan_tags = Vec::new();
    while ether_type.is_vlan() && vlan_tags.len() < MAX_VLAN_TAGS {
        let control = reader.u16().ok_or(truncated("802.1Q tag"))?;
        let inner = EtherType::from_u16(reader.u16().ok_or(truncated("802.1Q tag"))?);

        vlan_tags.push(VlanTag {
            tag_protocol: ether_type,
            // The tag control information packs three fields into 16 bits:
            // priority (3), drop eligible (1), VLAN id (12).
            priority: u8::try_from(control >> 13).unwrap_or(0),
            drop_eligible: control & 0x1000 != 0,
            id: control & 0x0fff,
        });
        ether_type = inner;
    }

    Ok(LinkResult {
        frame: LinkFrame::Ethernet(EthernetFrame {
            source,
            destination,
            ether_type,
            vlan_tags,
        }),
        payload_type: ether_type,
        payload: reader.rest(),
    })
}

/// Decodes a Linux SLL (version 1) cooked-capture header.
///
/// This 16-byte pseudo-header is what `pcap` produces on Linux's `any` device,
/// where frames from interfaces with different link layers are mixed together
/// and so cannot share one real link header.
///
/// # Errors
///
/// [`DecodeStop::Truncated`] if the header is incomplete.
pub fn decode_linux_sll(bytes: &[u8]) -> Result<LinkResult<'_>, DecodeStop> {
    let mut reader = ByteReader::new(bytes);

    let packet_type = SllPacketType::from_u16(reader.u16().ok_or(truncated("Linux SLL"))?);
    let arphrd_type = reader.u16().ok_or(truncated("Linux SLL"))?;
    let address_len = reader.u16().ok_or(truncated("Linux SLL"))?;
    let address_field = reader.array::<8>().ok_or(truncated("Linux SLL"))?;
    let protocol = EtherType::from_u16(reader.u16().ok_or(truncated("Linux SLL"))?);

    Ok(LinkResult {
        frame: LinkFrame::LinuxSll(LinuxSllFrame {
            version: SllVersion::V1,
            packet_type,
            arphrd_type,
            source_address: trim_address(&address_field, address_len),
            protocol,
        }),
        payload_type: protocol,
        payload: reader.rest(),
    })
}

/// Decodes a Linux SLL2 cooked-capture header.
///
/// SLL2 is 20 bytes and orders its fields differently from SLL: the protocol
/// comes first and the interface index is included.
///
/// # Errors
///
/// [`DecodeStop::Truncated`] if the header is incomplete.
pub fn decode_linux_sll2(bytes: &[u8]) -> Result<LinkResult<'_>, DecodeStop> {
    let mut reader = ByteReader::new(bytes);

    let protocol = EtherType::from_u16(reader.u16().ok_or(truncated("Linux SLL2"))?);
    reader.skip(2).ok_or(truncated("Linux SLL2"))?; // reserved, must be zero
    reader.skip(4).ok_or(truncated("Linux SLL2"))?; // interface index
    let arphrd_type = reader.u16().ok_or(truncated("Linux SLL2"))?;
    let packet_type =
        SllPacketType::from_u16(u16::from(reader.u8().ok_or(truncated("Linux SLL2"))?));
    let address_len = u16::from(reader.u8().ok_or(truncated("Linux SLL2"))?);
    let address_field = reader.array::<8>().ok_or(truncated("Linux SLL2"))?;

    Ok(LinkResult {
        frame: LinkFrame::LinuxSll(LinuxSllFrame {
            version: SllVersion::V2,
            packet_type,
            arphrd_type,
            source_address: trim_address(&address_field, address_len),
            protocol,
        }),
        payload_type: protocol,
        payload: reader.rest(),
    })
}

/// Keeps only the meaningful part of an SLL address field.
///
/// The field is always 8 bytes on the wire but the header says how many of them
/// are real; a 6-byte Ethernet MAC leaves two bytes of padding. A length larger
/// than the field is clamped rather than trusted.
fn trim_address(field: &[u8; 8], declared_len: u16) -> Vec<u8> {
    let len = usize::from(declared_len).min(field.len());
    field.get(..len).unwrap_or(&[]).to_vec()
}

/// Builds a truncation result for this layer.
fn truncated(protocol: &'static str) -> DecodeStop {
    DecodeStop::Truncated {
        layer: Layer::Link,
        protocol,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An Ethernet header carrying an IPv4 payload of three bytes.
    fn ethernet_ipv4() -> Vec<u8> {
        let mut frame = vec![
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // destination
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // source
            0x08, 0x00, // EtherType: IPv4
        ];
        frame.extend_from_slice(&[0x45, 0x00, 0x00]);
        frame
    }

    #[test]
    fn decodes_a_plain_ethernet_frame() {
        let frame = ethernet_ipv4();
        let Ok(result) = decode_ethernet(&frame) else {
            panic!("a well-formed frame must decode");
        };

        assert_eq!(result.payload_type, EtherType::Ipv4);
        assert_eq!(result.payload, &[0x45, 0x00, 0x00]);

        let LinkFrame::Ethernet(frame) = result.frame else {
            panic!("expected an Ethernet frame");
        };
        assert_eq!(frame.source.to_string(), "00:11:22:33:44:55");
        assert_eq!(frame.destination.to_string(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(frame.ether_type, EtherType::Ipv4);
        assert!(frame.vlan_tags.is_empty());
    }

    #[test]
    fn an_unknown_ether_type_still_decodes_the_frame() {
        let mut frame = ethernet_ipv4();
        // LLDP, which NetSentry does not decode.
        frame.splice(12..14, [0x88, 0xcc]);

        let Ok(result) = decode_ethernet(&frame) else {
            panic!("the link header is still valid");
        };
        assert_eq!(result.payload_type, EtherType::Other(0x88cc));
    }

    #[test]
    fn decodes_a_vlan_tagged_frame() {
        let mut frame = vec![
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, //
            0x81, 0x00, // EtherType: 802.1Q
            0xa0, 0x64, // priority 5, DEI 0, VLAN id 100
            0x08, 0x00, // inner EtherType: IPv4
        ];
        frame.push(0x45);

        let Ok(result) = decode_ethernet(&frame) else {
            panic!("a tagged frame must decode");
        };
        let LinkFrame::Ethernet(ethernet) = result.frame else {
            panic!("expected an Ethernet frame");
        };

        assert_eq!(ethernet.vlan_tags.len(), 1);
        let tag = ethernet.vlan_tags.first().copied();
        assert_eq!(tag.map(|t| t.id), Some(100));
        assert_eq!(tag.map(|t| t.priority), Some(5));
        assert_eq!(tag.map(|t| t.drop_eligible), Some(false));
        assert_eq!(tag.map(|t| t.tag_protocol), Some(EtherType::Vlan));
        // The frame's EtherType is the innermost one, not the tag's.
        assert_eq!(ethernet.ether_type, EtherType::Ipv4);
        assert_eq!(result.payload, &[0x45]);
    }

    #[test]
    fn decodes_a_double_tagged_frame() {
        let frame = vec![
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, //
            0x88, 0xa8, // outer: 802.1ad
            0x00, 0x0a, // VLAN id 10
            0x81, 0x00, // inner: 802.1Q
            0x00, 0x14, // VLAN id 20
            0x08, 0x00, // IPv4
        ];

        let Ok(result) = decode_ethernet(&frame) else {
            panic!("a double-tagged frame must decode");
        };
        let LinkFrame::Ethernet(ethernet) = result.frame else {
            panic!("expected an Ethernet frame");
        };

        let ids: Vec<u16> = ethernet.vlan_tags.iter().map(|tag| tag.id).collect();
        assert_eq!(ids, vec![10, 20], "outermost tag first");
        assert_eq!(ethernet.ether_type, EtherType::Ipv4);
    }

    #[test]
    fn vlan_nesting_is_bounded() {
        // A frame claiming to be tagged over and over. The decoder must stop,
        // not follow it as far as the attacker wants.
        let mut frame = vec![
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, //
            0x81, 0x00,
        ];
        for _ in 0..50 {
            frame.extend_from_slice(&[0x00, 0x01, 0x81, 0x00]);
        }

        let Ok(result) = decode_ethernet(&frame) else {
            panic!("bounded nesting is not a failure");
        };
        let LinkFrame::Ethernet(ethernet) = result.frame else {
            panic!("expected an Ethernet frame");
        };
        assert_eq!(ethernet.vlan_tags.len(), MAX_VLAN_TAGS);
    }

    #[test]
    fn every_truncation_of_a_frame_is_reported_not_guessed() {
        let frame = ethernet_ipv4();

        for length in 0..ETHERNET_HEADER_LEN {
            let prefix = frame.get(..length).unwrap_or(&[]);
            let outcome = decode_ethernet(prefix);
            assert!(
                matches!(outcome, Err(DecodeStop::Truncated { .. })),
                "a {length}-byte frame must be reported as truncated"
            );
        }

        // Exactly the header and nothing more is valid, with an empty payload.
        let header_only = frame.get(..ETHERNET_HEADER_LEN).unwrap_or(&[]);
        let Ok(result) = decode_ethernet(header_only) else {
            panic!("a header with no payload is still a valid header");
        };
        assert!(result.payload.is_empty());
    }

    #[test]
    fn a_vlan_tag_cut_in_half_is_reported() {
        let frame = vec![
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, //
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, //
            0x81, 0x00, // says a tag follows ...
            0xa0, // ... but only one of its four bytes is here
        ];

        assert!(matches!(
            decode_ethernet(&frame),
            Err(DecodeStop::Truncated { .. })
        ));
    }

    #[test]
    fn decodes_a_linux_sll_header() {
        let mut frame = vec![
            0x00, 0x00, // packet type: to us
            0x00, 0x01, // ARPHRD_ETHER
            0x00, 0x06, // address length: 6
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, // address + padding
            0x08, 0x00, // protocol: IPv4
        ];
        frame.push(0x45);

        let Ok(result) = decode_linux_sll(&frame) else {
            panic!("a well-formed SLL header must decode");
        };
        assert_eq!(result.payload_type, EtherType::Ipv4);
        assert_eq!(result.payload, &[0x45]);

        let LinkFrame::LinuxSll(sll) = result.frame else {
            panic!("expected an SLL frame");
        };
        assert_eq!(sll.version, SllVersion::V1);
        assert_eq!(sll.packet_type, SllPacketType::Host);
        assert_eq!(sll.arphrd_type, 1);
        // The padding is dropped: only the declared six bytes are kept.
        assert_eq!(sll.source_address, vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn decodes_a_linux_sll2_header() {
        let mut frame = vec![
            0x86, 0xdd, // protocol: IPv6
            0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x02, // interface index
            0x00, 0x01, // ARPHRD_ETHER
            0x04, // packet type: outgoing
            0x06, // address length
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00,
        ];
        frame.push(0x60);

        let Ok(result) = decode_linux_sll2(&frame) else {
            panic!("a well-formed SLL2 header must decode");
        };
        assert_eq!(result.payload_type, EtherType::Ipv6);
        assert_eq!(result.payload, &[0x60]);

        let LinkFrame::LinuxSll(sll) = result.frame else {
            panic!("expected an SLL frame");
        };
        assert_eq!(sll.version, SllVersion::V2);
        assert_eq!(sll.packet_type, SllPacketType::Outgoing);
    }

    #[test]
    fn an_sll_address_length_larger_than_the_field_is_clamped() {
        let frame = vec![
            0x00, 0x00, //
            0x00, 0x01, //
            0xff, 0xff, // a declared address length of 65535
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, //
            0x08, 0x00,
        ];

        let Ok(result) = decode_linux_sll(&frame) else {
            panic!("an absurd length must not stop the header decoding");
        };
        let LinkFrame::LinuxSll(sll) = result.frame else {
            panic!("expected an SLL frame");
        };
        assert_eq!(sll.source_address.len(), 8, "clamped to the real field");
    }

    #[test]
    fn every_truncation_of_an_sll_header_is_reported() {
        let full = [0u8; 16];
        for length in 0..16 {
            let prefix = full.get(..length).unwrap_or(&[]);
            assert!(
                matches!(decode_linux_sll(prefix), Err(DecodeStop::Truncated { .. })),
                "a {length}-byte SLL header must be reported as truncated"
            );
        }
        for length in 0..20 {
            let prefix = vec![0u8; length];
            assert!(
                matches!(
                    decode_linux_sll2(&prefix),
                    Err(DecodeStop::Truncated { .. })
                ),
                "a {length}-byte SLL2 header must be reported as truncated"
            );
        }
    }
}
