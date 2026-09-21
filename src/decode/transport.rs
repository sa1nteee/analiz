//! Transport-layer decoding: TCP, UDP and ICMP.

use crate::decode::bytes::ByteReader;
use crate::decode::model::{
    DecodeStop, IcmpFamily, IcmpMessage, Layer, TcpHeader, TransportLayer, UdpHeader,
};
use crate::decode::types::TcpFlags;

/// Length of a TCP header without options.
const TCP_MIN_HEADER_LEN: u8 = 20;

/// Decodes a TCP header, honouring its variable data offset.
///
/// TCP options are not parsed in this version, but their *length* is, because
/// the data offset is what says where the payload begins. Getting that wrong
/// would misplace everything above.
///
/// # Errors
///
/// [`DecodeStop::Truncated`] if the header is incomplete, or
/// [`DecodeStop::Malformed`] if the data offset is impossible.
pub fn decode_tcp(bytes: &[u8]) -> Result<TransportLayer, DecodeStop> {
    let mut reader = ByteReader::new(bytes);

    let source_port = reader.u16().ok_or(truncated("TCP"))?;
    let destination_port = reader.u16().ok_or(truncated("TCP"))?;
    let sequence = reader.u32().ok_or(truncated("TCP"))?;
    let acknowledgment = reader.u32().ok_or(truncated("TCP"))?;

    // The data offset (4 bits) and the control bits share these two octets.
    // The lowest bit of the first octet is the NS flag, so the flag field is
    // read as nine bits, not eight.
    let offset_and_flags = reader.u16().ok_or(truncated("TCP"))?;
    let data_offset = u8::try_from(offset_and_flags >> 12).unwrap_or(0);
    let flags = TcpFlags(offset_and_flags & 0x01ff);

    let window = reader.u16().ok_or(truncated("TCP"))?;
    let checksum = reader.u16().ok_or(truncated("TCP"))?;
    let urgent_pointer = reader.u16().ok_or(truncated("TCP"))?;

    let header_len = data_offset.saturating_mul(4);
    if header_len < TCP_MIN_HEADER_LEN {
        return Err(malformed("TCP", "data offset is below the 20-byte minimum"));
    }

    let options_len = header_len.saturating_sub(TCP_MIN_HEADER_LEN);
    reader
        .skip(usize::from(options_len))
        .ok_or(truncated("TCP options"))?;

    Ok(TransportLayer::Tcp(TcpHeader {
        source_port,
        destination_port,
        sequence,
        acknowledgment,
        header_len,
        flags,
        window,
        checksum,
        urgent_pointer,
        options_len,
    }))
}

/// Decodes a UDP header.
///
/// The declared length and the bytes actually present are both recorded rather
/// than reconciled. They legitimately disagree when the capture's snapshot
/// length truncated the packet, and they disagree illegitimately when something
/// crafted the header — telling those apart is not this layer's job, but losing
/// either number would make it impossible later.
///
/// # Errors
///
/// [`DecodeStop::Truncated`] if the header is incomplete, or
/// [`DecodeStop::Malformed`] if the length field cannot include the header.
pub fn decode_udp(bytes: &[u8]) -> Result<TransportLayer, DecodeStop> {
    let mut reader = ByteReader::new(bytes);

    let source_port = reader.u16().ok_or(truncated("UDP"))?;
    let destination_port = reader.u16().ok_or(truncated("UDP"))?;
    let length = reader.u16().ok_or(truncated("UDP"))?;
    let checksum = reader.u16().ok_or(truncated("UDP"))?;

    if length < UdpHeader::HEADER_LEN {
        return Err(malformed("UDP", "length field is shorter than the header"));
    }

    Ok(TransportLayer::Udp(UdpHeader {
        source_port,
        destination_port,
        length,
        checksum,
        captured_payload_len: u16::try_from(reader.remaining()).unwrap_or(u16::MAX),
    }))
}

/// Decodes the common four bytes at the head of every ICMP and ICMPv6 message.
///
/// Per-type bodies are deliberately not decoded: the type and code carry the
/// meaning, and a full ICMP decoder is far more surface than this version
/// needs.
///
/// # Errors
///
/// [`DecodeStop::Truncated`] if the message is incomplete.
pub fn decode_icmp(bytes: &[u8], family: IcmpFamily) -> Result<TransportLayer, DecodeStop> {
    let mut reader = ByteReader::new(bytes);
    let label = family.label();

    let message_type = reader.u8().ok_or(truncated(label))?;
    let code = reader.u8().ok_or(truncated(label))?;
    let checksum = reader.u16().ok_or(truncated(label))?;

    Ok(TransportLayer::Icmp(IcmpMessage {
        family,
        message_type,
        code,
        checksum,
    }))
}

/// Builds a truncation result for this layer.
fn truncated(protocol: &'static str) -> DecodeStop {
    DecodeStop::Truncated {
        layer: Layer::Transport,
        protocol,
    }
}

/// Builds a malformed-header result for this layer.
fn malformed(protocol: &'static str, reason: &'static str) -> DecodeStop {
    DecodeStop::Malformed {
        layer: Layer::Transport,
        protocol,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 20-byte TCP header with no options, SYN set.
    fn tcp_syn() -> Vec<u8> {
        vec![
            0xcf, 0x82, // source port 53122
            0x01, 0xbb, // destination port 443
            0x11, 0x22, 0x33, 0x44, // sequence
            0x00, 0x00, 0x00, 0x00, // acknowledgment
            0x50, // data offset 5 (20 bytes), reserved 0
            0x02, // flags: SYN
            0xfa, 0xf0, // window 64240
            0xab, 0xcd, // checksum
            0x00, 0x00, // urgent pointer
        ]
    }

    #[test]
    fn decodes_a_tcp_syn() {
        let Ok(TransportLayer::Tcp(header)) = decode_tcp(&tcp_syn()) else {
            panic!("a well-formed SYN must decode");
        };

        assert_eq!(header.source_port, 53122);
        assert_eq!(header.destination_port, 443);
        assert_eq!(header.sequence, 0x1122_3344);
        assert_eq!(header.acknowledgment, 0);
        assert_eq!(header.header_len, 20);
        assert_eq!(header.options_len, 0);
        assert_eq!(header.window, 64240);
        assert_eq!(header.flags.to_string(), "SYN");
        assert!(header.flags.is_syn());
    }

    #[test]
    fn decodes_a_tcp_syn_ack() {
        let mut packet = tcp_syn();
        packet[13] = 0x12; // SYN + ACK
        packet.splice(8..12, [0x55, 0x66, 0x77, 0x88]);

        let Ok(TransportLayer::Tcp(header)) = decode_tcp(&packet) else {
            panic!("a well-formed SYN/ACK must decode");
        };
        assert_eq!(header.flags.to_string(), "SYN,ACK");
        assert!(header.flags.is_syn_ack());
        assert_eq!(header.acknowledgment, 0x5566_7788);
    }

    #[test]
    fn decodes_the_other_common_flag_combinations() {
        for (raw, expected) in [
            (0x10u8, "ACK"),
            (0x11, "FIN,ACK"),
            (0x04, "RST"),
            (0x14, "RST,ACK"),
            (0x18, "PSH,ACK"),
            (0x00, "none"),
        ] {
            let mut packet = tcp_syn();
            packet[13] = raw;
            let Ok(TransportLayer::Tcp(header)) = decode_tcp(&packet) else {
                panic!("flags {raw:#04x} should decode");
            };
            assert_eq!(header.flags.to_string(), expected);
        }
    }

    #[test]
    fn the_data_offset_decides_where_the_payload_begins() {
        let mut packet = tcp_syn();
        packet[12] = 0x80; // data offset 8 => 32-byte header, 12 of options
        packet.extend_from_slice(&[0x01; 12]);

        let Ok(TransportLayer::Tcp(header)) = decode_tcp(&packet) else {
            panic!("options are not a failure");
        };
        assert_eq!(header.header_len, 32);
        assert_eq!(header.options_len, 12);
    }

    #[test]
    fn options_that_run_past_the_captured_bytes_are_reported() {
        let mut packet = tcp_syn();
        packet[12] = 0xf0; // data offset 15 => 60-byte header, 40 of options
        // ... none of which are present.
        assert!(matches!(
            decode_tcp(&packet),
            Err(DecodeStop::Truncated { .. })
        ));
    }

    #[test]
    fn a_data_offset_below_the_minimum_is_malformed() {
        for offset_nibble in [0x00u8, 0x10, 0x40] {
            let mut packet = tcp_syn();
            packet[12] = offset_nibble;
            assert!(
                matches!(decode_tcp(&packet), Err(DecodeStop::Malformed { .. })),
                "data offset {offset_nibble:#04x} must be rejected"
            );
        }
    }

    #[test]
    fn the_ns_flag_is_read_from_the_data_offset_octet() {
        let mut packet = tcp_syn();
        packet[12] = 0x51; // data offset 5, NS bit set
        let Ok(TransportLayer::Tcp(header)) = decode_tcp(&packet) else {
            panic!("must decode");
        };
        assert_eq!(header.header_len, 20);
        assert_eq!(header.flags.to_string(), "SYN,NS");
    }

    #[test]
    fn every_truncation_of_a_tcp_header_is_reported() {
        let packet = tcp_syn();
        for length in 0..packet.len() {
            let prefix = packet.get(..length).unwrap_or(&[]);
            assert!(
                decode_tcp(prefix).is_err(),
                "a {length}-byte TCP header must not decode"
            );
        }
        assert!(decode_tcp(&packet).is_ok());
    }

    /// An 8-byte UDP header for a DNS query, with 34 bytes of payload.
    fn udp_dns() -> Vec<u8> {
        vec![
            0xec, 0x10, // source port 60432
            0x00, 0x35, // destination port 53
            0x00, 0x2a, // length 42 (8 header + 34 payload)
            0x12, 0x34, // checksum
        ]
    }

    #[test]
    fn decodes_a_udp_header() {
        let mut packet = udp_dns();
        packet.extend_from_slice(&[0u8; 34]);

        let Ok(TransportLayer::Udp(header)) = decode_udp(&packet) else {
            panic!("a well-formed header must decode");
        };

        assert_eq!(header.source_port, 60432);
        assert_eq!(header.destination_port, 53);
        assert_eq!(header.length, 42);
        assert_eq!(header.declared_payload_len(), Some(34));
        assert_eq!(header.captured_payload_len, 34);
    }

    #[test]
    fn a_length_shorter_than_the_header_is_malformed() {
        for bad_length in [0u16, 1, 7] {
            let mut packet = udp_dns();
            packet.splice(4..6, bad_length.to_be_bytes());
            assert!(
                matches!(decode_udp(&packet), Err(DecodeStop::Malformed { .. })),
                "a declared length of {bad_length} must be rejected"
            );
        }
    }

    #[test]
    fn a_length_larger_than_the_capture_is_recorded_not_trusted() {
        // This is what a snapshot-length truncation looks like: the sender said
        // 1400 bytes, the capture kept 10. Both numbers are kept so a later
        // layer can tell truncation from a crafted header.
        let mut packet = udp_dns();
        packet.splice(4..6, 1400u16.to_be_bytes());
        packet.extend_from_slice(&[0u8; 10]);

        let Ok(TransportLayer::Udp(header)) = decode_udp(&packet) else {
            panic!("this is not a decoding failure");
        };
        assert_eq!(header.declared_payload_len(), Some(1392));
        assert_eq!(header.captured_payload_len, 10);
    }

    #[test]
    fn every_truncation_of_a_udp_header_is_reported() {
        let packet = udp_dns();
        for length in 0..8 {
            let prefix = packet.get(..length).unwrap_or(&[]);
            assert!(
                matches!(decode_udp(prefix), Err(DecodeStop::Truncated { .. })),
                "a {length}-byte UDP header must not decode"
            );
        }
        assert!(decode_udp(&packet).is_ok());
    }

    #[test]
    fn decodes_an_icmp_echo_request_and_reply() {
        let request = [0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01];
        let Ok(TransportLayer::Icmp(message)) = decode_icmp(&request, IcmpFamily::V4) else {
            panic!("must decode");
        };
        assert_eq!(message.message_type, 8);
        assert_eq!(message.code, 0);
        assert_eq!(message.description(), Some("Echo Request"));

        let reply = [0x00, 0x00, 0xff, 0xff, 0x00, 0x01, 0x00, 0x01];
        let Ok(TransportLayer::Icmp(message)) = decode_icmp(&reply, IcmpFamily::V4) else {
            panic!("must decode");
        };
        assert_eq!(message.description(), Some("Echo Reply"));
    }

    #[test]
    fn icmpv6_types_are_named_from_their_own_table() {
        // Type 128 is an Echo Request in ICMPv6 and unassigned in ICMP.
        let bytes = [0x80, 0x00, 0x00, 0x00];

        let Ok(TransportLayer::Icmp(v6)) = decode_icmp(&bytes, IcmpFamily::V6) else {
            panic!("must decode");
        };
        assert_eq!(v6.description(), Some("Echo Request"));

        let Ok(TransportLayer::Icmp(v4)) = decode_icmp(&bytes, IcmpFamily::V4) else {
            panic!("must decode");
        };
        assert_eq!(v4.description(), None, "type 128 has no ICMP meaning");
        assert_eq!(v4.message_type, 128, "but its number is still reported");
    }

    #[test]
    fn an_unknown_icmp_type_still_reports_its_numbers() {
        let bytes = [0x63, 0x07, 0x00, 0x00];
        let Ok(TransportLayer::Icmp(message)) = decode_icmp(&bytes, IcmpFamily::V4) else {
            panic!("must decode");
        };
        assert_eq!(message.message_type, 99);
        assert_eq!(message.code, 7);
        assert_eq!(message.description(), None);
    }

    #[test]
    fn every_truncation_of_an_icmp_header_is_reported() {
        let full = [0x08, 0x00, 0x00, 0x00];
        for length in 0..4 {
            let prefix = full.get(..length).unwrap_or(&[]);
            assert!(
                decode_icmp(prefix, IcmpFamily::V4).is_err(),
                "a {length}-byte ICMP header must not decode"
            );
        }
        assert!(decode_icmp(&full, IcmpFamily::V4).is_ok());
    }
}
