//! The packet pump shared by live and offline capture.
//!
//! # Why there is no `PacketSource` trait here
//!
//! A live interface and a capture file look like two different things, and the
//! obvious move is to invent a trait that hides the difference. That trait
//! would be redundant: the `pcap` crate already has one. `Capture<Active>` and
//! `Capture<Offline>` both implement `pcap::Activated`, and everything this
//! module needs — reading a packet, asking for the link type — is defined once
//! for any `Capture<T: Activated>`.
//!
//! So [`pump`] is generic over that existing trait, and live and offline
//! capture share one loop rather than two implementations kept in step by hand.
//! Adding our own abstraction on top would be a layer that renames someone
//! else's.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::capture::stats::{CaptureTally, PacketRun, StopReason, TimeSpan};
use crate::capture::timestamp::PacketTimestamp;
use crate::capture::writer::CaptureWriter;

/// The link-layer format of a capture, as reported by the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkType {
    /// Numeric `DLT_*` value.
    pub code: i32,
    /// Short name, such as `EN10MB`.
    pub name: String,
    /// Human readable description, when libpcap knows one.
    pub description: Option<String>,
}

/// What is known about one captured packet.
///
/// Note what is *not* here: the packet's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketMetadata {
    /// 1-based position within this capture run.
    pub number: u64,
    /// When the driver saw the packet.
    pub timestamp: PacketTimestamp,
    /// Bytes actually captured (limited by the snapshot length).
    pub caplen: u32,
    /// Bytes the packet had on the wire.
    pub wirelen: u32,
}

/// What a run of [`pump`] should do beyond reading packets.
///
/// The differences between a live capture and a file read are expressed here
/// rather than as separate loops.
#[derive(Default)]
pub struct PumpOptions<'a> {
    /// Stop after this many packets.
    pub limit: Option<u64>,
    /// The interrupt flag a live capture shares with its Ctrl+C handler. A file
    /// has nothing to interrupt, so it passes [`None`].
    pub stop: Option<&'a AtomicBool>,
    /// A capture file to copy every packet into, when `--write` asked for one.
    pub sink: Option<&'a mut CaptureWriter>,
}

/// Reads packets from any activated capture until it ends.
///
/// This is the one loop both capture modes run. The differences between them
/// are expressed as arguments rather than as separate code:
///
/// * `stop` is the interrupt flag a live capture shares with its Ctrl+C
///   handler. A file has nothing to interrupt, so it passes [`None`], and the
///   flag checks become constant `false`.
/// * `limit` stops the run after a number of packets, for `--count`.
///
/// The `pcap::Error` is returned alongside the run rather than in place of it.
/// A capture file truncated halfway through — a `tcpdump` killed mid-write, a
/// partial download — still contains valid packets before the damage, and
/// throwing those away because the tail is broken would lose real evidence.
pub fn pump<T, F>(
    handle: &mut pcap::Capture<T>,
    mut options: PumpOptions<'_>,
    mut on_packet: F,
) -> (PacketRun, Option<pcap::Error>)
where
    T: pcap::Activated + ?Sized,
    F: FnMut(&PacketMetadata, &[u8]) -> std::io::Result<()>,
{
    let stop = options.stop;
    let limit = options.limit;
    let interrupted = || stop.is_some_and(|flag| flag.load(Ordering::SeqCst));

    let mut tally = CaptureTally::default();
    let mut time_span = TimeSpan::default();
    let mut failure = None;

    let stop_reason = loop {
        if interrupted() {
            break StopReason::Interrupted;
        }

        match handle.next_packet() {
            Ok(packet) => {
                // Written before anything else looks at it, so the file holds
                // the driver's own packet rather than a reconstruction.
                if let Some(writer) = options.sink.as_deref_mut() {
                    writer.record(&packet);
                }

                tally.record(packet.header.caplen, packet.header.len);
                let timestamp = PacketTimestamp::from_parts(
                    widen(packet.header.ts.tv_sec),
                    widen(packet.header.ts.tv_usec),
                );
                time_span.record(timestamp);

                let metadata = PacketMetadata {
                    number: tally.packets(),
                    timestamp,
                    caplen: packet.header.caplen,
                    wirelen: packet.header.len,
                };

                // The packet's bytes are handed straight to the caller and
                // never retained here. What happens to them is the decode
                // layer's business, not the pump's.
                if on_packet(&metadata, packet.data).is_err() {
                    break StopReason::OutputClosed;
                }
                if tally.limit_reached(limit) {
                    break StopReason::CountReached;
                }
            }
            // A quiet interface: nothing arrived within the read timeout. This
            // is the normal idle path for a live capture, and never happens
            // when reading a file.
            Err(pcap::Error::TimeoutExpired) => continue,
            // End of file, or a live capture woken by `pcap_breakloop`.
            Err(pcap::Error::NoMorePackets) => {
                break if interrupted() {
                    StopReason::Interrupted
                } else {
                    StopReason::SourceEnded
                };
            }
            Err(error) => {
                failure = Some(error);
                break StopReason::ReadFailed;
            }
        }
    };

    (
        PacketRun {
            tally,
            time_span,
            stop_reason,
        },
        failure,
    )
}

/// Widens a `timeval` field to `i64`.
///
/// `time_t` and `suseconds_t` are 64-bit on Linux and macOS but 32-bit on
/// Windows, so this conversion is a no-op on some targets and load-bearing on
/// others. Clippy only ever sees one target at a time and calls it useless
/// there; the lint is suppressed here, in one place, rather than the code being
/// made non-portable to satisfy it.
#[allow(clippy::useless_conversion)]
fn widen(value: impl Into<i64>) -> i64 {
    value.into()
}

/// Turns a `DLT_*` value into something printable, without ever failing.
///
/// libpcap does not know every link type by name; an unknown one is reported by
/// its number rather than dropped or guessed at.
pub(crate) fn describe_link_type(link_type: pcap::Linktype) -> LinkType {
    LinkType {
        code: link_type.0,
        name: link_type
            .get_name()
            .unwrap_or_else(|_| format!("DLT_{}", link_type.0)),
        description: link_type.get_description().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeval_fields_widen_on_every_target() {
        // Exercised with both widths so the helper keeps compiling whichever
        // one the target platform uses.
        assert_eq!(widen(-1_i32), -1_i64);
        assert_eq!(widen(i32::MAX), 2_147_483_647_i64);
        assert_eq!(widen(i64::MIN), i64::MIN);
    }

    #[test]
    fn unknown_link_types_are_named_by_number() {
        let described = describe_link_type(pcap::Linktype(1));
        assert_eq!(described.code, 1);
        assert_eq!(described.name, "EN10MB");

        let unknown = describe_link_type(pcap::Linktype(31_337));
        assert_eq!(unknown.code, 31_337);
        assert_eq!(unknown.name, "DLT_31337");
        assert_eq!(unknown.description, None);
    }
}
