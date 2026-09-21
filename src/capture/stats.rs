//! Counting a capture and reporting how it went.
//!
//! None of this touches the network: it is the arithmetic and the outcome of a
//! capture run, split out from the engine so it can be tested on its own.

use std::time::Duration;

use crate::capture::timestamp::PacketTimestamp;
use crate::error::NetSentryError;

/// Packet counters reported by the capture driver itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverStats {
    /// Packets the driver received.
    pub received: u32,
    /// Packets dropped because the capture buffer was full.
    pub dropped: u32,
    /// Packets dropped by the interface or its driver.
    ///
    /// Not every platform reports this. libpcap sets it to zero where it is
    /// unsupported, and gives no way to tell that apart from "none dropped",
    /// so this number is presented with that caveat attached.
    pub if_dropped: u32,
}

/// Why a capture run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// The requested packet count was reached.
    CountReached,
    /// The user interrupted the capture.
    Interrupted,
    /// The capture source stopped producing packets.
    SourceEnded,
    /// The output the packets were being written to went away.
    OutputClosed,
}

/// Running totals for a capture.
///
/// Separated from the capture loop so the arithmetic can be tested on its own.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CaptureTally {
    packets: u64,
    captured_bytes: u64,
    wire_bytes: u64,
}

impl CaptureTally {
    /// Adds one packet to the totals.
    ///
    /// Saturating arithmetic: a counter that stops climbing is wrong, but a
    /// capture tool that aborts mid-run because a counter wrapped is worse.
    pub fn record(&mut self, caplen: u32, wirelen: u32) {
        self.packets = self.packets.saturating_add(1);
        self.captured_bytes = self.captured_bytes.saturating_add(u64::from(caplen));
        self.wire_bytes = self.wire_bytes.saturating_add(u64::from(wirelen));
    }

    /// Packets recorded so far.
    pub fn packets(self) -> u64 {
        self.packets
    }

    /// Bytes captured so far.
    pub fn captured_bytes(self) -> u64 {
        self.captured_bytes
    }

    /// Bytes those packets occupied on the wire.
    pub fn wire_bytes(self) -> u64 {
        self.wire_bytes
    }

    /// Whether a packet limit has been met.
    pub fn limit_reached(self, limit: Option<u64>) -> bool {
        limit.is_some_and(|limit| self.packets >= limit)
    }
}

/// Everything worth reporting once a capture run is over.
#[derive(Debug)]
pub struct CaptureSummary {
    /// Final packet and byte totals.
    pub tally: CaptureTally,
    /// Wall-clock duration of the run, measured monotonically.
    pub elapsed: Duration,
    /// When the run started, for the record.
    pub started_at: Option<PacketTimestamp>,
    /// Why the run ended.
    pub stop_reason: StopReason,
    /// Driver counters, or the error that prevented reading them.
    ///
    /// Held as a `Result` rather than returned as one: failing to read
    /// statistics must not cost the user the rest of the summary.
    pub driver_stats: std::result::Result<DriverStats, NetSentryError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tally_adds_up_captured_and_wire_bytes_separately() {
        let mut tally = CaptureTally::default();
        assert_eq!(tally.packets(), 0);

        // A truncated packet: 64 bytes captured out of 1514 on the wire.
        tally.record(64, 1514);
        tally.record(74, 74);

        assert_eq!(tally.packets(), 2);
        assert_eq!(tally.captured_bytes(), 138);
        assert_eq!(tally.wire_bytes(), 1588);
    }

    #[test]
    fn tally_saturates_instead_of_overflowing() {
        let mut tally = CaptureTally {
            packets: u64::MAX,
            captured_bytes: u64::MAX,
            wire_bytes: u64::MAX - 1,
        };
        tally.record(u32::MAX, u32::MAX);

        assert_eq!(tally.packets(), u64::MAX);
        assert_eq!(tally.captured_bytes(), u64::MAX);
        assert_eq!(tally.wire_bytes(), u64::MAX);
    }

    #[test]
    fn limit_reached_only_triggers_when_a_limit_exists() {
        let mut tally = CaptureTally::default();
        tally.record(10, 10);
        tally.record(10, 10);

        assert!(!tally.limit_reached(None));
        assert!(!tally.limit_reached(Some(3)));
        assert!(tally.limit_reached(Some(2)));
        assert!(tally.limit_reached(Some(1)));
    }
}
