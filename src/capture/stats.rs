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
    /// The source could not be read any further.
    ///
    /// On a file this means the capture is truncated or corrupt from that
    /// point on; the packets before it are still valid.
    ReadFailed,
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

/// The span of time a run's packets cover, as the packets themselves report it.
///
/// This is deliberately not the same thing as how long the run took. For a live
/// capture the two are close; for a file they are unrelated, because reading a
/// three-hour capture takes a fraction of a second. Confusing them would make
/// an offline summary say something false about when the traffic happened.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TimeSpan {
    first: Option<PacketTimestamp>,
    last: Option<PacketTimestamp>,
}

impl TimeSpan {
    /// Records a packet's timestamp.
    pub fn record(&mut self, timestamp: PacketTimestamp) {
        if self.first.is_none() {
            self.first = Some(timestamp);
        }
        self.last = Some(timestamp);
    }

    /// The timestamp of the first packet seen, if there was one.
    pub fn first(self) -> Option<PacketTimestamp> {
        self.first
    }

    /// The timestamp of the last packet seen, if there was one.
    pub fn last(self) -> Option<PacketTimestamp> {
        self.last
    }

    /// How much time the packets span.
    ///
    /// Returns [`None`] when the last packet is stamped *earlier* than the
    /// first. Capture files are not required to be in timestamp order and real
    /// ones sometimes are not, so rather than report a negative or wrapped
    /// duration this says it cannot tell — and [`TimeSpan::is_monotonic`] lets
    /// the caller explain why.
    pub fn duration(self) -> Option<Duration> {
        let micros = self.last?.micros_since_epoch()? - self.first?.micros_since_epoch()?;
        u64::try_from(micros).ok().map(Duration::from_micros)
    }

    /// Whether the last packet is stamped no earlier than the first.
    ///
    /// A capture whose timestamps go backwards is worth knowing about: it means
    /// merged files, a clock adjustment mid-capture, or tampering.
    pub fn is_monotonic(self) -> bool {
        match (self.first, self.last) {
            (Some(first), Some(last)) => {
                match (first.micros_since_epoch(), last.micros_since_epoch()) {
                    (Some(first), Some(last)) => last >= first,
                    _ => false,
                }
            }
            // An empty span cannot contradict itself.
            _ => true,
        }
    }
}

/// What one pass over a packet source produced, before either kind of capture
/// adds its own context to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketRun {
    /// Packet and byte totals.
    pub tally: CaptureTally,
    /// The span the packets themselves cover.
    pub time_span: TimeSpan,
    /// Why the pass ended.
    pub stop_reason: StopReason,
}

/// Everything worth reporting after analysing a capture file.
///
/// Separate from [`CaptureSummary`] because the two answer different questions.
/// A live summary reports what the driver saw and how long NetSentry watched; a
/// file summary reports what the file contains and when that traffic happened.
/// Driver statistics have no meaning here at all — libpcap says so plainly:
/// "Statistics aren't available from savefiles".
#[derive(Debug)]
pub struct FileSummary {
    /// Packet and byte totals read from the file.
    pub tally: CaptureTally,
    /// The span the file's packets cover, per their own timestamps.
    pub time_span: TimeSpan,
    /// Why reading stopped.
    pub stop_reason: StopReason,
    /// How long NetSentry took to read the file.
    ///
    /// Wall-clock time spent working, which says nothing about when the traffic
    /// happened. [`FileSummary::time_span`] answers that.
    pub processing_time: Duration,
    /// The failure that ended reading early, if one did.
    ///
    /// Held here rather than returned so that a truncated file still reports
    /// the packets it did contain.
    pub read_error: Option<NetSentryError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(seconds: i64, micros: i64) -> PacketTimestamp {
        PacketTimestamp::from_parts(seconds, micros)
    }

    #[test]
    fn an_empty_time_span_reports_nothing_rather_than_zero() {
        let span = TimeSpan::default();
        assert_eq!(span.first(), None);
        assert_eq!(span.last(), None);
        assert_eq!(span.duration(), None);
        assert!(span.is_monotonic(), "nothing cannot be out of order");
    }

    #[test]
    fn a_single_packet_spans_no_time() {
        let mut span = TimeSpan::default();
        span.record(ts(1_790_005_351, 123_456));

        assert_eq!(span.first(), span.last());
        assert_eq!(span.duration(), Some(Duration::ZERO));
    }

    #[test]
    fn the_span_runs_from_the_first_packet_to_the_last() {
        let mut span = TimeSpan::default();
        span.record(ts(1_790_005_351, 123_456));
        span.record(ts(1_790_005_352, 500_000));
        span.record(ts(1_790_005_355, 999_999));

        assert_eq!(span.first(), Some(ts(1_790_005_351, 123_456)));
        assert_eq!(span.last(), Some(ts(1_790_005_355, 999_999)));
        // 4.876543 seconds.
        assert_eq!(span.duration(), Some(Duration::from_micros(4_876_543)));
        assert!(span.is_monotonic());
    }

    #[test]
    fn timestamps_that_go_backwards_are_reported_not_wrapped() {
        let mut span = TimeSpan::default();
        span.record(ts(1_790_005_355, 0));
        span.record(ts(1_790_005_351, 0));

        assert!(!span.is_monotonic());
        assert_eq!(
            span.duration(),
            None,
            "a negative span must not become a huge positive one"
        );
        // Both ends are still reported, because both are facts.
        assert_eq!(span.first(), Some(ts(1_790_005_355, 0)));
        assert_eq!(span.last(), Some(ts(1_790_005_351, 0)));
    }

    #[test]
    fn a_timestamp_outside_any_calendar_still_yields_a_sane_span() {
        // i64::MAX seconds is not a date anyone can render, but the distance
        // between two such stamps is still arithmetic that must not wrap.
        let mut span = TimeSpan::default();
        span.record(ts(i64::MAX, 0));
        span.record(ts(i64::MAX, 1));

        assert_eq!(span.duration(), Some(Duration::from_micros(1)));
        assert!(span.is_monotonic());
    }

    #[test]
    fn a_malformed_timestamp_produces_no_duration_at_all() {
        // A timeval whose remainder is outside one second is not a point in
        // time, so no span can be measured from it.
        let mut span = TimeSpan::default();
        span.record(ts(1_790_005_351, -1));
        span.record(ts(1_790_005_352, 0));

        assert_eq!(span.duration(), None);
        assert!(!span.is_monotonic());
        // The raw values survive regardless.
        assert_eq!(span.first(), Some(ts(1_790_005_351, -1)));
    }

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
