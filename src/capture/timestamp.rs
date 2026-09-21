//! Packet timestamps.
//!
//! libpcap hands every packet a `struct timeval` — whole seconds since the Unix
//! epoch plus a microsecond remainder. This module keeps those raw numbers and
//! converts them to readable text on demand.
//!
//! Two decisions are worth knowing about:
//!
//! * **The raw values are never discarded.** Converting to a calendar date can
//!   fail (a driver can report a nonsensical `timeval`); when it does, the raw
//!   numbers are printed instead of a guess, and never a panic.
//! * **Times are UTC.** Determining the local offset is unreliable in a process
//!   that has spawned threads — and NetSentry has one, for the interrupt
//!   handler. More importantly, a capture is evidence: UTC means a timestamp
//!   still means the same thing on someone else's machine.

use time::OffsetDateTime;

/// Number of microseconds in a second.
const MICROS_PER_SECOND: i64 = 1_000_000;

/// A packet timestamp exactly as the capture driver reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketTimestamp {
    seconds: i64,
    microseconds: i64,
}

impl PacketTimestamp {
    /// Stores a `timeval` as reported, without validating it.
    ///
    /// Validation happens at formatting time so that an odd timestamp is
    /// *reported* rather than rejected — a capture driver producing nonsense is
    /// itself a finding worth seeing.
    pub fn from_parts(seconds: i64, microseconds: i64) -> Self {
        Self {
            seconds,
            microseconds,
        }
    }

    /// Whole seconds since the Unix epoch, as reported.
    pub fn seconds(self) -> i64 {
        self.seconds
    }

    /// Microsecond remainder, as reported.
    pub fn microseconds(self) -> i64 {
        self.microseconds
    }

    /// The timestamp as whole microseconds since the epoch.
    ///
    /// Returns [`None`] for a `timeval` that cannot be expressed that way, so
    /// arithmetic on timestamps can never silently wrap. `i128` is used because
    /// a nonsensical `tv_sec` near [`i64::MAX`] would overflow `i64` micros.
    pub fn micros_since_epoch(self) -> Option<i128> {
        if self.microseconds < 0 || self.microseconds >= MICROS_PER_SECOND {
            return None;
        }
        i128::from(self.seconds)
            .checked_mul(i128::from(MICROS_PER_SECOND))?
            .checked_add(i128::from(self.microseconds))
    }

    /// The timestamp as a UTC calendar time, or [`None`] if it is not a valid
    /// point in time.
    fn to_utc(self) -> Option<(OffsetDateTime, u32)> {
        // A well-formed timeval carries a remainder inside one second.
        if self.microseconds < 0 || self.microseconds >= MICROS_PER_SECOND {
            return None;
        }
        let datetime = OffsetDateTime::from_unix_timestamp(self.seconds).ok()?;
        let micros = u32::try_from(self.microseconds).ok()?;
        Some((datetime, micros))
    }

    /// `HH:MM:SS.ffffff` in UTC, for per-packet output.
    ///
    /// Falls back to `[raw <sec>.<usec>]` when the timestamp cannot be
    /// represented, so the evidence survives even when the conversion does not.
    pub fn format_time_of_day(self) -> String {
        match self.to_utc() {
            Some((datetime, micros)) => format!(
                "{:02}:{:02}:{:02}.{:06}",
                datetime.hour(),
                datetime.minute(),
                datetime.second(),
                micros
            ),
            None => self.format_raw(),
        }
    }

    /// `YYYY-MM-DD HH:MM:SS.ffffff UTC`, for summaries.
    pub fn format_datetime(self) -> String {
        match self.to_utc() {
            Some((datetime, micros)) => format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06} UTC",
                datetime.year(),
                u8::from(datetime.month()),
                datetime.day(),
                datetime.hour(),
                datetime.minute(),
                datetime.second(),
                micros
            ),
            None => self.format_raw(),
        }
    }

    /// The unconverted `timeval`, used whenever conversion is impossible.
    fn format_raw(self) -> String {
        format!("[raw {}.{}]", self.seconds, self.microseconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_a_known_instant_in_utc() {
        // 2026-09-21T15:42:31Z == 1790005351
        let ts = PacketTimestamp::from_parts(1_790_005_351, 381_204);
        assert_eq!(ts.format_time_of_day(), "15:42:31.381204");
        assert_eq!(ts.format_datetime(), "2026-09-21 15:42:31.381204 UTC");
    }

    #[test]
    fn microsecond_precision_is_preserved_and_zero_padded() {
        let ts = PacketTimestamp::from_parts(0, 7);
        assert_eq!(ts.format_time_of_day(), "00:00:00.000007");

        let ts = PacketTimestamp::from_parts(0, 999_999);
        assert_eq!(ts.format_time_of_day(), "00:00:00.999999");

        let ts = PacketTimestamp::from_parts(0, 0);
        assert_eq!(ts.format_datetime(), "1970-01-01 00:00:00.000000 UTC");
    }

    #[test]
    fn timestamps_before_the_epoch_still_convert() {
        let ts = PacketTimestamp::from_parts(-1, 500_000);
        assert_eq!(ts.format_time_of_day(), "23:59:59.500000");
    }

    #[test]
    fn out_of_range_microseconds_fall_back_to_raw_values() {
        for micros in [-1, MICROS_PER_SECOND, 5_000_000] {
            let ts = PacketTimestamp::from_parts(1_790_005_351, micros);
            let rendered = ts.format_time_of_day();
            assert_eq!(rendered, format!("[raw 1790005351.{micros}]"));
        }
    }

    #[test]
    fn absurd_seconds_fall_back_instead_of_panicking() {
        for seconds in [i64::MIN, i64::MAX, -1_000_000_000_000_000] {
            let ts = PacketTimestamp::from_parts(seconds, 1);
            // The only requirement is that this returns rather than panics.
            let rendered = ts.format_datetime();
            assert!(rendered.contains("raw"), "unexpected output: {rendered}");
        }
    }

    #[test]
    fn epoch_micros_are_exact_and_refuse_nonsense() {
        assert_eq!(
            PacketTimestamp::from_parts(2, 500_000).micros_since_epoch(),
            Some(2_500_000)
        );
        assert_eq!(
            PacketTimestamp::from_parts(-1, 500_000).micros_since_epoch(),
            Some(-500_000)
        );
        // An out-of-range remainder is not a point in time.
        assert_eq!(
            PacketTimestamp::from_parts(0, -1).micros_since_epoch(),
            None
        );
        assert_eq!(
            PacketTimestamp::from_parts(0, MICROS_PER_SECOND).micros_since_epoch(),
            None
        );
        // i64::MAX seconds would overflow i64 micros; i128 holds it.
        assert!(
            PacketTimestamp::from_parts(i64::MAX, 0)
                .micros_since_epoch()
                .is_some()
        );
    }

    #[test]
    fn raw_values_are_never_lost() {
        let ts = PacketTimestamp::from_parts(42, 7);
        assert_eq!(ts.seconds(), 42);
        assert_eq!(ts.microseconds(), 7);
    }
}
