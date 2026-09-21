//! Capture options, and the rules for what counts as a valid one.
//!
//! Validation lives here rather than in the argument parser so that there is
//! exactly one definition of what NetSentry accepts, and so it can be tested
//! without going through a command line.

use crate::error::{NetSentryError, Result};

/// Smallest snapshot length that is worth asking for.
pub const MIN_SNAPLEN: u32 = 1;

/// Largest snapshot length libpcap accepts (`MAXIMUM_SNAPLEN`).
pub const MAX_SNAPLEN: u32 = 262_144;

/// Default snapshot length: large enough for any normal Ethernet frame.
pub const DEFAULT_SNAPLEN: u32 = 65_535;

/// Validated options for a capture run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureSettings {
    snaplen: u32,
    promiscuous: bool,
    count: Option<u64>,
}

impl Default for CaptureSettings {
    /// Whole frames, promiscuous, no packet limit.
    fn default() -> Self {
        Self {
            snaplen: DEFAULT_SNAPLEN,
            promiscuous: true,
            count: None,
        }
    }
}

impl CaptureSettings {
    /// Validates raw user input into settings a capture can be opened with.
    ///
    /// Range checking lives here rather than in the argument parser so that
    /// there is exactly one definition of what is acceptable, and so it can be
    /// tested without going through a command line.
    ///
    /// # Errors
    ///
    /// [`NetSentryError::InvalidSnaplen`] or [`NetSentryError::InvalidCount`].
    pub fn new(snaplen: u32, promiscuous: bool, count: Option<u64>) -> Result<Self> {
        if !(MIN_SNAPLEN..=MAX_SNAPLEN).contains(&snaplen) {
            return Err(NetSentryError::InvalidSnaplen {
                value: snaplen,
                min: MIN_SNAPLEN,
                max: MAX_SNAPLEN,
            });
        }
        if count == Some(0) {
            return Err(NetSentryError::InvalidCount { value: 0 });
        }
        Ok(Self {
            snaplen,
            promiscuous,
            count,
        })
    }

    /// Snapshot length in bytes.
    pub fn snaplen(self) -> u32 {
        self.snaplen
    }

    /// Whether the interface is put into promiscuous mode.
    pub fn promiscuous(self) -> bool {
        self.promiscuous
    }

    /// Packet limit, or [`None`] to run until interrupted.
    pub fn count(self) -> Option<u64> {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_settings_are_valid_settings() {
        let default = CaptureSettings::default();
        assert_eq!(
            CaptureSettings::new(default.snaplen(), default.promiscuous(), default.count()).ok(),
            Some(default)
        );
    }

    #[test]
    fn default_settings_are_accepted() {
        let settings = CaptureSettings::new(DEFAULT_SNAPLEN, true, None);
        assert!(settings.is_ok());

        let settings = CaptureSettings::new(DEFAULT_SNAPLEN, true, None).ok();
        assert_eq!(settings.map(CaptureSettings::snaplen), Some(65_535));
        assert_eq!(settings.map(CaptureSettings::promiscuous), Some(true));
        assert_eq!(settings.map(CaptureSettings::count), Some(None));
    }

    #[test]
    fn snaplen_bounds_are_enforced() {
        for accepted in [MIN_SNAPLEN, 68, DEFAULT_SNAPLEN, MAX_SNAPLEN] {
            assert!(
                CaptureSettings::new(accepted, true, None).is_ok(),
                "snaplen {accepted} should be accepted"
            );
        }

        for rejected in [0, MAX_SNAPLEN + 1, u32::MAX] {
            let error = CaptureSettings::new(rejected, true, None).err();
            assert!(
                matches!(error, Some(NetSentryError::InvalidSnaplen { .. })),
                "snaplen {rejected} should be rejected"
            );
        }
    }

    #[test]
    fn a_count_of_zero_is_rejected_but_none_is_not() {
        let error = CaptureSettings::new(DEFAULT_SNAPLEN, true, Some(0)).err();
        assert!(matches!(
            error,
            Some(NetSentryError::InvalidCount { value: 0 })
        ));

        assert!(CaptureSettings::new(DEFAULT_SNAPLEN, true, Some(1)).is_ok());
        assert!(CaptureSettings::new(DEFAULT_SNAPLEN, true, Some(u64::MAX)).is_ok());
        assert!(CaptureSettings::new(DEFAULT_SNAPLEN, true, None).is_ok());
    }
}
