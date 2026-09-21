//! Live packet capture.
//!
//! This module opens a capture handle on an interface and pumps packets out of
//! it. It deliberately stops at *metadata*: how big a packet was and when it
//! arrived. Packet contents are never copied out, printed, stored or logged —
//! decoding is v0.2's job, and until there is a reason to touch payload bytes,
//! not touching them is the safer default.
//!
//! Options live in [`crate::capture::settings`], the counters a run produces
//! live in [`crate::capture::stats`], and the read loop itself lives in
//! [`crate::capture::pump`] because offline analysis runs the same one.
//!
//! See [`LiveCapture::run`] for how the capture loop stays interruptible.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::capture::device::NetworkInterface;
use crate::capture::pump::{LinkType, PacketMetadata, PumpOptions, describe_link_type, pump};
use crate::capture::settings::CaptureSettings;
use crate::capture::stats::{CaptureSummary, DriverStats};
use crate::capture::timestamp::PacketTimestamp;
use crate::capture::writer::CaptureWriter;
use crate::error::{NetSentryError, Result};

/// How long a single read may block before the loop regains control, in
/// milliseconds. See [`LiveCapture::run`] for why this exists.
///
/// 250 ms is short enough that a Ctrl+C feels instant and long enough that an
/// idle interface costs four wake-ups per second rather than a spinning CPU.
const READ_TIMEOUT_MS: i32 = 250;

/// Stops a running capture from another thread.
///
/// Both halves matter. The flag is what the loop checks; `pcap_breakloop()` is
/// what wakes the loop if it happens to be blocked inside a read right now.
/// Safe to send to a signal-handling thread: it holds a weak reference to the
/// capture handle, so interrupting a capture that has already finished does
/// nothing at all.
pub struct CaptureInterrupter {
    stop: Arc<AtomicBool>,
    breaker: pcap::BreakLoop,
}

impl CaptureInterrupter {
    /// Asks the capture loop to stop at the next opportunity.
    pub fn interrupt(&self) {
        // Order matters: the loop must be able to see the flag as soon as the
        // break wakes it up.
        self.stop.store(true, Ordering::SeqCst);
        self.breaker.breakloop();
    }
}

/// An open capture on a network interface.
pub struct LiveCapture {
    handle: pcap::Capture<pcap::Active>,
    link_type: LinkType,
    settings: CaptureSettings,
    stop: Arc<AtomicBool>,
}

impl LiveCapture {
    /// Opens a capture handle on `interface`.
    ///
    /// # Errors
    ///
    /// [`NetSentryError::CapturePermissionDenied`] when the driver refuses for
    /// lack of privileges, [`NetSentryError::CaptureOpen`] for anything else.
    pub fn open(interface: &NetworkInterface, settings: &CaptureSettings) -> Result<Self> {
        let device = pcap::Device::from(interface.name.as_str());

        let handle = pcap::Capture::from_device(device)
            .and_then(|inactive| {
                inactive
                    .snaplen(i32::try_from(settings.snaplen()).unwrap_or(i32::MAX))
                    .promisc(settings.promiscuous())
                    // Deliver packets as they arrive instead of waiting for the
                    // kernel buffer to fill. Without this a quiet interface can
                    // sit on a packet for a long time, which looks like a hang.
                    .immediate_mode(true)
                    // Bounds how long a single read may block. Never zero:
                    // libpcap reads a timeout of 0 as "wait forever".
                    .timeout(READ_TIMEOUT_MS)
                    .open()
            })
            .map_err(|source| classify_open_error(&interface.name, source))?;

        let link_type = describe_link_type(handle.get_datalink());

        Ok(Self {
            handle,
            link_type,
            settings: *settings,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The link-layer format packets on this capture will be in.
    pub fn link_type(&self) -> &LinkType {
        &self.link_type
    }

    /// The settings this capture was opened with.
    pub fn settings(&self) -> CaptureSettings {
        self.settings
    }

    /// Opens a pcap file to copy this capture's packets into.
    ///
    /// [`crate::capture::writer::prepare_capture_file`] must have been called
    /// first; it is what refuses an existing file and sets the permissions this
    /// one then inherits.
    ///
    /// # Errors
    ///
    /// [`NetSentryError::PathNotUtf8`] or [`NetSentryError::CaptureWriteOpen`].
    pub fn open_savefile(&self, path: &Path) -> Result<CaptureWriter> {
        // libpcap's binding unwraps this conversion internally, so a non-UTF-8
        // path would panic inside the dependency rather than fail here.
        if path.to_str().is_none() {
            return Err(NetSentryError::PathNotUtf8 {
                path: path.to_path_buf(),
            });
        }

        let savefile =
            self.handle
                .savefile(path)
                .map_err(|source| NetSentryError::CaptureWriteOpen {
                    path: path.to_path_buf(),
                    source,
                })?;
        Ok(CaptureWriter::new(savefile, path.to_path_buf()))
    }

    /// Creates a handle that can stop this capture from another thread.
    pub fn interrupter(&mut self) -> CaptureInterrupter {
        CaptureInterrupter {
            stop: Arc::clone(&self.stop),
            breaker: self.handle.breakloop_handle(),
        }
    }

    /// Runs the capture loop, calling `on_packet` with each packet's metadata
    /// and its raw bytes.
    ///
    /// # Staying interruptible
    ///
    /// Reading a packet blocks, which is a problem: a naive loop sitting in a
    /// blocking read cannot notice that the user pressed Ctrl+C. Two mechanisms
    /// cover that, and both are needed:
    ///
    /// * The capture is opened with a **read timeout**, so a read that finds no
    ///   packets gives up after [`READ_TIMEOUT_MS`] and the loop gets to check
    ///   the stop flag. This is the guarantee: it works on every platform, and
    ///   the waiting happens in the kernel, so an idle capture uses no CPU.
    /// * [`CaptureInterrupter`] additionally calls `pcap_breakloop()`, which
    ///   wakes a blocked read immediately where the platform supports it.
    ///
    /// The timeout alone would be correct but up to 250 ms late; `breakloop`
    /// alone would be immediate but is not guaranteed to interrupt a blocked
    /// read on every libpcap version. Together they are both immediate in
    /// practice and correct in the worst case.
    ///
    /// # Errors
    ///
    /// [`NetSentryError::CaptureRead`] if the driver reports a read failure.
    pub fn run<F>(
        &mut self,
        writer: Option<&mut CaptureWriter>,
        on_packet: F,
    ) -> Result<CaptureSummary>
    where
        F: FnMut(&PacketMetadata, &[u8]) -> std::io::Result<()>,
    {
        let started_at = wall_clock_now();
        let clock = Instant::now();

        let options = PumpOptions {
            limit: self.settings.count(),
            stop: Some(&self.stop),
            sink: writer,
        };
        let (run, failure) = pump(&mut self.handle, options, on_packet);

        // On a live capture a read failure means the interface went away
        // mid-run. There is no partial file to salvage, so it is reported as
        // the error it is.
        if let Some(source) = failure {
            return Err(NetSentryError::CaptureRead { source });
        }

        Ok(CaptureSummary {
            tally: run.tally,
            elapsed: clock.elapsed(),
            started_at,
            stop_reason: run.stop_reason,
            driver_stats: self.driver_stats(),
        })
    }

    /// Reads the driver's own packet counters.
    fn driver_stats(&mut self) -> std::result::Result<DriverStats, NetSentryError> {
        self.handle
            .stats()
            .map(|stat| DriverStats {
                received: stat.received,
                dropped: stat.dropped,
                if_dropped: stat.if_dropped,
            })
            .map_err(|source| NetSentryError::CaptureStatistics { source })
    }
}

/// Decides whether a failure to open a capture was a privilege problem.
///
/// libpcap reports this as free text, so this is a best-effort reading of that
/// text. It only ever changes which advice the user is given: the generic
/// variant mentions privileges too, because that is by far the most common
/// cause of a capture failing to open.
fn classify_open_error(interface: &str, source: pcap::Error) -> NetSentryError {
    let message = source.to_string().to_ascii_lowercase();
    let denied = [
        "permission denied",
        "operation not permitted",
        "you don't have permission",
        "access is denied",
        "not permitted",
    ]
    .iter()
    .any(|needle| message.contains(needle));

    if denied {
        NetSentryError::CapturePermissionDenied {
            interface: interface.to_owned(),
            source,
        }
    } else {
        NetSentryError::CaptureOpen {
            interface: interface.to_owned(),
            source,
        }
    }
}

/// The current wall-clock time, or [`None`] if the system clock is before the
/// Unix epoch.
fn wall_clock_now() -> Option<PacketTimestamp> {
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    Some(PacketTimestamp::from_parts(
        i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX),
        i64::from(since_epoch.subsec_micros()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_failures_are_told_apart_from_other_failures() {
        let denied = [
            "socket: Operation not permitted",
            "eth0: You don't have permission to capture on that device",
            "Permission denied",
            "Error opening adapter: Access is denied. (5)",
        ];
        for message in denied {
            let error = classify_open_error("eth0", pcap::Error::PcapError(message.into()));
            assert!(
                matches!(error, NetSentryError::CapturePermissionDenied { .. }),
                "{message:?} should be read as a privilege problem"
            );
        }

        let other = [
            "eth0: No such device exists",
            "BIOCSETIF failed: Device not configured",
        ];
        for message in other {
            let error = classify_open_error("eth0", pcap::Error::PcapError(message.into()));
            assert!(
                matches!(error, NetSentryError::CaptureOpen { .. }),
                "{message:?} should not be read as a privilege problem"
            );
        }
    }
}
