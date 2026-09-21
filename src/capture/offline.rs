//! Offline analysis of capture files.
//!
//! Reading a `.pcap` file and watching a live interface differ in exactly two
//! places: how the handle is opened, and what the summary means afterwards.
//! Everything between — reading packets, counting them, timing them — is
//! [`crate::capture::pump`], shared with [`crate::capture::live`].
//!
//! Analysis is strictly read-only. The file is opened for reading, never
//! written to, and never sent anywhere.

use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::capture::pump::{LinkType, PacketMetadata, PumpOptions, describe_link_type, pump};
use crate::capture::stats::FileSummary;
use crate::error::{NetSentryError, Result};

/// An open capture file.
pub struct CaptureFile {
    handle: pcap::Capture<pcap::Offline>,
    link_type: LinkType,
    path: PathBuf,
}

impl CaptureFile {
    /// Opens a capture file for analysis.
    ///
    /// The path is user input, so the ordinary filesystem problems are
    /// diagnosed here with [`std::fs`] rather than left to libpcap. libpcap
    /// reports all of them as one English string ("No such file or directory",
    /// "Is a directory", "unknown file format"), and telling them apart by
    /// reading that text would be both fragile and untranslatable.
    ///
    /// # Errors
    ///
    /// [`NetSentryError::CaptureFileMissing`],
    /// [`NetSentryError::CaptureFilePermissionDenied`],
    /// [`NetSentryError::CaptureFileIsDirectory`],
    /// [`NetSentryError::CaptureFileUnreadable`] or
    /// [`NetSentryError::CaptureFileFormat`].
    pub fn open(path: &Path) -> Result<Self> {
        check_readable(path)?;

        let handle =
            pcap::Capture::from_file(path).map_err(|source| NetSentryError::CaptureFileFormat {
                path: path.to_path_buf(),
                source,
            })?;
        let link_type = describe_link_type(handle.get_datalink());

        Ok(Self {
            handle,
            link_type,
            path: path.to_path_buf(),
        })
    }

    /// The link-layer format every packet in this file is in.
    ///
    /// A capture file has exactly one, fixed when the file was written.
    pub fn link_type(&self) -> &LinkType {
        &self.link_type
    }

    /// The path this file was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the file, calling `on_packet` for each packet.
    ///
    /// `limit` stops after that many packets, leaving the rest of the file
    /// unread.
    ///
    /// A read failure part way through does not fail this call. A truncated
    /// capture still contains everything before the damage, and a forensics
    /// tool that discarded those packets because the tail was broken would be
    /// destroying evidence. The failure is reported in
    /// [`FileSummary::read_error`] instead.
    pub fn run<F>(&mut self, limit: Option<u64>, on_packet: F) -> FileSummary
    where
        F: FnMut(&PacketMetadata, &[u8]) -> std::io::Result<()>,
    {
        let clock = Instant::now();
        // No interrupt flag: a file read is not blocked waiting on a network,
        // so there is nothing to wake up. No sink either: offline analysis is
        // read-only and never writes a capture.
        let options = PumpOptions {
            limit,
            ..PumpOptions::default()
        };
        let (run, failure) = pump(&mut self.handle, options, on_packet);

        FileSummary {
            tally: run.tally,
            time_span: run.time_span,
            stop_reason: run.stop_reason,
            processing_time: clock.elapsed(),
            read_error: failure.map(|source| NetSentryError::CaptureFileCorrupt {
                path: self.path.clone(),
                source,
            }),
        }
    }
}

/// Diagnoses whether a path can be read, before libpcap is asked to try.
///
/// Opening the file rather than only inspecting its metadata is deliberate:
/// metadata can be readable when the file itself is not. There is a window
/// between this check and libpcap's own open, but for a read-only analysis the
/// worst outcome is a less precise error message.
fn check_readable(path: &Path) -> Result<()> {
    let file = std::fs::File::open(path).map_err(|error| classify_open_error(path, &error))?;

    // Opening a directory *succeeds* on Unix, so a successful open is not proof
    // that there is a file here. Asking the open handle rather than the path
    // also closes the gap where the path could change underneath us.
    match file.metadata() {
        Ok(metadata) if metadata.is_dir() => Err(NetSentryError::CaptureFileIsDirectory {
            path: path.to_path_buf(),
        }),
        Ok(_) => Ok(()),
        Err(error) => Err(classify_open_error(path, &error)),
    }
}

/// Maps a filesystem error to the NetSentry error that explains it.
fn classify_open_error(path: &Path, error: &std::io::Error) -> NetSentryError {
    let path = path.to_path_buf();
    match error.kind() {
        std::io::ErrorKind::NotFound => NetSentryError::CaptureFileMissing { path },
        std::io::ErrorKind::PermissionDenied => {
            NetSentryError::CaptureFilePermissionDenied { path }
        }
        // Some platforms refuse to open a directory at all, with an error whose
        // kind differs between them. Asking what the path *is* answers it
        // portably; on Unix the open succeeds and `check_readable` catches it.
        _ if path.is_dir() => NetSentryError::CaptureFileIsDirectory { path },
        _ => NetSentryError::CaptureFileUnreadable {
            path,
            reason: error.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_is_named_as_missing() {
        let error = CaptureFile::open(Path::new("/nonexistent/netsentry-test.pcap")).err();
        assert!(matches!(
            error,
            Some(NetSentryError::CaptureFileMissing { .. })
        ));
    }

    #[test]
    fn a_directory_is_not_mistaken_for_a_capture_file() {
        let error = CaptureFile::open(Path::new("/tmp")).err();
        assert!(
            matches!(error, Some(NetSentryError::CaptureFileIsDirectory { .. })),
            "got {error:?}"
        );
    }

    #[test]
    fn filesystem_errors_map_to_their_own_variants() {
        let path = Path::new("/some/where.pcap");

        let missing =
            classify_open_error(path, &std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(matches!(missing, NetSentryError::CaptureFileMissing { .. }));

        let denied = classify_open_error(
            path,
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(matches!(
            denied,
            NetSentryError::CaptureFilePermissionDenied { .. }
        ));

        let other =
            classify_open_error(path, &std::io::Error::from(std::io::ErrorKind::InvalidData));
        assert!(matches!(
            other,
            NetSentryError::CaptureFileUnreadable { .. }
        ));
    }
}
