//! Writing captured packets to a pcap file.
//!
//! This is the only place NetSentry creates a lasting copy of someone's
//! traffic, so it is deliberately hard to do by accident: nothing is written
//! unless `--write` names a file, an existing file is refused rather than
//! replaced, and the file is created with restrictive permissions before
//! libpcap is allowed near it.

use std::path::{Path, PathBuf};

use crate::error::{NetSentryError, Result};

/// An open pcap file that captured packets are being written to.
pub struct CaptureWriter {
    savefile: pcap::Savefile,
    path: PathBuf,
}

impl CaptureWriter {
    /// Wraps an open libpcap dump handle.
    pub(crate) fn new(savefile: pcap::Savefile, path: PathBuf) -> Self {
        Self { savefile, path }
    }

    /// Writes one packet exactly as it was captured.
    ///
    /// Takes the driver's own packet rather than a reconstruction of it. The
    /// alternative — rebuilding a `pcap::Packet` from our metadata — would need
    /// a `#[doc(hidden)]` constructor, and would risk the file disagreeing with
    /// what was actually on the wire.
    pub(crate) fn record(&mut self, packet: &pcap::Packet<'_>) {
        self.savefile.write(packet);
    }

    /// The file being written to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Pushes everything buffered out to disk.
    ///
    /// # Errors
    ///
    /// [`NetSentryError::CaptureWriteFailed`] if the write could not complete.
    pub fn flush(&mut self) -> Result<()> {
        self.savefile
            .flush()
            .map_err(|source| NetSentryError::CaptureWriteFailed {
                path: self.path.clone(),
                source,
            })
    }
}

/// Checks that a capture can be written to `path`, and creates it safely.
///
/// Called before the interface is opened, so a mistyped path costs nothing. It
/// does three things:
///
/// 1. **Rejects a non-UTF-8 path.** libpcap's Rust binding unwraps the path
///    conversion internally, so handing it one would panic inside the
///    dependency. Catching it here turns a crash into a message.
/// 2. **Refuses an existing file** unless `overwrite` was asked for. A capture
///    cannot be re-recorded; silently truncating one is not a recoverable
///    mistake.
/// 3. **Creates the file with owner-only permissions** on Unix, before libpcap
///    opens it. libpcap's own `fopen` would create it world-readable subject to
///    the umask, and this file is about to contain other people's credentials.
///    `fopen(path, "w")` truncates an existing file without touching its mode,
///    so the restriction survives.
///
/// # Errors
///
/// [`NetSentryError::PathNotUtf8`], [`NetSentryError::OutputFileExists`] or
/// [`NetSentryError::OutputFileUnwritable`].
pub fn prepare_capture_file(path: &Path, overwrite: bool) -> Result<()> {
    if path.to_str().is_none() {
        return Err(NetSentryError::PathNotUtf8 {
            path: path.to_path_buf(),
        });
    }

    let exists = path.try_exists().unwrap_or(false);
    if exists && !overwrite {
        return Err(NetSentryError::OutputFileExists {
            path: path.to_path_buf(),
        });
    }

    create_private_file(path).map_err(|error| NetSentryError::OutputFileUnwritable {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

/// Creates (or truncates) the file so that only its owner can read it.
#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map(|_| ())
}

/// Creates (or truncates) the file.
///
/// Windows has no mode bits to set here; the file inherits the directory's ACL,
/// which for a user's own directory is already owner-only.
#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch path that cleans itself up.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("netsentry-test-{}-{name}", std::process::id()));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn preparing_a_new_file_creates_it() {
        let scratch = Scratch::new("new");
        assert!(prepare_capture_file(scratch.path(), false).is_ok());
        assert!(scratch.path().exists());
    }

    #[test]
    fn an_existing_file_is_refused_unless_overwriting_was_asked_for() {
        let scratch = Scratch::new("existing");
        let precious = b"a capture someone cares about";
        std::fs::write(scratch.path(), precious).unwrap_or_default();

        let refused = prepare_capture_file(scratch.path(), false).err();
        assert!(
            matches!(refused, Some(NetSentryError::OutputFileExists { .. })),
            "got {refused:?}"
        );
        // The refusal must not have touched the file.
        assert_eq!(
            std::fs::read(scratch.path()).unwrap_or_default(),
            precious,
            "the existing file was modified by a refused write"
        );

        assert!(prepare_capture_file(scratch.path(), true).is_ok());
        assert_eq!(
            std::fs::read(scratch.path()).unwrap_or_default().len(),
            0,
            "--overwrite should have truncated it"
        );
    }

    #[test]
    fn an_unwritable_directory_is_reported_rather_than_panicking() {
        let error = prepare_capture_file(
            Path::new("/nonexistent-directory-netsentry/out.pcap"),
            false,
        )
        .err();
        assert!(
            matches!(error, Some(NetSentryError::OutputFileUnwritable { .. })),
            "got {error:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_capture_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt as _;

        let scratch = Scratch::new("perms");
        assert!(prepare_capture_file(scratch.path(), false).is_ok());

        let mode = std::fs::metadata(scratch.path())
            .map(|meta| meta.permissions().mode() & 0o777)
            .unwrap_or(0o777);
        assert_eq!(
            mode, 0o600,
            "a file about to hold credentials must not be group- or world-readable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_path_is_rejected_before_libpcap_can_panic_on_it() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;

        let path = PathBuf::from(OsStr::from_bytes(b"/tmp/netsentry-\xff\xfe.pcap"));
        let error = prepare_capture_file(&path, false).err();
        assert!(
            matches!(error, Some(NetSentryError::PathNotUtf8 { .. })),
            "got {error:?}"
        );
    }
}
