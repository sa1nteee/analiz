//! Typed error handling for NetSentry.
//!
//! Every fallible operation in this crate returns [`Result`], which carries a
//! [`NetSentryError`]. Errors are *typed* rather than stringly-typed so that
//! callers (today the CLI, tomorrow the Tauri layer) can react to a specific
//! failure instead of pattern matching on English text.
//!
//! Each variant knows how to explain itself in three parts:
//!
//! * the [`Display`](std::fmt::Display) message — *what* went wrong,
//! * the [`source`](std::error::Error::source) chain — *why* it went wrong,
//! * [`NetSentryError::hints`] — what the *user* can do about it.

use std::path::PathBuf;

/// Convenience alias for results produced by NetSentry.
pub type Result<T> = std::result::Result<T, NetSentryError>;

/// Every way a NetSentry operation can fail.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetSentryError {
    /// `pcap_findalldevs()` failed, so no interface list could be built.
    #[error("could not enumerate network interfaces")]
    InterfaceEnumeration {
        /// The underlying libpcap/Npcap failure.
        #[source]
        source: pcap::Error,
    },

    /// The capture driver responded, but reported zero interfaces.
    #[error("no network interfaces are visible to the capture driver")]
    NoInterfacesFound,

    /// The interface selector matched nothing.
    #[error("interface {selector:?} not found ({available} interface(s) available)")]
    InterfaceNotFound {
        /// What the user asked for.
        selector: String,
        /// How many interfaces the driver reported.
        available: usize,
    },

    /// A listing index was given that no interface has.
    #[error("interface #{index} not found ({available} interface(s) available)")]
    InterfaceIndexOutOfRange {
        /// The index the user asked for.
        index: usize,
        /// How many interfaces the driver reported.
        available: usize,
    },

    /// A name matched several interfaces once letter case was ignored.
    #[error("interface {selector:?} matches more than one interface")]
    AmbiguousInterface {
        /// What the user asked for.
        selector: String,
    },

    /// `--snaplen` was outside the range libpcap accepts.
    #[error("invalid snapshot length {value}: must be between {min} and {max} bytes")]
    InvalidSnaplen {
        /// The rejected value.
        value: u32,
        /// Smallest accepted value.
        min: u32,
        /// Largest accepted value.
        max: u32,
    },

    /// `--count` was zero, which would capture nothing.
    #[error("invalid packet count {value}: must be at least 1")]
    InvalidCount {
        /// The rejected value.
        value: u64,
    },

    /// The capture driver refused to open the interface for lack of privileges.
    #[error("not allowed to capture on {interface:?}")]
    CapturePermissionDenied {
        /// The interface that was being opened.
        interface: String,
        /// The underlying libpcap/Npcap failure.
        #[source]
        source: pcap::Error,
    },

    /// The capture driver refused to open the interface.
    #[error("could not open {interface:?} for capture")]
    CaptureOpen {
        /// The interface that was being opened.
        interface: String,
        /// The underlying libpcap/Npcap failure.
        #[source]
        source: pcap::Error,
    },

    /// Reading from an open capture failed.
    #[error("capture failed while reading packets")]
    CaptureRead {
        /// The underlying libpcap/Npcap failure.
        #[source]
        source: pcap::Error,
    },

    /// The driver would not report its packet counters.
    #[error("capture statistics are unavailable")]
    CaptureStatistics {
        /// The underlying libpcap/Npcap failure.
        #[source]
        source: pcap::Error,
    },

    /// The capture file does not exist.
    #[error("capture file not found: {}", path.display())]
    CaptureFileMissing {
        /// The path that was asked for.
        path: PathBuf,
    },

    /// The capture file exists but cannot be opened by this user.
    #[error("not allowed to read capture file: {}", path.display())]
    CaptureFilePermissionDenied {
        /// The path that was asked for.
        path: PathBuf,
    },

    /// The path names a directory, not a file.
    #[error("{} is a directory, not a capture file", path.display())]
    CaptureFileIsDirectory {
        /// The path that was asked for.
        path: PathBuf,
    },

    /// The capture file could not be opened, for some other reason.
    #[error("could not read capture file: {}", path.display())]
    CaptureFileUnreadable {
        /// The path that was asked for.
        path: PathBuf,
        /// What the operating system said.
        reason: String,
    },

    /// The file opened but is not a capture file NetSentry can read.
    #[error("{} is not a capture file NetSentry can read", path.display())]
    CaptureFileFormat {
        /// The path that was asked for.
        path: PathBuf,
        /// The underlying libpcap/Npcap failure.
        #[source]
        source: pcap::Error,
    },

    /// The capture file ended or became unreadable part way through.
    ///
    /// The packets before the damage were still analysed; this reports that
    /// the rest of the file could not be.
    #[error("capture file is truncated or corrupt: {}", path.display())]
    CaptureFileCorrupt {
        /// The path that was being read.
        path: PathBuf,
        /// The underlying libpcap/Npcap failure.
        #[source]
        source: pcap::Error,
    },

    /// A path could not be given to libpcap, which requires valid UTF-8.
    #[error("path is not valid UTF-8: {}", path.display())]
    PathNotUtf8 {
        /// The offending path.
        path: PathBuf,
    },

    /// The output file already exists and overwriting was not requested.
    #[error("{} already exists", path.display())]
    OutputFileExists {
        /// The path that would have been overwritten.
        path: PathBuf,
    },

    /// The capture file could not be created.
    #[error("could not create capture file: {}", path.display())]
    OutputFileUnwritable {
        /// The path that was asked for.
        path: PathBuf,
        /// What the operating system said.
        reason: String,
    },

    /// libpcap refused to start writing the capture file.
    #[error("could not start writing capture file: {}", path.display())]
    CaptureWriteOpen {
        /// The path that was asked for.
        path: PathBuf,
        /// The underlying libpcap/Npcap failure.
        #[source]
        source: pcap::Error,
    },

    /// Writing to the capture file failed.
    #[error("could not write capture file: {}", path.display())]
    CaptureWriteFailed {
        /// The file being written.
        path: PathBuf,
        /// The underlying libpcap/Npcap failure.
        #[source]
        source: pcap::Error,
    },

    /// The interrupt handler could not be installed.
    #[error("could not install the Ctrl+C handler")]
    SignalHandler {
        /// The underlying failure.
        #[source]
        source: ctrlc::Error,
    },
}

impl NetSentryError {
    /// Actionable suggestions for the user, one per line.
    ///
    /// Returning a slice (rather than formatting into a string) keeps the
    /// presentation decision — indentation, colour, JSON — with the caller.
    pub fn hints(&self) -> &'static [&'static str] {
        match self {
            Self::InterfaceEnumeration { .. } => &[
                "packet capture requires elevated privileges",
                "Windows: run this terminal as Administrator",
                "Linux:   run as root, or grant the binary CAP_NET_RAW and CAP_NET_ADMIN",
            ],
            Self::NoInterfacesFound => &[
                "Windows: install Npcap from https://npcap.com and enable",
                "         \"WinPcap API-compatible Mode\" during setup",
                "Linux:   make sure libpcap is installed and you have capture privileges",
            ],
            Self::InterfaceNotFound { .. } | Self::InterfaceIndexOutOfRange { .. } => &[
                "run `netsentry list` to see the available interfaces",
                "an interface can be given by its [n] index or by its system name",
            ],
            Self::AmbiguousInterface { .. } => {
                &["run `netsentry list` and pass the interface's exact system name"]
            }
            Self::InvalidSnaplen { .. } => &[
                "--snaplen is how many bytes of each packet to keep",
                "65535 captures whole frames; smaller values truncate them",
            ],
            Self::InvalidCount { .. } => &[
                "--count is how many packets to capture before stopping",
                "omit --count to capture until you press Ctrl+C",
            ],
            Self::CapturePermissionDenied { .. } => &[
                "capturing packets needs more privileges than listing interfaces",
                "Windows: run this terminal as Administrator",
                "Linux:   run as root, or grant the binary CAP_NET_RAW and CAP_NET_ADMIN:",
                "         sudo setcap cap_net_raw,cap_net_admin=eip ./netsentry",
            ],
            Self::CaptureOpen { .. } => &[
                "check the interface still exists with `netsentry list`",
                "an interface that is down cannot be captured on",
                "capturing also needs elevated privileges (Administrator, or root/CAP_NET_RAW)",
            ],
            Self::CaptureRead { .. } => &[
                "the interface may have been removed or reconfigured mid-capture",
                "re-run `netsentry list` to check it is still present",
            ],
            Self::CaptureStatistics { .. } => &[
                "the captured packets are still correct; only the driver's own counters are missing",
                "not every capture source keeps statistics",
            ],
            Self::CaptureFileMissing { .. } => {
                &["check the path, including its spelling and any quoting the shell may have eaten"]
            }
            Self::CaptureFilePermissionDenied { .. } => &[
                "capture files often belong to root, because capturing needs privileges",
                "check the file's owner and mode, or copy it somewhere you can read",
            ],
            Self::CaptureFileIsDirectory { .. } => {
                &["pass the capture file itself, not the folder containing it"]
            }
            Self::CaptureFileUnreadable { .. } => {
                &["check that the path is a regular file and that its device is available"]
            }
            Self::CaptureFileFormat { .. } => &[
                "NetSentry reads pcap and pcapng files, as written by tcpdump, Wireshark or dumpcap",
                "a compressed capture (.gz, .zst) has to be decompressed first",
            ],
            Self::CaptureFileCorrupt { .. } => &[
                "the packets reported above were read successfully; the rest of the file was not",
                "a capture cut short like this usually means its writer was killed mid-write",
            ],
            Self::PathNotUtf8 { .. } => &[
                "libpcap only accepts paths that are valid UTF-8",
                "rename the file, or move it somewhere with a plain ASCII path",
            ],
            Self::OutputFileExists { .. } => &[
                "pass --overwrite to replace it, or choose another name",
                "a capture file is refused rather than replaced, because it cannot be re-recorded",
            ],
            Self::CaptureWriteFailed { .. } => {
                &["the disk may be full, or the file may have been removed mid-capture"]
            }
            Self::OutputFileUnwritable { .. } | Self::CaptureWriteOpen { .. } => {
                &["check that the directory exists and that you can write to it"]
            }
            Self::SignalHandler { .. } => {
                &["another handler for Ctrl+C may already be installed in this process"]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn enumeration_error_keeps_its_source() {
        let err = NetSentryError::InterfaceEnumeration {
            source: pcap::Error::PcapError("socket: Operation not permitted".into()),
        };

        // The top-level message stays stable and human readable ...
        assert_eq!(err.to_string(), "could not enumerate network interfaces");
        // ... while the driver's own words survive in the source chain.
        let cause = err.source().map(ToString::to_string).unwrap_or_default();
        assert!(
            cause.contains("Operation not permitted"),
            "cause was {cause:?}"
        );
    }

    #[test]
    fn every_variant_offers_at_least_one_hint() {
        let variants = [
            NetSentryError::InterfaceEnumeration {
                source: pcap::Error::InvalidString,
            },
            NetSentryError::NoInterfacesFound,
            NetSentryError::InterfaceNotFound {
                selector: "eth9".into(),
                available: 2,
            },
            NetSentryError::InterfaceIndexOutOfRange {
                index: 9,
                available: 2,
            },
            NetSentryError::AmbiguousInterface {
                selector: "eth0".into(),
            },
            NetSentryError::InvalidSnaplen {
                value: 0,
                min: 1,
                max: 262_144,
            },
            NetSentryError::InvalidCount { value: 0 },
            NetSentryError::CapturePermissionDenied {
                interface: "eth0".into(),
                source: pcap::Error::InvalidString,
            },
            NetSentryError::CaptureOpen {
                interface: "eth0".into(),
                source: pcap::Error::InvalidString,
            },
            NetSentryError::CaptureRead {
                source: pcap::Error::InvalidString,
            },
            NetSentryError::CaptureStatistics {
                source: pcap::Error::InvalidString,
            },
            NetSentryError::CaptureFileMissing {
                path: "/tmp/x.pcap".into(),
            },
            NetSentryError::CaptureFilePermissionDenied {
                path: "/tmp/x.pcap".into(),
            },
            NetSentryError::CaptureFileIsDirectory {
                path: "/tmp".into(),
            },
            NetSentryError::CaptureFileUnreadable {
                path: "/tmp/x.pcap".into(),
                reason: "device not ready".into(),
            },
            NetSentryError::CaptureFileFormat {
                path: "/tmp/x.pcap".into(),
                source: pcap::Error::InvalidString,
            },
            NetSentryError::CaptureFileCorrupt {
                path: "/tmp/x.pcap".into(),
                source: pcap::Error::InvalidString,
            },
            NetSentryError::PathNotUtf8 {
                path: "/tmp/x.pcap".into(),
            },
            NetSentryError::OutputFileExists {
                path: "/tmp/x.pcap".into(),
            },
            NetSentryError::OutputFileUnwritable {
                path: "/tmp/x.pcap".into(),
                reason: "read-only filesystem".into(),
            },
            NetSentryError::CaptureWriteOpen {
                path: "/tmp/x.pcap".into(),
                source: pcap::Error::InvalidString,
            },
        ];

        for variant in &variants {
            assert!(
                !variant.hints().is_empty(),
                "{variant} should tell the user what to do next"
            );
        }
    }
}
