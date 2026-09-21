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
        ];

        for variant in &variants {
            assert!(
                !variant.hints().is_empty(),
                "{variant} should tell the user what to do next"
            );
        }
    }
}
