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
        ];

        for variant in &variants {
            assert!(
                !variant.hints().is_empty(),
                "{variant} should tell the user what to do next"
            );
        }
    }
}
