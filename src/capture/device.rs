//! Network interface discovery.
//!
//! This module turns what the capture driver reports into NetSentry's own
//! types. Keeping our own [`NetworkInterface`] (instead of passing
//! [`pcap::Device`] upwards) means the rest of the program never depends on the
//! FFI layer, and that the presentation layer can be unit tested without
//! touching the operating system.

use std::net::IpAddr;

use crate::error::{NetSentryError, Result};

/// Operational state of an interface, taken verbatim from the
/// `PCAP_IF_UP` / `PCAP_IF_RUNNING` flags of `pcap_findalldevs()`.
///
/// NetSentry deliberately does *not* consult platform specific APIs to refine
/// this. If the driver does not populate the flags, the interface is reported
/// as [`LinkStatus::Down`] rather than guessed at — see the limitations section
/// of the README.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    /// `UP` and `RUNNING`: administratively enabled and operational.
    Running,
    /// `UP` without `RUNNING`: enabled, but not carrying traffic.
    Up,
    /// `UP` is not set.
    Down,
}

impl LinkStatus {
    /// Short lowercase label used in terminal output.
    pub fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Up => "up",
            Self::Down => "down",
        }
    }

    /// Derives the status from the flag set reported by the driver.
    fn from_flags(flags: &pcap::DeviceFlags) -> Self {
        match (flags.is_up(), flags.is_running()) {
            (true, true) => Self::Running,
            (true, false) => Self::Up,
            (false, _) => Self::Down,
        }
    }
}

/// An additional fact the driver reported about an interface.
///
/// Only facts that libpcap/Npcap state explicitly are listed here; nothing is
/// inferred. `ConnectionStatus::Unknown` and `NotApplicable` produce no
/// attribute at all, because they carry no information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceAttribute {
    /// `PCAP_IF_LOOPBACK`: traffic never leaves this machine.
    Loopback,
    /// `PCAP_IF_WIRELESS`: radio based link (Wi-Fi, 802.15.4, IrDA).
    Wireless,
    /// The adapter reports itself as connected / associated.
    Connected,
    /// The adapter reports itself as disconnected.
    Disconnected,
}

impl InterfaceAttribute {
    /// Short lowercase label used in terminal output.
    pub fn label(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Wireless => "wireless",
            Self::Connected => "connected",
            Self::Disconnected => "disconnected",
        }
    }

    /// Collects every attribute the driver explicitly reported.
    fn from_flags(flags: &pcap::DeviceFlags) -> Vec<Self> {
        let mut attributes = Vec::new();
        if flags.is_loopback() {
            attributes.push(Self::Loopback);
        }
        if flags.is_wireless() {
            attributes.push(Self::Wireless);
        }
        match flags.connection_status {
            pcap::ConnectionStatus::Connected => attributes.push(Self::Connected),
            pcap::ConnectionStatus::Disconnected => attributes.push(Self::Disconnected),
            // "Unknown" and "NotApplicable" are the driver saying it has no
            // answer. Rendering them as a status would invent information.
            pcap::ConnectionStatus::Unknown | pcap::ConnectionStatus::NotApplicable => {}
        }
        attributes
    }
}

/// A single address bound to an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddress {
    /// The address itself.
    pub addr: IpAddr,
    /// The network mask, when the driver supplied one.
    pub netmask: Option<IpAddr>,
}

/// A network interface that the capture driver can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInterface {
    /// 1-based position in the listing. This is a *presentation* handle for
    /// humans, not a stable system identifier — it can change between runs.
    /// Anything that must survive a restart uses [`NetworkInterface::name`].
    pub index: usize,
    /// The system name that must be passed to the capture driver
    /// (`eth0` on Linux, `\Device\NPF_{GUID}` on Windows).
    ///
    /// This is the driver's string verbatim, because it has to survive a round
    /// trip back to the driver. It is *not* safe to print as-is; the rendering
    /// layer sanitises it.
    pub name: String,
    /// Human readable description, when the driver supplies one.
    pub description: Option<String>,
    /// Operational state.
    pub status: LinkStatus,
    /// Extra facts reported by the driver.
    pub attributes: Vec<InterfaceAttribute>,
    /// Addresses bound to this interface.
    pub addresses: Vec<InterfaceAddress>,
}

/// Lists every interface the capture driver exposes.
///
/// # Errors
///
/// Returns [`NetSentryError::InterfaceEnumeration`] if the driver refuses the
/// request (most often a privilege problem), or
/// [`NetSentryError::NoInterfacesFound`] if it succeeds but reports nothing —
/// which on Windows usually means Npcap is not installed correctly.
pub fn list_interfaces() -> Result<Vec<NetworkInterface>> {
    let devices =
        pcap::Device::list().map_err(|source| NetSentryError::InterfaceEnumeration { source })?;

    if devices.is_empty() {
        return Err(NetSentryError::NoInterfacesFound);
    }

    Ok(devices
        .iter()
        .enumerate()
        .map(|(position, device)| from_pcap_device(position + 1, device))
        .collect())
}

/// Finds the interface a user asked for, by name or by listing index.
///
/// Accepted selectors, in this order of preference:
///
/// 1. An **exact system name** (`eth0`, `\Device\NPF_{...}`).
/// 2. A **listing index** as shown by `netsentry list` (1-based).
/// 3. A **case-insensitive system name**, if it matches exactly one interface.
///    Windows device names are GUIDs that users retype or paste in either case,
///    and the underlying filesystem is case-insensitive anyway.
///
/// Names are tried before numbers so that an interface literally called `3`
/// still wins over index 3. That case is absurd, but silently opening the wrong
/// interface is the kind of bug a security tool must not have.
///
/// # Errors
///
/// Returns [`NetSentryError::InterfaceIndexOutOfRange`] when a number is given
/// that no interface has, [`NetSentryError::AmbiguousInterface`] when only a
/// case-insensitive match is possible and it is not unique, and
/// [`NetSentryError::InterfaceNotFound`] otherwise.
pub fn resolve_interface<'a>(
    interfaces: &'a [NetworkInterface],
    selector: &str,
) -> Result<&'a NetworkInterface> {
    let selector = selector.trim();

    if let Some(found) = interfaces.iter().find(|iface| iface.name == selector) {
        return Ok(found);
    }

    if let Some(index) = parse_index(selector) {
        return interfaces.iter().find(|iface| iface.index == index).ok_or(
            NetSentryError::InterfaceIndexOutOfRange {
                index,
                available: interfaces.len(),
            },
        );
    }

    let mut case_insensitive = interfaces
        .iter()
        .filter(|iface| iface.name.eq_ignore_ascii_case(selector));

    match (case_insensitive.next(), case_insensitive.next()) {
        (Some(only), None) => Ok(only),
        (Some(_), Some(_)) => Err(NetSentryError::AmbiguousInterface {
            selector: selector.to_owned(),
        }),
        _ => Err(NetSentryError::InterfaceNotFound {
            selector: selector.to_owned(),
            available: interfaces.len(),
        }),
    }
}

/// Parses a listing index, rejecting anything that is not a plain positive
/// decimal number.
///
/// `str::parse::<usize>` alone would accept `"+3"`, so the input is checked to
/// be digits only. Index `0` is rejected because the listing is 1-based, and a
/// user typing `0` has misunderstood rather than picked something.
fn parse_index(selector: &str) -> Option<usize> {
    if selector.is_empty() || !selector.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    selector.parse::<usize>().ok().filter(|&index| index >= 1)
}

/// Converts one driver-reported device into a [`NetworkInterface`].
///
/// Kept free of I/O on purpose: this is where every field is normalised and
/// sanitised, and it is fully unit testable.
fn from_pcap_device(index: usize, device: &pcap::Device) -> NetworkInterface {
    NetworkInterface {
        index,
        // The name is kept byte-for-byte: it is the handle that must be
        // passed back to the driver to open a capture. Making it safe to
        // print is the rendering layer's job, not this one's.
        name: device.name.clone(),
        description: device
            .desc
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(ToOwned::to_owned),
        status: LinkStatus::from_flags(&device.flags),
        attributes: InterfaceAttribute::from_flags(&device.flags),
        addresses: device
            .addresses
            .iter()
            .map(|address| InterfaceAddress {
                addr: address.addr,
                netmask: address.netmask,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Builds a `pcap::Device` by hand so the conversion can be tested without
    /// a network card, a driver, or elevated privileges.
    fn device(
        name: &str,
        desc: Option<&str>,
        flags: u32,
        addresses: Vec<pcap::Address>,
    ) -> pcap::Device {
        pcap::Device {
            name: name.to_owned(),
            desc: desc.map(ToOwned::to_owned),
            addresses,
            flags: pcap::DeviceFlags::from(flags),
        }
    }

    fn address(addr: IpAddr, netmask: Option<IpAddr>) -> pcap::Address {
        pcap::Address {
            addr,
            netmask,
            broadcast_addr: None,
            dst_addr: None,
        }
    }

    const PCAP_IF_LOOPBACK: u32 = 0x0000_0001;
    const PCAP_IF_UP: u32 = 0x0000_0002;
    const PCAP_IF_RUNNING: u32 = 0x0000_0004;
    const PCAP_IF_WIRELESS: u32 = 0x0000_0008;
    const PCAP_IF_CONNECTED: u32 = 0x0000_0010;
    const PCAP_IF_DISCONNECTED: u32 = 0x0000_0020;

    fn interfaces(names: &[&str]) -> Vec<NetworkInterface> {
        names
            .iter()
            .enumerate()
            .map(|(position, name)| NetworkInterface {
                index: position + 1,
                name: (*name).to_owned(),
                description: None,
                status: LinkStatus::Down,
                attributes: vec![],
                addresses: vec![],
            })
            .collect()
    }

    #[test]
    fn resolves_by_listing_index() {
        let list = interfaces(&["eth0", "wlan0", "lo"]);

        for (selector, expected) in [("1", "eth0"), ("2", "wlan0"), ("3", "lo")] {
            let found = resolve_interface(&list, selector).ok();
            assert_eq!(found.map(|iface| iface.name.as_str()), Some(expected));
        }
    }

    #[test]
    fn resolves_by_exact_system_name() {
        let list = interfaces(&["eth0", "\\Device\\NPF_{ABC-123}"]);

        let found = resolve_interface(&list, "\\Device\\NPF_{ABC-123}").ok();
        assert_eq!(found.map(|iface| iface.index), Some(2));
    }

    #[test]
    fn resolves_windows_names_case_insensitively() {
        let list = interfaces(&["\\Device\\NPF_{Abc-123}"]);

        let found = resolve_interface(&list, "\\device\\npf_{abc-123}").ok();
        assert_eq!(found.map(|iface| iface.index), Some(1));
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let list = interfaces(&["eth0", "wlan0"]);

        assert_eq!(
            resolve_interface(&list, "  2  ")
                .ok()
                .map(|iface| iface.name.as_str()),
            Some("wlan0")
        );
        assert_eq!(
            resolve_interface(&list, " eth0 ")
                .ok()
                .map(|iface| iface.index),
            Some(1)
        );
    }

    #[test]
    fn an_interface_named_like_a_number_wins_over_that_index() {
        // Pathological, but silently opening the wrong interface would be worse
        // than any amount of pedantry here.
        let list = interfaces(&["eth0", "3", "lo"]);

        let found = resolve_interface(&list, "3").ok();
        assert_eq!(found.map(|iface| iface.index), Some(2));
    }

    #[test]
    fn out_of_range_index_reports_how_many_exist() {
        let list = interfaces(&["eth0", "wlan0"]);

        let error = resolve_interface(&list, "9").err();
        assert!(matches!(
            error,
            Some(NetSentryError::InterfaceIndexOutOfRange {
                index: 9,
                available: 2
            })
        ));
    }

    #[test]
    fn index_zero_is_rejected_because_the_listing_starts_at_one() {
        let list = interfaces(&["eth0"]);
        assert!(resolve_interface(&list, "0").is_err());
    }

    #[test]
    fn unknown_names_are_reported_not_guessed() {
        let list = interfaces(&["eth0", "wlan0"]);

        for selector in ["eth1", "", "  ", "-1", "+1", "1.0", "0x1", "eth0 extra"] {
            let outcome = resolve_interface(&list, selector);
            assert!(
                outcome.is_err(),
                "selector {selector:?} should not resolve, got {:?}",
                outcome.map(|iface| iface.name.clone())
            );
        }
    }

    #[test]
    fn an_ambiguous_case_insensitive_match_is_refused() {
        let list = interfaces(&["Eth0", "ETH0"]);

        let error = resolve_interface(&list, "eth0").err();
        assert!(matches!(
            error,
            Some(NetSentryError::AmbiguousInterface { .. })
        ));
    }

    #[test]
    fn resolving_against_an_empty_list_is_an_error_not_a_panic() {
        assert!(resolve_interface(&[], "1").is_err());
        assert!(resolve_interface(&[], "eth0").is_err());
    }

    #[test]
    fn link_status_maps_up_and_running_flags() {
        let cases = [
            (PCAP_IF_UP | PCAP_IF_RUNNING, LinkStatus::Running),
            (PCAP_IF_UP, LinkStatus::Up),
            (PCAP_IF_RUNNING, LinkStatus::Down),
            (0, LinkStatus::Down),
        ];

        for (flags, expected) in cases {
            let iface = from_pcap_device(1, &device("eth0", None, flags, vec![]));
            assert_eq!(iface.status, expected, "flags {flags:#x}");
        }
    }

    #[test]
    fn attributes_only_report_what_the_driver_states() {
        let wifi = from_pcap_device(
            1,
            &device("wlan0", None, PCAP_IF_WIRELESS | PCAP_IF_CONNECTED, vec![]),
        );
        assert_eq!(
            wifi.attributes,
            vec![InterfaceAttribute::Wireless, InterfaceAttribute::Connected]
        );

        let loopback = from_pcap_device(
            2,
            &device("lo", None, PCAP_IF_LOOPBACK | PCAP_IF_DISCONNECTED, vec![]),
        );
        assert_eq!(
            loopback.attributes,
            vec![
                InterfaceAttribute::Loopback,
                InterfaceAttribute::Disconnected
            ]
        );

        // An unknown connection status must not become an attribute.
        let plain = from_pcap_device(3, &device("eth0", None, PCAP_IF_UP, vec![]));
        assert!(plain.attributes.is_empty());
    }

    #[test]
    fn blank_descriptions_become_none() {
        for blank in ["", "   ", "\t\n"] {
            let iface = from_pcap_device(1, &device("eth0", Some(blank), 0, vec![]));
            assert_eq!(iface.description, None, "input was {blank:?}");
        }

        let iface = from_pcap_device(1, &device("eth0", Some("  Intel Wi-Fi 6  "), 0, vec![]));
        assert_eq!(iface.description.as_deref(), Some("Intel Wi-Fi 6"));
    }

    #[test]
    fn addresses_are_carried_over_in_order() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15));
        let v4_mask = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        let iface = from_pcap_device(
            7,
            &device(
                "eth0",
                None,
                PCAP_IF_UP,
                vec![address(v4, Some(v4_mask)), address(v6, None)],
            ),
        );

        assert_eq!(iface.index, 7);
        assert_eq!(
            iface.addresses,
            vec![
                InterfaceAddress {
                    addr: v4,
                    netmask: Some(v4_mask)
                },
                InterfaceAddress {
                    addr: v6,
                    netmask: None
                },
            ]
        );
    }
}
