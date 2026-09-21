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

/// Converts one driver-reported device into a [`NetworkInterface`].
///
/// Kept free of I/O on purpose: this is where every field is normalised and
/// sanitised, and it is fully unit testable.
fn from_pcap_device(index: usize, device: &pcap::Device) -> NetworkInterface {
    NetworkInterface {
        index,
        name: sanitize_display_text(&device.name),
        description: device
            .desc
            .as_deref()
            .map(sanitize_display_text)
            .filter(|text| !text.is_empty()),
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

/// Makes driver-supplied text safe to print to a terminal.
///
/// Interface names and descriptions come from the operating system, and on
/// Windows ultimately from the registry. They are *not* trusted input: a
/// control character or ANSI escape sequence in a description would let
/// whatever wrote that string move the cursor, recolour, or erase parts of our
/// output. For a tool whose whole job is reporting facts truthfully, that is a
/// real (if small) output-integrity problem, so control characters are replaced
/// with U+FFFD REPLACEMENT CHARACTER.
///
/// The text is never truncated: hiding part of an interface name would be worse
/// than printing an ugly one.
fn sanitize_display_text(text: &str) -> String {
    text.trim()
        .chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
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
    fn control_characters_from_the_driver_are_neutralised() {
        // A description carrying an ANSI escape sequence must not be able to
        // repaint the terminal.
        let hostile = "Realtek\u{1b}[2J\u{7}NIC";
        let iface = from_pcap_device(1, &device("eth0", Some(hostile), 0, vec![]));
        let description = iface.description.unwrap_or_default();

        assert!(
            !description.contains('\u{1b}'),
            "escape survived: {description:?}"
        );
        assert!(!description.chars().any(char::is_control));
        assert!(description.contains("Realtek") && description.contains("NIC"));
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
