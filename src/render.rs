//! Terminal rendering.
//!
//! Every function here is pure: data in, [`String`] out. Nothing touches the
//! network, the filesystem or stdout. That makes the whole presentation layer
//! unit testable, and means the same data can later be rendered as JSON or
//! handed to a UI without rewriting anything.

use std::fmt::Write as _;
use std::net::IpAddr;

use crate::capture::{InterfaceAddress, NetworkInterface};
use crate::error::NetSentryError;

/// Indentation of an interface's detail lines.
const INDENT: &str = "    ";
/// Width of the detail label column ("description" is the longest label).
const LABEL_WIDTH: usize = 11;
/// Gap between the label column and its value.
const LABEL_GAP: &str = "  ";

/// Renders the full `netsentry list` output, trailing newline included.
pub fn interface_list(interfaces: &[NetworkInterface]) -> String {
    let mut out = String::new();

    out.push_str(concat!(
        "NetSentry ",
        env!("CARGO_PKG_VERSION"),
        " \u{2014} network interfaces\n\n"
    ));

    for interface in interfaces {
        out.push_str(&interface_block(interface));
        out.push('\n');
    }

    let _ = writeln!(out, "{} found.", count_phrase(interfaces.len()));
    out
}

/// Renders one interface as a labelled block.
///
/// A block layout is used rather than a table because Windows interface names
/// (`\Device\NPF_{3F2A8C10-4B7D-11EE-9C1A-9A2B0C3D4E5F}`) are far too wide for
/// a column without truncating them, and truncating the very string the user
/// must pass back to the tool would be a usability bug.
fn interface_block(interface: &NetworkInterface) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "[{}] {}", interface.index, interface.name);

    detail(
        &mut out,
        "description",
        interface.description.as_deref().unwrap_or("(none)"),
    );

    let attributes = interface
        .attributes
        .iter()
        .map(|attribute| attribute.label())
        .collect::<Vec<_>>();
    let status = if attributes.is_empty() {
        interface.status.label().to_owned()
    } else {
        format!("{}  [{}]", interface.status.label(), attributes.join(", "))
    };
    detail(&mut out, "status", &status);

    if interface.addresses.is_empty() {
        detail(&mut out, "addresses", "(none)");
    } else {
        for (position, address) in interface.addresses.iter().enumerate() {
            let label = if position == 0 { "addresses" } else { "" };
            detail(&mut out, label, &format_address(address));
        }
    }

    out
}

/// Writes one `label   value` detail line.
fn detail(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "{INDENT}{label:<LABEL_WIDTH$}{LABEL_GAP}{value}");
}

/// Formats an address as CIDR when possible.
///
/// Falls back to spelling the mask out whenever it cannot be expressed as a
/// prefix length, so a strange mask is reported rather than quietly rounded
/// into a plausible looking one.
pub fn format_address(address: &InterfaceAddress) -> String {
    match address.netmask {
        None => address.addr.to_string(),
        Some(netmask) => match netmask_to_prefix_len(netmask) {
            Some(prefix) if same_family(address.addr, netmask) => {
                format!("{}/{}", address.addr, prefix)
            }
            _ => format!("{} (netmask {})", address.addr, netmask),
        },
    }
}

/// True when both addresses are IPv4, or both are IPv6.
fn same_family(a: IpAddr, b: IpAddr) -> bool {
    a.is_ipv4() == b.is_ipv4()
}

/// Converts a netmask into a prefix length.
///
/// Returns [`None`] if the mask is not a run of ones followed by a run of
/// zeroes. Non-contiguous masks are legal to configure on some systems and are
/// occasionally a sign of a misconfigured (or deliberately odd) host, so they
/// must be surfaced rather than normalised away.
pub fn netmask_to_prefix_len(netmask: IpAddr) -> Option<u32> {
    let (bits, width) = match netmask {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32_u32),
        IpAddr::V6(v6) => (u128::from(v6), 128_u32),
    };

    // Left-align the mask in the u128 so `leading_ones` counts the prefix.
    let aligned = bits << (128 - width);
    let prefix = aligned.leading_ones();

    // Everything after the prefix must be zero for the mask to be contiguous.
    let remainder = aligned.checked_shl(prefix).unwrap_or(0);
    if remainder == 0 { Some(prefix) } else { None }
}

/// Renders a failure as *what happened*, *why*, and *what to do about it*.
///
/// A security tool is only useful if the person running it can tell the
/// difference between "there is nothing to see" and "I could not look", so
/// every failure is reported with its full source chain rather than a single
/// summarised line.
pub fn error_report(error: &NetSentryError) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "error: {error}");

    // Walk the source chain so the driver's own wording is never swallowed.
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        let _ = writeln!(out, "cause: {cause}");
        source = cause.source();
    }

    for (position, hint) in error.hints().iter().enumerate() {
        let label = if position == 0 { "hint: " } else { "      " };
        let _ = writeln!(out, "{label} {hint}");
    }

    out
}

/// "1 interface" / "4 interfaces" — English pluralisation for the summary line.
fn count_phrase(count: usize) -> String {
    if count == 1 {
        "1 interface".to_owned()
    } else {
        format!("{count} interfaces")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{InterfaceAttribute, LinkStatus};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn sample() -> NetworkInterface {
        NetworkInterface {
            index: 1,
            name: "eth0".into(),
            description: Some("Intel Wi-Fi 6 AX201".into()),
            status: LinkStatus::Running,
            attributes: vec![InterfaceAttribute::Wireless, InterfaceAttribute::Connected],
            addresses: vec![
                InterfaceAddress {
                    addr: v4(10, 0, 2, 15),
                    netmask: Some(v4(255, 255, 255, 0)),
                },
                InterfaceAddress {
                    addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                    netmask: None,
                },
            ],
        }
    }

    #[test]
    fn contiguous_netmasks_become_prefix_lengths() {
        assert_eq!(netmask_to_prefix_len(v4(255, 255, 255, 0)), Some(24));
        assert_eq!(netmask_to_prefix_len(v4(255, 255, 255, 255)), Some(32));
        assert_eq!(netmask_to_prefix_len(v4(255, 0, 0, 0)), Some(8));
        assert_eq!(netmask_to_prefix_len(v4(0, 0, 0, 0)), Some(0));
        assert_eq!(netmask_to_prefix_len(v4(255, 255, 254, 0)), Some(23));

        let v6_64 = IpAddr::V6(Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0));
        assert_eq!(netmask_to_prefix_len(v6_64), Some(64));
        assert_eq!(
            netmask_to_prefix_len(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            Some(0)
        );
    }

    #[test]
    fn non_contiguous_netmasks_are_rejected() {
        assert_eq!(netmask_to_prefix_len(v4(255, 255, 0, 3)), None);
        assert_eq!(netmask_to_prefix_len(v4(0, 255, 255, 0)), None);
        assert_eq!(netmask_to_prefix_len(v4(255, 0, 255, 0)), None);
    }

    #[test]
    fn addresses_render_as_cidr_and_degrade_honestly() {
        let cidr = format_address(&InterfaceAddress {
            addr: v4(10, 0, 2, 15),
            netmask: Some(v4(255, 255, 255, 0)),
        });
        assert_eq!(cidr, "10.0.2.15/24");

        let no_mask = format_address(&InterfaceAddress {
            addr: v4(10, 0, 2, 15),
            netmask: None,
        });
        assert_eq!(no_mask, "10.0.2.15");

        // A mask we cannot express as a prefix is shown, not rounded.
        let odd = format_address(&InterfaceAddress {
            addr: v4(10, 0, 2, 15),
            netmask: Some(v4(255, 255, 0, 3)),
        });
        assert_eq!(odd, "10.0.2.15 (netmask 255.255.0.3)");

        // A mask from the wrong address family must not produce a fake prefix.
        let mismatched = format_address(&InterfaceAddress {
            addr: v4(10, 0, 2, 15),
            netmask: Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        });
        assert_eq!(mismatched, "10.0.2.15 (netmask ::)");
    }

    #[test]
    fn interface_block_shows_every_field() {
        let block = interface_block(&sample());

        assert!(block.starts_with("[1] eth0\n"), "block was:\n{block}");
        assert!(block.contains("description  Intel Wi-Fi 6 AX201"));
        assert!(block.contains("status       running  [wireless, connected]"));
        assert!(block.contains("addresses    10.0.2.15/24"));
        assert!(block.contains("::1"));
    }

    #[test]
    fn missing_data_is_labelled_rather_than_left_blank() {
        let bare = NetworkInterface {
            index: 2,
            name: "any".into(),
            description: None,
            status: LinkStatus::Down,
            attributes: vec![],
            addresses: vec![],
        };
        let block = interface_block(&bare);

        assert!(block.contains("description  (none)"));
        assert!(block.contains("addresses    (none)"));
        // With no attributes there must be no empty bracket pair.
        assert!(block.contains("status       down\n"), "block was:\n{block}");
        assert!(!block.contains("[]"));
    }

    #[test]
    fn additional_addresses_align_under_the_first() {
        let block = interface_block(&sample());
        let continuation = format!("{INDENT}{:width$}{LABEL_GAP}::1", "", width = LABEL_WIDTH);
        assert!(block.contains(&continuation), "block was:\n{block}");
    }

    #[test]
    fn listing_has_a_header_and_a_summary() {
        let listing = interface_list(&[sample()]);
        assert!(listing.starts_with("NetSentry "));
        assert!(listing.contains("network interfaces"));
        assert!(listing.ends_with("1 interface found.\n"));

        let empty = interface_list(&[]);
        assert!(empty.ends_with("0 interfaces found.\n"));
    }

    #[test]
    fn error_report_states_what_why_and_next_step() {
        let report = error_report(&NetSentryError::InterfaceEnumeration {
            source: pcap::Error::PcapError("socket: Operation not permitted".into()),
        });

        assert!(report.starts_with("error: could not enumerate network interfaces\n"));
        assert!(report.contains("cause: "));
        assert!(report.contains("Operation not permitted"));
        assert!(report.contains("hint: "));
        assert!(report.ends_with('\n'));
    }

    #[test]
    fn error_report_indents_continuation_hints() {
        let report = error_report(&NetSentryError::NoInterfacesFound);
        let hint_lines: Vec<&str> = report
            .lines()
            .filter(|line| line.starts_with("hint: ") || line.starts_with("      "))
            .collect();

        assert_eq!(
            hint_lines.len(),
            NetSentryError::NoInterfacesFound.hints().len()
        );
        assert!(hint_lines[0].starts_with("hint: "));
        for line in &hint_lines[1..] {
            assert!(line.starts_with("      "), "unaligned hint: {line:?}");
        }
    }

    #[test]
    fn summary_line_pluralises() {
        assert_eq!(count_phrase(0), "0 interfaces");
        assert_eq!(count_phrase(1), "1 interface");
        assert_eq!(count_phrase(4), "4 interfaces");
    }
}
