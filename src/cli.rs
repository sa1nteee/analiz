//! Command line surface.
//!
//! The CLI is deliberately only a *description* of the interface: clap parses
//! arguments into these types and the binary decides what to do with them. No
//! work happens here, which keeps the command surface easy to change (and, at
//! v0.9, easy to sit next to a Tauri front end rather than be replaced by one).

use clap::{Args, Parser, Subcommand};

use crate::capture::settings::{DEFAULT_SNAPLEN, MAX_SNAPLEN, MIN_SNAPLEN};

/// Top level NetSentry command.
#[derive(Debug, Parser)]
#[command(
    name = "netsentry",
    version,
    about = "NetSentry \u{2014} network traffic analysis toolkit",
    long_about = "NetSentry inspects network traffic for security analysis.\n\n\
                  Packet capture requires elevated privileges and a capture driver:\n\
                  Npcap on Windows, libpcap on Linux and macOS.\n\n\
                  Only capture traffic on networks you own or are authorised to monitor.",
    propagate_version = true
)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Everything NetSentry can be asked to do.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List the network interfaces visible to the capture driver
    #[command(
        long_about = "Lists every network interface the capture driver reports, with its\n\
                      system name, description, operational status and bound addresses.\n\n\
                      The system name is what identifies an interface to the driver; the\n\
                      [n] index is a convenience for humans and may change between runs.\n\n\
                      Status is taken directly from the driver's UP/RUNNING flags. Drivers\n\
                      that do not report those flags will show every interface as 'down'."
    )]
    List,

    /// Capture live packets from a network interface
    #[command(
        long_about = "Captures packets from one network interface and prints one line of\n\
                      metadata per packet: when it arrived, how many bytes were captured,\n\
                      and how many bytes it had on the wire.\n\n\
                      Packet contents are never printed, saved or logged in this version.\n\n\
                      Capturing requires elevated privileges: Administrator on Windows,\n\
                      root or CAP_NET_RAW on Linux. Only capture on networks you own or\n\
                      are authorised to monitor.\n\n\
                      Press Ctrl+C to stop a capture that has no --count limit."
    )]
    Capture(CaptureArgs),
}

/// Options for the `capture` command.
#[derive(Debug, Args)]
pub struct CaptureArgs {
    /// Interface to capture on: a `netsentry list` index, or a system name
    #[arg(short = 'i', long, value_name = "INTERFACE")]
    pub interface: String,

    /// Stop after this many packets [default: run until Ctrl+C]
    #[arg(short = 'c', long, value_name = "N")]
    pub count: Option<u64>,

    /// Bytes to keep from each packet
    #[arg(
        short = 's',
        long,
        value_name = "BYTES",
        default_value_t = DEFAULT_SNAPLEN,
        long_help = snaplen_help()
    )]
    pub snaplen: u32,

    /// Put the interface into promiscuous mode
    #[arg(
        short = 'p',
        long,
        value_name = "BOOL",
        default_value_t = true,
        action = clap::ArgAction::Set,
        long_help = "Whether to accept frames not addressed to this machine.\n\n\
                     On a switched network this usually changes little, because the\n\
                     switch only forwards traffic meant for this port. Turn it off\n\
                     with --promiscuous false to capture only this host's own traffic."
    )]
    pub promiscuous: bool,
}

/// Builds the `--snaplen` long help from the library's own bounds, so the two
/// can never drift apart.
fn snaplen_help() -> String {
    format!(
        "How many bytes to keep from each packet (the snapshot length).\n\n\
         Accepted range is {MIN_SNAPLEN} to {MAX_SNAPLEN}; the default of {DEFAULT_SNAPLEN}\n\
         keeps whole Ethernet frames. Smaller values capture less of each\n\
         packet, which is faster but discards data later analysis may need."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        // clap's own consistency check: catches duplicate flags, bad argument
        // combinations and malformed help text at test time instead of runtime.
        Cli::command().debug_assert();
    }

    #[test]
    fn list_subcommand_parses() {
        let cli = Cli::try_parse_from(["netsentry", "list"]);
        assert!(matches!(
            cli.map(|parsed| parsed.command),
            Ok(Command::List)
        ));
    }

    #[test]
    fn unknown_input_is_rejected_rather_than_ignored() {
        assert!(Cli::try_parse_from(["netsentry"]).is_err());
        assert!(Cli::try_parse_from(["netsentry", "captrue"]).is_err());
        assert!(Cli::try_parse_from(["netsentry", "list", "--everything"]).is_err());
    }

    #[test]
    fn capture_requires_an_interface() {
        assert!(Cli::try_parse_from(["netsentry", "capture"]).is_err());
    }

    #[test]
    fn capture_accepts_an_index_or_a_name() {
        for selector in ["1", "eth0", r"\Device\NPF_{ABC-123}"] {
            let parsed = Cli::try_parse_from(["netsentry", "capture", "-i", selector]);
            match parsed.map(|cli| cli.command) {
                Ok(Command::Capture(args)) => assert_eq!(args.interface, selector),
                other => panic!("{selector:?} did not parse: {other:?}"),
            }
        }
    }

    #[test]
    fn capture_defaults_are_the_documented_ones() {
        let parsed = Cli::try_parse_from(["netsentry", "capture", "-i", "1"]);
        match parsed.map(|cli| cli.command) {
            Ok(Command::Capture(args)) => {
                assert_eq!(args.count, None, "no --count means run until Ctrl+C");
                assert_eq!(args.snaplen, DEFAULT_SNAPLEN);
                assert!(args.promiscuous);
            }
            other => panic!("did not parse: {other:?}"),
        }
    }

    #[test]
    fn capture_options_parse_long_and_short_forms() {
        let parsed = Cli::try_parse_from([
            "netsentry",
            "capture",
            "--interface",
            "eth0",
            "--count",
            "20",
            "--snaplen",
            "128",
            "--promiscuous",
            "false",
        ]);
        match parsed.map(|cli| cli.command) {
            Ok(Command::Capture(args)) => {
                assert_eq!(args.count, Some(20));
                assert_eq!(args.snaplen, 128);
                assert!(!args.promiscuous);
            }
            other => panic!("did not parse: {other:?}"),
        }

        let short =
            Cli::try_parse_from(["netsentry", "capture", "-i", "eth0", "-c", "5", "-s", "96"]);
        match short.map(|cli| cli.command) {
            Ok(Command::Capture(args)) => {
                assert_eq!(args.count, Some(5));
                assert_eq!(args.snaplen, 96);
            }
            other => panic!("did not parse: {other:?}"),
        }
    }

    #[test]
    fn capture_rejects_values_of_the_wrong_shape() {
        // Range checking belongs to CaptureSettings; the parser's job is to
        // reject things that are not numbers at all.
        for bad in [
            vec!["--count", "-1"],
            vec!["--count", "abc"],
            vec!["--snaplen", "-5"],
            vec!["--snaplen", "1.5"],
            vec!["--promiscuous", "yes-please"],
            vec!["--promiscuous"],
        ] {
            let mut argv = vec!["netsentry", "capture", "-i", "1"];
            argv.extend(bad.iter().copied());
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "{argv:?} should have been rejected"
            );
        }
    }

    #[test]
    fn snaplen_help_quotes_the_librarys_own_bounds() {
        let help = snaplen_help();
        assert!(help.contains(&MIN_SNAPLEN.to_string()));
        assert!(help.contains(&MAX_SNAPLEN.to_string()));
        assert!(help.contains(&DEFAULT_SNAPLEN.to_string()));
    }

    #[test]
    fn help_and_version_are_available() {
        for flag in ["--help", "--version"] {
            let err = Cli::try_parse_from(["netsentry", flag])
                .err()
                .map(|e| e.kind());
            assert!(
                matches!(
                    err,
                    Some(clap::error::ErrorKind::DisplayHelp)
                        | Some(clap::error::ErrorKind::DisplayVersion)
                ),
                "{flag} did not produce output"
            );
        }
    }
}
