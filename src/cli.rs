//! Command line surface.
//!
//! The CLI is deliberately only a *description* of the interface: clap parses
//! arguments into these types and the binary decides what to do with them. No
//! work happens here, which keeps the command surface easy to change (and, at
//! v0.9, easy to sit next to a Tauri front end rather than be replaced by one).

use std::path::PathBuf;

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

    /// Analyse a saved capture file
    #[command(
        visible_alias = "analyze",
        long_about = "Reads a pcap or pcapng file and decodes it exactly as a live capture\n\
                      is decoded, printing one line of metadata per packet.\n\n\
                      The file is opened read-only and never modified. No privileges are\n\
                      needed: reading a file is not capturing.\n\n\
                      Capture files routinely contain credentials, session cookies, visited\n\
                      hostnames and internal network layout. Treat one as you would the\n\
                      traffic it came from."
    )]
    Read(ReadArgs),
}

/// Options for the `read` command.
#[derive(Debug, Args)]
pub struct ReadArgs {
    /// The capture file to analyse
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Stop after this many packets [default: read the whole file]
    #[arg(
        short = 'c',
        long,
        value_name = "N",
        long_help = "Analyse only the first N packets of the file.\n\n\
                     This reads the file from the start and stops early; it is not a\n\
                     filter, and it does not skip anything. The rest of the file is\n\
                     left unread, so the summary describes what was analysed rather\n\
                     than what the file contains."
    )]
    pub count: Option<u64>,
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

    /// Also write the captured packets to a pcap file
    #[arg(
        short = 'w',
        long,
        value_name = "FILE",
        long_help = "Write every captured packet to FILE in pcap format, in addition to\n\
                     printing it.\n\n\
                     This writes FULL PACKET CONTENTS to disk, including payload: \n\
                     passwords, cookies and tokens carried in plaintext protocols end\n\
                     up in the file. Without this option NetSentry writes nothing at\n\
                     all. An existing file is refused unless --overwrite is given."
    )]
    pub write: Option<PathBuf>,

    /// Replace the --write file if it already exists
    #[arg(long, requires = "write")]
    pub overwrite: bool,
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
    fn read_takes_a_path_and_an_optional_count() {
        let parsed = Cli::try_parse_from(["netsentry", "read", "capture.pcap"]);
        match parsed.map(|cli| cli.command) {
            Ok(Command::Read(args)) => {
                assert_eq!(args.file, PathBuf::from("capture.pcap"));
                assert_eq!(args.count, None, "no --count means read the whole file");
            }
            other => panic!("did not parse: {other:?}"),
        }

        let parsed = Cli::try_parse_from(["netsentry", "read", "/tmp/a b.pcap", "-c", "100"]);
        match parsed.map(|cli| cli.command) {
            Ok(Command::Read(args)) => {
                assert_eq!(args.file, PathBuf::from("/tmp/a b.pcap"));
                assert_eq!(args.count, Some(100));
            }
            other => panic!("did not parse: {other:?}"),
        }
    }

    #[test]
    fn analyze_is_accepted_as_a_name_for_read() {
        let parsed = Cli::try_parse_from(["netsentry", "analyze", "capture.pcap"]);
        assert!(matches!(
            parsed.map(|cli| cli.command),
            Ok(Command::Read(_))
        ));
    }

    #[test]
    fn read_requires_a_file() {
        assert!(Cli::try_parse_from(["netsentry", "read"]).is_err());
    }

    #[test]
    fn capture_writes_nothing_unless_asked() {
        let parsed = Cli::try_parse_from(["netsentry", "capture", "-i", "1"]);
        match parsed.map(|cli| cli.command) {
            Ok(Command::Capture(args)) => {
                assert_eq!(args.write, None, "no --write means nothing is written");
                assert!(!args.overwrite);
            }
            other => panic!("did not parse: {other:?}"),
        }
    }

    #[test]
    fn capture_accepts_a_write_target() {
        let parsed = Cli::try_parse_from(["netsentry", "capture", "-i", "1", "-w", "session.pcap"]);
        match parsed.map(|cli| cli.command) {
            Ok(Command::Capture(args)) => {
                assert_eq!(args.write, Some(PathBuf::from("session.pcap")));
                assert!(!args.overwrite);
            }
            other => panic!("did not parse: {other:?}"),
        }
    }

    #[test]
    fn overwrite_is_meaningless_without_write() {
        // --overwrite on its own would silently do nothing, which is exactly
        // the kind of option that gets typed in the belief it did something.
        assert!(Cli::try_parse_from(["netsentry", "capture", "-i", "1", "--overwrite"]).is_err());
        assert!(
            Cli::try_parse_from([
                "netsentry",
                "capture",
                "-i",
                "1",
                "-w",
                "out.pcap",
                "--overwrite"
            ])
            .is_ok()
        );
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
