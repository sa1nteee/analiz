//! Command line surface.
//!
//! The CLI is deliberately only a *description* of the interface: clap parses
//! arguments into these types and the binary decides what to do with them. No
//! work happens here, which keeps the command surface easy to change (and, at
//! v0.9, easy to sit next to a Tauri front end rather than be replaced by one).

use clap::{Parser, Subcommand};

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
