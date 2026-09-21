//! NetSentry command line entry point.
//!
//! This binary does three things and nothing else: parse arguments, ask the
//! library to do the work, and report the outcome. All logic — including how a
//! failure is worded — lives in the `netsentry` library crate, so that a future
//! desktop front end can reuse it instead of reimplementing it.

use std::process::ExitCode;

use clap::Parser as _;
use netsentry::cli::{Cli, Command};

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprint!("{}", netsentry::render::error_report(&error));
            ExitCode::FAILURE
        }
    }
}

/// Dispatches a parsed command and returns what should be printed.
///
/// Returning the output instead of printing it keeps stdout handling in exactly
/// one place.
fn run(cli: &Cli) -> netsentry::Result<String> {
    match cli.command {
        Command::List => {
            let interfaces = netsentry::capture::list_interfaces()?;
            Ok(netsentry::render::interface_list(&interfaces))
        }
    }
}
