//! NetSentry command line entry point.
//!
//! This binary does three things and nothing else: parse arguments, ask the
//! library to do the work, and report the outcome. All logic — including how a
//! failure is worded — lives in the `netsentry` library crate, so that a future
//! desktop front end can reuse it instead of reimplementing it.

use std::io::Write as _;
use std::process::ExitCode;

use clap::Parser as _;
use netsentry::capture::{self, CaptureSettings, LiveCapture};
use netsentry::cli::{CaptureArgs, Cli, Command};
use netsentry::decode::{self, LinkLayer};
use netsentry::error::NetSentryError;
use netsentry::render;

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprint!("{}", render::error_report(&error));
            ExitCode::FAILURE
        }
    }
}

/// Dispatches a parsed command.
fn run(cli: &Cli) -> netsentry::Result<()> {
    match &cli.command {
        Command::List => run_list(),
        Command::Capture(args) => run_capture(args),
    }
}

/// Prints the interface listing.
fn run_list() -> netsentry::Result<()> {
    let interfaces = capture::list_interfaces()?;
    print!("{}", render::interface_list(&interfaces));
    Ok(())
}

/// Opens a live capture and prints one line of metadata per packet.
fn run_capture(args: &CaptureArgs) -> netsentry::Result<()> {
    // Validate the user's numbers before touching the network, so bad input
    // fails immediately and without needing any privileges.
    let settings = CaptureSettings::new(args.snaplen, args.promiscuous, args.count)?;

    let interfaces = capture::list_interfaces()?;
    let interface = capture::resolve_interface(&interfaces, &args.interface)?;

    let mut session = LiveCapture::open(interface, &settings)?;
    print!(
        "{}",
        render::capture_header(interface, settings, session.link_type())
    );

    // Installed only once the capture is open, so Ctrl+C before that point
    // still behaves the way the shell expects.
    let interrupter = session.interrupter();
    ctrlc::set_handler(move || interrupter.interrupt())
        .map_err(|source| NetSentryError::SignalHandler { source })?;

    // Locked once rather than per packet. stdout is line buffered, so each
    // packet still reaches the terminal as it is captured.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    // Capture hands over bytes, decode interprets them, render prints the
    // result. Each step knows only about the one below it.
    let link_layer = LinkLayer::from_dlt(session.link_type().code);
    let summary = session.run(|metadata, bytes| {
        let decoded = decode::decode(link_layer, bytes);
        writeln!(out, "{}", render::packet_line(metadata, &decoded))
    })?;

    print!("{}", render::capture_summary(&summary));
    Ok(())
}
