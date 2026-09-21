//! NetSentry command line entry point.
//!
//! This binary does three things and nothing else: parse arguments, ask the
//! library to do the work, and report the outcome. All logic — including how a
//! failure is worded — lives in the `netsentry` library crate, so that a future
//! desktop front end can reuse it instead of reimplementing it.

use std::io::Write as _;
use std::process::ExitCode;

use clap::Parser as _;
use netsentry::capture::{self, CaptureFile, CaptureSettings, LiveCapture};
use netsentry::cli::{CaptureArgs, Cli, Command, ReadArgs};
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
        Command::Read(args) => run_read(args),
    }
}

/// Prints the interface listing.
fn run_list() -> netsentry::Result<()> {
    let interfaces = capture::list_interfaces()?;
    print!("{}", render::interface_list(&interfaces));
    Ok(())
}

/// Opens a live capture and prints one line per packet.
fn run_capture(args: &CaptureArgs) -> netsentry::Result<()> {
    // Validate the user's numbers before touching the network, so bad input
    // fails immediately and without needing any privileges.
    let settings = CaptureSettings::new(args.snaplen, args.promiscuous, args.count)?;

    // Refuse an existing output file before opening the interface, so a
    // mistyped path cannot cost the user a capture that has already started.
    if let Some(path) = &args.write {
        capture::prepare_capture_file(path, args.overwrite)?;
    }

    let interfaces = capture::list_interfaces()?;
    let interface = capture::resolve_interface(&interfaces, &args.interface)?;

    let mut session = LiveCapture::open(interface, &settings)?;
    print!(
        "{}",
        render::capture_header(interface, settings, session.link_type())
    );

    let mut writer = match &args.write {
        Some(path) => {
            print!("{}", render::write_warning(path));
            Some(session.open_savefile(path)?)
        }
        None => None,
    };

    // Installed only once the capture is open, so Ctrl+C before that point
    // still behaves the way the shell expects.
    let interrupter = session.interrupter();
    ctrlc::set_handler(move || interrupter.interrupt())
        .map_err(|source| NetSentryError::SignalHandler { source })?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let link_layer = LinkLayer::from_dlt(session.link_type().code);
    // The writer is handed to the pump, which copies each packet as the driver
    // delivered it; this closure only ever sees metadata and bytes.
    let summary = session.run(writer.as_mut(), |metadata, bytes| {
        let decoded = decode::decode(link_layer, bytes);
        writeln!(out, "{}", render::packet_line(metadata, &decoded))
    })?;

    print!("{}", render::capture_summary(&summary));

    if let Some(writer) = writer.as_mut() {
        writer.flush()?;
        println!("[*] Capture written to {}", writer.path().display());
    }
    Ok(())
}

/// Reads a capture file and prints one line per packet.
///
/// The pipeline below the source is identical to a live capture's: the same
/// decoder, the same renderer, the same output.
fn run_read(args: &ReadArgs) -> netsentry::Result<()> {
    let mut file = CaptureFile::open(&args.file)?;
    print!(
        "{}",
        render::file_header(file.path(), file.link_type(), args.count)
    );

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let link_layer = LinkLayer::from_dlt(file.link_type().code);
    let summary = file.run(args.count, |metadata, bytes| {
        let decoded = decode::decode(link_layer, bytes);
        writeln!(out, "{}", render::packet_line(metadata, &decoded))
    });

    print!("{}", render::file_summary(&summary));

    // A corrupt tail is reported after the packets that were readable, and
    // still sets a failing exit code so a script notices.
    match summary.read_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
