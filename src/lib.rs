//! NetSentry core.
//!
//! NetSentry is a network traffic analysis toolkit. This crate holds all of its
//! logic; the `netsentry` binary is a thin shell around it, and later versions
//! will put a desktop UI next to that shell without changing anything here.
//!
//! The layering is strictly one-directional — upper layers know about lower
//! ones, never the reverse:
//!
//! ```text
//! render    presentation, pure string formatting
//! capture   where packets come from: interface discovery and live capture
//! error     the failure vocabulary shared by everything above
//! ```
//!
//! Packet *contents* stop at the capture layer. Nothing above it receives
//! payload bytes, and in this version nothing reads them at all.
//!
//! # Example
//!
//! ```no_run
//! let interfaces = netsentry::capture::list_interfaces()?;
//! print!("{}", netsentry::render::interface_list(&interfaces));
//! # Ok::<(), netsentry::NetSentryError>(())
//! ```

pub mod capture;
pub mod cli;
pub mod error;
pub mod render;

pub use error::{NetSentryError, Result};
