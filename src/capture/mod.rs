//! Packet capture sources.
//!
//! The layer is split by responsibility: [`device`] finds interfaces,
//! [`settings`] says what a capture may be asked to do, [`live`] captures from
//! an interface, [`offline`] reads a capture file, [`pump`] is the read loop
//! both of those share, [`stats`] counts the result and [`timestamp`] times it.
//! Nothing above this layer ever sees a `pcap` type.

pub mod device;
pub mod live;
pub mod offline;
pub mod pump;
pub mod settings;
pub mod stats;
pub mod timestamp;
pub mod writer;

pub use device::{
    InterfaceAddress, InterfaceAttribute, LinkStatus, NetworkInterface, list_interfaces,
    resolve_interface,
};
pub use live::{CaptureInterrupter, LiveCapture};
pub use offline::CaptureFile;
pub use pump::{LinkType, PacketMetadata, PumpOptions};
pub use settings::{CaptureSettings, DEFAULT_SNAPLEN, MAX_SNAPLEN, MIN_SNAPLEN};
pub use stats::{
    CaptureSummary, CaptureTally, DriverStats, FileSummary, PacketRun, StopReason, TimeSpan,
};
pub use timestamp::PacketTimestamp;
pub use writer::{CaptureWriter, prepare_capture_file};
