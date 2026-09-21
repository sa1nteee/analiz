//! Packet capture sources.
//!
//! The layer is split by responsibility: [`device`] finds interfaces,
//! [`settings`] says what a capture may be asked to do, [`live`] is the engine
//! that does it, [`stats`] counts the result and [`timestamp`] times it.
//! Nothing above this layer ever sees a `pcap` type.

pub mod device;
pub mod live;
pub mod settings;
pub mod stats;
pub mod timestamp;

pub use device::{
    InterfaceAddress, InterfaceAttribute, LinkStatus, NetworkInterface, list_interfaces,
    resolve_interface,
};
pub use live::{CaptureInterrupter, LinkType, LiveCapture, PacketMetadata};
pub use settings::{CaptureSettings, DEFAULT_SNAPLEN, MAX_SNAPLEN, MIN_SNAPLEN};
pub use stats::{CaptureSummary, CaptureTally, DriverStats, StopReason};
pub use timestamp::PacketTimestamp;
