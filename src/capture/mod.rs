//! Packet capture sources.
//!
//! In v0.1 this layer can only *discover* capture sources. Opening a source and
//! reading packets from it arrives in the next step.

pub mod device;

pub use device::{
    InterfaceAddress, InterfaceAttribute, LinkStatus, NetworkInterface, list_interfaces,
};
