//! Headless authority runtime for the privileged service boundary.
//!
//! The desktop and service temporarily compile the same implementation files
//! while the desktop API is moved onto authenticated IPC. This crate has no GUI
//! dependency. Merely using this runtime is NOT an isolation boundary: the host
//! must establish its protected OS identity and storage before opening authority.

pub use ekubo_wallet_core::*;

pub mod framing;
#[cfg(target_os = "linux")]
pub mod linux;
#[path = "../../../src/mcp_transport.rs"]
mod mcp_transport;

#[path = "../../../src/authority.rs"]
pub mod authority;
#[path = "../../../src/batch_read.rs"]
pub mod batch_read;
#[path = "../../../bridge_protocol.rs"]
pub mod bridge_protocol;
#[path = "../../../src/events.rs"]
pub mod events;
#[path = "../../../src/mcp.rs"]
pub mod mcp;
#[path = "../../../src/preview.rs"]
pub mod preview;
#[path = "../../../src/release_check.rs"]
pub mod release_check;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_VERSION: &str = env!("EKUBO_WALLET_BUILD_VERSION");
