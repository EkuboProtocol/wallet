//! Headless authority runtime for the privileged service boundary.
//!
//! The desktop and service temporarily compile the same implementation files
//! while the desktop API is moved onto authenticated IPC. This crate has no GUI
//! dependency. Merely using this runtime is NOT an isolation boundary: the host
//! must establish its protected OS identity and storage before opening authority.

pub use ekubo_wallet_core::*;

pub use ekubo_wallet_client::framing;
#[path = "../../../src/dapp_identity.rs"]
pub mod dapp_identity;
pub mod dapp_reviews;
pub mod dapp_runtime;
mod desktop_sessions;
#[path = "../../../src/gui_review.rs"]
mod gui_review;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
mod linux_owner_rpc;
#[path = "../../../src/mcp_transport.rs"]
mod mcp_transport;
pub mod owner_rpc;
pub mod runtime;
mod transaction_previews;
mod transaction_reviews;
#[path = "../../../src/walletconnect.rs"]
pub mod walletconnect;
#[path = "../../../src/walletconnect_handler.rs"]
mod walletconnect_handler;
#[path = "../../../src/walletconnect_review.rs"]
mod walletconnect_review;

#[path = "../../../src/authority.rs"]
pub mod authority;
#[path = "../../../src/automation_runtime.rs"]
pub mod automation_runtime;
#[path = "../../../src/batch_read.rs"]
pub mod batch_read;
#[path = "../../../bridge_protocol.rs"]
pub mod bridge_protocol;
#[path = "../../../src/events.rs"]
pub mod events;
#[path = "../../../src/mcp.rs"]
pub mod mcp;
#[path = "../../../src/owner_snapshot.rs"]
mod owner_snapshot;
#[path = "../../../src/preview.rs"]
pub mod preview;
#[path = "../../../src/release_check.rs"]
pub mod release_check;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_VERSION: &str = env!("EKUBO_WALLET_BUILD_VERSION");
