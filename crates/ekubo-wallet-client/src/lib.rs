//! Client-side wallet IPC and the shared wire protocol. This crate does not
//! depend on the service runtime or open authoritative wallet storage.

pub mod account;
pub mod activity;
pub mod automation_report;
pub mod dapp_review;
pub mod dapp_session;
pub mod desktop_session;
pub mod desktop_snapshot;
pub mod events;
pub mod export_lease;
pub mod framing;
pub mod import_key;
#[cfg(target_os = "linux")]
mod owner_client;
pub mod owner_connection;
pub mod owner_protocol;
pub mod owner_stream_protocol;
pub mod portfolio;
pub mod simulation_display;
pub mod token_import;
pub mod transaction_review;
#[cfg(target_os = "linux")]
pub use owner_client::OwnerClient;
mod owner_api;

#[cfg(any(target_os = "windows", test))]
mod stream_owner_client;
#[cfg(target_os = "windows")]
mod windows_owner_client;
#[cfg(target_os = "windows")]
pub use windows_owner_client::{OwnerClient, connect_agent_stream};
