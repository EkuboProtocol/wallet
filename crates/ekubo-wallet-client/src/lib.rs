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
pub mod owner_protocol;
pub mod portfolio;
pub mod simulation_display;
pub mod token_import;
pub mod transaction_review;
#[cfg(target_os = "linux")]
pub use owner_client::OwnerClient;
#[cfg(target_os = "linux")]
mod owner_api;

// owner_api is transport-independent. Windows should provide an owner_client
// module with the same connect/call/close/session contract and enable this same
// implementation, rather than duplicating the protocol or wallet operations.
