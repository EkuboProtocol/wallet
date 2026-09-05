pub use ekubo_wallet_core::{
    abi_decoder, agent_authority, approval, approval_summary, automation, automation_scheduler,
    automation_store, clear_signing, config, core, custody, desktop_store, execution, fork,
    human_presence, input_validation, legal, message, orchestrator, pending, plan_fetch,
    policy_store, reconcile, rpc, sanitize, simulation, simulation_store, token_list, token_store,
    typed_data,
};

pub mod agent_config;
pub mod assets;
pub mod authority;
pub mod batch_read;
/// Shared verbatim with the stdio bridge, which includes the same file.
#[path = "../bridge_protocol.rs"]
pub mod bridge_protocol;
pub mod dapp_identity;
pub mod desktop;
mod ekubo_positions;
pub mod events;
pub mod gui_review;
pub mod ipc_server;
pub mod mcp;
pub mod notifications;
pub mod release_check;
pub mod review;
pub mod single_instance;
pub mod tray;
pub mod walletconnect;
mod walletconnect_handler;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_VERSION: &str = env!("EKUBO_WALLET_BUILD_VERSION");
/// cargo-packager Minisign public key embedded by release CI. Development
/// builds intentionally leave this empty and cannot install updates.
pub const UPDATER_PUBLIC_KEY: &str = ekubo_wallet_core::update_trust::UPDATER_PUBLIC_KEY;
pub use desktop::run_desktop;
