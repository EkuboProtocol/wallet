pub use ekubo_wallet_core::{
    abi_decoder, address_book, approval, approval_summary, clear_signing, config, core, custody,
    desktop_store, execution, fork, human_presence, input_validation, legal, message, orchestrator,
    pending, plan_fetch, policy_store, reconcile, rpc, sanitize, simulation, simulation_store,
    token_list, token_store, typed_data,
};

pub mod agent_config;
pub mod authority;
pub mod batch_read;
pub mod desktop;
pub mod events;
pub mod gui_review;
pub mod http_server;
pub mod mcp;
pub mod notifications;
pub mod release_check;
pub mod review;
pub mod single_instance;
pub mod tray;
pub mod updater;
pub mod walletconnect;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_VERSION: &str = env!("EKUBO_WALLET_BUILD_VERSION");

pub use desktop::run_desktop;
