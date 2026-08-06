pub mod address_book_browser;
// The security kernel. Re-exported under the old module paths so the
// presentation layer reads unchanged; the crate boundary, not the paths, is
// the audit boundary.
pub use ekubo_wallet_core::{
    abi_decoder, address_book, approval, approval_summary, clear_signing, config, core, custody,
    execution, fork, human_presence, input_validation, legal, message, orchestrator, pending,
    plan_fetch, policy_store, reconcile, rpc, sanitize, simulation, simulation_store, token_store,
    typed_data,
};

pub mod approve_tui;
pub mod batch_read;
pub mod cli;
pub mod fullscreen;
pub mod mcp;
pub mod pager;
pub mod render;
pub mod token_picker;
pub mod tui;
pub mod tx_browser;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Shared entry point for the `ekubo-wallet` binary and its `ew` alias.
pub async fn run_cli() -> anyhow::Result<()> {
    use clap::Parser as _;
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    cli::Cli::parse().run().await
}

#[cfg(test)]
#[path = "lib_test.rs"]
mod tests;
