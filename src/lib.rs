pub mod address_book_browser;
// The security kernel. Re-exported under the old module paths so the
// presentation layer reads unchanged; the crate boundary, not the paths, is
// the audit boundary.
pub use ekubo_wallet_core::{
    abi_decoder, address_book, approval, approval_summary, clear_signing, config, core, custody,
    execution, fork, human_presence, input_validation, legal, message, orchestrator, pending,
    plan_fetch, policy_store, reconcile, rpc, sanitize, simulation, simulation_store, token_list,
    token_store, typed_data,
};

pub mod approve_tui;
pub mod batch_read;
pub mod cli;
pub mod completion;
pub mod connect;
pub mod connect_screen;
pub mod fullscreen;
pub mod mcp;
pub mod pager;
pub mod release_check;
pub mod render;
pub mod signing_review;
pub mod token_picker;
pub mod tui;
pub mod tx_browser;
pub mod walletconnect;

/// The crate version, exactly as the manifest declares it.
///
/// For anywhere the version is a protocol field rather than something a person
/// reads. [`BUILD_VERSION`] is what to print.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The version of *this binary*: [`VERSION`] on a released build, and
/// `1.0.0-rc.0+8133a00` on anything built from an untagged commit.
///
/// Everything a person or an agent reads uses this. A version alone cannot
/// distinguish two builds of the same unreleased crate version, which is
/// exactly the distinction that matters when someone reports that a fix did
/// not take — the first question is whether they are running it. See
/// `build.rs`.
pub const BUILD_VERSION: &str = env!("EKUBO_WALLET_BUILD_VERSION");

/// Entry point for the `ekubo-wallet` binary.
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
