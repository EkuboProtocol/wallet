pub mod abi_decoder;
pub mod approval;
pub mod approval_summary;
pub mod batch_read;
pub mod cli;
pub mod config;
pub mod core;
pub mod custody;
pub mod execution;
pub mod human_presence;
pub mod mcp;
pub mod pending;
pub mod policy_store;
pub mod rpc;
pub mod simulation;

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
