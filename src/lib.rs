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
mod tests {
    /// Guards the `RUST_MIN_STACK` plumbing in `.cargo/config.toml` and CI.
    ///
    /// Test threads are spawned by the harness without an explicit stack size,
    /// so `std` sizes them from `RUST_MIN_STACK`. Debug frames for this crate's
    /// deeply generic dependency chains have overflowed default-sized test
    /// threads on Windows MSVC. This test recurses through ~24 MiB of stack —
    /// three times the common 8 MiB default — so it fails on exactly the
    /// configurations where the raised floor is not actually in effect, instead
    /// of an arbitrary business test failing there first.
    #[test]
    fn raised_test_thread_stack_floor_is_in_effect() {
        use std::hint::black_box;

        // ~4 KiB per frame, resistant to being collapsed at low opt levels.
        #[inline(never)]
        fn recurse(depth: u64) -> u64 {
            let pad = black_box([depth; 512]);
            if depth == 0 {
                pad[0]
            } else {
                black_box(recurse(depth - 1)) + pad[511]
            }
        }

        assert_eq!(recurse(6_000), 18_003_000);
    }
}
