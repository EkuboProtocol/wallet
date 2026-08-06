pub mod abi_decoder;
pub mod address_book;
pub mod address_book_browser;
pub mod approval;
pub mod approval_summary;
pub mod batch_read;
pub mod clear_signing;
pub mod cli;
pub mod config;
pub mod core;
pub mod custody;
pub mod execution;
pub mod fork;
pub mod fullscreen;
pub mod human_presence;
pub mod input_validation;
pub mod legal;
pub mod mcp;
pub mod message;
pub mod pager;
pub mod pending;
pub mod plan_fetch;
pub mod policy_store;
pub mod reconcile;
pub mod render;
pub mod rpc;
pub mod sanitize;
pub mod simulation;
pub mod simulation_store;
pub mod token_store;
pub mod tui;
pub mod tx_browser;
pub mod typed_data;

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
