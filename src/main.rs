use anyhow::Result;

fn main() -> Result<()> {
    // Must run before the Tokio runtime below exists -- see the doc comment
    // on `warm_up_credential_store` for why nesting runtimes here panics.
    ekubo_wallet_core::policy_store::warm_up_credential_store();

    tokio::runtime::Runtime::new()?.block_on(ekubo_wallet::run_cli())
}
