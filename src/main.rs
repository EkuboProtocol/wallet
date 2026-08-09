use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    ekubo_wallet::run_cli().await
}
