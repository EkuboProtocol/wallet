//! Production-authenticated move driver. Test hooks would bypass source consent.
#[cfg(all(target_os = "linux", not(feature = "test-hooks")))]
#[path = "../src/linux_move_client_test.rs"]
mod acceptance;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(all(target_os = "linux", not(feature = "test-hooks")))]
    return acceptance::run().await;
    #[cfg(not(all(target_os = "linux", not(feature = "test-hooks"))))]
    anyhow::bail!("Linux move acceptance client must be built WITHOUT test-hooks")
}
