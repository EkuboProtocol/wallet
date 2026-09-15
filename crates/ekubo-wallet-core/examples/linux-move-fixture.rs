//! Disposable source construction only. Never install this as the service.
#[cfg(all(target_os = "linux", feature = "test-hooks"))]
#[path = "../src/linux_move_fixture_test.rs"]
mod fixture;

fn main() -> anyhow::Result<()> {
    #[cfg(all(target_os = "linux", feature = "test-hooks"))]
    return fixture::run();
    #[cfg(not(all(target_os = "linux", feature = "test-hooks")))]
    anyhow::bail!("Linux source fixture requires test-hooks")
}
