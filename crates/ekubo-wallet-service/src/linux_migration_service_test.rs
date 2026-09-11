//! Cross-user production migration fixture for disposable Linux CI.
#[cfg(target_os = "linux")]
#[path = "linux_migration_service_fixture_test.rs"]
mod fixture;

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    fixture::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("Linux migration fixture requires Linux")
}
