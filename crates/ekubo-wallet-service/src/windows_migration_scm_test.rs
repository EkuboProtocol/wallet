//! Disposable native CI fixture for the full production provisioning pipeline.
//! Explicit synthetic keys and test-only stores never consult the login keyring.
#[cfg(target_os = "windows")]
#[path = "windows_migration_scm_fixture_test.rs"]
mod fixture;

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    fixture::run()
}

#[cfg(not(target_os = "windows"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("the SCM migration fixture requires Windows")
}
