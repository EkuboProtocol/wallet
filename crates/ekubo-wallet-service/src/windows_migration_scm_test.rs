//! Disposable native CI fixture for the full production provisioning pipeline.
//! Synthetic keys and a fresh profile relay use only the disposable CI owner store.
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
