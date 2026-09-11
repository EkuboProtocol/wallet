//! Service-manager entry point; never launches a desktop or reads user secrets.

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    anyhow::ensure!(
        args.next().as_deref() == Some("--owner-uid"),
        "expected --owner-uid <uid>"
    );
    let owner_uid: u32 = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing owner UID"))?
        .parse()?;
    anyhow::ensure!(args.next().is_none(), "unexpected service argument");
    ekubo_wallet_service::linux::run(owner_uid).await
}

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    anyhow::ensure!(
        args.next().as_deref() == Some("--owner-sid"),
        "expected --owner-sid <sid>"
    );
    let owner_sid = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing owner SID"))?;
    anyhow::ensure!(args.next().is_none(), "unexpected service argument");
    ekubo_wallet_core::windows_service_manager::run(&owner_sid, run_windows_host)
}

#[cfg(target_os = "windows")]
fn run_windows_host(
    owner_sid: &str,
    running: ekubo_wallet_core::windows_service_manager::Running,
    stop: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(ekubo_wallet_service::windows::run(
            owner_sid,
            || running.ready(),
            stop,
        ))
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("the service host is not implemented for this platform yet")
}
