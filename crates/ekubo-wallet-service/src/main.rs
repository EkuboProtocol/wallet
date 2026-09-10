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

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("the service host is not implemented for this platform yet")
}
