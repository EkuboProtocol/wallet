#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    // There is no test approval mode, including in debug executables. A process
    // launched independently cannot provide the broker's retained process handle.
    let verified = (|| -> anyhow::Result<bool> {
        let mut args = std::env::args().skip(1);
        anyhow::ensure!(args.next().as_deref() == Some("--verify"), "invalid mode");
        let input = args
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing challenge"))?;
        anyhow::ensure!(
            args.next().is_none() && input.len() <= 4096,
            "invalid arguments"
        );
        let challenge: ekubo_wallet_windows_owner_auth::Challenge = serde_json::from_str(&input)?;
        challenge.validate()?;
        ekubo_wallet_windows_owner_auth::collect(&challenge)
    })();
    std::process::exit(if matches!(verified, Ok(true)) {
        ekubo_wallet_windows_owner_auth::VERIFIED_EXIT.cast_signed()
    } else {
        1
    });
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Windows native owner authentication requires Windows");
    std::process::exit(1);
}
