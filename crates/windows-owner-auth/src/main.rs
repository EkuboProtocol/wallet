#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    // There is no test approval mode, including in debug executables. A process
    // launched independently cannot provide the broker's retained process handle.
    let outcome = (|| -> anyhow::Result<u32> {
        let mut args = std::env::args().skip(1);
        let mode = args.next();
        anyhow::ensure!(
            matches!(mode.as_deref(), Some("--verify" | "--probe-availability")),
            "invalid mode"
        );
        let input = args
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing challenge"))?;
        anyhow::ensure!(
            args.next().is_none() && input.len() <= 4096,
            "invalid arguments"
        );
        let challenge: ekubo_wallet_windows_owner_auth::Challenge = serde_json::from_str(&input)?;
        challenge.validate()?;
        if mode.as_deref() == Some("--probe-availability") {
            // A diagnostic never maps Available (or any error) to VERIFIED_EXIT.
            return Ok(
                match ekubo_wallet_windows_owner_auth::probe_availability(&challenge) {
                    Ok(code) => code,
                    Err(error) => ekubo_wallet_windows_owner_auth::probe_failure_exit(&error),
                },
            );
        }
        Ok(if ekubo_wallet_windows_owner_auth::collect(&challenge)? {
            ekubo_wallet_windows_owner_auth::VERIFIED_EXIT
        } else {
            1
        })
    })();
    std::process::exit(outcome.unwrap_or(1).cast_signed());
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Windows native owner authentication requires Windows");
    std::process::exit(1);
}
