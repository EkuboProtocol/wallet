//! Client activation only. Running status is not endpoint authentication or
//! custody readiness; the client must still complete the authenticated relay.

use anyhow::{Result, ensure};

#[cfg(target_os = "windows")]
#[path = "windows_service_start_native.rs"]
mod native;
#[cfg(target_os = "windows")]
pub use native::ensure_running;

#[derive(Clone, Copy)]
enum State {
    Stopped,
    Starting,
    Running,
    Unavailable,
}

trait Backend {
    fn state(&mut self) -> Result<State>;
    /// An already-running race is success; all other start errors propagate.
    fn start(&mut self) -> Result<()>;
}

fn activate(
    backend: &mut impl Backend,
    active: impl Fn() -> bool,
    mut wait: impl FnMut(),
) -> Result<()> {
    let mut first = true;
    loop {
        ensure!(active(), "wallet service activation ended or timed out");
        let state = backend.state()?;
        ensure!(active(), "wallet service activation ended or timed out");
        match state {
            State::Running => return Ok(()),
            State::Stopped if first => backend.start()?,
            State::Starting => {}
            State::Stopped => anyhow::bail!("wallet service stopped during activation"),
            State::Unavailable => anyhow::bail!("wallet service is not available for activation"),
        }
        // Never restart a service that stopped while another client started it,
        // nor replay a start after an ambiguous failure.
        first = false;
        wait();
    }
}

#[cfg(test)]
#[path = "windows_service_start_test.rs"]
mod tests;
