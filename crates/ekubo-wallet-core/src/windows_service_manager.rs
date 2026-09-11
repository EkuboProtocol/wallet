//! SCM lifecycle with a serialized status reporter. This grants no wallet or
//! owner authority; the native adapter validates the installed service identity
//! before invoking the host, which must establish protected custody separately.

use anyhow::{Result, ensure};
use tokio::sync::watch;

#[cfg(target_os = "windows")]
#[path = "windows_service_manager_native.rs"]
mod native;
#[cfg(target_os = "windows")]
pub use native::{Running, run};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Starting,
    Running,
    Stopping,
    Stopped,
}

trait Reporter {
    fn report(&mut self, phase: Phase, failed: bool) -> Result<()>;
}

struct Control<R> {
    reporter: R,
    phase: Phase,
    stop: watch::Sender<bool>,
}

impl<R: Reporter> Control<R> {
    fn new(reporter: R, stop: watch::Sender<bool>) -> Self {
        Self {
            reporter,
            phase: Phase::Starting,
            stop,
        }
    }

    fn initialize(&mut self) -> Result<()> {
        ensure!(
            self.phase == Phase::Starting,
            "service initialization has ended"
        );
        if *self.stop.borrow() {
            self.phase = Phase::Stopping;
        }
        self.report(false)
    }

    fn running(&mut self) -> Result<()> {
        ensure!(self.phase != Phase::Stopped, "service has already stopped");
        if self.phase == Phase::Starting {
            self.phase = Phase::Running;
            self.report(false)?;
        }
        Ok(())
    }

    fn request_stop(&mut self) -> Result<()> {
        self.stop.send_replace(true);
        if matches!(self.phase, Phase::Starting | Phase::Running) {
            self.phase = Phase::Stopping;
            self.report(false)?;
        }
        Ok(())
    }

    fn finish(&mut self, failed: bool) -> Result<()> {
        if self.phase == Phase::Stopped {
            return Ok(());
        }
        // SetServiceStatus(STOPPED) consumes the SCM context. Never retry it,
        // including after a reporting failure or a late control callback.
        self.phase = Phase::Stopped;
        self.report(failed)
    }

    fn report(&mut self, failed: bool) -> Result<()> {
        let result = self.reporter.report(self.phase, failed);
        if result.is_err() {
            self.stop.send_replace(true);
        }
        result
    }
}

#[cfg(test)]
#[path = "windows_service_manager_test.rs"]
mod tests;
