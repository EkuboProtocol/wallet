//! Setting up polkit owner authentication on Linux.
//!
//! The Linux backend in [`crate::human_presence`] asks polkit to authenticate
//! the owner for one action, [`ACTION_ID`]. polkit reads action definitions
//! only from the root-owned [`ACTIONS_DIR`], and neither an `AppImage` nor a
//! `cargo run` build can write there: the one file the wallet needs is the
//! one file it cannot install by itself. Until it is installed, every owner
//! operation — signing, key export, account removal, policy widening — fails
//! with the same "unavailable" error and a path to copy by hand.
//!
//! This module turns that dead end into one click. `pkexec` runs `install(1)`
//! as root under polkit's own `org.freedesktop.policykit.exec` action, which
//! ships with polkit itself and so is present on every machine that has a
//! polkit daemon at all. The same authentication agent the wallet will use
//! from then on authorizes installing the definition that enables it. The
//! wallet never gains privilege: the only thing done as root is a copy of a
//! file whose bytes were checked against the copy compiled into this build.
//!
//! A `.deb` install never gets here — the package puts the definition in
//! place directly (`deb.files` in the workspace manifest). Neither does a
//! machine without polkit: there is nothing to bootstrap with, and the
//! settings section says so instead of prompting.

use std::{
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    time::Duration,
};
use thiserror::Error;

/// The action the owner-authentication backend asks polkit to authorize.
pub const ACTION_ID: &str = "com.ekubo.wallet.human-presence";

/// The file name polkit expects in [`ACTIONS_DIR`].
pub const POLICY_FILE_NAME: &str = "com.ekubo.wallet.policy";

/// Where polkit reads action definitions from. Root-owned on every
/// distribution; there is no per-user location.
pub const ACTIONS_DIR: &str = "/usr/share/polkit-1/actions";

/// The definition this build ships, byte for byte. The bundled file is
/// compared against it before `pkexec` is asked to copy anything as root, so
/// a swapped or stale resource cannot ride the owner's password into the
/// actions directory.
pub const POLICY_DOCUMENT: &str = include_str!("../../../contrib/polkit/com.ekubo.wallet.policy");

/// Whether polkit can currently answer an owner-authentication request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Readiness {
    /// polkit knows the wallet's action; a prompt will appear as long as the
    /// session has an authentication agent, which the desktop provides.
    Ready,
    /// polkit is running but has no definition of the wallet's action, which
    /// is the state of every fresh `AppImage` install.
    PolicyMissing,
    /// No polkit authority answered on the system bus: polkit is not
    /// installed, not running, or the bus is unreachable.
    Unreachable(String),
}

impl Readiness {
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Ask polkit whether it knows the wallet's action.
pub async fn readiness() -> Readiness {
    use zbus::Connection;
    use zbus_polkit::policykit1::AuthorityProxy;

    let connection = match Connection::system().await {
        Ok(connection) => connection,
        Err(error) => return Readiness::Unreachable(error.to_string()),
    };
    let authority = match AuthorityProxy::new(&connection).await {
        Ok(authority) => authority,
        Err(error) => return Readiness::Unreachable(error.to_string()),
    };
    match authority.enumerate_actions("").await {
        Ok(actions) if actions.iter().any(|action| action.action_id == ACTION_ID) => {
            Readiness::Ready
        }
        Ok(_) => Readiness::PolicyMissing,
        Err(error) => Readiness::Unreachable(error.to_string()),
    }
}

/// Poll [`readiness`] until it reports [`Readiness::Ready`] or `timeout`
/// passes, returning the last answer. polkit watches its actions directory
/// and reloads on its own; the reload is quick but not synchronous with the
/// `install(1)` that triggered it.
pub async fn await_readiness(timeout: Duration) -> Readiness {
    const INTERVAL: Duration = Duration::from_millis(200);
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let state = readiness().await;
        if state.is_ready() || tokio::time::Instant::now() >= deadline {
            return state;
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

#[derive(Debug, Error)]
pub enum SetupError {
    /// The definition is not where the package layout puts it.
    #[error("the bundled polkit policy is missing: {0}")]
    BundleMissing(String),
    /// A file is there, but it is not the one compiled into this build.
    #[error("the bundled polkit policy at {} is not the one this build ships", .0.display())]
    BundleMismatch(PathBuf),
    /// `pkexec` could not be started at all.
    #[error("pkexec could not be started: {0}")]
    PkexecUnavailable(String),
    /// The owner closed the authentication dialog.
    #[error("the authentication prompt was dismissed")]
    Dismissed,
    /// polkit refused: no agent to ask, a failed password, or a user who is
    /// not an administrator.
    #[error("polkit did not authorize the installation: {0}")]
    NotAuthorized(String),
    /// `install(1)` itself failed after authorization.
    #[error("installing the polkit policy failed: {0}")]
    InstallFailed(String),
}

/// The policy file this build ships beside its executable, verified to be the
/// one compiled into it.
///
/// cargo-packager puts resources under `usr/lib/ekubo-wallet/` beside the
/// `usr/bin/` the executable lives in, for both the `AppImage` and the `.deb`.
/// A workspace build has no such tree and falls back to the source file.
pub fn bundled_policy() -> Result<PathBuf, SetupError> {
    let executable =
        std::env::current_exe().map_err(|error| SetupError::BundleMissing(error.to_string()))?;
    let mut candidates = Vec::new();
    if let Some(bin_dir) = executable.parent() {
        candidates.push(
            bin_dir
                .join("..")
                .join("lib")
                .join("ekubo-wallet")
                .join(POLICY_FILE_NAME),
        );
    }
    if cfg!(debug_assertions) {
        candidates.push(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../contrib/polkit")
                .join(POLICY_FILE_NAME),
        );
    }
    let Some(found) = candidates.iter().find(|path| path.is_file()) else {
        let looked_in: Vec<String> = candidates
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        return Err(SetupError::BundleMissing(looked_in.join(", ")));
    };
    verify_bundled_policy(found)
}

fn verify_bundled_policy(path: &Path) -> Result<PathBuf, SetupError> {
    let contents =
        std::fs::read(path).map_err(|error| SetupError::BundleMissing(error.to_string()))?;
    if contents != POLICY_DOCUMENT.as_bytes() {
        return Err(SetupError::BundleMismatch(path.to_path_buf()));
    }
    // `install(1)` runs as root from a working directory that is not ours.
    path.canonicalize()
        .map_err(|error| SetupError::BundleMissing(error.to_string()))
}

/// The destination `install(1)` writes.
#[must_use]
pub fn installed_policy_path() -> PathBuf {
    Path::new(ACTIONS_DIR).join(POLICY_FILE_NAME)
}

/// The command to run by hand when `pkexec` cannot help — no authentication
/// agent in the session, or a user outside the administrator group who has
/// `sudo` rights all the same.
#[must_use]
pub fn manual_install_command(source: &Path) -> String {
    format!(
        "sudo install -m 644 {} {}",
        shell_quote(&source.display().to_string()),
        installed_policy_path().display()
    )
}

/// Single-quote a word for `sh`, which is the one quoting every shell
/// accepts. A path from `current_exe` can contain anything.
fn shell_quote(word: &str) -> String {
    if !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-+".contains(&byte))
    {
        return word.to_owned();
    }
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// Install the bundled definition into [`ACTIONS_DIR`] through `pkexec`.
///
/// Blocking: it waits on the authentication dialog. Run it on a blocking
/// thread. On success polkit needs a moment to notice the file; follow with
/// [`await_readiness`].
pub fn install_policy() -> Result<(), SetupError> {
    let source = bundled_policy()?;
    let output = Command::new("pkexec")
        // Without an agent pkexec would otherwise try to authenticate on a
        // controlling terminal, and a desktop process has none to offer.
        .arg("--disable-internal-agent")
        .arg(install_program())
        .args(["-m", "644", "-o", "root", "-g", "root"])
        .arg(&source)
        .arg(installed_policy_path())
        .output()
        .map_err(|error| SetupError::PkexecUnavailable(error.to_string()))?;
    classify(output.status, &String::from_utf8_lossy(&output.stderr))
}

/// `install(1)` from coreutils. pkexec resolves a bare name through `PATH`,
/// but the absolute path leaves nothing for a hostile `PATH` to redirect.
fn install_program() -> PathBuf {
    let system = Path::new("/usr/bin/install");
    if system.is_file() {
        system.to_path_buf()
    } else {
        PathBuf::from("install")
    }
}

/// Map pkexec's documented exit codes: 126 when the owner dismissed the
/// dialog, 127 when polkit would not authorize or could not ask, anything
/// else from the program it ran.
fn classify(status: ExitStatus, stderr: &str) -> Result<(), SetupError> {
    let detail = || {
        let trimmed = stderr.trim();
        if trimmed.is_empty() {
            format!("pkexec exited with {status}")
        } else {
            crate::sanitize::terminal_safe_line(trimmed)
        }
    };
    match status.code() {
        Some(0) => Ok(()),
        Some(126) => Err(SetupError::Dismissed),
        Some(127) => Err(SetupError::NotAuthorized(detail())),
        _ => Err(SetupError::InstallFailed(detail())),
    }
}

#[cfg(test)]
#[path = "polkit_test.rs"]
mod tests;
