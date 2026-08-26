//! Setting up polkit owner authentication on Linux.
//!
//! The Linux backend in [`crate::human_presence`] asks polkit to authenticate
//! the owner for one action, [`ACTION_ID`]. polkit reads action definitions
//! only from the root-owned [`ACTIONS_DIR`], and neither an `AppImage` nor a
//! `cargo run` build can write there: the one file the wallet needs is the
//! one file it cannot install by itself. Until it is installed, every owner
//! operation — signing, key export, account removal, policy widening — fails
//! with the same "unavailable" error.
//!
//! This module turns that dead end into one click. `pkexec` runs `install(1)`
//! as root under polkit's own `org.freedesktop.policykit.exec` action, which
//! ships with the polkit daemon, so the same authentication agent the wallet
//! will use from then on authorizes installing the definition that enables
//! it. The definition itself is [`POLICY_DOCUMENT`], compiled into this build
//! and streamed to `install(1)` over standard input: root reads no file that
//! this user could swap, and no path inside an `AppImage`'s FUSE mount — which
//! root cannot read at all, `allow_other` being off — is ever handed across.
//! The wallet holds no privilege before, during, or after.
//!
//! Three things it does not paper over. `pkexec` is a separate package from
//! the daemon on Debian 12 and Ubuntu 23.04 onward, so a machine can have
//! polkit and no way to prompt; a session can lack an authentication agent;
//! and on an immutable distribution `/usr` is read-only, or polkit's actions
//! directory is somewhere else entirely, so neither `pkexec` nor `sudo` can
//! put the file where polkit looks. [`actions_dir`] tells the three apart up
//! front, [`export_policy`] writes the document somewhere root *can* read,
//! and [`manual_install_command`] is the `sudo` line for the sessions where
//! that is the answer. A `.deb` install never gets here — the package puts
//! the definition in place itself (`deb.files` in the workspace manifest).

use std::{
    future::Future,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    time::Duration,
};
use thiserror::Error;
use zbus_polkit::policykit1::AuthorityProxy;

/// The action the owner-authentication backend asks polkit to authorize.
pub const ACTION_ID: &str = "com.ekubo.wallet.human-presence";

/// The file name polkit expects in [`ACTIONS_DIR`].
pub const POLICY_FILE_NAME: &str = "com.ekubo.wallet.policy";

/// Where polkit reads action definitions from. Root-owned on every
/// distribution; there is no per-user location.
pub const ACTIONS_DIR: &str = "/usr/share/polkit-1/actions";

/// The definition this build ships, byte for byte. It is what `install(1)`
/// receives over standard input, so what lands in [`ACTIONS_DIR`] is exactly
/// this and nothing a same-user process could put in a file first.
pub const POLICY_DOCUMENT: &str = include_str!("../../../contrib/polkit/com.ekubo.wallet.policy");

/// Absolute on every distribution; a bare name would be resolved by pkexec
/// through a `PATH` this process does not control.
const PKEXEC: &str = "/usr/bin/pkexec";
const INSTALL: &str = "/usr/bin/install";

/// zbus 5 sets no method timeout of its own, and a polkit daemon that is
/// running but stuck — blocked on a slow name service, say — would otherwise
/// hold a probe open for as long as it liked.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether polkit can currently answer an owner-authentication request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Readiness {
    /// polkit knows the wallet's action; a prompt will appear as long as the
    /// session has an authentication agent, which the desktop provides.
    Ready,
    /// polkit answered and has no definition of the wallet's action, which is
    /// the state of every fresh `AppImage` install.
    PolicyMissing,
    /// No answer from polkit on the system bus: not installed, not running,
    /// the bus unreachable, or one call that failed or timed out.
    Unreachable(String),
}

/// One question to the bus, with a deadline, and its failure as one line of
/// text fit for a label. A D-Bus error's text is whatever the peer put in
/// it.
async fn ask<T>(question: impl Future<Output = zbus::Result<T>>) -> Result<T, String> {
    match tokio::time::timeout(CALL_TIMEOUT, question).await {
        Ok(Ok(answer)) => Ok(answer),
        Ok(Err(error)) => Err(crate::sanitize::terminal_safe_line(&error.to_string())),
        Err(_) => Err(format!(
            "no answer within {} seconds",
            CALL_TIMEOUT.as_secs()
        )),
    }
}

/// polkit's authority on the system bus.
pub(crate) async fn connect() -> Result<AuthorityProxy<'static>, String> {
    ask(async {
        let connection = zbus::Connection::system().await?;
        AuthorityProxy::new(&connection).await
    })
    .await
}

/// Whether the authority knows [`ACTION_ID`].
///
/// polkit has no lookup for one action; `EnumerateActions` is the only
/// question it answers, and the reply lists every action on the system.
pub(crate) async fn probe(authority: &AuthorityProxy<'_>) -> Readiness {
    match ask(authority.enumerate_actions("")).await {
        Ok(actions) if actions.iter().any(|action| action.action_id == ACTION_ID) => {
            Readiness::Ready
        }
        Ok(_) => Readiness::PolicyMissing,
        Err(detail) => Readiness::Unreachable(detail),
    }
}

/// Ask polkit whether it knows the wallet's action.
pub async fn readiness() -> Readiness {
    match connect().await {
        Ok(authority) => probe(&authority).await,
        Err(detail) => Readiness::Unreachable(detail),
    }
}

/// Poll polkit until it knows the action or `timeout` passes. polkit watches
/// its actions directory and reloads on its own; the reload is quick but not
/// synchronous with the `install(1)` that triggered it. One connection
/// serves every poll, and the answer is the best one seen, not the last: one
/// failed call at the end of the wait must not turn a definition polkit had
/// already listed as missing into "polkit did not answer".
pub async fn await_readiness(timeout: Duration) -> Readiness {
    const INTERVAL: Duration = Duration::from_millis(250);
    let deadline = tokio::time::Instant::now() + timeout;
    let authority = match connect().await {
        Ok(authority) => authority,
        Err(detail) => return Readiness::Unreachable(detail),
    };
    let mut best = None;
    loop {
        match probe(&authority).await {
            Readiness::Ready => return Readiness::Ready,
            Readiness::PolicyMissing => best = Some(Readiness::PolicyMissing),
            unreachable @ Readiness::Unreachable(_) => {
                if best.is_none() {
                    best = Some(unreachable);
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return best.expect("one poll has run");
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

/// Whether `pkexec` is installed. The daemon alone is not enough: Debian and
/// Ubuntu ship `pkexec` as its own package since polkit 121.
#[must_use]
pub fn pkexec_available() -> bool {
    Path::new(PKEXEC).is_file()
}

/// Whether anything can be put into [`ACTIONS_DIR`] at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionsDir {
    /// The ordinary case: root can write it, so `pkexec` or `sudo` can.
    Writable,
    /// The directory does not exist. NixOS keeps polkit's definitions under
    /// `/run/current-system`, and a distribution that ships no polkit at all
    /// has nothing here either.
    Missing,
    /// The directory is on a read-only mount — Fedora Silverblue, `SteamOS`,
    /// and the other immutable distributions — so neither `pkexec` nor
    /// `sudo` can install into it; the definition has to be layered with the
    /// distribution's own tooling.
    ReadOnly,
}

#[must_use]
pub fn actions_dir() -> ActionsDir {
    if !Path::new(ACTIONS_DIR).is_dir() {
        return ActionsDir::Missing;
    }
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    if mounted_read_only(&mounts, ACTIONS_DIR) {
        ActionsDir::ReadOnly
    } else {
        ActionsDir::Writable
    }
}

/// Whether the mount holding `path` is read-only, from the kernel's own
/// mount table: the innermost mount point that contains `path`, and of two
/// mounts on the same point the later one, which is the one on top.
fn mounted_read_only(mounts: &str, path: &str) -> bool {
    // The innermost mount so far, as (length of its mount point, options).
    let mut innermost: Option<(usize, &str)> = None;
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let (Some(_device), Some(point), Some(_kind), Some(options)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        // /proc escapes the four characters that would break the format;
        // a space in a mount point is the one that occurs in practice.
        let point = point.replace("\\040", " ");
        let contains = point == "/"
            || path == point
            || path
                .strip_prefix(point.as_str())
                .is_some_and(|rest| rest.starts_with('/'));
        if contains && innermost.is_none_or(|(deepest, _)| point.len() >= deepest) {
            innermost = Some((point.len(), options));
        }
    }
    innermost.is_some_and(|(_, options)| options.split(',').any(|option| option == "ro"))
}

#[derive(Debug, Error)]
pub enum SetupError {
    /// The copy for the manual command could not be written.
    #[error("the polkit policy could not be written for a manual install: {0}")]
    ExportFailed(String),
    /// `pkexec` could not be started at all.
    #[error("pkexec could not be started: {0}")]
    PkexecUnavailable(String),
    /// coreutils `install(1)` is not where every distribution puts it.
    #[error("{INSTALL} is missing, so there is nothing for pkexec to run")]
    InstallUnavailable,
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

/// The destination `install(1)` writes.
#[must_use]
pub fn installed_policy_path() -> PathBuf {
    Path::new(ACTIONS_DIR).join(POLICY_FILE_NAME)
}

/// Write [`POLICY_DOCUMENT`] to `directory`, for the owner to install by hand.
///
/// The wallet's own data directory is the right `directory`: root can read
/// anything there, which is not true of the `AppImage`'s FUSE mount. The
/// file is rewritten every time so it is always this build's copy, through
/// the kernel's own private-file path — the name is opened `O_NOFOLLOW` and
/// the handle is what gets written, so a link planted at that name is
/// refused rather than followed to the database beside it.
pub fn export_policy(directory: &Path) -> Result<PathBuf, SetupError> {
    let path = directory.join(POLICY_FILE_NAME);
    let write = || -> anyhow::Result<PathBuf> {
        crate::config::create_private_dir(directory)?;
        let mut file = crate::config::open_private_file(&path)?;
        file.set_len(0)?;
        file.write_all(POLICY_DOCUMENT.as_bytes())?;
        Ok(path.canonicalize()?)
    };
    write().map_err(|error| SetupError::ExportFailed(format!("{}: {error:#}", path.display())))
}

/// The command to run by hand when `pkexec` cannot help — it is not
/// installed, no authentication agent is in the session, or the owner is
/// outside the administrator group but has `sudo` rights all the same.
#[must_use]
pub fn manual_install_command(source: &Path) -> String {
    format!(
        "sudo install -m 644 {} {}",
        shell_quote(&source.display().to_string()),
        installed_policy_path().display()
    )
}

/// Single-quote a word for `sh`, which is the one quoting every shell
/// accepts. A data directory can contain anything.
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

/// Install [`POLICY_DOCUMENT`] into [`ACTIONS_DIR`] through `pkexec`.
///
/// Blocking: it waits on the authentication dialog. Run it on a blocking
/// thread. On success polkit needs a moment to notice the file; follow with
/// [`await_readiness`].
pub fn install_policy() -> Result<(), SetupError> {
    if !Path::new(INSTALL).is_file() {
        return Err(SetupError::InstallUnavailable);
    }
    let mut child = Command::new(PKEXEC)
        // Without an agent pkexec would otherwise try to authenticate on a
        // controlling terminal, and a desktop process has none to offer.
        .arg("--disable-internal-agent")
        // pkexec refuses, before asking polkit anything, a caller whose
        // SHELL is not listed in /etc/shells — a shell from nix or Homebrew,
        // say. Unset, it uses the account's login shell instead.
        .env_remove("SHELL")
        .arg(INSTALL)
        .args(["-m", "644", "-o", "root", "-g", "root", "/dev/stdin"])
        .arg(installed_policy_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| SetupError::PkexecUnavailable(error.to_string()))?;
    if let Some(mut stdin) = child.stdin.take() {
        // A refusal closes the pipe before anything reads it; the exit
        // status below says so better than a broken-pipe error here would.
        let _ = stdin.write_all(POLICY_DOCUMENT.as_bytes());
    }
    let output = child
        .wait_with_output()
        .map_err(|error| SetupError::PkexecUnavailable(error.to_string()))?;
    classify(output.status, &String::from_utf8_lossy(&output.stderr))
}

/// Map pkexec's documented exit codes: 126 when the owner dismissed the
/// dialog, 127 when polkit would not authorize or could not ask, anything
/// else from `install(1)`. pkexec also exits 127 for its own refusals —
/// a program it cannot run, a `SHELL` it will not accept — so the stderr
/// text, which every non-zero branch carries into the message, is what
/// tells those apart; the program's presence and the shell are dealt with
/// before it is asked.
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
