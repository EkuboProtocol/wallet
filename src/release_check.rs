//! Whether a newer signed desktop release exists.
//!
//! This module answers "am I behind?" for the Updates screen and the read-only
//! `wallet_check_for_updates` MCP tool. The security kernel owns authenticated
//! update discovery, download, authorization, and installation. The release tag
//! used for the informational check is validated before it enters a URL. Every
//! failure here — offline, rate limited, malformed JSON, an unwritable cache —
//! resolves to "no update known" rather than an error, because nothing that
//! depends on this answer should fail when the answer is merely unavailable.

use anyhow::Context as _;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

pub use ekubo_wallet_core::update_trust::InstallableUpdate;

pub fn check_installable() -> anyhow::Result<Option<InstallableUpdate>> {
    ekubo_wallet_core::update_trust::check_installable()
}

/// Gives an opaque, authenticated package back to core for re-verification and
/// installation, then starts the replacement application on platforms whose
/// installer does not do that itself.
pub fn install_and_relaunch(
    prepared: ekubo_wallet_core::update_trust::PreparedUpdate,
    authorization: ekubo_wallet_core::update_trust::UpdateAuthorization,
    before_relaunch: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let relaunch_path = match ekubo_wallet_core::update_trust::install_update(
        prepared,
        authorization,
    ) {
        Ok(path) => path,
        Err(install_error) => {
            before_relaunch().context("could not release the current wallet before recovery")?;
            relaunch_current_application().with_context(|| {
                format!(
                    "update installation failed ({install_error:#}) and the current application could not be restarted"
                )
            })?;
            return Err(install_error);
        }
    };
    before_relaunch().context("could not release the current wallet before update relaunch")?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let executable = relaunch_path.context("the updater did not return a relaunch path")?;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = relaunch_path;
    #[cfg(target_os = "macos")]
    relaunch_macos_application(&executable).context("could not relaunch updated application")?;
    #[cfg(target_os = "linux")]
    std::process::Command::new(executable)
        .spawn()
        .context("could not relaunch updated application")?;
    Ok(())
}

const UPDATE_DIAGNOSTICS_FILE: &str = "update-install.log";

#[must_use]
pub fn update_diagnostics_path(data_dir: &Path) -> PathBuf {
    data_dir.join(UPDATE_DIAGNOSTICS_FILE)
}

/// Append one durable, local-only updater lifecycle event. The updater runs
/// after the window has closed, so this file remains inspectable even when a
/// replacement or relaunch fails before any UI can report it.
pub fn record_update_diagnostic(data_dir: &Path, message: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let path = update_diagnostics_path(data_dir);
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&path)?;
    let message = message
        .chars()
        .take(8 * 1024)
        .map(|character| {
            if character == '\n' || character == '\r' || character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    writeln!(
        file,
        "{} wallet={} {message}",
        Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        crate::VERSION
    )?;
    file.sync_data()?;
    Ok(())
}

/// A failed post-quit update must not strand the owner with no wallet process.
/// This path is used only after core refused or rolled back an installation.
fn relaunch_current_application() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let executable = std::env::current_exe().context("could not locate the current wallet")?;
        let bundle = executable
            .parent()
            .and_then(std::path::Path::parent)
            .and_then(std::path::Path::parent)
            .context("could not locate the current application bundle")?;
        relaunch_macos_application(bundle).context("could not restart the current application")?;
    }
    #[cfg(target_os = "linux")]
    {
        let executable = std::env::var_os("APPIMAGE")
            .map(std::path::PathBuf::from)
            .map_or_else(std::env::current_exe, Ok)?;
        std::process::Command::new(executable)
            .spawn()
            .context("could not restart the current application")?;
    }
    #[cfg(target_os = "windows")]
    std::process::Command::new(
        std::env::current_exe().context("could not locate the current wallet")?,
    )
    .spawn()
    .context("could not restart the current application")?;
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    anyhow::bail!("automatic updates are unsupported on this platform");
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_relaunch_command(application: &Path) -> std::process::Command {
    let mut command = std::process::Command::new("/usr/bin/open");
    command.arg("-n").arg(application);
    command
}

#[cfg(target_os = "macos")]
fn relaunch_macos_application(application: &Path) -> anyhow::Result<()> {
    let status = macos_relaunch_command(application)
        .status()
        .context("could not run macOS LaunchServices")?;
    anyhow::ensure!(
        status.success(),
        "macOS LaunchServices rejected the relaunch with {status}"
    );
    Ok(())
}

/// The repository from which signed desktop releases are published.
const DEFAULT_REPOSITORY: &str = "EkuboProtocol/wallet";

/// Set to `1` to make every check here a no-op.
const SKIP_ENVIRONMENT_VARIABLE: &str = "EKUBO_WALLET_SKIP_UPDATE_CHECK";

/// Overrides the repository for development and tests.
const REPOSITORY_ENVIRONMENT_VARIABLE: &str = "EKUBO_WALLET_REPOSITORY";

const CACHE_FILE: &str = "release-check.json";

/// A day. Releases are not frequent enough for a shorter window to tell anyone
/// anything, and GitHub's unauthenticated limit is 60 requests an hour per
/// address — which this stays far below even with both surfaces asking.
const CACHE_TTL_SECONDS: i64 = 24 * 60 * 60;

/// Short enough that a hung endpoint cannot delay a desktop action or a tool call
/// by anything a person would notice.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// The release JSON is a few kilobytes. Anything past this is not that.
const MAX_RESPONSE_BYTES: u64 = 1 << 20;

/// Where the answer came from, so a caller can tell "you are current" apart
/// from "nobody could say".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckSource {
    /// Asked the release endpoint just now.
    Network,
    /// Reused an answer from within the last day.
    Cache,
    /// Turned off by the environment.
    Disabled,
    /// Nothing answered, and no cached answer was usable.
    Unavailable,
}

/// The complete answer, shaped so the desktop and the MCP tool read
/// the same fields.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ReleaseCheck {
    /// The running build, exactly as the Legal & Version screen presents it.
    pub installed_version: String,
    /// The newest published release, when one could be determined.
    pub latest_version: Option<String>,
    /// True only when both versions parsed and the published one is newer.
    /// An unknown answer is never reported as an update.
    pub update_available: bool,
    /// The repository's stable latest-release page.
    pub release_url: Option<String>,
    /// When `latest_version` was learned — now, or when the cache was written.
    pub checked_at: Option<DateTime<Utc>>,
    pub source: CheckSource,
    /// What the caller should do about it, in words, because the caller is
    /// usually a model.
    pub instruction: String,
}

impl ReleaseCheck {
    /// The answer when there is nothing to say, which is also the answer to
    /// every failure.
    fn unknown(installed_version: &str, source: CheckSource) -> Self {
        Self {
            installed_version: installed_version.to_string(),
            latest_version: None,
            update_available: false,
            release_url: None,
            checked_at: None,
            source,
            instruction: "The latest published release could not be determined, so nothing \
is known about whether this build is current. This is not an error and nothing is wrong with \
the wallet. Do not retry, and do not tell the user to upgrade."
                .to_string(),
        }
    }

    /// The short notice the desktop displays, or nothing when there is no news.
    #[must_use]
    pub fn notice(&self) -> Option<String> {
        let latest = self.latest_version.as_ref()?;
        if !self.update_available {
            return None;
        }
        Some(format!(
            "Ekubo Wallet {latest} is available; you are running {}. Open Updates to install the verified stable release.",
            self.installed_version
        ))
    }
}

/// Release tags become part of the release page URL, so only the expected
/// semantic-version punctuation is admitted.
fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

/// A repository, as `owner/name`. Read from the environment rather than the
/// network, but it reaches the same release URL.
fn valid_repository(repository: &str) -> bool {
    let mut parts = repository.split('/');
    let (Some(owner), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let segment = |segment: &str| {
        !segment.is_empty()
            && segment.len() <= 100
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    };
    segment(owner) && segment(name)
}

fn repository() -> String {
    std::env::var(REPOSITORY_ENVIRONMENT_VARIABLE)
        .ok()
        .filter(|repository| valid_repository(repository))
        .unwrap_or_else(|| DEFAULT_REPOSITORY.to_string())
}

fn skip_requested() -> bool {
    std::env::var(SKIP_ENVIRONMENT_VARIABLE).is_ok_and(|value| value == "1")
}

/// A version split into the parts that order it.
struct Version {
    /// The dot-separated numeric core, `1.4.2`.
    core: Vec<u64>,
    /// Whether a `-rc.1`-style prerelease suffix followed it.
    prerelease: bool,
}

fn parse_version(text: &str) -> Option<Version> {
    // `BUILD_VERSION` is `1.0.0-rc.0+8133a00` on an untagged build, and tags
    // carry a leading `v`; both reduce to the same core.
    let text = text.trim().strip_prefix('v').unwrap_or(text.trim());
    let without_build = text.split('+').next()?;
    let (core_text, prerelease) = match without_build.split_once('-') {
        Some((core, _)) => (core, true),
        None => (without_build, false),
    };
    let core = core_text
        .split('.')
        .map(|component| component.parse::<u64>().ok())
        .collect::<Option<Vec<u64>>>()?;
    (!core.is_empty()).then_some(Version { core, prerelease })
}

/// Whether `latest` supersedes `installed`, or `None` when either is not a
/// version this understands. `None` is deliberately not `false`: the caller
/// reports nothing rather than guessing in either direction.
fn is_newer(installed: &str, latest: &str) -> Option<bool> {
    let installed = parse_version(installed)?;
    let latest = parse_version(latest)?;
    let length = installed.core.len().max(latest.core.len());
    for index in 0..length {
        let running = installed.core.get(index).copied().unwrap_or(0);
        let published = latest.core.get(index).copied().unwrap_or(0);
        if published != running {
            return Some(published > running);
        }
    }
    // Same numeric core. A release supersedes a prerelease of itself, which is
    // the case that matters while `BUILD_VERSION` is an `-rc` build.
    Some(installed.prerelease && !latest.prerelease)
}

#[derive(Serialize, Deserialize)]
struct Cache {
    /// Which repository the tag was read from. A tag only means something
    /// alongside the repository that published it: without this, pointing
    /// `EKUBO_WALLET_REPOSITORY` somewhere else would keep answering with the
    /// previous repository's tag for a day, and build a release URL and an
    /// install command naming a tag the new repository does not have.
    repository: String,
    latest_version: String,
    checked_at: DateTime<Utc>,
}

fn read_cache(data_dir: &Path, repository: &str) -> Option<Cache> {
    let text = std::fs::read_to_string(data_dir.join(CACHE_FILE)).ok()?;
    let cache: Cache = serde_json::from_str(&text).ok()?;
    (cache.repository == repository && valid_tag(&cache.latest_version)).then_some(cache)
}

/// Best effort in both directions: a cache that cannot be written costs a
/// request next time and nothing else, so no failure here reaches the caller.
fn write_cache(data_dir: &Path, cache: &Cache) {
    let Ok(text) = serde_json::to_string(cache) else {
        return;
    };
    // Written beside the target and renamed, so a concurrent reader sees one
    // whole file or the previous one, never a half-written mix.
    let temporary = data_dir.join(format!("{CACHE_FILE}.tmp"));
    if std::fs::create_dir_all(data_dir).is_err() {
        return;
    }
    if std::fs::write(&temporary, text).is_err() {
        return;
    }
    if std::fs::rename(&temporary, data_dir.join(CACHE_FILE)).is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
}

/// Read a response body, stopping at `MAX_RESPONSE_BYTES`.
///
/// The `content_length` check above is a courtesy the server extends. It can
/// omit the header entirely -- chunked encoding does -- or state one length
/// and send another, and `text()` then buffers whatever arrives. So the header
/// is worth checking because it refuses the honest oversized case before a
/// single byte is read, and it is not worth trusting.
///
/// Accumulated chunk by chunk and abandoned the moment it passes the ceiling,
/// so the memory this costs is bounded by the ceiling rather than by what the
/// far end decided to send. `None` rather than a truncated body: a partial
/// JSON document is not a release, and the whole call is already best-effort.
async fn bounded_body(mut response: reqwest::Response) -> Option<String> {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        // Compared as `u64`, the type the ceiling is declared in. Casting it
        // down would truncate on a 32-bit target, which is the one place a
        // ceiling silently becoming a different number matters.
        let total = body.len() as u64 + chunk.len() as u64;
        if total > MAX_RESPONSE_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).ok()
}

async fn fetch_latest_tag(repository: String) -> Option<String> {
    let client = reqwest::Client::builder()
        .connect_timeout(REQUEST_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .user_agent(format!("ekubo-wallet/{}", crate::BUILD_VERSION))
        .build()
        .ok()?;
    let response = client
        .get(format!(
            "https://api.github.com/repos/{repository}/releases/latest"
        ))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        return None;
    }
    let body = bounded_body(response).await?;
    let value: serde_json::Value = serde_json::from_str(&body).ok()?;
    let tag = value.get("tag_name")?.as_str()?.trim().to_string();
    valid_tag(&tag).then_some(tag)
}

/// The check, with the network call and the clock supplied by the caller so
/// the whole of the logic is reachable from a test without either.
async fn check_with<F, Fut>(
    data_dir: &Path,
    installed_version: &str,
    repository: &str,
    now: DateTime<Utc>,
    disabled: bool,
    fetch: F,
) -> ReleaseCheck
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    if disabled {
        return ReleaseCheck::unknown(installed_version, CheckSource::Disabled);
    }

    let cached = read_cache(data_dir, repository);
    // A half-open range rather than a `<`, so a cache dated in the future —
    // a clock that moved backwards, a file copied between machines — is stale
    // rather than fresh forever.
    let fresh = cached.as_ref().filter(|cache| {
        (0..CACHE_TTL_SECONDS).contains(&now.signed_duration_since(cache.checked_at).num_seconds())
    });

    let (tag, checked_at, source) = match fresh {
        Some(cache) => (
            cache.latest_version.clone(),
            cache.checked_at,
            CheckSource::Cache,
        ),
        // Validated here rather than only in the fetch, so the guard sits
        // where the tag is used: everything downstream — the cache it is
        // written to and the release URL trust this point and
        // nothing re-checks. Rejecting one is the same as being offline.
        None => match fetch().await.filter(|tag| valid_tag(tag)) {
            Some(tag) => {
                write_cache(
                    data_dir,
                    &Cache {
                        repository: repository.to_string(),
                        latest_version: tag.clone(),
                        checked_at: now,
                    },
                );
                (tag, now, CheckSource::Network)
            }
            // Offline with a stale answer is still a better answer than none:
            // the version it names was published, and the only thing its age
            // can cause is under-reporting a newer one.
            None => match cached {
                Some(cache) => (cache.latest_version, cache.checked_at, CheckSource::Cache),
                None => {
                    return ReleaseCheck::unknown(installed_version, CheckSource::Unavailable);
                }
            },
        },
    };

    let Some(update_available) = is_newer(installed_version, &tag) else {
        return ReleaseCheck::unknown(installed_version, source);
    };

    let release_url = format!("https://github.com/{repository}/releases/latest");
    let instruction = if update_available {
        "A newer stable desktop release is published. Tell the user to open Updates in Ekubo Wallet, where the wallet can download, verify, and install it after explicit confirmation."
            .to_string()
    } else {
        "This build is the latest published release. Say so if asked; there is nothing to do."
            .to_string()
    };

    ReleaseCheck {
        installed_version: installed_version.to_string(),
        latest_version: Some(tag.clone()),
        update_available,
        release_url: Some(release_url),
        checked_at: Some(checked_at),
        source,
        instruction,
    }
}

/// Ask whether a newer release exists, reusing a cached answer for a day.
pub async fn check(data_dir: &Path) -> ReleaseCheck {
    let repository = repository();
    check_with(
        data_dir,
        crate::BUILD_VERSION,
        &repository,
        Utc::now(),
        skip_requested(),
        || fetch_latest_tag(repository.clone()),
    )
    .await
}

#[cfg(test)]
#[path = "release_check_test.rs"]
mod tests;
