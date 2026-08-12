//! Whether a newer signed desktop release exists.
//!
//! This module answers "am I behind?" for the Updates screen and the read-only
//! `wallet_check_for_updates` MCP tool. The desktop can additionally consume
//! the stable release's cargo-packager manifest and verify its native artifact
//! with the public key compiled into the application. The release tag is
//! validated before it enters a URL. Every
//! failure here — offline, rate limited, malformed JSON, an unwritable cache —
//! resolves to "no update known" rather than an error, because nothing that
//! depends on this answer should fail when the answer is merely unavailable.

use anyhow::Context as _;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

const UPDATE_MANIFEST_URL: &str =
    "https://github.com/EkuboProtocol/wallet/releases/latest/download/latest.json";
const UPDATE_TIMEOUT: Duration = Duration::from_secs(15);

/// An update whose artifact URL and signature came from cargo-packager's
/// stable-release manifest. `download` verifies the artifact with the public
/// key compiled into this exact application binary before returning bytes.
pub type InstallableUpdate = cargo_packager_updater::Update;

pub fn check_installable() -> anyhow::Result<Option<InstallableUpdate>> {
    anyhow::ensure!(
        !crate::UPDATER_PUBLIC_KEY.is_empty(),
        "this development build has no updater verification key"
    );
    #[cfg(target_os = "linux")]
    anyhow::ensure!(
        std::env::var_os("APPIMAGE").is_some(),
        "automatic updates are available for the AppImage distribution"
    );
    let current = semver::Version::parse(crate::VERSION)
        .context("the application version is not valid semantic versioning")?;
    let endpoint = UPDATE_MANIFEST_URL
        .parse()
        .context("the compiled update manifest URL is invalid")?;
    let config = cargo_packager_updater::Config {
        endpoints: vec![endpoint],
        pubkey: crate::UPDATER_PUBLIC_KEY.to_owned(),
        windows: None,
    };
    cargo_packager_updater::UpdaterBuilder::new(current, config)
        .timeout(UPDATE_TIMEOUT)
        .build()
        .context("could not initialize the signed updater")?
        .check()
        .context("could not read the signed release manifest")
}

/// Installs bytes already verified by [`InstallableUpdate::download`] and
/// starts the replacement application where the platform installer does not
/// do that itself.
pub fn install_and_relaunch(update: &InstallableUpdate, bytes: Vec<u8>) -> anyhow::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let executable = update.extract_path.clone();
    update.install(bytes).context("could not install update")?;
    #[cfg(target_os = "macos")]
    std::process::Command::new("open")
        .arg(executable)
        .spawn()
        .context("could not relaunch updated application")?;
    #[cfg(target_os = "linux")]
    std::process::Command::new(executable)
        .spawn()
        .context("could not relaunch updated application")?;
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
