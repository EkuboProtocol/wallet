//! Signed, owner-confirmed application updates.

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cargo_packager_updater::{
    Config, RemoteRelease, Update, UpdateFormat,
    reqwest::{blocking::Client, header::HeaderMap},
    semver::Version,
};
use minisign_verify::{PublicKey, Signature};
use std::{io::Read as _, path::PathBuf, process::Command, time::Duration};

const UPDATE_ENDPOINT: &str =
    "https://github.com/EkuboProtocol/wallet/releases/latest/download/latest.json";
const UPDATE_METADATA_SIGNATURE_ENDPOINT: &str =
    "https://github.com/EkuboProtocol/wallet/releases/latest/download/latest.json.sig";
const MAX_UPDATE_METADATA_BYTES: u64 = 1 << 20;
const MAX_UPDATE_METADATA_SIGNATURE_BYTES: u64 = 16 << 10;
const UPDATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Release CI injects the Minisign public key at compile time. Private update
/// keys are never present in the source tree or application bundle.
const UPDATE_PUBLIC_KEY: Option<&str> = option_env!("EKUBO_UPDATER_PUBLIC_KEY");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateSummary {
    pub version: String,
    pub notes: Option<String>,
    pub requires_package_handoff: bool,
}

pub struct VerifiedUpdate(Update);

impl VerifiedUpdate {
    #[must_use]
    pub fn summary(&self) -> UpdateSummary {
        UpdateSummary {
            version: self.0.version.clone(),
            notes: self.0.body.clone(),
            requires_package_handoff: cfg!(target_os = "linux")
                && !matches!(self.0.format, UpdateFormat::AppImage),
        }
    }

    /// Download and verify the complete package without installing it. This
    /// is called only after the owner confirms the version and release notes.
    pub fn download_verified(&self) -> Result<Vec<u8>> {
        self.download_verified_with_progress(|_, _| {})
    }

    /// Download and verify while reporting each received chunk and the total
    /// size when the server declared one. The callback never receives package
    /// bytes, so UI progress cannot accidentally retain executable content.
    pub fn download_verified_with_progress(
        &self,
        on_progress: impl Fn(usize, Option<u64>),
    ) -> Result<Vec<u8>> {
        self.0
            .download_extended(on_progress, || {})
            .context("update download or signature verification failed")
    }

    /// Install bytes that have already passed Minisign verification. The GUI
    /// must stop MCP and disconnect `WalletConnect` before invoking this.
    pub fn install(self, bytes: Vec<u8>) -> Result<()> {
        ensure!(!bytes.is_empty(), "verified update package is empty");
        self.0.install(bytes).context("update installation failed")
    }
}

pub fn check_for_update() -> Result<Option<VerifiedUpdate>> {
    let public_key = UPDATE_PUBLIC_KEY.context(
        "this development build has no embedded update public key; update installation is disabled",
    )?;
    let config = updater_config(public_key)?;
    let current = Version::parse(crate::BUILD_VERSION)?;
    let client = Client::builder()
        .timeout(UPDATE_REQUEST_TIMEOUT)
        .build()
        .context("failed to build the update client")?;
    let metadata = fetch_bounded(
        &client,
        UPDATE_ENDPOINT,
        MAX_UPDATE_METADATA_BYTES,
        "update metadata",
    )?;
    let metadata_signature = fetch_bounded(
        &client,
        UPDATE_METADATA_SIGNATURE_ENDPOINT,
        MAX_UPDATE_METADATA_SIGNATURE_BYTES,
        "update metadata signature",
    )?;
    verify_metadata_signature(&metadata, &metadata_signature, public_key)?;
    let release: RemoteRelease =
        serde_json::from_slice(&metadata).context("signed update metadata is invalid")?;
    if release.version <= current {
        return Ok(None);
    }
    let json_target =
        cargo_packager_updater::target().context("this platform has no supported update target")?;
    let download_url = release.download_url(&json_target)?.to_owned();
    ensure!(
        download_url.scheme() == "https"
            && download_url.username().is_empty()
            && download_url.password().is_none()
            && download_url.host().is_some(),
        "signed update metadata contains an unsafe package URL"
    );
    let target = json_target
        .split_once('-')
        .map_or(json_target.as_str(), |(target, _)| target)
        .to_owned();
    let signature = release.signature(&json_target)?.to_owned();
    let format = release.format(&json_target)?;
    Ok(Some(VerifiedUpdate(Update {
        config,
        body: release.notes,
        current_version: current.to_string(),
        version: release.version.to_string(),
        date: release.pub_date,
        target,
        extract_path: update_extract_path()?,
        download_url,
        signature,
        timeout: Some(UPDATE_REQUEST_TIMEOUT),
        headers: HeaderMap::new(),
        format,
    })))
}

fn fetch_bounded(client: &Client, url: &str, limit: u64, label: &str) -> Result<Vec<u8>> {
    let mut response = client
        .get(url)
        .send()
        .with_context(|| format!("failed to fetch {label}"))?
        .error_for_status()
        .with_context(|| format!("{label} endpoint refused the request"))?;
    ensure!(
        response
            .content_length()
            .is_none_or(|length| length <= limit),
        "{label} exceeds its size limit"
    );
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label}"))?;
    ensure!(
        bytes.len() as u64 <= limit,
        "{label} exceeds its size limit"
    );
    Ok(bytes)
}

fn verify_metadata_signature(
    metadata: &[u8],
    encoded_signature: &[u8],
    encoded_key: &str,
) -> Result<()> {
    let decoded_key = STANDARD
        .decode(encoded_key)
        .context("embedded update public key is not valid base64")?;
    let key_text =
        std::str::from_utf8(&decoded_key).context("embedded update public key is not UTF-8")?;
    let signature_text =
        std::str::from_utf8(encoded_signature).context("update metadata signature is not UTF-8")?;
    let key = PublicKey::decode(key_text).context("embedded update public key is invalid")?;
    let signature =
        Signature::decode(signature_text).context("update metadata signature is invalid")?;
    key.verify(metadata, &signature, true)
        .context("update metadata signature verification failed")
}

#[cfg(target_os = "linux")]
fn update_extract_path() -> Result<PathBuf> {
    Ok(std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .map_or_else(std::env::current_exe, Ok)?)
}

#[cfg(target_os = "macos")]
fn update_extract_path() -> Result<PathBuf> {
    let executable = std::env::current_exe()?;
    Ok(macos_bundle_path(&executable).unwrap_or_else(|| {
        executable
            .parent()
            .map_or_else(|| executable.clone(), std::path::Path::to_path_buf)
    }))
}

#[cfg(windows)]
fn update_extract_path() -> Result<PathBuf> {
    let executable = std::env::current_exe()?;
    executable
        .parent()
        .map(std::path::Path::to_path_buf)
        .context("failed to determine the Windows update directory")
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn update_extract_path() -> Result<PathBuf> {
    anyhow::bail!("this platform does not support application updates")
}

fn updater_config(public_key: &str) -> Result<Config> {
    ensure!(
        !public_key.trim().is_empty(),
        "embedded update public key is empty"
    );
    Ok(Config {
        endpoints: vec![UPDATE_ENDPOINT.parse()?],
        pubkey: public_key.to_owned(),
        ..Default::default()
    })
}

/// Start the newly installed application after the current process exits.
/// `AppImage` exposes the stable outer image path through `APPIMAGE`; bundled
/// macOS and Windows builds relaunch through their executable path.
pub fn relaunch() -> Result<()> {
    #[cfg(target_os = "linux")]
    let executable = std::env::var_os("APPIMAGE")
        .map(std::path::PathBuf::from)
        .map_or_else(std::env::current_exe, Ok)?;
    #[cfg(not(target_os = "linux"))]
    let executable = std::env::current_exe()?;

    #[cfg(target_os = "macos")]
    let mut command = if let Some(bundle) = macos_bundle_path(&executable) {
        let mut command = Command::new("/usr/bin/open");
        command.arg("-n").arg(bundle);
        command
    } else {
        Command::new(&executable)
    };
    #[cfg(not(target_os = "macos"))]
    let mut command = Command::new(&executable);

    command
        .spawn()
        .with_context(|| format!("failed to relaunch {}", executable.display()))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_bundle_path(executable: &std::path::Path) -> Option<std::path::PathBuf> {
    executable
        .ancestors()
        .find(|path| path.extension().is_some_and(|extension| extension == "app"))
        .map(std::path::Path::to_path_buf)
}

#[cfg(test)]
#[path = "updater_test.rs"]
mod tests;
