//! Authenticated discovery and owner-authorized installation of desktop updates.

use crate::human_presence::{
    HumanPresenceError, OwnerAuthorization, OwnerAuthorizationScope, authorize_owner,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cargo_packager_updater::{RemoteRelease, RemoteReleaseData, Update, UpdateFormat};
use minisign_verify::{PublicKey, Signature};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    io::Read as _,
    path::{Path, PathBuf},
    time::Duration,
};

pub const UPDATER_PUBLIC_KEY: &str = env!("EKUBO_COMPILED_UPDATER_PUBLIC_KEY");
pub const UPDATE_PUBLISHER: &str = "Ekubo, Inc.";
/// A unique marker retained in the packaged application binary. Update
/// verification reads it back from the candidate package rather than trusting
/// the release manifest's version claim alone.
pub const PACKAGE_VERSION_MARKER: &str = concat!(
    "\0EKUBO-WALLET-PACKAGE-VERSION:",
    env!("CARGO_PKG_VERSION"),
    "\0"
);
#[cfg(any(target_os = "macos", target_os = "linux", test))]
const PACKAGE_VERSION_MARKER_PREFIX: &[u8] = b"\0EKUBO-WALLET-PACKAGE-VERSION:";
const UPDATE_MANIFEST_URL: &str =
    "https://github.com/EkuboProtocol/wallet/releases/latest/download/latest.json";
const UPDATE_MANIFEST_SIGNATURE_URL: &str =
    "https://github.com/EkuboProtocol/wallet/releases/latest/download/latest.json.sig";
const UPDATE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_MANIFEST_BYTES: u64 = 1 << 20;
const MAX_SIGNATURE_BYTES: u64 = 64 << 10;
const MAX_ARTIFACT_BYTES: u64 = 1 << 30;
#[cfg(any(target_os = "macos", target_os = "linux"))]
const MAX_PACKAGED_BINARY_BYTES: u64 = 512 << 20;

/// Authenticated metadata for a strictly newer update on this exact target.
///
/// Every field is private. Presentation code may show the version and ask core
/// to download it, but cannot obtain the updater's raw installation primitive.
#[derive(Clone, Debug)]
pub struct InstallableUpdate {
    update: Update,
    artifact_sha256: String,
    signed_manifest: Vec<u8>,
    manifest_signature: String,
}

impl InstallableUpdate {
    #[must_use]
    pub fn version(&self) -> &str {
        &self.update.version
    }

    /// Download and authenticate the artifact while retaining everything core
    /// needs to repeat the verification after owner authentication.
    pub fn download(&self) -> Result<PreparedUpdate> {
        let client = update_client()?;
        let bytes = download_bounded(
            &client,
            self.update.download_url.as_str(),
            MAX_ARTIFACT_BYTES,
            "update artifact",
        )?;
        self.verify_authenticated_payload(&bytes)?;
        Ok(PreparedUpdate {
            update: self.clone(),
            bytes,
        })
    }

    fn verify_authenticated_payload(&self, bytes: &[u8]) -> Result<()> {
        self.verify_authenticated_payload_with_key(bytes, UPDATER_PUBLIC_KEY)
    }

    fn verify_authenticated_payload_with_key(&self, bytes: &[u8], public_key: &str) -> Result<()> {
        self.verify_signed_payload_with_key(bytes, public_key)?;
        verify_embedded_package_version(&self.update, bytes)
    }

    fn verify_signed_payload_with_key(&self, bytes: &[u8], public_key: &str) -> Result<()> {
        verify_packager_signature(&self.signed_manifest, &self.manifest_signature, public_key)
            .context("the update manifest signature did not verify")?;
        let digest = update_matches_signed_manifest(&self.update, &self.signed_manifest)?;
        ensure!(
            digest == self.artifact_sha256,
            "the authenticated update digest changed after discovery"
        );
        verify_packager_signature(bytes, &self.update.signature, public_key)
            .context("the update artifact signature did not verify")?;
        ensure!(
            hex::encode(Sha256::digest(bytes)) == digest,
            "the update artifact does not match the digest bound by signed metadata"
        );
        Ok(())
    }
}

/// Exact downloaded bytes plus the authenticated envelope from which they came.
/// Its fields stay private so only core can commit them as an update.
pub struct PreparedUpdate {
    update: InstallableUpdate,
    bytes: Vec<u8>,
}

impl PreparedUpdate {
    #[must_use]
    pub fn review(&self) -> UpdateReview {
        UpdateReview::from_verified_update(&self.update.update, &self.bytes)
    }
}

/// Fields shown to and authenticated by the owner before installation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct UpdateReview {
    pub version: String,
    pub publisher: String,
    pub target: String,
    pub format: String,
    pub download_url: String,
    pub artifact_sha256: String,
}

impl UpdateReview {
    fn from_verified_update(update: &Update, bytes: &[u8]) -> Self {
        Self {
            version: update.version.clone(),
            publisher: UPDATE_PUBLISHER.to_owned(),
            target: cargo_packager_updater::target().unwrap_or_else(|| update.target.clone()),
            format: update.format.to_string(),
            download_url: update.download_url.to_string(),
            artifact_sha256: hex::encode(Sha256::digest(bytes)),
        }
    }

    fn identity(&self) -> String {
        let encoded = serde_json::to_vec(self).expect("update review fields are serializable");
        hex::encode(Sha256::digest(encoded))
    }
}

/// Single-use, short-lived proof for one exact update package.
pub struct UpdateAuthorization {
    owner: OwnerAuthorization,
    review_identity: String,
}

pub async fn authorize_update(
    review: &UpdateReview,
) -> std::result::Result<UpdateAuthorization, HumanPresenceError> {
    let owner = authorize_owner(OwnerAuthorizationScope::UpdateTrust).await?;
    Ok(UpdateAuthorization {
        owner,
        review_identity: review.identity(),
    })
}

/// Discover a newer release only after authenticating the exact metadata bytes.
pub fn check_installable() -> Result<Option<InstallableUpdate>> {
    ensure!(
        !UPDATER_PUBLIC_KEY.is_empty(),
        "this development build has no updater verification key"
    );
    #[cfg(target_os = "linux")]
    ensure!(
        std::env::var_os("APPIMAGE").is_some(),
        "automatic updates are available for the AppImage distribution"
    );

    let current = cargo_packager_updater::semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .context("the application version is not valid semantic versioning")?;
    let client = update_client()?;
    let manifest = download_bounded(
        &client,
        UPDATE_MANIFEST_URL,
        MAX_MANIFEST_BYTES,
        "update manifest",
    )?;
    let manifest_signature = String::from_utf8(download_bounded(
        &client,
        UPDATE_MANIFEST_SIGNATURE_URL,
        MAX_SIGNATURE_BYTES,
        "update manifest signature",
    )?)
    .context("the update manifest signature is not UTF-8")?;
    verify_packager_signature(&manifest, &manifest_signature, UPDATER_PUBLIC_KEY)
        .context("the update manifest signature did not verify")?;

    let release: RemoteRelease =
        serde_json::from_slice(&manifest).context("signed update manifest is malformed")?;
    if release.version <= current {
        return Ok(None);
    }
    let target = cargo_packager_updater::target().context("this updater target is unsupported")?;
    let platform = match &release.data {
        RemoteReleaseData::Static { platforms } => platforms
            .get(&target)
            .cloned()
            .context("the updater target is absent from the signed manifest")?,
        RemoteReleaseData::Dynamic(_) => {
            anyhow::bail!("signed update metadata must bind an explicit platform target")
        }
    };
    ensure!(
        platform.url.scheme() == "https",
        "the signed update URL must use HTTPS"
    );
    let artifact_sha256 = manifest_digest(&manifest, &target)?;
    let update = Update {
        config: cargo_packager_updater::Config {
            endpoints: Vec::new(),
            pubkey: UPDATER_PUBLIC_KEY.to_owned(),
            windows: None,
        },
        body: release.notes,
        current_version: current.to_string(),
        version: release.version.to_string(),
        date: release.pub_date,
        target: target
            .split_once('-')
            .map_or_else(|| target.clone(), |(os, _)| os.to_owned()),
        extract_path: updater_extract_path()?,
        download_url: platform.url,
        signature: platform.signature,
        timeout: Some(UPDATE_TIMEOUT),
        headers: cargo_packager_updater::http::HeaderMap::default(),
        format: platform.format,
    };
    update_matches_signed_manifest(&update, &manifest)?;
    Ok(Some(InstallableUpdate {
        update,
        artifact_sha256,
        signed_manifest: manifest,
        manifest_signature,
    }))
}

/// Re-authenticate the exact envelope and bytes after owner presence, then let
/// the core-owned updater primitive commit them once.
pub fn install_update(
    prepared: PreparedUpdate,
    authorization: UpdateAuthorization,
) -> Result<Option<PathBuf>> {
    let UpdateAuthorization {
        owner,
        review_identity,
    } = authorization;
    owner.require(OwnerAuthorizationScope::UpdateTrust)?;
    ensure!(
        review_identity == prepared.review().identity(),
        "update metadata or package bytes changed after owner authentication"
    );
    let PreparedUpdate { update, bytes } = prepared;
    update.verify_authenticated_payload(&bytes)?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let relaunch_path = Some(update.update.extract_path.clone());
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let relaunch_path = None;
    #[cfg(target_os = "macos")]
    install_macos_application(&update.update.extract_path, &bytes)?;
    #[cfg(not(target_os = "macos"))]
    update
        .update
        .install(bytes)
        .context("could not install update")?;
    Ok(relaunch_path)
}

/// Extract the signed bundle beside the installed application, then atomically
/// exchange their names. `RENAME_SWAP` either leaves both paths untouched or
/// commits the complete replacement, so an I/O failure cannot consume the
/// working application while reporting that installation failed.
#[cfg(target_os = "macos")]
fn install_macos_application(application: &Path, bytes: &[u8]) -> Result<()> {
    use std::path::Component;

    ensure!(
        std::fs::symlink_metadata(application)?.file_type().is_dir(),
        "the installed macOS application is not a directory"
    );
    let parent = application
        .parent()
        .context("the installed macOS application has no parent directory")?;
    let application_name = application
        .file_name()
        .context("the installed macOS application has no bundle name")?;
    let transaction = tempfile::Builder::new()
        .prefix(".ekubo-wallet-update-")
        .tempdir_in(parent)
        .context("could not stage the update beside the installed application")?;
    let staging_root = transaction.path().join("staged");
    std::fs::create_dir(&staging_root).context("could not create the update staging directory")?;

    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut entries = 0usize;
    for entry in archive
        .entries()
        .context("the macOS update archive is invalid")?
    {
        let mut entry = entry.context("the macOS update archive entry is invalid")?;
        let path = entry
            .path()
            .context("the macOS update archive path is invalid")?
            .into_owned();
        let mut components = path.components();
        ensure!(
            matches!(components.next(), Some(Component::Normal(root)) if root == application_name),
            "the macOS update archive has an unexpected bundle root"
        );
        ensure!(
            components.all(|component| matches!(component, Component::Normal(_))),
            "the macOS update archive contains an unsafe path"
        );
        ensure!(
            entry
                .unpack_in(&staging_root)
                .context("could not extract the macOS update archive")?,
            "the macOS update archive escapes its staging directory"
        );
        entries = entries
            .checked_add(1)
            .context("the macOS update archive has too many entries")?;
    }
    ensure!(entries != 0, "the macOS update archive is empty");

    let staged_application = staging_root.join(application_name);
    ensure!(
        std::fs::symlink_metadata(&staged_application)?
            .file_type()
            .is_dir(),
        "the macOS update archive contains no application bundle"
    );
    swap_macos_paths(application, &staged_application)
        .context("could not atomically replace the macOS application")?;

    // The old application now lives under `transaction`; dropping it removes
    // that backup only after the atomic exchange has succeeded.
    drop(transaction);
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn swap_macos_paths(left: &Path, right: &Path) -> Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt as _};

    let left = CString::new(left.as_os_str().as_bytes())
        .context("the installed application path contains a null byte")?;
    let right = CString::new(right.as_os_str().as_bytes())
        .context("the staged application path contains a null byte")?;
    // SAFETY: both pointers come from live `CString`s and remain valid for the
    // duration of the call. `renamex_np` does not retain either pointer.
    let result = unsafe { libc::renamex_np(left.as_ptr(), right.as_ptr(), libc::RENAME_SWAP) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn verify_packager_signature(
    data: &[u8],
    encoded_signature: &str,
    encoded_key: &str,
) -> Result<()> {
    let key_text = decode_packager_box(encoded_key, "updater public key")?;
    let signature_text = decode_packager_box(encoded_signature, "update signature")?;
    let public_key = PublicKey::decode(&key_text)
        .or_else(|_| PublicKey::from_base64(key_text.trim()))
        .context("the updater public key is invalid")?;
    let signature =
        Signature::decode(&signature_text).context("the update signature is invalid")?;
    public_key
        .verify(data, &signature, false)
        .context("signature verification failed")
}

fn update_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(UPDATE_TIMEOUT)
        .user_agent(format!("ekubo-wallet/{}", env!("CARGO_PKG_VERSION")))
        .build()?)
}

fn download_bounded(
    client: &reqwest::blocking::Client,
    url: &str,
    maximum: u64,
    label: &str,
) -> Result<Vec<u8>> {
    let response = client.get(url).send()?.error_for_status()?;
    if let Some(length) = response.content_length() {
        ensure!(length <= maximum, "the {label} is too large");
    }
    read_bounded(response, maximum, label)
}

fn read_bounded(reader: impl std::io::Read, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "the {label} is too large");
    Ok(bytes)
}

fn decode_packager_box(encoded: &str, label: &str) -> Result<String> {
    let decoded = STANDARD
        .decode(encoded.trim())
        .with_context(|| format!("the {label} is not cargo-packager base64"))?;
    String::from_utf8(decoded).with_context(|| format!("the {label} is not UTF-8"))
}

fn update_matches_signed_manifest(update: &Update, manifest: &[u8]) -> Result<String> {
    let signed: RemoteRelease =
        serde_json::from_slice(manifest).context("signed update manifest is malformed")?;
    let target = cargo_packager_updater::target().context("this updater target is unsupported")?;
    let platform = match &signed.data {
        RemoteReleaseData::Static { platforms } => platforms
            .get(&target)
            .context("the updater target is absent from the signed manifest")?,
        RemoteReleaseData::Dynamic(_) => {
            anyhow::bail!("signed update metadata must bind an explicit platform target")
        }
    };
    ensure!(
        signed.version.to_string() == update.version,
        "update version is not bound by the signed manifest"
    );
    let current = cargo_packager_updater::semver::Version::parse(&update.current_version)
        .context("the installed application version is malformed")?;
    ensure!(
        signed.version > current,
        "the authenticated update is not newer than the installed application"
    );
    let expected_target = target.split_once('-').map_or(target.as_str(), |(os, _)| os);
    ensure!(
        update.target == expected_target,
        "the updater platform changed after authenticated discovery"
    );
    ensure!(
        platform.url == update.download_url,
        "update URL is not bound by the signed manifest"
    );
    ensure!(
        platform.url.scheme() == "https",
        "the signed update URL must use HTTPS"
    );
    ensure!(
        platform.signature == update.signature,
        "artifact signature is not bound by the signed manifest"
    );
    ensure!(
        format_name(platform.format) == format_name(update.format),
        "update format is not bound by the signed manifest"
    );
    manifest_digest(manifest, &target)
}

fn verify_embedded_package_version(update: &Update, bytes: &[u8]) -> Result<()> {
    let embedded = embedded_package_version(bytes, update.format)?;
    verify_embedded_version_claim(update, &embedded)
}

fn verify_embedded_version_claim(
    update: &Update,
    embedded: &cargo_packager_updater::semver::Version,
) -> Result<()> {
    let authenticated = cargo_packager_updater::semver::Version::parse(&update.version)
        .context("the authenticated update version is malformed")?;
    ensure!(
        embedded == &authenticated,
        "the packaged application version {embedded} does not match authenticated update version {authenticated}"
    );
    let current = cargo_packager_updater::semver::Version::parse(&update.current_version)
        .context("the installed application version is malformed")?;
    ensure!(
        embedded > &current,
        "the packaged application is not newer than the installed application"
    );
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn embedded_binary_version(bytes: &[u8]) -> Result<cargo_packager_updater::semver::Version> {
    let mut versions = BTreeSet::new();
    for index in bytes
        .windows(PACKAGE_VERSION_MARKER_PREFIX.len())
        .enumerate()
        .filter_map(|(index, window)| (window == PACKAGE_VERSION_MARKER_PREFIX).then_some(index))
    {
        let value = &bytes[index + PACKAGE_VERSION_MARKER_PREFIX.len()..];
        let Some(end) = value.iter().take(128).position(|byte| *byte == 0) else {
            continue;
        };
        let Ok(value) = std::str::from_utf8(&value[..end]) else {
            continue;
        };
        if let Ok(version) = cargo_packager_updater::semver::Version::parse(value) {
            versions.insert(version);
        }
    }
    ensure!(
        versions.len() == 1,
        "the packaged application does not contain one unambiguous embedded version"
    );
    versions
        .pop_first()
        .context("the packaged application version is absent")
}

#[cfg(target_os = "macos")]
fn embedded_package_version(
    bytes: &[u8],
    format: UpdateFormat,
) -> Result<cargo_packager_updater::semver::Version> {
    ensure!(
        matches!(format, UpdateFormat::App),
        "the macOS updater package has the wrong format"
    );
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut version = None;
    for entry in archive
        .entries()
        .context("the macOS update archive is invalid")?
    {
        let mut entry = entry.context("the macOS update archive entry is invalid")?;
        let path = entry
            .path()
            .context("the macOS update archive path is invalid")?;
        if entry.header().entry_type().is_file()
            && path.ends_with(std::path::Path::new("Contents/MacOS/ekubo-wallet"))
        {
            ensure!(
                version.is_none(),
                "the macOS package has multiple wallet binaries"
            );
            ensure!(
                entry.size() <= MAX_PACKAGED_BINARY_BYTES,
                "the packaged application binary is too large"
            );
            let binary = read_bounded(
                &mut entry,
                MAX_PACKAGED_BINARY_BYTES,
                "packaged application binary",
            )?;
            version = Some(embedded_binary_version(&binary)?);
        }
    }
    version.context("the macOS package contains no wallet application binary")
}

#[cfg(target_os = "linux")]
fn embedded_package_version(
    bytes: &[u8],
    format: UpdateFormat,
) -> Result<cargo_packager_updater::semver::Version> {
    ensure!(
        matches!(format, UpdateFormat::AppImage),
        "the Linux updater package has the wrong format"
    );
    for (offset, magic) in bytes.windows(4).enumerate() {
        if magic != b"hsqs" {
            continue;
        }
        let Ok(filesystem) = backhand::FilesystemReader::from_reader_with_offset(
            std::io::Cursor::new(bytes),
            offset as u64,
        ) else {
            continue;
        };
        for node in filesystem.files() {
            if !node
                .fullpath
                .ends_with(std::path::Path::new("usr/bin/ekubo-wallet"))
            {
                continue;
            }
            let backhand::InnerNode::File(file) = &node.inner else {
                continue;
            };
            ensure!(
                file.file_len() as u64 <= MAX_PACKAGED_BINARY_BYTES,
                "the packaged application binary is too large"
            );
            let binary = read_bounded(
                filesystem.file(file).reader(),
                MAX_PACKAGED_BINARY_BYTES,
                "packaged application binary",
            )?;
            return embedded_binary_version(&binary);
        }
    }
    anyhow::bail!("the AppImage contains no readable wallet application binary")
}

#[cfg(target_os = "windows")]
fn embedded_package_version(
    bytes: &[u8],
    format: UpdateFormat,
) -> Result<cargo_packager_updater::semver::Version> {
    ensure!(
        matches!(format, UpdateFormat::Nsis),
        "the Windows updater package has the wrong format"
    );
    let image = pelite::PeFile::from_bytes(bytes).context("the NSIS package is not a PE image")?;
    let information = image
        .resources()
        .context("the NSIS package has no resources")?
        .version_info()
        .context("the NSIS package has no version information")?;
    let mut versions = BTreeSet::new();
    for language in information.translation() {
        if let Some(value) = information.value(*language, "ProductVersion") {
            versions.insert(
                cargo_packager_updater::semver::Version::parse(value.trim())
                    .context("the NSIS ProductVersion is malformed")?,
            );
        }
    }
    ensure!(
        versions.len() == 1,
        "the NSIS package does not contain one unambiguous ProductVersion"
    );
    versions
        .pop_first()
        .context("the NSIS ProductVersion is absent")
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn embedded_package_version(
    _bytes: &[u8],
    _format: UpdateFormat,
) -> Result<cargo_packager_updater::semver::Version> {
    anyhow::bail!("automatic updates are unsupported on this platform")
}

fn manifest_digest(manifest: &[u8], target: &str) -> Result<String> {
    let value: serde_json::Value = serde_json::from_slice(manifest)?;
    let digest = value
        .get("platforms")
        .and_then(|platforms| platforms.get(target))
        .and_then(|platform| platform.get("sha256"))
        .and_then(serde_json::Value::as_str)
        .context("signed update target has no artifact digest")?;
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "signed artifact digest is not lowercase SHA-256"
    );
    Ok(digest.to_owned())
}

const fn format_name(format: UpdateFormat) -> &'static str {
    match format {
        UpdateFormat::Nsis => "nsis",
        UpdateFormat::Wix => "wix",
        UpdateFormat::AppImage => "appimage",
        UpdateFormat::App => "app",
    }
}

#[cfg(target_os = "linux")]
fn updater_extract_path() -> Result<PathBuf> {
    std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .context("the AppImage path is unavailable")
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn updater_extract_path() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("could not locate the wallet executable")?;
    let parent = executable
        .parent()
        .map(PathBuf::from)
        .context("could not determine the update extraction path")?;
    #[cfg(target_os = "macos")]
    if parent.to_string_lossy().contains("Contents/MacOS") {
        return parent
            .parent()
            .and_then(std::path::Path::parent)
            .map(PathBuf::from)
            .context("could not determine the application bundle path");
    }
    Ok(parent)
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn updater_extract_path() -> Result<PathBuf> {
    anyhow::bail!("automatic updates are unsupported on this platform")
}

#[cfg(test)]
#[path = "update_trust_test.rs"]
mod tests;
