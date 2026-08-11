//! Signed, owner-confirmed application updates.

use anyhow::{Context, Result, ensure};
use cargo_packager_updater::{Config, Update, UpdateFormat, check_update, semver::Version};

const UPDATE_ENDPOINT: &str =
    "https://github.com/EkuboProtocol/wallet-mcp-server/releases/latest/download/latest.json";

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
        self.0
            .download()
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
    ensure!(
        !public_key.trim().is_empty(),
        "embedded update public key is empty"
    );
    let config = Config {
        endpoints: vec![UPDATE_ENDPOINT.parse()?],
        pubkey: public_key.to_owned(),
        ..Default::default()
    };
    let current = Version::parse(crate::BUILD_VERSION)?;
    Ok(check_update(current, config)?.map(VerifiedUpdate))
}
