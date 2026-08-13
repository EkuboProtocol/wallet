//! Owner-authorized installation of an exact, already verified update.

use crate::human_presence::{
    HumanPresenceError, OwnerAuthorization, OwnerAuthorizationScope, authorize_owner,
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha256};

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
    #[must_use]
    pub fn from_verified_update(
        update: &cargo_packager_updater::Update,
        bytes: &[u8],
        publisher: &str,
    ) -> Self {
        Self {
            version: update.version.clone(),
            publisher: publisher.to_owned(),
            target: update.target.clone(),
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
) -> Result<UpdateAuthorization, HumanPresenceError> {
    let owner = authorize_owner(OwnerAuthorizationScope::UpdateTrust).await?;
    Ok(UpdateAuthorization {
        owner,
        review_identity: review.identity(),
    })
}

/// Re-read all authenticated fields and bytes immediately before core commits
/// the update. No raw installer is exposed to the presentation crate.
pub fn install_update(
    update: &cargo_packager_updater::Update,
    bytes: Vec<u8>,
    publisher: &str,
    authorization: UpdateAuthorization,
) -> Result<()> {
    let UpdateAuthorization {
        owner,
        review_identity,
    } = authorization;
    owner.require(OwnerAuthorizationScope::UpdateTrust)?;
    let current = UpdateReview::from_verified_update(update, &bytes, publisher);
    ensure!(
        review_identity == current.identity(),
        "update metadata or package bytes changed after owner authentication"
    );
    update.install(bytes).context("could not install update")
}

#[cfg(test)]
#[path = "update_trust_test.rs"]
mod tests;
