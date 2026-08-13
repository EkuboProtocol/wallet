use super::*;

fn update() -> cargo_packager_updater::Update {
    cargo_packager_updater::Update {
        config: cargo_packager_updater::Config::default(),
        body: None,
        current_version: "1.0.0".into(),
        version: "2.0.0".into(),
        date: None,
        target: "linux".into(),
        extract_path: "does-not-exist.AppImage".into(),
        download_url: "https://example.test/wallet.AppImage".parse().unwrap(),
        signature: "signature".into(),
        timeout: None,
        headers: cargo_packager_updater::http::HeaderMap::default(),
        format: cargo_packager_updater::UpdateFormat::AppImage,
    }
}

#[test]
fn update_review_identity_binds_every_displayed_field_and_bytes() {
    let original = UpdateReview {
        version: "2.0.0".into(),
        publisher: "Ekubo, Inc.".into(),
        target: "linux".into(),
        format: "appimage".into(),
        download_url: "https://example.test/v2.AppImage".into(),
        artifact_sha256: "aa".repeat(32),
    };
    let mut changed = original.clone();
    changed.version = "1.0.0".into();
    assert_ne!(original.identity(), changed.identity());
    changed = original.clone();
    changed.artifact_sha256 = "bb".repeat(32);
    assert_ne!(original.identity(), changed.identity());
}

#[test]
fn install_rejects_wrong_scope_and_bytes_changed_after_authentication() {
    let update = update();
    let original = b"verified package";
    let review = UpdateReview::from_verified_update(&update, original, "Ekubo, Inc.");
    let wrong_scope = UpdateAuthorization {
        owner: OwnerAuthorization::for_test(OwnerAuthorizationScope::DappAccess),
        review_identity: review.identity(),
    };
    assert!(install_update(&update, original.to_vec(), "Ekubo, Inc.", wrong_scope).is_err());

    let changed_bytes = UpdateAuthorization {
        owner: OwnerAuthorization::for_test(OwnerAuthorizationScope::UpdateTrust),
        review_identity: review.identity(),
    };
    assert!(
        install_update(
            &update,
            b"modified package".to_vec(),
            "Ekubo, Inc.",
            changed_bytes,
        )
        .is_err()
    );
}
