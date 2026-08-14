use super::*;
use std::io::Cursor;

const FIXTURE_PUBLIC_KEY: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
const FIXTURE_SIGNATURE: &str = "untrusted comment: signature from minisign secret key\n\
RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\n\
trusted comment: timestamp:1633700835\tfile:test\tprehashed\n\
wLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJpIidRJnp94ABQkJAgAooBQ==";

fn update(version: &str, url: &str) -> Update {
    Update {
        config: cargo_packager_updater::Config::default(),
        body: None,
        current_version: "1.0.0".into(),
        version: version.into(),
        date: None,
        target: std::env::consts::OS.into(),
        extract_path: "does-not-exist.AppImage".into(),
        download_url: url.parse().unwrap(),
        signature: "artifact-signature".into(),
        timeout: None,
        headers: cargo_packager_updater::http::HeaderMap::default(),
        format: platform_format(),
    }
}

fn platform_format() -> UpdateFormat {
    #[cfg(target_os = "windows")]
    return UpdateFormat::Nsis;
    #[cfg(target_os = "macos")]
    return UpdateFormat::App;
    #[cfg(target_os = "linux")]
    return UpdateFormat::AppImage;
    #[allow(unreachable_code)]
    UpdateFormat::AppImage
}

fn manifest(version: &str, url: &str, signature: &str, digest: &str) -> Vec<u8> {
    let target = cargo_packager_updater::target().expect("a supported test target");
    serde_json::to_vec(&serde_json::json!({
        "version": version,
        "platforms": {
            (target): {
                "url": url,
                "signature": signature,
                "sha256": digest,
                "format": format_name(platform_format())
            }
        }
    }))
    .unwrap()
}

fn installable(bytes: &[u8]) -> InstallableUpdate {
    let url = "https://example.test/wallet-update";
    let digest = hex::encode(Sha256::digest(bytes));
    InstallableUpdate {
        update: update("2.0.0", url),
        artifact_sha256: digest.clone(),
        signed_manifest: manifest("2.0.0", url, "artifact-signature", &digest),
        manifest_signature: "manifest-signature".into(),
    }
}

fn encoded_public_key(key: &minisign::PublicKey) -> String {
    STANDARD.encode(key.to_box().unwrap().to_string())
}

fn encoded_signature(key: &minisign::SecretKey, bytes: &[u8]) -> String {
    let signature = minisign::sign(None, key, Cursor::new(bytes), None, None).unwrap();
    STANDARD.encode(signature.to_string())
}

#[test]
fn updater_uses_only_the_stable_release_manifest_and_no_private_material() {
    assert_eq!(
        UPDATE_MANIFEST_URL,
        "https://github.com/EkuboProtocol/wallet/releases/latest/download/latest.json"
    );
    assert!(!UPDATE_MANIFEST_URL.contains("prerelease"));
    let source = include_str!("update_trust.rs");
    assert!(source.contains("UPDATER_PUBLIC_KEY"));
    assert!(!source.contains("UPDATER_PRIVATE_KEY"));
}

#[test]
fn cargo_packager_signature_envelope_is_verified_before_parsing() {
    let public_key = STANDARD.encode(FIXTURE_PUBLIC_KEY);
    let signature = STANDARD.encode(FIXTURE_SIGNATURE);
    verify_packager_signature(b"test", &signature, &public_key).unwrap();
    assert!(verify_packager_signature(b"Test", &signature, &public_key).is_err());
}

#[test]
fn a_correctly_signed_envelope_accepts_only_its_exact_metadata_and_artifact() {
    let minisign::KeyPair { pk, sk } = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let public_key = encoded_public_key(&pk);
    let artifact = b"new wallet fixture";
    let artifact_signature = encoded_signature(&sk, artifact);
    let digest = hex::encode(Sha256::digest(artifact));
    let url = "https://example.test/wallet-2.0.0";
    let signed_manifest = manifest("2.0.0", url, &artifact_signature, &digest);
    let manifest_signature = encoded_signature(&sk, &signed_manifest);
    let mut authenticated = InstallableUpdate {
        update: Update {
            signature: artifact_signature,
            ..update("2.0.0", url)
        },
        artifact_sha256: digest,
        signed_manifest,
        manifest_signature,
    };

    authenticated
        .verify_signed_payload_with_key(artifact, &public_key)
        .unwrap();
    assert!(
        authenticated
            .verify_signed_payload_with_key(b"old wallet fixture", &public_key)
            .is_err()
    );
    authenticated.update.version = "2.0.1".into();
    assert!(
        authenticated
            .verify_signed_payload_with_key(artifact, &public_key)
            .is_err()
    );
    authenticated.update.version = "2.0.0".into();
    authenticated.signed_manifest[0] ^= 1;
    assert!(
        authenticated
            .verify_signed_payload_with_key(artifact, &public_key)
            .is_err()
    );
}

#[test]
fn package_version_marker_is_unambiguous_and_old_signed_bytes_cannot_claim_a_new_version() {
    let old_binary = b"prefix\0EKUBO-WALLET-PACKAGE-VERSION:1.0.0\0suffix";
    let embedded = embedded_binary_version(old_binary).unwrap();
    assert_eq!(embedded.to_string(), "1.0.0");
    assert!(
        verify_embedded_version_claim(&update("2.0.0", "https://example.test/v2"), &embedded)
            .is_err()
    );

    let ambiguous = b"\0EKUBO-WALLET-PACKAGE-VERSION:1.0.0\0\0EKUBO-WALLET-PACKAGE-VERSION:2.0.0\0";
    assert!(embedded_binary_version(ambiguous).is_err());
}

#[cfg(target_os = "macos")]
fn macos_archive(version: &str) -> Vec<u8> {
    let binary = format!("prefix\0EKUBO-WALLET-PACKAGE-VERSION:{version}\0suffix");
    let mut compressed = Vec::new();
    {
        let encoder =
            flate2::write::GzEncoder::new(&mut compressed, flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(binary.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                "Ekubo Wallet.app/Contents/MacOS/ekubo-wallet",
                Cursor::new(binary.as_bytes()),
            )
            .unwrap();
        archive.into_inner().unwrap().finish().unwrap();
    }
    compressed
}

#[cfg(target_os = "macos")]
fn signed_macos_update(secret_key: &minisign::SecretKey, package: &[u8]) -> InstallableUpdate {
    let url = "https://example.test/wallet-2.0.0.app.tar.gz";
    let artifact_signature = encoded_signature(secret_key, package);
    let digest = hex::encode(Sha256::digest(package));
    let signed_manifest = manifest("2.0.0", url, &artifact_signature, &digest);
    InstallableUpdate {
        update: Update {
            signature: artifact_signature,
            ..update("2.0.0", url)
        },
        artifact_sha256: digest,
        manifest_signature: encoded_signature(secret_key, &signed_manifest),
        signed_manifest,
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_update_archive_extracts_the_version_from_the_packaged_wallet_binary() {
    let compressed = macos_archive("2.0.0");

    assert_eq!(
        embedded_package_version(&compressed, UpdateFormat::App)
            .unwrap()
            .to_string(),
        "2.0.0"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn fully_signed_metadata_cannot_claim_an_old_macos_package_is_new() {
    let minisign::KeyPair { pk, sk } = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let public_key = encoded_public_key(&pk);
    let new_package = macos_archive("2.0.0");
    signed_macos_update(&sk, &new_package)
        .verify_authenticated_payload_with_key(&new_package, &public_key)
        .unwrap();

    let old_package = macos_archive("1.0.0");
    let replay = signed_macos_update(&sk, &old_package);
    assert!(
        replay
            .verify_authenticated_payload_with_key(&old_package, &public_key)
            .is_err()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_updater_replaces_a_disposable_application_bundle() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let app = directory.path().join("Ekubo Wallet.app");
    let binary = app.join("Contents/MacOS/ekubo-wallet");
    std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
    std::fs::write(&binary, b"old\0EKUBO-WALLET-PACKAGE-VERSION:1.0.4\0").unwrap();

    install_macos_application(&app, &macos_archive("2.0.0"))
        .expect("core atomically replaces the disposable bundle");

    let installed = std::fs::read(binary).expect("the replacement binary exists");
    assert!(
        installed
            .windows(b"EKUBO-WALLET-PACKAGE-VERSION:2.0.0".len())
            .any(|bytes| { bytes == b"EKUBO-WALLET-PACKAGE-VERSION:2.0.0" })
    );
}

#[cfg(target_os = "macos")]
#[test]
fn failed_macos_swap_leaves_the_installed_application_untouched() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let app = directory.path().join("Ekubo Wallet.app");
    let binary = app.join("Contents/MacOS/ekubo-wallet");
    std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
    std::fs::write(&binary, b"known-working-wallet").unwrap();

    assert!(swap_macos_paths(&app, &directory.path().join("missing.app")).is_err());
    assert_eq!(std::fs::read(binary).unwrap(), b"known-working-wallet");
}

#[cfg(target_os = "macos")]
#[test]
fn malformed_macos_archive_cannot_move_the_installed_application() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let app = directory.path().join("Ekubo Wallet.app");
    let binary = app.join("Contents/MacOS/ekubo-wallet");
    std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
    std::fs::write(&binary, b"known-working-wallet").unwrap();

    assert!(install_macos_application(&app, b"not a gzip archive").is_err());
    assert_eq!(std::fs::read(binary).unwrap(), b"known-working-wallet");
}

#[test]
fn untrusted_downloads_are_bounded_even_without_a_content_length() {
    assert_eq!(
        read_bounded(Cursor::new(b"1234"), 4, "fixture").unwrap(),
        b"1234"
    );
    assert!(read_bounded(Cursor::new(b"12345"), 4, "fixture").is_err());
}

#[test]
fn signed_metadata_cannot_select_a_different_version_url_signature_format_or_digest() {
    let url = "https://example.test/wallet-2.0.0";
    let digest = "aa".repeat(32);
    let valid_manifest = manifest("2.0.0", url, "artifact-signature", &digest);
    let valid = update("2.0.0", url);
    assert_eq!(
        update_matches_signed_manifest(&valid, &valid_manifest).unwrap(),
        digest
    );

    let cases = [
        update("2.0.1", url),
        update("2.0.0", "https://example.test/old-wallet"),
        Update {
            signature: "different-signature".into(),
            ..valid.clone()
        },
        Update {
            format: match platform_format() {
                UpdateFormat::AppImage => UpdateFormat::App,
                _ => UpdateFormat::AppImage,
            },
            ..valid
        },
    ];
    for changed in cases {
        assert!(update_matches_signed_manifest(&changed, &valid_manifest).is_err());
    }
    assert!(
        manifest_digest(
            &manifest("2.0.0", url, "artifact-signature", "AA"),
            &cargo_packager_updater::target().unwrap()
        )
        .is_err()
    );
}

#[test]
fn update_review_identity_binds_every_displayed_field() {
    let original = UpdateReview {
        version: "2.0.0".into(),
        publisher: UPDATE_PUBLISHER.into(),
        target: "linux-x86_64".into(),
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
    changed = original.clone();
    changed.download_url = "https://example.test/other".into();
    assert_ne!(original.identity(), changed.identity());
}

#[test]
fn install_rejects_wrong_scope_or_artifact_swapped_after_authentication() {
    let original = b"verified package";
    let prepared = PreparedUpdate {
        update: installable(original),
        bytes: original.to_vec(),
    };
    let review_identity = prepared.review().identity();
    let wrong_scope = UpdateAuthorization {
        owner: OwnerAuthorization::for_test(OwnerAuthorizationScope::DappAccess),
        review_identity: review_identity.clone(),
    };
    assert!(install_update(prepared, wrong_scope).is_err());

    let changed = PreparedUpdate {
        update: installable(original),
        bytes: b"modified package".to_vec(),
    };
    let authorization = UpdateAuthorization {
        owner: OwnerAuthorization::for_test(OwnerAuthorizationScope::UpdateTrust),
        review_identity,
    };
    assert!(install_update(changed, authorization).is_err());
}

#[test]
fn install_rejects_an_expired_update_authorization() {
    let bytes = b"verified package";
    let prepared = PreparedUpdate {
        update: installable(bytes),
        bytes: bytes.to_vec(),
    };
    let authorization = UpdateAuthorization {
        owner: OwnerAuthorization::expired_for_test(OwnerAuthorizationScope::UpdateTrust),
        review_identity: prepared.review().identity(),
    };
    assert!(install_update(prepared, authorization).is_err());
}

#[test]
fn install_rejects_metadata_swapped_after_authentication() {
    let bytes = b"verified package";
    let original = PreparedUpdate {
        update: installable(bytes),
        bytes: bytes.to_vec(),
    };
    let authorization = UpdateAuthorization {
        owner: OwnerAuthorization::for_test(OwnerAuthorizationScope::UpdateTrust),
        review_identity: original.review().identity(),
    };
    let mut changed = original;
    changed.update.update.version = "2.0.1".into();
    assert!(install_update(changed, authorization).is_err());
}
