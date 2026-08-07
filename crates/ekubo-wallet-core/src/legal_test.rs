//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

#[test]
fn documents_have_stable_nonempty_digests() {
    for document in [
        LegalDocument::TermsOfService,
        LegalDocument::PrivacyPolicy,
        LegalDocument::ThirdPartyLicenses,
    ] {
        assert!(!document.text().is_empty());
        assert_eq!(document.digest(), document.digest());
        assert!(document.digest().starts_with("0x"));
    }
}

#[test]
fn privacy_policy_discloses_every_default_endpoint() {
    let policy = privacy_policy();
    for network in crate::config::default_networks() {
        for url in network.rpc_urls.iter().map(url::Url::as_str) {
            assert!(
                policy.contains(url),
                "privacy policy does not disclose default endpoint {url}"
            );
        }
    }
    assert!(policy.contains("Apart from these RPC endpoints"));
}

/// The only outbound requests that are not a configured RPC are the
/// reference fetches in `crate::plan_fetch`, so the policy has to name
/// them, say the wallet performs the fetch, and say what the host learns.
#[test]
fn privacy_policy_discloses_reference_fetches() {
    let policy = privacy_policy();
    assert!(policy.contains("## 4. Execution plans fetched by reference"));
    assert!(policy.contains("this process fetches the body from that URL\nitself"));
    assert!(policy.contains("observe your IP address, the time of the fetch"));
    assert!(policy.contains("data:application/json"));
}

#[test]
fn terms_disclaim_agent_signing_losses() {
    assert!(TERMS_OF_SERVICE.contains("NOT RESPONSIBLE OR LIABLE FOR ANY LOSSES"));
    assert!(TERMS_OF_SERVICE.contains("USING AN AGENT"));
}

fn store() -> (tempfile::TempDir, LegalStore) {
    let directory = tempfile::tempdir().unwrap();
    let database = PolicyStore::open(
        &directory.path().join("policies.db"),
        &crate::policy_store::DatabaseKey::new([7; 32]),
    )
    .unwrap();
    (directory, LegalStore::new(database))
}

#[test]
fn signing_requires_both_current_documents() {
    let (_directory, store) = store();
    assert!(!store.status().unwrap().signing_allowed);
    assert!(require_status_allows_use(&store.status().unwrap()).is_err());

    store
        .record_acceptance(
            LegalDocument::TermsOfService,
            &LegalDocument::TermsOfService.digest(),
        )
        .unwrap();
    assert!(!store.status().unwrap().signing_allowed);
    assert!(require_status_allows_use(&store.status().unwrap()).is_err());

    store
        .record_acceptance(
            LegalDocument::PrivacyPolicy,
            &LegalDocument::PrivacyPolicy.digest(),
        )
        .unwrap();
    let status = store.status().unwrap();
    assert!(status.signing_allowed);
    assert!(status.terms_of_service.accepted_at.is_some());
    require_status_allows_use(&status).unwrap();
}

#[test]
fn stale_digests_cannot_be_recorded_and_stale_acceptance_is_superseded() {
    let (_directory, store) = store();
    assert!(
        store
            .record_acceptance(LegalDocument::TermsOfService, "0xdeadbeef")
            .is_err()
    );
    assert!(
        store
            .record_acceptance(
                LegalDocument::ThirdPartyLicenses,
                &LegalDocument::ThirdPartyLicenses.digest(),
            )
            .is_err()
    );

    // Simulate acceptance of a previous revision by writing the row
    // directly, as a build shipping older document text would have.
    store
        .database
        .connection
        .execute(
            "INSERT INTO legal_acceptance(document, digest, accepted_at)
                 VALUES ('terms_of_service', '0xoutdated', ?1)",
            [Utc::now().to_rfc3339()],
        )
        .unwrap();
    let status = store.status().unwrap();
    assert!(!status.terms_of_service.accepted);
    assert_eq!(
        status.terms_of_service.superseded_digest.as_deref(),
        Some("0xoutdated")
    );
    assert!(status.terms_of_service.accepted_at.is_none());
}
