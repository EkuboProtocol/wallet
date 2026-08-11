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

/// A `connect` session opens a websocket to a relay operated by someone else,
/// which is an outbound connection no other command makes. The policy has to
/// name it, say what the operator can see, and say what it cannot.
#[test]
fn privacy_policy_discloses_the_walletconnect_relay() {
    let policy = privacy_policy();
    assert!(policy.contains("## 5. The WalletConnect relay"));
    assert!(policy.contains("wss://relay.walletconnect.org"));
    assert!(policy.contains("end-to-end encrypted"));
    assert!(policy.contains("the size and timing of every message"));
    // Section 2's "nothing else leaves this machine" claim has to account for
    // it, or the disclosure contradicts the section that promises exhaustion.
    assert!(policy.contains(
        "the WalletConnect relay described in section 5, and the release\ncheck described in \
section 6, this software makes no network requests."
    ));
}

/// The release check reaches a host that is neither a configured RPC endpoint,
/// nor a producer named by a reference, nor a relay — the three the policy
/// used to enumerate as exhaustive. It has to name the endpoint, say what
/// triggers a request, say nothing of the owner's is sent, and say it can be
/// turned off.
#[test]
fn privacy_policy_discloses_the_release_check() {
    let policy = privacy_policy();
    assert!(policy.contains("## 6. The release check"));
    assert!(
        policy.contains(
            "https://api.github.com/repos/EkuboProtocol/wallet-mcp-server/releases/latest"
        )
    );
    assert!(policy.contains("EKUBO_WALLET_SKIP_UPDATE_CHECK=1"));
    // What triggers it, because "when you run a command" is the difference
    // between this and the background telemetry section 1 promises is absent.
    assert!(policy.contains("Automatic checks follow the updater"));
    assert!(policy.contains("An update is never installed silently."));
    assert!(policy.contains("requires your explicit\nconfirmation"));
    // Section 4's exhaustive claim has to account for it too, not just
    // section 2's.
    assert!(policy.contains(
        "Apart from the WalletConnect relay in section 5 and the release check\nin section 6,"
    ));
}

#[test]
fn terms_disclaim_agent_signing_losses() {
    assert!(TERMS_OF_SERVICE.contains("NOT RESPONSIBLE OR LIABLE FOR ANY LOSSES"));
    assert!(TERMS_OF_SERVICE.contains("USING AN AGENT"));
}

/// A dapp is a second way a signature request reaches this wallet, and the
/// relay carrying it is a third party the developer does not run. The
/// disclaimer covers agents by name, so it has to cover these by name too.
#[test]
fn terms_disclaim_dapp_directed_signing_and_the_relay() {
    assert!(TERMS_OF_SERVICE.contains("CONNECTED OVER WALLETCONNECT"));
    assert!(TERMS_OF_SERVICE.contains("ANY RELAY\nOPERATOR"));
    assert!(TERMS_OF_SERVICE.contains("IMPERSONATED DAPP"));
    // Section 1 says the developer runs no servers; the relay it now names is
    // somebody else's, and saying so is what keeps that claim true.
    assert!(TERMS_OF_SERVICE.contains("wss://relay.walletconnect.org"));
    assert!(TERMS_OF_SERVICE.contains("under the control of the developer"));
}

/// Key loss is the one unrecoverable failure this wallet has, and nothing in
/// the software prevents it: there is no seed, no escrow, and no second copy
/// anywhere. A user who learns that only after losing a machine learned it too
/// late, so the terms have to say it before anything signs.
#[test]
fn terms_disclaim_key_backup_and_recovery() {
    assert!(TERMS_OF_SERVICE.contains("THE FUNDS CONTROLLED BY THAT KEY ARE PERMANENTLY LOST"));
    assert!(TERMS_OF_SERVICE.contains("no recovery phrase, no seed"));
    // The data directory is deliberately not key-bearing, which also means a
    // backup of it is not a backup of a key. Somebody who copies it and
    // believes otherwise is the exact person this section exists for.
    assert!(
        TERMS_OF_SERVICE.contains("Copying\nthe wallet's data directory does not copy any key")
    );
    // Saying a copy is the user's job is only fair if the terms also say how
    // to get one, and `account export` is the supported route.
    assert!(TERMS_OF_SERVICE.contains("Export Private Key"));
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
    // directly, as a build shipping older document text would have. It is a
    // real digest of some other text rather than a placeholder string: the
    // column holds 32 bytes, so there is no way to write anything else.
    let superseded = B256::repeat_byte(0xAA);
    store
        .database
        .connection
        .execute(
            "INSERT INTO legal_acceptance(document, digest, accepted_at)
                 VALUES ('terms_of_service', ?1, ?2)",
            rusqlite::params![crate::sql::Blob(superseded), crate::sql::Millis(Utc::now())],
        )
        .unwrap();
    let status = store.status().unwrap();
    assert!(!status.terms_of_service.accepted);
    assert_eq!(
        status.terms_of_service.superseded_digest,
        Some(format!("{superseded:#x}"))
    );
    assert!(status.terms_of_service.accepted_at.is_none());
}
