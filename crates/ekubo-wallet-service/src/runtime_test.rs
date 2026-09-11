use super::*;
use crate::{authority::OwnerApi, legal::LegalDocument};

#[tokio::test]
async fn runtime_desktop_leases_gate_dapp_admission_until_the_last_disconnect() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    for document in [LegalDocument::TermsOfService, LegalDocument::PrivacyPolicy] {
        let (_, digest) = owner.legal_document(document);
        owner.accept_legal(document, &digest).unwrap();
    }
    let authority = ApplicationAuthority::open(owner.config().clone()).unwrap();
    let runtime = ServiceRuntime::new(authority);
    let no_desktop = || {
        assert_eq!(
            runtime
                .dapps
                .begin("not-a-pairing")
                .unwrap_err()
                .to_string(),
            "no desktop session is active"
        );
    };
    no_desktop();
    let reservation = runtime.reserve_desktop().unwrap();
    no_desktop();
    let first = reservation.activate();
    let second = runtime.reserve_desktop().unwrap().activate();
    drop(first);
    // Activity reaches the real dapp runtime, which now proceeds to the next
    // prerequisite. There are no accounts, so no relay/network worker starts.
    assert_eq!(
        runtime
            .dapps
            .begin("not-a-pairing")
            .unwrap_err()
            .to_string(),
        "create an account before connecting a dapp"
    );
    drop(second);
    no_desktop();
    runtime.close_owner_reviews().unwrap();
    runtime.shutdown_dapps().await.unwrap();
}
