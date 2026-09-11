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

#[tokio::test]
async fn ending_the_desktop_period_closes_an_agent_waiting_for_its_first_handshake() {
    use tokio::io::AsyncReadExt as _;
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let runtime = ServiceRuntime::new(ApplicationAuthority::open(owner.config().clone()).unwrap());
    assert!(runtime.agent_connection().is_err());
    let desktop = runtime.reserve_desktop().unwrap().activate();
    let agent = runtime.agent_connection().unwrap();
    let (mut client, stream) = tokio::io::duplex(1024);
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let task = tokio::spawn(agent.serve(stream, active.clone()));
    tokio::task::yield_now().await;
    drop(desktop);
    tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 0);
}
