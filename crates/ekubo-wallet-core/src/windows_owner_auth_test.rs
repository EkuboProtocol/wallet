use super::*;

#[tokio::test]
async fn missing_proof_never_falls_back_to_service_or_desktop_consent() {
    // Calls the actual production adapter, not authorize_owner's test hook.
    for request in [
        PresenceRequest::ChangeProtectedSettings {
            scope: crate::human_presence::OwnerAuthorizationScope::ActivityHistory,
        },
        PresenceRequest::ChangeProtectedSettings {
            scope: crate::human_presence::OwnerAuthorizationScope::AcceptTerms,
        },
        PresenceRequest::ExportPrivateKey {
            wallet: "primary".into(),
        },
        PresenceRequest::SignTransaction {
            wallet: "primary".into(),
        },
    ] {
        assert!(matches!(
            confirm(&request).await,
            Err(HumanPresenceError::Unavailable(_))
        ));
    }
}
