use super::*;

fn agent_authorization() -> OwnerAuthorization {
    OwnerAuthorization::for_test(OwnerAuthorizationScope::AgentAccess)
}

#[test]
fn tokens_are_individual_rotatable_and_revocable() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = DesktopStore::open(
        &directory.path().join("wallet.db"),
        &DatabaseKey::new([31; 32]),
    )
    .unwrap();
    let first = store
        .register_client("Codex", AgentKind::Codex, None, &agent_authorization())
        .unwrap();
    let old = first.token.expose_base64url();
    assert_eq!(
        store.authenticate(&old).unwrap().unwrap().id,
        first.client.id
    );

    let replacement = store
        .rotate_client_token(first.client.id, &agent_authorization())
        .unwrap();
    assert!(store.authenticate(&old).unwrap().is_none());
    assert!(
        store
            .authenticate(&replacement.expose_base64url())
            .unwrap()
            .is_some()
    );

    store
        .revoke_client(first.client.id, &agent_authorization())
        .unwrap();
    assert!(
        store
            .authenticate(&replacement.expose_base64url())
            .unwrap()
            .is_none()
    );
}

#[test]
fn malformed_and_noncanonical_tokens_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = DesktopStore::open(
        &directory.path().join("wallet.db"),
        &DatabaseKey::new([32; 32]),
    )
    .unwrap();
    store
        .register_client("Agent", AgentKind::Other, None, &agent_authorization())
        .unwrap();
    assert!(store.authenticate("not a token").unwrap().is_none());
    assert!(store.authenticate(&"A".repeat(43)).unwrap().is_none());
}

#[test]
fn an_active_token_can_be_recovered_only_for_repair() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = DesktopStore::open(
        &directory.path().join("wallet.db"),
        &DatabaseKey::new([33; 32]),
    )
    .unwrap();
    let registered = store
        .register_client("Codex", AgentKind::Codex, None, &agent_authorization())
        .unwrap();
    let expected = registered.token.expose_base64url();
    assert_eq!(
        store
            .repair_client_token(registered.client.id, &agent_authorization())
            .unwrap()
            .expose_base64url(),
        expected
    );
    store
        .revoke_client(registered.client.id, &agent_authorization())
        .unwrap();
    assert!(
        store
            .repair_client_token(registered.client.id, &agent_authorization())
            .is_err()
    );
}

#[test]
fn protected_desktop_settings_reject_the_wrong_authorization_scope() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = DesktopStore::open(
        &directory.path().join("wallet.db"),
        &DatabaseKey::new([34; 32]),
    )
    .unwrap();
    let wrong_scope = OwnerAuthorization::for_test(OwnerAuthorizationScope::NetworkSettings);
    assert!(
        store
            .set_detailed_notification_previews(true, &wrong_scope)
            .is_err()
    );
    assert!(!store.detailed_notification_previews().unwrap());
    assert!(
        store
            .register_client("Codex", AgentKind::Codex, None, &wrong_scope)
            .is_err()
    );
    assert!(store.clients().unwrap().is_empty());
}
