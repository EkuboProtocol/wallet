use super::*;
use ekubo_wallet_client::{desktop_snapshot::DesktopSnapshot, import_key::ImportKey};
use ekubo_wallet_core::{
    core::source::RequestSource, message::MessageEncoding, policy_store::PolicyStore,
};

fn fixture() -> (tempfile::TempDir, OwnerApi, WalletMetadata) {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    // Public account metadata only; no native credential exists for this fixture.
    let wallet: WalletMetadata = serde_json::from_value(serde_json::json!({
        "instance_id": uuid::Uuid::new_v4(), "id": "primary",
        "address": "0x1111111111111111111111111111111111111111",
        "created_at": chrono::Utc::now(), "source": "created"
    }))
    .unwrap();
    owner
        .config()
        .update_for_test(|config| {
            config.wallets.push(wallet.clone());
            Ok(())
        })
        .unwrap();
    let mut store = PolicyStore::production(directory.path()).unwrap();
    store.register_wallet_without_policy(&wallet).unwrap();
    store
        .install_policy_for_instance(
            &wallet.id,
            wallet.instance_id,
            wallet.address,
            &WalletPolicy::require_approval_for_everything(),
            None,
            None,
        )
        .unwrap();
    (directory, owner, wallet)
}

#[tokio::test]
async fn snapshot_adapter_preserves_stored_records_and_review_content() {
    let (_directory, local, wallet) = fixture();
    let message = local
        .queue_message(
            &wallet.id,
            1,
            b"review this exact text",
            MessageEncoding::Text,
            "test",
            &RequestSource::Unknown,
        )
        .unwrap();
    let before = DesktopSnapshot::capture(&local).await;
    let owner = DesktopOwner::from(local);
    let after = DesktopSnapshot::capture(&owner).await;
    assert_eq!(after.accounts.unwrap(), before.accounts.unwrap());
    assert_eq!(after.networks.unwrap(), before.networks.unwrap());
    assert_eq!(
        serde_json::to_value(after.reviews.unwrap()).unwrap(),
        serde_json::to_value(before.reviews.unwrap()).unwrap()
    );
    assert_eq!(
        serde_json::to_value(after.activity.unwrap().as_ref()).unwrap(),
        serde_json::to_value(before.activity.unwrap().as_ref()).unwrap()
    );
    assert_eq!(
        after.message_documents[&message.request_id]
            .as_ref()
            .unwrap()
            .identity,
        before.message_documents[&message.request_id]
            .as_ref()
            .unwrap()
            .identity
    );
    assert_eq!(
        owner
            .message(message.request_id)
            .await
            .unwrap()
            .message_bytes()
            .unwrap(),
        b"review this exact text"
    );
}

#[tokio::test]
async fn async_settings_reach_the_existing_store_and_publish_its_events() {
    let (_directory, local, _wallet) = fixture();
    let mut events = local.event_bus().subscribe();
    let owner = DesktopOwner::from(local.clone());
    owner
        .set_appearance_preference(AppearancePreference::Dark)
        .await
        .unwrap();
    owner.set_testnet_mode(true).await.unwrap();
    let setup = GuidedSetupState {
        completed: ["future-compatible-task".into()].into(),
    };
    owner.set_guided_setup(&setup).await.unwrap();
    assert_eq!(
        local.appearance_preference().unwrap(),
        AppearancePreference::Dark
    );
    assert!(local.testnet_mode().unwrap());
    assert_eq!(local.guided_setup().unwrap(), setup);
    assert_eq!(owner.guided_setup().await.unwrap(), setup);
    for _ in 0..2 {
        assert!(matches!(
            events.try_recv().unwrap().kind,
            crate::events::DomainEventKind::ConfigurationChanged
        ));
    }
}

#[tokio::test]
async fn stale_removal_and_invalid_import_fail_before_native_custody() {
    let (_directory, local, wallet) = fixture();
    let owner = DesktopOwner::from(local.clone());
    let mut review = owner.account_removal_document(&wallet.id).await.unwrap();
    review.document.identity = "stale review".into();
    assert!(
        owner
            .remove_account(&review)
            .await
            .unwrap_err()
            .to_string()
            .contains("review its removal again")
    );
    let scalar = format!("{:064x}", 1);
    for id in ["../escape", wallet.id.as_str()] {
        let error = owner
            .import_account(id, ImportKey::from_hex(scalar.clone()).unwrap())
            .await
            .unwrap_err();
        assert!(!error.to_string().contains(&scalar));
    }
    assert_eq!(local.accounts().unwrap(), vec![wallet]);
}
