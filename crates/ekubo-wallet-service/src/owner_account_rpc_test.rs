use super::*;
use crate::dapp_reviews::DappReviews;
use ekubo_wallet_client::account::OwnerAccountRemovalReview;
use ekubo_wallet_core::{config::WalletMetadata, policy_store::PolicyStore};

async fn call<T: serde::de::DeserializeOwned>(
    owner: &OwnerApi,
    request: Request,
) -> anyhow::Result<T> {
    let wire = serde_json::to_vec(&request)?;
    let result = dispatch(
        owner,
        &DappReviews::default(),
        serde_json::from_slice(&wire)?,
    )
    .await?;
    Ok(serde_json::from_value(result)?)
}

fn wallet(owner: &OwnerApi) -> WalletMetadata {
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
    PolicyStore::production(owner.config().data_dir())
        .unwrap()
        .register_wallet_without_policy(&wallet)
        .unwrap();
    wallet
}

#[tokio::test]
async fn export_uses_the_direct_encoder_and_cannot_accept_an_authorization_flag() {
    use crate::{dapp_runtime::DappRuntime, owner_rpc::OwnerDispatcher};
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let activity = crate::desktop_sessions::DesktopSessions::default();
    let dapps = Arc::new(DappRuntime::new(
        owner.clone(),
        DappReviews::default(),
        activity,
    ));
    let dispatcher = OwnerDispatcher::new(owner, dapps);
    assert!(
        dispatcher
            .dispatch(Request::BeginPrivateKeyExport {
                wallet_id: "missing".into()
            })
            .await
            .unwrap_err()
            .to_string()
            .contains("direct reply encoder")
    );
    // An absent account fails before native authentication or credential access.
    assert!(
        dispatcher
            .encode(Request::BeginPrivateKeyExport {
                wallet_id: "missing".into()
            })
            .await
            .is_err()
    );
    let accounts = dispatcher.encode(Request::Accounts).await.unwrap();
    assert_eq!(accounts.as_str(), "[]");
    for field in ["authorization", "approved", "key", "lease_id", "owner_uid"] {
        let mut request = serde_json::json!({"method": "begin_private_key_export", "params": {"wallet_id": "missing"}});
        request["params"][field] = serde_json::json!(true);
        assert!(serde_json::from_value::<Request>(request).is_err());
    }
}

#[tokio::test]
async fn imports_cannot_replace_an_account_or_select_policy_and_storage() {
    use ekubo_wallet_client::import_key::ImportKey;
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let wallet = wallet(&owner);
    // Synthetic scalar used only to reach name validation. Neither request
    // reaches the platform credential store.
    let scalar = format!("{:064x}", 1);
    for wallet_id in ["../escape", "primary"] {
        let error = call::<WalletMetadata>(
            &owner,
            Request::ImportAccount {
                wallet_id: wallet_id.into(),
                key: ImportKey::from_hex(scalar.clone()).unwrap(),
            },
        )
        .await
        .unwrap_err();
        assert!(!error.to_string().contains(&scalar));
        assert_eq!(owner.accounts().unwrap(), vec![wallet.clone()]);
    }
    for field in ["policy", "database_path", "owner_uid", "authorization"] {
        let mut request = serde_json::json!({"method": "import_account", "params": {
            "wallet_id": "new", "key": scalar
        }});
        request["params"][field] = serde_json::json!(true);
        assert!(serde_json::from_value::<Request>(request).is_err());
    }
}

#[tokio::test]
async fn removal_checks_the_document_and_account_instance_before_native_authentication() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let wallet = wallet(&owner);
    let review: OwnerAccountRemovalReview = call(
        &owner,
        Request::AccountRemovalDocument {
            wallet_id: wallet.id.clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(review.wallet.instance_id, wallet.instance_id);
    assert!(review.document.request.summary.contains("Delete"));
    let mut wrong_instance = wallet.clone();
    wrong_instance.instance_id = uuid::Uuid::new_v4();
    let mut wrong_address = wallet.clone();
    wrong_address.address = "0x2222222222222222222222222222222222222222"
        .parse()
        .unwrap();
    for (reviewed, reviewed_identity) in [
        (wallet.clone(), "forged document".into()),
        (wrong_instance, review.document.identity.clone()),
        (wrong_address, review.document.identity.clone()),
    ] {
        let error = call::<WalletMetadata>(
            &owner,
            Request::RemoveAccount {
                reviewed,
                reviewed_identity,
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("review its removal again"));
        assert_eq!(owner.account(&wallet.id).unwrap(), wallet);
    }
    // Reusing the address and display name still cannot remove a new instance
    // using the document/metadata from the former account.
    owner
        .config()
        .update_for_test(|config| {
            config.wallets[0].instance_id = uuid::Uuid::new_v4();
            Ok(())
        })
        .unwrap();
    let error = call::<WalletMetadata>(
        &owner,
        Request::RemoveAccount {
            reviewed: wallet,
            reviewed_identity: review.document.identity,
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("review its removal again"));
}

#[tokio::test]
async fn creation_rejects_invalid_or_existing_names_and_cannot_choose_a_policy() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let wallet = wallet(&owner);
    for wallet_id in ["../escape", "", "primary"] {
        assert!(
            call::<WalletMetadata>(
                &owner,
                Request::CreateAccount {
                    wallet_id: wallet_id.into(),
                }
            )
            .await
            .is_err()
        );
        assert_eq!(owner.accounts().unwrap(), vec![wallet.clone()]);
    }
    for field in ["policy", "private_key", "owner_uid", "database_path"] {
        let mut request =
            serde_json::json!({"method": "create_account", "params": {"wallet_id": "new"}});
        request["params"][field] = serde_json::json!(true);
        assert!(serde_json::from_value::<Request>(request).is_err());
    }
}
