use super::*;
use crate::dapp_reviews::DappReviews;
use ekubo_wallet_core::{
    config::WalletMetadata,
    core::{policy::WalletPolicy, source::RequestSource},
    message::{MessageEncoding, MessageStatus, MessageStore, PendingMessage},
    policy_store::PolicyStore,
    typed_data::{PendingTypedData, TypedDataStatus, TypedDataStore, parse_typed_data},
};

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

async fn wallet(owner: &OwnerApi) -> WalletMetadata {
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
    owner
        .install_policy(
            &wallet.id,
            &WalletPolicy::require_approval_for_everything(),
            None,
        )
        .await
        .unwrap();
    wallet
}

#[tokio::test]
async fn message_decisions_require_the_stored_digest_and_core_signing_prerequisites() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let wallet = wallet(&owner).await;
    let mut store = MessageStore::production(directory.path()).unwrap();
    let request = store
        .create_for_wallet(
            &wallet,
            Some("1"),
            b"synthetic message",
            MessageEncoding::Text,
            None,
            &RequestSource::Unknown,
        )
        .unwrap();
    let stale = call::<PendingMessage>(
        &owner,
        Request::SignMessage {
            request_id: request.request_id,
            reviewed_digest: "not what was reviewed".into(),
        },
    )
    .await
    .unwrap_err();
    assert!(stale.to_string().contains("changed during review"));
    // Correct digest is still not a signing grant. Leave legal acceptance
    // unset so the production core fails before native authentication or keys.
    let prerequisites = call::<PendingMessage>(
        &owner,
        Request::SignMessage {
            request_id: request.request_id,
            reviewed_digest: request.digest.clone(),
        },
    )
    .await
    .unwrap_err();
    assert!(prerequisites.to_string().contains("Terms of Service"));
    assert_eq!(store.get(request.request_id).unwrap(), request);
    let rejected: PendingMessage = call(
        &owner,
        Request::RejectMessage {
            request_id: request.request_id,
        },
    )
    .await
    .unwrap();
    assert_eq!(rejected.status, MessageStatus::Rejected);
    assert!(rejected.signature.is_none());
    assert!(
        call::<PendingMessage>(
            &owner,
            Request::RejectMessage {
                request_id: request.request_id
            }
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn typed_data_decisions_preserve_exact_payload_and_cannot_bypass_core() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let wallet = wallet(&owner).await;
    let payload = serde_json::json!({
        "types": {
            "EIP712Domain": [{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],
            "Test": [{"name":"note","type":"string"}]
        },
        "primaryType": "Test", "domain": {"name":"Synthetic test","chainId":1},
        "message": {"note":"exact reviewed text"}
    });
    let (_, chain_id, digest) = parse_typed_data(&payload).unwrap();
    let mut store = TypedDataStore::production(directory.path()).unwrap();
    let request = store
        .create_for_wallet(
            &wallet,
            chain_id,
            &payload,
            digest,
            None,
            &RequestSource::Unknown,
        )
        .unwrap();
    let stale = call::<PendingTypedData>(
        &owner,
        Request::SignTypedData {
            request_id: request.request_id,
            reviewed_digest: "different digest".into(),
        },
    )
    .await
    .unwrap_err();
    assert!(stale.to_string().contains("changed during review"));
    let prerequisites = call::<PendingTypedData>(
        &owner,
        Request::SignTypedData {
            request_id: request.request_id,
            reviewed_digest: request.digest.clone(),
        },
    )
    .await
    .unwrap_err();
    assert!(prerequisites.to_string().contains("Terms of Service"));
    assert_eq!(store.get(request.request_id).unwrap(), request);
    let rejected: PendingTypedData = call(
        &owner,
        Request::RejectTypedData {
            request_id: request.request_id,
        },
    )
    .await
    .unwrap();
    assert_eq!(rejected.status, TypedDataStatus::Rejected);
    assert_eq!(rejected.typed_data, payload);
    assert!(rejected.signature.is_none());
    assert!(
        call::<PendingTypedData>(
            &owner,
            Request::RejectTypedData {
                request_id: request.request_id
            }
        )
        .await
        .is_err()
    );
}
