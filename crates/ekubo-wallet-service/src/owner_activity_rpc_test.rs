use super::*;
use crate::dapp_reviews::DappReviews;
use ekubo_wallet_client::activity::{OwnerActivityRecord, OwnerReviewQueues};
use ekubo_wallet_core::{
    config::WalletMetadata,
    core::{execution_plan::ExecutionPlan, policy::WalletPolicy, source::RequestSource},
    message::{MessageEncoding, MessageStore, PendingMessage},
    pending::{PendingStatus, PendingStore, PendingTransaction},
    policy_store::PolicyStore,
};

async fn call<T: serde::de::DeserializeOwned>(
    owner: &OwnerApi,
    request: Request,
) -> anyhow::Result<T> {
    let wire = serde_json::to_vec(&request)?;
    let response = dispatch(
        owner,
        &DappReviews::default(),
        serde_json::from_slice(&wire)?,
    )
    .await?;
    Ok(serde_json::from_value(response)?)
}

async fn register(owner: &OwnerApi, id: &str) -> WalletMetadata {
    let wallet: WalletMetadata = serde_json::from_value(serde_json::json!({
        "instance_id": uuid::Uuid::new_v4(), "id": id,
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
        .install_policy(id, &WalletPolicy::require_approval_for_everything(), None)
        .await
        .unwrap();
    wallet
}

fn plan() -> ExecutionPlan {
    ExecutionPlan::parse(serde_json::json!({
        "schema_version": "1", "chain_id": "1", "caip2_chain_id": "eip155:1",
        "sender": "0x1111111111111111111111111111111111111111",
        "ordered_steps": [{ "step": 1, "kind": "execution", "transaction": {
            "chain_id": "1", "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222", "data": "0x", "value": "1"
        }}]
    }))
    .unwrap()
}

#[tokio::test]
async fn activity_reads_keep_terminal_records_out_of_the_review_queue() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let wallet = register(&owner, "primary").await;
    let mut pending = PendingStore::production(directory.path()).unwrap();
    let transaction = pending
        .create(&wallet.id, "ethereum", &plan(), None, 1)
        .unwrap();
    let mut messages = MessageStore::production(directory.path()).unwrap();
    let message = messages
        .create_for_wallet(
            &wallet,
            Some("1"),
            b"synthetic request",
            MessageEncoding::Text,
            None,
            &RequestSource::Unknown,
        )
        .unwrap();
    let queues: OwnerReviewQueues = call(
        &owner,
        Request::Reviews {
            wallet_id: Some(wallet.id.clone()),
        },
    )
    .await
    .unwrap();
    assert_eq!(queues.transactions, vec![transaction.clone()]);
    assert_eq!(queues.messages, vec![message.clone()]);
    let rejected = messages.reject(message.request_id).unwrap();
    let queues: OwnerReviewQueues = call(&owner, Request::Reviews { wallet_id: None })
        .await
        .unwrap();
    assert!(queues.messages.is_empty());
    assert_eq!(queues.transactions.len(), 1);
    let activity: Vec<OwnerActivityRecord> = call(
        &owner,
        Request::Activity {
            wallet_id: Some(wallet.id),
            limit: 10,
        },
    )
    .await
    .unwrap();
    assert_eq!(activity.len(), 2);
    assert!(
        activity
            .windows(2)
            .all(|pair| (pair[0].created_at(), pair[0].request_id())
                >= (pair[1].created_at(), pair[1].request_id()))
    );
    assert!(
        activity
            .iter()
            .any(|record| matches!(record, OwnerActivityRecord::Message(row) if row == &rejected))
    );
    let fetched: PendingMessage = call(
        &owner,
        Request::Message {
            request_id: message.request_id,
        },
    )
    .await
    .unwrap();
    assert_eq!(fetched, rejected);
    let document: ekubo_wallet_core::approval::ReviewDocument = call(
        &owner,
        Request::MessageReviewDocument {
            request_id: message.request_id,
        },
    )
    .await
    .unwrap();
    assert!(!document.identity.is_empty());
    let other: Vec<OwnerActivityRecord> = call(
        &owner,
        Request::Activity {
            wallet_id: Some("other".into()),
            limit: 10,
        },
    )
    .await
    .unwrap();
    assert!(other.is_empty());
    assert!(
        call::<serde_json::Value>(
            &owner,
            Request::Activity {
                wallet_id: None,
                limit: 0
            }
        )
        .await
        .is_err()
    );
    assert!(
        call::<serde_json::Value>(
            &owner,
            Request::Activity {
                wallet_id: None,
                limit: 1001
            }
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn hidden_activity_remains_addressable_and_presentations_use_stored_records() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let wallet = register(&owner, "primary").await;
    let mut pending = PendingStore::production(directory.path()).unwrap();
    let transaction = pending
        .create(&wallet.id, "ethereum", &plan(), None, 1)
        .unwrap();
    pending.reject(transaction.request_id).unwrap();
    pending.clear_terminal_history(None).unwrap();
    let list: Vec<PendingTransaction> = call(
        &owner,
        Request::Transactions {
            wallet_id: None,
            limit: 10,
        },
    )
    .await
    .unwrap();
    assert!(list.is_empty());
    let record: OwnerActivityRecord = call(
        &owner,
        Request::ActivityRecord {
            request_id: transaction.request_id,
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(record, OwnerActivityRecord::Transaction(row) if row.status == PendingStatus::Rejected)
    );
    let headlines: std::collections::BTreeMap<uuid::Uuid, String> = call(
        &owner,
        Request::TransactionHeadlines {
            request_ids: vec![transaction.request_id],
        },
    )
    .await
    .unwrap();
    // This plain fallback plan has no recognized contract descriptor. The
    // remote read must preserve the absent headline rather than invent one.
    assert!(headlines.is_empty());
    let refreshed: PendingTransaction = call(
        &owner,
        Request::RefreshTransaction {
            request_id: transaction.request_id,
        },
    )
    .await
    .unwrap();
    assert_eq!(refreshed.status, PendingStatus::Rejected);
    let inspection: ekubo_wallet_client::activity::OwnerTransactionInspection = call(
        &owner,
        Request::TransactionInspection {
            request_id: transaction.request_id,
        },
    )
    .await
    .unwrap();
    assert!(!inspection.receipt_loaded);
    assert!(inspection.receipt_error.is_none());
    assert!(!inspection.document.identity.is_empty());
    let saved: std::collections::BTreeMap<uuid::Uuid, String> = call(
        &owner,
        Request::SavedTransactionSummaries {
            request_ids: vec![transaction.request_id],
        },
    )
    .await
    .unwrap();
    assert!(saved.is_empty());
    assert!(
        call::<serde_json::Value>(
            &owner,
            Request::TransactionHeadlines {
                request_ids: vec![uuid::Uuid::new_v4()]
            }
        )
        .await
        .is_err()
    );
    assert!(
        call::<serde_json::Value>(
            &owner,
            Request::SavedTransactionSummaries {
                request_ids: vec![transaction.request_id; 1001]
            }
        )
        .await
        .is_err()
    );
    assert!(
        pending
            .get(transaction.request_id)
            .unwrap()
            .serialized_transaction
            .is_none()
    );
}
