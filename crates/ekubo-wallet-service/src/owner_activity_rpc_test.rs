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
    plan_with_value("1")
}

fn plan_with_value(value: &str) -> ExecutionPlan {
    ExecutionPlan::parse(serde_json::json!({
        "schema_version": "1", "chain_id": "1", "caip2_chain_id": "eip155:1",
        "sender": "0x1111111111111111111111111111111111111111",
        "ordered_steps": [{ "step": 1, "kind": "execution", "transaction": {
            "chain_id": "1", "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222", "data": "0x", "value": value
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
    let index: Vec<ekubo_wallet_client::activity::OwnerActivityReference> = call(
        &owner,
        Request::ActivityIndex {
            wallet_id: None,
            limit: 10,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        index,
        activity
            .iter()
            .map(OwnerActivityRecord::reference)
            .collect::<Vec<_>>()
    );
    let paged: Vec<OwnerActivityRecord> =
        call(&owner, Request::ActivityRecords { references: index })
            .await
            .unwrap();
    assert_eq!(
        serde_json::to_value(&paged).unwrap(),
        serde_json::to_value(&activity).unwrap()
    );
    for references in [Vec::new(), vec![activity[0].reference(); 1001]] {
        assert!(
            call::<serde_json::Value>(&owner, Request::ActivityRecords { references })
                .await
                .is_err()
        );
    }
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
    assert!(
        call::<PendingTransaction>(
            &owner,
            Request::DiscardUnsentTransaction {
                request_id: transaction.request_id
            }
        )
        .await
        .is_err()
    );
    assert_eq!(
        pending.get(transaction.request_id).unwrap().status,
        PendingStatus::AwaitingApproval
    );
    pending.reject(transaction.request_id).unwrap();
    assert!(
        call::<PendingTransaction>(
            &owner,
            Request::DiscardUnsentTransaction {
                request_id: transaction.request_id
            }
        )
        .await
        .is_err()
    );
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

#[tokio::test]
async fn transaction_actions_cannot_send_or_cancel_an_unapproved_record() {
    use ekubo_wallet_core::legal::LegalDocument;
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let wallet = register(&owner, "primary").await;
    let mut pending = PendingStore::production(directory.path()).unwrap();
    let record = pending
        .create(&wallet.id, "ethereum", &plan(), None, 1)
        .unwrap();
    for accepted in [false, true] {
        if accepted {
            for document in [LegalDocument::TermsOfService, LegalDocument::PrivacyPolicy] {
                let (_, digest) = owner.legal_document(document);
                owner.accept_legal(document, &digest).unwrap();
            }
        }
        for request in [
            Request::RebroadcastTransaction {
                request_id: record.request_id,
            },
            Request::AttemptTransactionCancellation {
                request_id: record.request_id,
            },
        ] {
            let expected = match &request {
                Request::RebroadcastTransaction { .. } => "only one that is signed but unsent",
                Request::AttemptTransactionCancellation { .. } => "nothing to cancel on chain",
                _ => unreachable!(),
            };
            let error = call::<serde_json::Value>(&owner, request)
                .await
                .unwrap_err();
            if accepted {
                assert!(error.to_string().contains(expected), "{error:#}");
            } else {
                assert!(error.to_string().contains("Terms of Service"));
            }
            assert_eq!(pending.get(record.request_id).unwrap(), record);
        }
    }
}

#[tokio::test]
async fn clearing_owner_history_keeps_live_records_and_hides_finished_transactions() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let wallet = register(&owner, "primary").await;
    let mut pending = PendingStore::production(directory.path()).unwrap();
    let live_transaction = pending
        .create(&wallet.id, "ethereum", &plan(), None, 1)
        .unwrap();
    let finished = pending
        .create(&wallet.id, "ethereum", &plan_with_value("2"), None, 1)
        .unwrap();
    let finished = pending.reject(finished.request_id).unwrap();
    let live_message = owner
        .queue_message(
            &wallet.id,
            1,
            b"waiting",
            MessageEncoding::Text,
            "synthetic",
            &RequestSource::Unknown,
        )
        .unwrap();
    let decided_message = owner
        .queue_message(
            &wallet.id,
            1,
            b"decided",
            MessageEncoding::Text,
            "synthetic",
            &RequestSource::Unknown,
        )
        .unwrap();
    owner.reject_message(decided_message.request_id).unwrap();
    let payload = |note: &str| {
        serde_json::json!({
            "types": {
                "EIP712Domain": [{"name":"chainId","type":"uint256"}],
                "Test": [{"name":"note","type":"string"}]
            }, "primaryType": "Test", "domain": {"chainId":1}, "message": {"note":note}
        })
    };
    let live_typed = owner
        .queue_typed_data(
            &wallet.id,
            1,
            &payload("waiting"),
            "synthetic",
            &RequestSource::Unknown,
        )
        .unwrap();
    let decided_typed = owner
        .queue_typed_data(
            &wallet.id,
            1,
            &payload("decided"),
            "synthetic",
            &RequestSource::Unknown,
        )
        .unwrap();
    owner.reject_typed_data(decided_typed.request_id).unwrap();
    assert_eq!(
        call::<usize>(&owner, Request::ClearActivityHistory)
            .await
            .unwrap(),
        3
    );
    let activity: Vec<OwnerActivityRecord> = call(
        &owner,
        Request::Activity {
            wallet_id: None,
            limit: 20,
        },
    )
    .await
    .unwrap();
    let ids: std::collections::BTreeSet<_> = activity
        .iter()
        .map(OwnerActivityRecord::request_id)
        .collect();
    assert_eq!(
        ids,
        [
            live_transaction.request_id,
            live_message.request_id,
            live_typed.request_id
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        owner.transaction(live_transaction.request_id).unwrap(),
        live_transaction
    );
    assert_eq!(
        owner.message(live_message.request_id).unwrap(),
        live_message
    );
    assert_eq!(owner.typed_data(live_typed.request_id).unwrap(), live_typed);
    let hidden = owner.transaction(finished.request_id).unwrap();
    assert_eq!(hidden.status, PendingStatus::Rejected);
    assert_eq!(hidden.execution_plan, finished.execution_plan);
    assert!(owner.message(decided_message.request_id).is_err());
    assert!(owner.typed_data(decided_typed.request_id).is_err());
    assert_eq!(
        call::<usize>(&owner, Request::ClearActivityHistory)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn preview_rpc_reads_saved_text_without_replacing_transaction_state() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let wallet = register(&owner, "primary").await;
    let mut pending = PendingStore::production(directory.path()).unwrap();
    let record = pending
        .create(&wallet.id, "ethereum", &plan(), None, 1)
        .unwrap();
    let saved = pending
        .save_transaction_summary(&record, "Synthetic saved summary")
        .unwrap();
    let result: std::collections::BTreeMap<uuid::Uuid, String> = call(
        &owner,
        Request::TransactionPreviews {
            request_ids: vec![record.request_id],
        },
    )
    .await
    .unwrap();
    assert_eq!(result, [(record.request_id, saved)].into_iter().collect());
    assert_eq!(pending.get(record.request_id).unwrap(), record);
    assert!(
        call::<serde_json::Value>(
            &owner,
            Request::TransactionPreviews {
                request_ids: vec![uuid::Uuid::new_v4()]
            }
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn shared_snapshot_capture_uses_local_async_reads_and_preserves_saved_summaries() {
    let directory = tempfile::tempdir().unwrap();
    let owner = OwnerApi::for_test(directory.path()).unwrap();
    let wallet = register(&owner, "primary").await;
    let mut pending = PendingStore::production(directory.path()).unwrap();
    let record = pending
        .create(&wallet.id, "ethereum", &plan(), None, 1)
        .unwrap();
    let summary = pending
        .save_transaction_summary(&record, "Saved display text")
        .unwrap();
    let snapshot = ekubo_wallet_client::desktop_snapshot::DesktopSnapshot::capture(&owner).await;
    assert_eq!(snapshot.accounts.unwrap(), vec![wallet]);
    assert_eq!(snapshot.reviews.unwrap().transactions, vec![record.clone()]);
    assert_eq!(snapshot.activity.unwrap().len(), 1);
    assert_eq!(
        snapshot.transaction_previews.get(&record.request_id),
        Some(&summary)
    );
    assert!(
        !snapshot
            .transaction_headlines
            .contains_key(&record.request_id)
    );
    assert_eq!(pending.get(record.request_id).unwrap(), record);
}
