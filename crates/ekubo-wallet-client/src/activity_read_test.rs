use super::*;
use crate::activity::OwnerActivityRecord;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone)]
struct Transport {
    replies: Arc<Mutex<VecDeque<Option<Value>>>>,
    sent: Arc<Mutex<Vec<Value>>>,
}

impl crate::owner_connection::sealed::Sealed for Transport {}
impl OwnerTransport for Transport {
    async fn exchange(&self, request: &str) -> Result<Zeroizing<String>> {
        // Exercise the reader across actual suspension between batches.
        tokio::task::yield_now().await;
        self.sent
            .lock()
            .unwrap()
            .push(serde_json::from_str(request)?);
        let response = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .flatten()
            .ok_or_else(|| anyhow::anyhow!("connection lost"))?;
        Ok(Zeroizing::new(serde_json::to_string(&response)?))
    }
    async fn hold(&self, _ready: tokio::sync::oneshot::Sender<()>) -> Result<()> {
        std::future::pending().await
    }
    fn close(&self) -> impl std::future::Future<Output = Result<()>> + Send {
        std::future::ready(Ok(()))
    }
}

fn client(replies: Vec<Option<Value>>) -> (OwnerConnection<Transport>, Transport) {
    let transport = Transport {
        replies: Arc::new(Mutex::new(replies.into())),
        sent: Arc::default(),
    };
    (
        OwnerConnection::from_transport(transport.clone()),
        transport,
    )
}

fn record(id: Uuid) -> OwnerActivityRecord {
    serde_json::from_value(json!({"Message": {
        "request_id": id,
        "wallet_instance_id": Uuid::nil(),
        "wallet_id": "test",
        "wallet_address": "0x1111111111111111111111111111111111111111",
        "message_hex": "0x01",
        "encoding": "text",
        "digest": "synthetic digest",
        "status": "awaiting_approval",
        "created_at": "2026-09-10T00:00:00Z",
        "updated_at": "2026-09-10T00:00:00Z"
    }}))
    .unwrap()
}

#[tokio::test]
async fn activity_batches_preserve_the_index_order_and_request_only_the_remaining_records() {
    let rows = (0..3).map(|_| record(Uuid::new_v4())).collect::<Vec<_>>();
    let index = rows
        .iter()
        .map(OwnerActivityRecord::reference)
        .collect::<Vec<_>>();
    let (client, transport) = client(vec![
        Some(json!(index)),
        Some(json!(&rows[..1])),
        Some(json!(&rows[1..])),
    ]);
    let fetched = client.activity(Some("test"), 3).await.unwrap();
    assert_eq!(json!(fetched), json!(rows));
    let sent = transport.sent.lock().unwrap();
    assert_eq!(sent.len(), 3);
    assert_eq!(
        sent[0],
        json!({"method":"activity_index", "params":{"wallet_id":"test", "limit":3}})
    );
    assert_eq!(sent[1]["params"]["references"], json!(index));
    assert_eq!(sent[2]["params"]["references"], json!(&index[1..]));
}

#[tokio::test]
async fn mismatched_and_excess_batches_fail_without_returning_partial_activity() {
    let row = record(Uuid::new_v4());
    let wrong = record(Uuid::new_v4());
    for batch in [json!([wrong]), json!([row.clone(), row.clone()])] {
        let (client, transport) = client(vec![Some(json!([row.reference()])), Some(batch)]);
        assert!(client.activity(None, 1).await.is_err());
        assert_eq!(transport.sent.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn duplicate_or_excess_index_entries_are_rejected_before_hydration() {
    let first = record(Uuid::new_v4()).reference();
    let second = record(Uuid::new_v4()).reference();
    for (index, limit) in [(vec![first, first], 2), (vec![first, second], 1)] {
        let (client, transport) = client(vec![Some(json!(index))]);
        assert!(client.activity(None, limit).await.is_err());
        assert_eq!(transport.sent.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn a_disconnect_during_hydration_does_not_replay_or_return_a_partial_list() {
    let first = record(Uuid::new_v4());
    let second = record(Uuid::new_v4());
    let (client, transport) = client(vec![
        Some(json!([first.reference(), second.reference()])),
        Some(json!([first])),
        None,
    ]);
    assert!(client.activity(None, 2).await.is_err());
    assert_eq!(transport.sent.lock().unwrap().len(), 3);
}

fn preview_page(id: Uuid, offset: usize, total: usize, text: &str) -> Value {
    json!({"transfer_id":id, "offset":offset, "total_bytes":total, "text":text})
}

fn record_pages(value: &impl serde::Serialize) -> Vec<Option<Value>> {
    let text = serde_json::to_string(value).unwrap();
    let id = Uuid::new_v4();
    let mut pages = Vec::new();
    let mut offset = 0;
    while offset < text.len() {
        let mut end = (offset + crate::preview_page::PAGE_BYTES).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        pages.push(Some(preview_page(
            id,
            offset,
            text.len(),
            &text[offset..end],
        )));
        offset = end;
    }
    pages
}

#[tokio::test]
async fn reviews_hydrate_only_exact_ordered_index_entries() {
    use crate::activity::OwnerReviewRecord;
    let rows = (0..70)
        .map(|_| OwnerReviewRecord::Activity(Box::new(record(Uuid::new_v4()))))
        .collect::<Vec<_>>();
    let index = rows
        .iter()
        .map(OwnerReviewRecord::reference)
        .collect::<Vec<_>>();
    let mut replies = record_pages(&index);
    replies.extend([Some(json!(&rows[..64])), Some(json!(&rows[64..]))]);
    let (client, transport) = client(replies);
    let queues = client.reviews(None).await.unwrap();
    assert_eq!(json!(queues.into_records()), json!(rows));
    let sent = transport.sent.lock().unwrap();
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[1]["params"]["references"], json!(&index[..64]));
    assert_eq!(sent[2]["params"]["references"], json!(&index[64..]));
}

#[tokio::test]
async fn oversized_activity_record_is_read_completely_after_an_empty_batch() {
    let mut row = json!(record(Uuid::new_v4()));
    row["Message"]["message_hex"] = json!("ab".repeat(crate::framing::MAX_FRAME_BYTES / 2));
    let row: OwnerActivityRecord = serde_json::from_value(row).unwrap();
    let mut replies = vec![Some(json!([row.reference()])), Some(json!([]))];
    replies.extend(record_pages(&row));
    let (client, transport) = client(replies);
    assert_eq!(json!(client.activity(None, 1).await.unwrap()), json!([row]));
    let sent = transport.sent.lock().unwrap();
    assert_eq!(sent[2]["method"], "activity_record");
    assert!(
        sent[3..]
            .iter()
            .all(|request| request["method"] == "read_page")
    );
}

#[tokio::test]
async fn record_pages_reject_generation_offset_and_length_changes() {
    let id = Uuid::new_v4();
    for bad in [
        preview_page(Uuid::new_v4(), 1, 2, "]"),
        preview_page(id, 0, 2, "]"),
        preview_page(id, 1, 3, "]"),
        preview_page(id, 1, 2, ""),
        preview_page(id, 1, 2, "]extra"),
    ] {
        let (client, transport) = client(vec![Some(preview_page(id, 0, 2, "[")), Some(bad)]);
        assert!(client.reviews(None).await.is_err());
        assert_eq!(transport.sent.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn large_completed_mutation_reply_is_fetched_without_replaying_the_write() {
    let id = Uuid::new_v4();
    let (client, transport) = client(vec![
        Some(json!({"owner_record_transfer": preview_page(id, 0, 2, "4")})),
        Some(preview_page(id, 1, 2, "2")),
    ]);
    assert_eq!(client.clear_activity_history().await.unwrap(), 42);
    let sent = transport.sent.lock().unwrap();
    assert_eq!(sent[0]["method"], "clear_activity_history");
    assert_eq!(sent[1]["method"], "read_page");
    assert_eq!(sent.len(), 2);
}

#[tokio::test]
async fn reviews_reject_duplicate_and_substituted_records() {
    use crate::activity::OwnerReviewRecord;
    let row = OwnerReviewRecord::Activity(Box::new(record(Uuid::new_v4())));
    let other = OwnerReviewRecord::Activity(Box::new(record(Uuid::new_v4())));
    let (duplicate, transport) = client(record_pages(&vec![row.reference(), row.reference()]));
    assert!(duplicate.reviews(None).await.is_err());
    assert_eq!(transport.sent.lock().unwrap().len(), 1);
    let mut replies = record_pages(&vec![row.reference()]);
    replies.push(Some(json!([other])));
    let (substitution, transport) = client(replies);
    assert!(substitution.reviews(None).await.is_err());
    assert_eq!(transport.sent.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn preview_pages_reconstruct_exact_inputs_without_replaying_generation() {
    let id = Uuid::new_v4();
    let (client, transport) = client(vec![
        Some(preview_page(id, 0, 2, "[")),
        Some(preview_page(id, 1, 2, "]")),
    ]);
    assert!(
        client
            .transaction_preview_inputs(&[])
            .await
            .unwrap()
            .is_empty()
    );
    let sent = transport.sent.lock().unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0]["method"], "transaction_preview_inputs");
    assert_eq!(
        sent[1],
        json!({"method":"transaction_preview_page",
        "params":{"transfer_id":id,"offset":1}})
    );
}

#[tokio::test]
async fn preview_pages_reject_mixed_truncated_and_oversized_snapshots() {
    let id = Uuid::new_v4();
    for bad in [
        preview_page(Uuid::new_v4(), 1, 2, "]"),
        preview_page(id, 0, 2, "]"),
        preview_page(id, 1, 3, "]"),
        preview_page(id, 1, 2, ""),
        preview_page(id, 1, 2, "]extra"),
    ] {
        let (client, transport) = client(vec![Some(preview_page(id, 0, 2, "[")), Some(bad)]);
        assert!(client.transaction_preview_inputs(&[]).await.is_err());
        assert_eq!(transport.sent.lock().unwrap().len(), 2);
    }
    let (oversized, _) = client(vec![Some(preview_page(
        id,
        0,
        crate::preview_page::MAX_EVIDENCE_BYTES + 1,
        "[",
    ))]);
    assert!(oversized.transaction_preview_inputs(&[]).await.is_err());
    let (lost, transport) = client(vec![Some(preview_page(id, 0, 2, "[")), None]);
    assert!(lost.transaction_preview_inputs(&[]).await.is_err());
    assert_eq!(transport.sent.lock().unwrap().len(), 2);
}
