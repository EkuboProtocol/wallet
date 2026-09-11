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
    async fn hold(&self) -> Result<()> {
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
async fn empty_mismatched_and_excess_batches_fail_without_returning_partial_activity() {
    let row = record(Uuid::new_v4());
    let wrong = record(Uuid::new_v4());
    for batch in [json!([]), json!([wrong]), json!([row.clone(), row.clone()])] {
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
