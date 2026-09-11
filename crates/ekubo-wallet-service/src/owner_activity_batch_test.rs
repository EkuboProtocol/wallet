use super::*;
use ekubo_wallet_core::typed_data::PendingTypedData;
use uuid::Uuid;

fn record(id: Uuid, bytes: usize) -> OwnerActivityRecord {
    let record: PendingTypedData = serde_json::from_value(serde_json::json!({
        "request_id": id,
        "wallet_instance_id": Uuid::nil(),
        "wallet_id": "test",
        "wallet_address": "0x1111111111111111111111111111111111111111",
        "chain_id": "1",
        "typed_data": {
            "types": {
                "EIP712Domain": [{"name": "chainId", "type": "uint256"}],
                "Large": [{"name": "payload", "type": "string"}]
            },
            "primaryType": "Large",
            "domain": {"chainId": 1},
            "message": {"payload": "x".repeat(bytes)}
        },
        "digest": "synthetic digest",
        "status": "awaiting_approval",
        "created_at": "2026-09-10T00:00:00Z",
        "updated_at": "2026-09-10T00:00:00Z"
    }))
    .unwrap();
    OwnerActivityRecord::TypedData(record)
}

#[test]
fn a_large_activity_inventory_is_split_without_omitting_or_reordering_records() {
    let records = (0..90)
        .map(|_| record(Uuid::new_v4(), 240_000))
        .collect::<Vec<_>>();
    assert!(serde_json::to_vec(&records).unwrap().len() > crate::framing::MAX_FRAME_BYTES);
    let mut next = 0;
    let mut batches = 0;
    while next < records.len() {
        let batch = bounded_batch(records[next..].iter().cloned().map(Ok)).unwrap();
        let encoded = serde_json::to_vec(&batch).unwrap();
        assert!(encoded.len() <= crate::framing::MAX_FRAME_BYTES);
        let decoded: Vec<OwnerActivityRecord> = serde_json::from_slice(&encoded).unwrap();
        assert!(!decoded.is_empty());
        assert_eq!(
            batch,
            serde_json::to_value(&records[next..next + decoded.len()]).unwrap()
        );
        next += decoded.len();
        batches += 1;
    }
    assert_eq!(next, records.len());
    assert!(batches > 1);
}

#[test]
fn an_individually_oversized_record_or_read_failure_is_not_silently_skipped() {
    let oversized = record(Uuid::new_v4(), crate::framing::MAX_FRAME_BYTES);
    assert!(bounded_batch(std::iter::once(Ok(oversized))).is_err());
    assert!(
        bounded_batch(
            [
                Ok(record(Uuid::new_v4(), 1)),
                Err(anyhow::anyhow!("missing row"))
            ]
            .into_iter()
        )
        .is_err()
    );
}
