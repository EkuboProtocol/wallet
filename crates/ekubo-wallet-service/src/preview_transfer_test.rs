use super::*;

#[tokio::test]
async fn evidence_larger_than_an_ipc_frame_round_trips_without_truncation() {
    let transfers = PreviewTransfers::default();
    // Non-ASCII text exercises UTF-8 boundaries; quotes exercise outer JSON escaping.
    let source = "€\"".repeat(5 * 1024 * 1024);
    assert!(source.len() > ekubo_wallet_client::framing::MAX_FRAME_BYTES);
    let mut page = transfers.begin(source.clone()).unwrap();
    let id = page.transfer_id;
    let mut collected = String::new();
    loop {
        assert!(
            serde_json::to_vec(&page).unwrap().len()
                < ekubo_wallet_client::framing::MAX_FRAME_BYTES
        );
        assert_eq!(page.offset, collected.len());
        assert_eq!(page.total_bytes, source.len());
        assert_eq!(page.transfer_id, id);
        collected.push_str(&page.text);
        if collected.len() == page.total_bytes {
            break;
        }
        page = transfers.read(id, collected.len()).unwrap();
    }
    assert_eq!(collected, source);
    assert!(transfers.read(id, 0).is_err());
    assert!(transfers.0.lock().unwrap().snapshots.is_empty());
}

#[tokio::test]
async fn invalid_offsets_expiration_and_shutdown_cannot_return_another_snapshot() {
    let transfers = PreviewTransfers::default();
    let first = transfers.begin("€".repeat(PAGE_BYTES)).unwrap();
    assert!(transfers.read(Uuid::new_v4(), 0).is_err());
    assert!(transfers.read(first.transfer_id, 1).is_err());
    assert!(transfers.read(first.transfer_id, usize::MAX).is_err());
    transfers
        .0
        .lock()
        .unwrap()
        .snapshots
        .get_mut(&first.transfer_id)
        .unwrap()
        .expires = Instant::now();
    assert!(transfers.read(first.transfer_id, 0).is_err());
    assert!(transfers.0.lock().unwrap().snapshots.is_empty());
    let next = transfers.begin("a".repeat(PAGE_BYTES + 1)).unwrap();
    transfers.clear();
    assert!(transfers.read(next.transfer_id, 0).is_err());
}

#[tokio::test]
async fn abandoned_transfers_have_bounded_admission() {
    let transfers = PreviewTransfers::default();
    for _ in 0..MAX_TRANSFERS {
        transfers.begin("x".repeat(PAGE_BYTES + 1)).unwrap();
    }
    assert!(transfers.begin("x".repeat(PAGE_BYTES + 1)).is_err());
    // Small one-frame responses consume no retained snapshot slots.
    assert!(transfers.begin("[]".into()).is_ok());
    transfers.clear();
    assert!(transfers.begin("x".repeat(PAGE_BYTES + 1)).is_err());
    assert!(transfers.begin("[]".into()).is_err());
}
