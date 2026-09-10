use super::*;

#[test]
fn broadcast_display_does_not_transport_observation_authority() {
    let display = BroadcastDisplay::from(ekubo_wallet_core::execution::BroadcastResult {
        transaction_hash: "synthetic hash".into(),
        receipt_status: ekubo_wallet_core::execution::ReceiptStatus::Pending,
        block_number: None,
        mined_fee: None,
        broadcast_error: Some("synthetic failure".into()),
        absence_established: true,
    });
    let mut wire = serde_json::to_value(&display).unwrap();
    assert!(wire.get("absence_established").is_none());
    let received: BroadcastDisplay = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(received.receipt_status, ReceiptDisplayStatus::Pending);
    assert_eq!(received.broadcast_error, display.broadcast_error);
    wire["absence_established"] = true.into();
    assert!(serde_json::from_value::<BroadcastDisplay>(wire).is_err());
}
