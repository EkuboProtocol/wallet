use super::*;
use chrono::Utc;

#[cfg(target_os = "macos")]
#[test]
fn macos_notifications_name_the_packaged_wallet_instead_of_the_fallback_placeholder() {
    assert_eq!(MACOS_BUNDLE_IDENTIFIER, "org.ekubo.wallet");
    assert_ne!(MACOS_BUNDLE_IDENTIFIER, "use_default");
}

#[test]
fn every_transaction_lifecycle_stage_has_a_lock_screen_safe_notification() {
    for stage in [
        TransactionStage::Proposed,
        TransactionStage::Signed,
        TransactionStage::Broadcast,
        TransactionStage::Confirmed,
        TransactionStage::Reverted,
        TransactionStage::Replaced,
        TransactionStage::Cancelled,
    ] {
        let event = DomainEvent {
            occurred_at: Utc::now(),
            kind: DomainEventKind::Transaction {
                request_id: Uuid::new_v4(),
                stage,
            },
        };
        let notification = notification_for(&event, NotificationPreferences::default()).unwrap();
        assert!(!notification.body.contains(&request_id(&event).to_string()));
    }
}

fn request_id(event: &DomainEvent) -> Uuid {
    match &event.kind {
        DomainEventKind::Transaction { request_id, .. } => *request_id,
        _ => unreachable!(),
    }
}
