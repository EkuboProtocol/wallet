use super::*;
use chrono::Utc;

#[cfg(target_os = "macos")]
#[test]
fn macos_notifications_name_the_packaged_wallet_instead_of_the_fallback_placeholder() {
    assert_eq!(MACOS_BUNDLE_IDENTIFIER, "org.ekubo.wallet");
    assert_ne!(MACOS_BUNDLE_IDENTIFIER, "use_default");
}

#[test]
fn every_transaction_lifecycle_stage_has_a_detailed_notification() {
    for (stage, expected_verb) in [
        (TransactionStage::Proposed, "needs your attention"),
        (TransactionStage::Signed, "was signed"),
        (TransactionStage::Broadcast, "was broadcast"),
        (TransactionStage::Confirmed, "was confirmed"),
        (TransactionStage::Reverted, "was reverted"),
        (TransactionStage::Replaced, "was replaced"),
        (TransactionStage::Cancelled, "was cancelled"),
    ] {
        let event = DomainEvent {
            occurred_at: Utc::now(),
            kind: DomainEventKind::Transaction {
                request_id: Uuid::new_v4(),
                stage,
            },
        };
        let notification = notification_for(&event, NotificationPreferences).unwrap();
        assert_eq!(
            notification.body,
            format!("Transaction {} {expected_verb}.", request_id(&event))
        );
    }
}

#[test]
fn proposed_transactions_route_to_review_and_lifecycle_updates_route_to_activity() {
    let request_id = Uuid::new_v4();
    for (stage, expected_route) in [
        (
            TransactionStage::Proposed,
            NotificationRoute::Review(request_id),
        ),
        (
            TransactionStage::Signed,
            NotificationRoute::Activity(request_id),
        ),
        (
            TransactionStage::Broadcast,
            NotificationRoute::Activity(request_id),
        ),
        (
            TransactionStage::Confirmed,
            NotificationRoute::Activity(request_id),
        ),
        (
            TransactionStage::Reverted,
            NotificationRoute::Activity(request_id),
        ),
        (
            TransactionStage::Replaced,
            NotificationRoute::Activity(request_id),
        ),
        (
            TransactionStage::Cancelled,
            NotificationRoute::Activity(request_id),
        ),
    ] {
        let event = DomainEvent {
            occurred_at: Utc::now(),
            kind: DomainEventKind::Transaction { request_id, stage },
        };
        let notification = notification_for(&event, NotificationPreferences).unwrap();
        assert_eq!(notification.route, expected_route);
    }
}

fn request_id(event: &DomainEvent) -> Uuid {
    match &event.kind {
        DomainEventKind::Transaction { request_id, .. } => *request_id,
        _ => unreachable!(),
    }
}
