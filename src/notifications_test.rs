use super::*;
use chrono::Utc;

#[cfg(target_os = "macos")]
#[test]
fn macos_notifications_name_the_packaged_wallet_instead_of_the_fallback_placeholder() {
    assert_eq!(MACOS_BUNDLE_IDENTIFIER, "org.ekubo.wallet");
    assert_ne!(MACOS_BUNDLE_IDENTIFIER, "use_default");
}

fn context() -> TransactionContext {
    TransactionContext {
        account: "trading".into(),
        network: "Ethereum".into(),
    }
}

fn transaction_event(stage: TransactionStage, request_id: Uuid) -> DomainEvent {
    DomainEvent {
        occurred_at: Utc::now(),
        kind: DomainEventKind::Transaction { request_id, stage },
    }
}

const EVERY_STAGE: [TransactionStage; 7] = [
    TransactionStage::Proposed,
    TransactionStage::Signed,
    TransactionStage::Broadcast,
    TransactionStage::Confirmed,
    TransactionStage::Reverted,
    TransactionStage::Replaced,
    TransactionStage::Cancelled,
];

fn detailed() -> NotificationPreferences {
    NotificationPreferences {
        detailed_previews: true,
    }
}

#[test]
fn every_transaction_lifecycle_stage_says_what_happened_and_where() {
    for (stage, expected_title) in [
        (TransactionStage::Proposed, "Approval needed"),
        (TransactionStage::Signed, "Transaction signed"),
        (TransactionStage::Broadcast, "Transaction sent"),
        (TransactionStage::Confirmed, "Transaction succeeded"),
        (TransactionStage::Reverted, "Transaction failed on chain"),
        (TransactionStage::Replaced, "Transaction superseded"),
        (TransactionStage::Cancelled, "Transaction cancelled"),
    ] {
        let event = transaction_event(stage, Uuid::new_v4());
        let notification = notification_for(&event, &context(), detailed()).unwrap();

        assert_eq!(notification.title, expected_title);
        assert!(
            notification.body.starts_with("trading on Ethereum."),
            "{} does not name the account and network",
            notification.body
        );
    }
}

#[test]
fn banner_text_never_shows_the_request_identifier() {
    // A UUID is how the window finds the row again; it is not something a
    // person can read, remember, or act on. It used to be the only concrete
    // noun in the sentence.
    let request_id = Uuid::new_v4();
    for stage in EVERY_STAGE {
        let event = transaction_event(stage, request_id);
        let notification = notification_for(&event, &context(), detailed()).unwrap();
        let text = format!("{} {}", notification.title, notification.body);

        assert!(
            !text.contains(&request_id.to_string()),
            "{text} leaks the request identifier"
        );
        assert!(
            !text.contains(&request_id.simple().to_string()),
            "{text} leaks the request identifier"
        );
        assert!(!text.contains("0x"), "{text} shows raw chain data");
    }
}

#[test]
fn proposed_transactions_route_to_review_and_lifecycle_updates_route_to_activity() {
    let request_id = Uuid::new_v4();
    for stage in EVERY_STAGE {
        let expected = if stage == TransactionStage::Proposed {
            NotificationRoute::Review(request_id)
        } else {
            NotificationRoute::Activity(request_id)
        };
        let event = transaction_event(stage, request_id);
        let notification = notification_for(&event, &context(), detailed()).unwrap();

        assert_eq!(notification.route, expected);
    }
}

#[test]
fn only_transaction_events_raise_a_banner() {
    let event = DomainEvent {
        occurred_at: Utc::now(),
        kind: DomainEventKind::ConfigurationChanged,
    };

    assert_eq!(notification_for(&event, &context(), detailed()), None);
}

#[test]
fn private_previews_hide_account_and_network_names() {
    let event = transaction_event(TransactionStage::Proposed, Uuid::new_v4());
    let notification = notification_for(
        &event,
        &context(),
        NotificationPreferences {
            detailed_previews: false,
        },
    )
    .unwrap();

    assert_eq!(
        notification.body,
        "Open Ekubo Wallet for details. Nothing is signed or sent until you decide."
    );
    assert!(!notification.body.contains("trading"));
    assert!(!notification.body.contains("Ethereum"));
}

#[test]
fn only_the_platform_default_action_opens_a_notification_route() {
    assert!(notification_action_opens("default"));
    assert!(!notification_action_opens("Open"));
    assert!(!notification_action_opens("__closed"));
}
