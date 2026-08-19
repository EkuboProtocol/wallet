use super::*;
use chrono::Utc;

#[cfg(target_os = "macos")]
#[test]
fn macos_notifications_name_the_packaged_wallet_instead_of_the_fallback_placeholder() {
    assert_eq!(MACOS_BUNDLE_IDENTIFIER, "org.ekubo.wallet");
    assert_ne!(MACOS_BUNDLE_IDENTIFIER, "use_default");
}

fn context() -> NotificationContext {
    NotificationContext::Wallet(WalletContext {
        account: "trading".into(),
        network: Some("Ethereum".into()),
    })
}

fn signature_event(kind: SignatureKind, stage: SignatureStage, request_id: Uuid) -> DomainEvent {
    DomainEvent {
        occurred_at: Utc::now(),
        kind: DomainEventKind::Signature {
            request_id,
            kind,
            stage,
        },
    }
}

const EVERY_SIGNATURE: [(SignatureKind, SignatureStage); 6] = [
    (SignatureKind::Message, SignatureStage::Queued),
    (SignatureKind::Message, SignatureStage::Signed),
    (SignatureKind::Message, SignatureStage::Rejected),
    (SignatureKind::TypedData, SignatureStage::Queued),
    (SignatureKind::TypedData, SignatureStage::Signed),
    (SignatureKind::TypedData, SignatureStage::Rejected),
];

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
            NotificationRoute::Review {
                subject: NotificationSubject::Transaction,
                request_id,
            }
        } else {
            NotificationRoute::Activity {
                subject: NotificationSubject::Transaction,
                request_id,
            }
        };
        let event = transaction_event(stage, request_id);
        let notification = notification_for(&event, &context(), detailed()).unwrap();

        assert_eq!(notification.route, expected);
    }
}

#[test]
fn background_bookkeeping_raises_no_banner() {
    // Only the events a person is being asked about, or told the outcome of,
    // reach a banner. A configuration write is neither.
    for kind in [
        DomainEventKind::ConfigurationChanged,
        DomainEventKind::McpStatusChanged { online: true },
        DomainEventKind::ReviewChanged {
            request_id: Uuid::new_v4(),
        },
        DomainEventKind::WalletConnectChanged {
            session_id: "session".into(),
        },
    ] {
        let event = DomainEvent {
            occurred_at: Utc::now(),
            kind,
        };

        assert_eq!(notification_for(&event, &context(), detailed()), None);
    }
}

#[test]
fn every_signature_request_says_what_happened_and_where() {
    // A queued signature used to raise nothing at all: the only event it
    // published was `ReviewChanged`, which says a queue moved and nothing
    // about which one or why.
    for ((kind, stage), expected_title) in EVERY_SIGNATURE.into_iter().zip([
        "Message signature needed",
        "Message signed",
        "Message signature declined",
        "Typed-data signature needed",
        "Typed data signed",
        "Typed-data signature declined",
    ]) {
        let event = signature_event(kind, stage, Uuid::new_v4());
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
fn a_waiting_signature_routes_to_its_own_review_and_a_decided_one_to_activity() {
    // The subject travels with the id because the id alone does not say which
    // store holds it. Routing every banner into the transaction review is how
    // a message notification could only ever open an empty screen.
    let request_id = Uuid::new_v4();
    for (kind, stage) in EVERY_SIGNATURE {
        let subject = match kind {
            SignatureKind::Message => NotificationSubject::Message,
            SignatureKind::TypedData => NotificationSubject::TypedData,
        };
        let expected = if stage == SignatureStage::Queued {
            NotificationRoute::Review {
                subject,
                request_id,
            }
        } else {
            NotificationRoute::Activity {
                subject,
                request_id,
            }
        };
        let event = signature_event(kind, stage, request_id);
        let notification = notification_for(&event, &context(), detailed()).unwrap();

        assert_eq!(notification.route, expected);
    }
}

#[test]
fn a_chainless_message_names_the_account_alone_rather_than_inventing_a_network() {
    // An EIP-191 message binds no chain. "trading on no network" would be a
    // fact the request never stated.
    let event = signature_event(
        SignatureKind::Message,
        SignatureStage::Queued,
        Uuid::new_v4(),
    );
    let context = NotificationContext::Wallet(WalletContext {
        account: "trading".into(),
        network: None,
    });
    let notification = notification_for(&event, &context, detailed()).unwrap();

    assert_eq!(
        notification.body,
        "trading. Nothing is signed until you decide."
    );
}

#[test]
fn signature_banner_text_never_shows_the_request_identifier() {
    let request_id = Uuid::new_v4();
    for (kind, stage) in EVERY_SIGNATURE {
        let event = signature_event(kind, stage, request_id);
        let notification = notification_for(&event, &context(), detailed()).unwrap();
        let text = format!("{} {}", notification.title, notification.body);

        assert!(
            !text.contains(&request_id.to_string()),
            "{text} leaks the request identifier"
        );
        assert!(!text.contains("0x"), "{text} shows raw chain data");
    }
}

fn pairing_event() -> DomainEvent {
    DomainEvent {
        occurred_at: Utc::now(),
        kind: DomainEventKind::WalletConnectProposed {
            session_id: "session".into(),
            dapp: "Ekubo (app.ekubo.org)".into(),
        },
    }
}

#[test]
fn a_pairing_proposal_names_the_dapp_and_routes_to_the_connection_screen() {
    // A proposal has no account and no chain yet — nothing has been approved —
    // so the dapp is the only fact there is to judge, and it rides on the
    // event rather than being looked up.
    let notification = notification_for(&pairing_event(), &NotificationContext::Dapp, detailed())
        .expect("a pairing proposal is a decision and deserves a banner");

    assert_eq!(notification.title, "Connection request");
    assert_eq!(
        notification.body,
        "Ekubo (app.ekubo.org) wants to connect. Nothing is approved until you decide."
    );
    assert_eq!(notification.route, NotificationRoute::WalletConnect);
}

#[test]
fn private_previews_hide_the_dapp_name_too() {
    let notification = notification_for(
        &pairing_event(),
        &NotificationContext::Dapp,
        NotificationPreferences {
            detailed_previews: false,
        },
    )
    .unwrap();

    assert!(!notification.body.contains("ekubo"));
    assert_eq!(
        notification.body,
        "Open Ekubo Wallet for details. Nothing is approved until you decide."
    );
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

/// A policy binds no single chain, so the context a proposal is described
/// against never names a network.
fn policy_context() -> NotificationContext {
    NotificationContext::Wallet(WalletContext {
        account: "trading".into(),
        network: None,
    })
}

fn policy_event(wallet_id: &str) -> DomainEvent {
    DomainEvent {
        occurred_at: Utc::now(),
        kind: DomainEventKind::PolicyProposed {
            wallet_id: wallet_id.to_owned(),
        },
    }
}

#[test]
fn a_proposed_policy_change_asks_the_owner_and_routes_to_its_own_account() {
    // The wallet asking for more authority than it has is a decision, and it
    // used to be the only decision that arrived in silence: the event fell
    // through to `_ => None` and the owner found the proposal by opening the
    // screen and looking.
    let notification = notification_for(&policy_event("trading"), &policy_context(), detailed())
        .expect("a decision the owner has to make raises a banner");

    assert_eq!(notification.title, "Policy change proposed");
    assert_eq!(
        notification.body,
        "trading. Nothing changes until you approve it."
    );
    assert_eq!(
        notification.route,
        NotificationRoute::PolicyProposal {
            wallet_id: "trading".into()
        },
        "the banner has to open the account whose policy is being rewritten"
    );
}

#[test]
fn a_policy_banner_carries_no_agent_authored_text() {
    // `PolicyProposal::rationale` is the agent's own case for the change and
    // is documented as untrusted display data. A banner is drawn by the
    // operating system, outside every surface this wallet sanitizes text for,
    // so the rationale must not reach one — an agent that could write there
    // would be arguing to the owner with the diff nowhere in sight.
    //
    // The event carries no rationale at all, which is what makes that
    // structural rather than a rule someone has to remember. This pins it:
    // the banner is composed from the wallet id and fixed prose.
    let notification =
        notification_for(&policy_event("trading"), &policy_context(), detailed()).unwrap();
    let DomainEventKind::PolicyProposed { wallet_id } = &policy_event("trading").kind else {
        panic!("the proposal event names only the wallet");
    };
    assert_eq!(wallet_id, "trading");
    assert!(
        notification.body.starts_with("trading. "),
        "{}",
        notification.body
    );
}

#[test]
fn a_private_policy_preview_still_says_a_decision_is_waiting() {
    let notification = notification_for(
        &policy_event("trading"),
        &policy_context(),
        NotificationPreferences {
            detailed_previews: false,
        },
    )
    .unwrap();

    assert_eq!(
        notification.body,
        "Open Ekubo Wallet for details. Nothing changes until you approve it."
    );
    assert!(!notification.body.contains("trading"));
    // Turning previews down hides which account, never that something is
    // waiting: the owner still has to know to come and look.
    assert_eq!(notification.title, "Policy change proposed");
}

#[test]
fn only_the_platform_default_action_opens_a_notification_route() {
    assert!(notification_action_opens("default"));
    assert!(!notification_action_opens("Open"));
    assert!(!notification_action_opens("__closed"));
}
