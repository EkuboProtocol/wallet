use crate::events::{DomainEvent, DomainEventKind, TransactionStage};
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;

#[cfg(target_os = "macos")]
const MACOS_BUNDLE_IDENTIFIER: &str = "org.ekubo.wallet";

/// Select the wallet as the notification sender before notify-rust performs
/// its macOS fallback lookup. That fallback asks `AppleScript` to find an app
/// literally named `use_default`, which opens an application picker when the
/// wallet is run directly through Cargo rather than from an installed bundle.
pub fn initialize_platform_notifications() {
    #[cfg(target_os = "macos")]
    {
        // An unbundled development binary has no Launch Services registration,
        // so this may fail. Calling it still consumes notify-rust's one-time
        // sender initialization and prevents its interactive fallback lookup.
        let _ = notify_rust::set_application(MACOS_BUNDLE_IDENTIFIER);
    }
}

/// Where a click on the notification should land.
///
/// The request UUID stays here because this is addressing, not prose: it is
/// how the window finds the row again. It is never shown to the reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationRoute {
    Review(Uuid),
    Activity(Uuid),
}

/// Deliberately has no action-button field. Approval and rejection are only
/// available in the complete native review window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletNotification {
    pub title: String,
    pub body: String,
    pub route: NotificationRoute,
}

/// The two facts a person can act on when a banner appears: whose money moved
/// and on which chain. Read from the lifecycle row the event points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionContext {
    pub account: String,
    pub network: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NotificationPreferences;

/// Compose the banner for one lifecycle change.
///
/// The body used to be `Transaction <uuid> was confirmed.` — a sentence whose
/// only concrete noun was an identifier the reader has never seen and cannot
/// use. It now names the account and the network instead, and says what the
/// state means where that is not obvious from the headline.
#[must_use]
pub fn notification_for(
    event: &DomainEvent,
    context: &TransactionContext,
    _preferences: NotificationPreferences,
) -> Option<WalletNotification> {
    let DomainEventKind::Transaction { request_id, stage } = &event.kind else {
        return None;
    };
    let where_from = format!("{} on {}", context.account, context.network);
    let (title, body, review) = match stage {
        TransactionStage::Proposed => (
            "Approval needed",
            format!("{where_from}. Nothing is signed or sent until you decide."),
            true,
        ),
        TransactionStage::Signed => (
            "Transaction signed",
            format!("{where_from}. It has not reached the network yet."),
            false,
        ),
        TransactionStage::Broadcast => (
            "Transaction sent",
            format!("{where_from}. Waiting for it to be mined."),
            false,
        ),
        TransactionStage::Confirmed => ("Transaction succeeded", format!("{where_from}."), false),
        TransactionStage::Reverted => (
            "Transaction failed on chain",
            format!("{where_from}. Nothing moved except the network fee."),
            false,
        ),
        TransactionStage::Replaced => (
            "Transaction superseded",
            format!("{where_from}. Another transaction from this account used the same nonce."),
            false,
        ),
        TransactionStage::Cancelled => (
            "Transaction cancelled",
            format!("{where_from}. Your replacement was mined first."),
            false,
        ),
    };
    Some(WalletNotification {
        title: title.to_owned(),
        body,
        route: if review {
            NotificationRoute::Review(*request_id)
        } else {
            NotificationRoute::Activity(*request_id)
        },
    })
}

pub trait NotificationService: Send + Sync {
    fn show(&self, notification: WalletNotification);
}

#[derive(Clone)]
pub struct PlatformNotificationService {
    clicked: UnboundedSender<NotificationRoute>,
}

impl PlatformNotificationService {
    #[must_use]
    pub fn new(clicked: UnboundedSender<NotificationRoute>) -> Self {
        Self { clicked }
    }
}

impl NotificationService for PlatformNotificationService {
    fn show(&self, notification: WalletNotification) {
        let clicked = self.clicked.clone();
        std::thread::spawn(move || {
            let handle = notify_rust::Notification::new()
                .appname("Ekubo Wallet")
                .summary(&notification.title)
                .body(&notification.body)
                .show();
            if let Ok(handle) = handle {
                handle.wait_for_action(move |action| {
                    if action == "default" {
                        let _ = clicked.send(notification.route);
                    }
                });
            }
        });
    }
}

#[cfg(test)]
#[path = "notifications_test.rs"]
mod tests;
