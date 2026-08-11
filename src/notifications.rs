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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NotificationPreferences {
    pub detailed_previews: bool,
}

#[must_use]
pub fn notification_for(
    event: &DomainEvent,
    preferences: NotificationPreferences,
) -> Option<WalletNotification> {
    let DomainEventKind::Transaction { request_id, stage } = &event.kind else {
        return None;
    };
    let (verb, review) = match stage {
        TransactionStage::Proposed => ("needs review", true),
        TransactionStage::Signed => ("was signed", false),
        TransactionStage::Broadcast => ("was broadcast", false),
        TransactionStage::Confirmed => ("was confirmed", false),
        TransactionStage::Reverted => ("reverted", false),
        TransactionStage::Replaced => ("was replaced", false),
        TransactionStage::Cancelled => ("was cancelled", false),
    };
    Some(WalletNotification {
        title: "Ekubo Wallet".into(),
        body: if preferences.detailed_previews {
            format!("Transaction {request_id} {verb}.")
        } else {
            "Wallet activity changed. Open Ekubo Wallet for details.".into()
        },
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
