use crate::events::{
    DomainEvent, DomainEventKind, SignatureKind, SignatureStage, TransactionStage,
};
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

/// Which queue a routed request lives in.
///
/// A request id alone does not say which store holds it, and the three stores
/// open three different review documents. A banner that could only ever mean
/// "transaction" is how message signatures ended up routing into the
/// transaction review and finding nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationSubject {
    Transaction,
    Message,
    TypedData,
}

/// Where a click on the notification should land.
///
/// The request UUID stays here because this is addressing, not prose: it is
/// how the window finds the row again. It is never shown to the reader. The
/// same is true of the wallet id a policy proposal carries, which is how the
/// Policies screen knows whose tab to open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotificationRoute {
    /// Something is waiting on the owner: open its review.
    Review {
        subject: NotificationSubject,
        request_id: Uuid,
    },
    /// Something already resolved: open its row in the decided list.
    Activity {
        subject: NotificationSubject,
        request_id: Uuid,
    },
    /// A dapp is waiting to pair. The proposal is presented as a modal the
    /// moment it arrives, so this only has to raise the window and land on the
    /// screen the connection belongs to.
    WalletConnect,
    /// An agent's policy proposal is waiting. Addressed by wallet rather than
    /// by request id: a proposal is the account's pending one, not a row in a
    /// queue, and the Policies screen shows one account at a time.
    PolicyProposal { wallet_id: String },
}

/// Deliberately has no action-button field. Approval and rejection are only
/// available in the complete native review window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletNotification {
    pub title: String,
    pub body: String,
    pub route: NotificationRoute,
}

/// The facts a person can act on when a banner appears.
///
/// Transactions and signature requests name an account and a chain, both read
/// from the row the event points at. A pairing proposal has neither yet — no
/// account has been chosen and no chain approved — and the only thing it can
/// name is the dapp, which the event already carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotificationContext {
    Wallet(WalletContext),
    Dapp,
}

/// Whose money moved and on which chain.
///
/// `network` is optional because an EIP-191 message binds no chain at all: a
/// login proof is valid wherever the address is. Naming a network there would
/// mean inventing one, so the clause simply stops after the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletContext {
    pub account: String,
    pub network: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotificationPreferences {
    pub detailed_previews: bool,
}

/// Compose the banner for one lifecycle change.
///
/// The body used to be `Transaction <uuid> was confirmed.` — a sentence whose
/// only concrete noun was an identifier the reader has never seen and cannot
/// use. It now names the account and the network instead, and says what the
/// state means where that is not obvious from the headline.
#[must_use]
pub fn notification_for(
    event: &DomainEvent,
    context: &NotificationContext,
    preferences: NotificationPreferences,
) -> Option<WalletNotification> {
    match &event.kind {
        DomainEventKind::Transaction { request_id, stage } => Some(transaction_notification(
            *request_id,
            *stage,
            context,
            preferences,
        )),
        DomainEventKind::Signature {
            request_id,
            kind,
            stage,
        } => Some(signature_notification(
            *request_id,
            *kind,
            *stage,
            context,
            preferences,
        )),
        DomainEventKind::WalletConnectProposed { dapp, .. } => {
            Some(pairing_notification(dapp, preferences))
        }
        DomainEventKind::PolicyProposed { wallet_id } => Some(policy_proposal_notification(
            wallet_id,
            context,
            preferences,
        )),
        _ => None,
    }
}

/// The account-and-network clause every wallet banner opens with, or the
/// stand-in that names nothing when previews are turned down.
///
/// A private preview still has to be a sentence, so callers append their own
/// second clause to whichever of the two comes back.
fn where_from(context: &NotificationContext, preferences: NotificationPreferences) -> String {
    match context {
        NotificationContext::Wallet(wallet) if preferences.detailed_previews => {
            match &wallet.network {
                Some(network) => format!("{} on {network}", wallet.account),
                None => wallet.account.clone(),
            }
        }
        _ => "Open Ekubo Wallet for details".to_owned(),
    }
}

fn transaction_notification(
    request_id: Uuid,
    stage: TransactionStage,
    context: &NotificationContext,
    preferences: NotificationPreferences,
) -> WalletNotification {
    let where_from = where_from(context, preferences);
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
    WalletNotification {
        title: title.to_owned(),
        body,
        route: route_for(NotificationSubject::Transaction, request_id, review),
    }
}

/// A signature request has no on-chain half, so its banners say what the
/// signature itself did rather than where it got to. The two kinds are named
/// apart because reviewing them asks for different things: a message is read,
/// typed data is checked field by field.
fn signature_notification(
    request_id: Uuid,
    kind: SignatureKind,
    stage: SignatureStage,
    context: &NotificationContext,
    preferences: NotificationPreferences,
) -> WalletNotification {
    let where_from = where_from(context, preferences);
    let subject = match kind {
        SignatureKind::Message => NotificationSubject::Message,
        SignatureKind::TypedData => NotificationSubject::TypedData,
    };
    let (title, body, review) = match (kind, stage) {
        (SignatureKind::Message, SignatureStage::Queued) => (
            "Message signature needed",
            format!("{where_from}. Nothing is signed until you decide."),
            true,
        ),
        (SignatureKind::TypedData, SignatureStage::Queued) => (
            "Typed-data signature needed",
            format!("{where_from}. Nothing is signed until you decide."),
            true,
        ),
        (SignatureKind::Message, SignatureStage::Signed) => (
            "Message signed",
            format!("{where_from}. The signature went back to whoever asked."),
            false,
        ),
        (SignatureKind::TypedData, SignatureStage::Signed) => (
            "Typed data signed",
            format!("{where_from}. The signature went back to whoever asked."),
            false,
        ),
        (SignatureKind::Message, SignatureStage::Rejected) => (
            "Message signature declined",
            format!("{where_from}. Nothing was signed."),
            false,
        ),
        (SignatureKind::TypedData, SignatureStage::Rejected) => (
            "Typed-data signature declined",
            format!("{where_from}. Nothing was signed."),
            false,
        ),
    };
    WalletNotification {
        title: title.to_owned(),
        body,
        route: route_for(subject, request_id, review),
    }
}

/// A pairing proposal names the dapp, because that is the only fact the owner
/// has to judge and the wallet has nothing else to say yet. The name is
/// dapp-authored, so it arrives already sanitized by `DappIdentity`.
fn pairing_notification(dapp: &str, preferences: NotificationPreferences) -> WalletNotification {
    let body = if preferences.detailed_previews {
        format!("{dapp} wants to connect. Nothing is approved until you decide.")
    } else {
        "Open Ekubo Wallet for details. Nothing is approved until you decide.".to_owned()
    };
    WalletNotification {
        title: "Connection request".to_owned(),
        body,
        route: NotificationRoute::WalletConnect,
    }
}

/// A policy proposal names the account and stops.
///
/// The proposal's `rationale` is agent-authored and explicitly untrusted, so
/// it is the one thing this must not carry: a banner is drawn by the operating
/// system, outside every surface the wallet sanitizes text for, and an agent
/// that could write there would be able to put its own case to the owner
/// without the diff beside it. What the proposal actually does is read on the
/// Policies screen, where the permission diff is.
fn policy_proposal_notification(
    wallet_id: &str,
    context: &NotificationContext,
    preferences: NotificationPreferences,
) -> WalletNotification {
    let where_from = where_from(context, preferences);
    WalletNotification {
        title: "Policy change proposed".to_owned(),
        body: format!("{where_from}. Nothing changes until you approve it."),
        route: NotificationRoute::PolicyProposal {
            wallet_id: wallet_id.to_owned(),
        },
    }
}

fn route_for(subject: NotificationSubject, request_id: Uuid, review: bool) -> NotificationRoute {
    if review {
        NotificationRoute::Review {
            subject,
            request_id,
        }
    } else {
        NotificationRoute::Activity {
            subject,
            request_id,
        }
    }
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
                // XDG servers only promise an activation signal for actions
                // the notification advertised. macOS and Windows also map a
                // body click to this conventional default action.
                .action("default", "Open")
                .show();
            if let Ok(handle) = handle {
                handle.wait_for_action(move |action| {
                    if notification_action_opens(action) {
                        let _ = clicked.send(notification.route);
                    }
                });
            }
        });
    }
}

fn notification_action_opens(action: &str) -> bool {
    action == "default"
}

#[cfg(test)]
#[path = "notifications_test.rs"]
mod tests;
