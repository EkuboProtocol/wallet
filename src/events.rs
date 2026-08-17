use chrono::{DateTime, Utc};
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionStage {
    Proposed,
    Signed,
    Broadcast,
    Confirmed,
    Reverted,
    Replaced,
    Cancelled,
}

/// Which signature request a [`DomainEventKind::Signature`] is about. The two
/// kinds live in separate stores and open separate review documents, so a
/// listener holding only a request id cannot tell them apart on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureKind {
    Message,
    TypedData,
}

/// The lifecycle of one signature request, mirroring [`TransactionStage`].
///
/// A signature request has no on-chain half, so it ends the moment the owner
/// decides: there is nothing to broadcast, confirm, or replace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureStage {
    /// Queued and waiting for the owner. Nothing has been signed yet.
    Queued,
    Signed,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainEventKind {
    Transaction {
        request_id: Uuid,
        stage: TransactionStage,
    },
    /// A message or typed-data signature request changed state.
    ///
    /// Distinct from `ReviewChanged`, which says only that some queue moved: a
    /// banner has to know whether the request just arrived or was already
    /// decided, and which store to read it back from. Signature requests used
    /// to publish `ReviewChanged` alone, which is why an arriving message
    /// raised no notification — nothing downstream could tell it apart from
    /// the owner rejecting one.
    Signature {
        request_id: Uuid,
        kind: SignatureKind,
        stage: SignatureStage,
    },
    /// A dapp asked to pair over `WalletConnect` and the proposal is now waiting
    /// on the owner. Carries the dapp's self-declared name for the banner;
    /// `WalletConnectChanged` covers settled and closed sessions instead, which
    /// are not decisions anyone is being asked to make.
    WalletConnectProposed {
        session_id: String,
        dapp: String,
    },
    ConfigurationChanged,
    AgentConnectionChanged {
        active_connections: usize,
    },
    WalletConnectChanged {
        session_id: String,
    },
    ReviewChanged {
        request_id: Uuid,
    },
    PolicyProposalChanged {
        wallet_id: String,
    },
    /// An automation was installed, replaced, or stopped. Carries the wallet
    /// rather than the automation because the Automations tab redraws the
    /// wallet's whole list either way.
    AutomationsChanged {
        wallet_id: String,
    },
    McpStatusChanged {
        online: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainEvent {
    pub occurred_at: DateTime<Utc>,
    pub kind: DomainEventKind,
}

#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<DomainEvent>,
}

impl Default for EventBus {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(512);
        Self { sender }
    }
}

impl EventBus {
    pub fn publish(&self, kind: DomainEventKind) {
        let _ = self.sender.send(DomainEvent {
            occurred_at: Utc::now(),
            kind,
        });
    }

    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<DomainEvent> {
        self.sender.subscribe()
    }
}
