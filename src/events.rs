use chrono::{DateTime, Utc};
use tokio::sync::broadcast;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionStage {
    Proposed,
    Signed,
    Broadcast,
    Confirmed,
    Reverted,
    Replaced,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainEventKind {
    Transaction {
        request_id: Uuid,
        stage: TransactionStage,
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
