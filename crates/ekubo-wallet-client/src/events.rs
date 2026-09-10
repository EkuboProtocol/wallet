//! Shared notification metadata. Events confer no signing authority.

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionStage {
    Proposed,
    Signed,
    Broadcast,
    Confirmed,
    Reverted,
    Replaced,
    Cancelled,
    /// The agent that queued a request took it back before anyone decided.
    ///
    /// Separate from [`Self::Cancelled`], which is the on-chain outcome of a
    /// replacement winning a nonce race. Both leave the row `cancelled`, but
    /// the owner is being told two different things: one that their money
    /// moved a way they asked for, and one that a review they had not looked
    /// at yet is gone and nothing happened.
    Withdrawn,
}

/// Which signature request a [`DomainEventKind::Signature`] is about. The two
/// kinds live in separate stores and open separate review documents, so a
/// listener holding only a request id cannot tell them apart on its own.
#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureKind {
    Message,
    TypedData,
}

/// The lifecycle of one signature request, mirroring [`TransactionStage`].
///
/// A signature request has no on-chain half, so it ends the moment the owner
/// decides: there is nothing to broadcast, confirm, or replace.
#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureStage {
    /// Queued and waiting for the owner. Nothing has been signed yet.
    Queued,
    Signed,
    Rejected,
    /// The agent that asked took the request back before the owner decided.
    /// Distinct from [`Self::Rejected`], which is the owner's verdict.
    Withdrawn,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
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
    /// An agent proposed a policy change and it is now waiting on the owner.
    ///
    /// Published only where a proposal is written. The owner's own decisions
    /// about one — applying it, rejecting it — publish `ConfigurationChanged`
    /// instead, so this never fires for a question the owner has already
    /// answered and a banner raised from it cannot interrupt them with their
    /// own press. It was called `PolicyProposalChanged`, which described the
    /// three of those together and so read as the one event that could not be
    /// notified on.
    PolicyProposed {
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

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DomainEvent {
    pub occurred_at: DateTime<Utc>,
    pub kind: DomainEventKind,
}

/// A position in one running service's event stream. This is a read cursor,
/// not an authorization capability; the transport must authenticate its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventCursor {
    pub epoch: Uuid,
    pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EventBatch {
    pub cursor: EventCursor,
    /// Capture fresh authoritative state before continuing from this cursor.
    /// Initial connection, service restart, and lost history all require this.
    pub refresh_required: bool,
    pub events: Vec<DomainEvent>,
}
