//! Read-only `WalletConnect` session status shared by both hosts and the client.

use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionStatus {
    Pairing,
    AwaitingProposal,
    Connected,
    /// The relay connection dropped and the session is dialing again.
    ///
    /// A distinct state rather than a silent one, because the session is still
    /// the owner's and the dapp still believes in it — what has gone away is
    /// the socket in between, and a row that went on saying "Connected"
    /// through an outage would be the wallet asserting something it cannot
    /// currently do.
    Reconnecting,
    Disconnecting,
}

impl SessionStatus {
    /// Owner-facing wording for the state of one dapp connection.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pairing => "Connecting",
            Self::AwaitingProposal => "Waiting for the dapp",
            Self::Connected => "Connected",
            Self::Reconnecting => "Reconnecting",
            Self::Disconnecting => "Disconnecting",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionSummary {
    pub id: Uuid,
    pub status: SessionStatus,
    pub active_requests: usize,
    pub dapp_name: Option<String>,
    pub last_error: Option<String>,
    /// The controller-selected settlement deadline. Peers cannot extend it.
    pub expires_at: Option<i64>,
    /// Whether the owner has approved this dapp and the session settled.
    ///
    /// Everything before that point is a pairing with a stranger: the relay
    /// carries nothing but a proposal, and the only thing the wallet knows
    /// about the peer is whatever the proposal will claim. A connection list
    /// that draws those rows invites the reader to treat "it is in the list"
    /// as "I let it in". The review window is where a dapp is met; the list is
    /// what came out of that decision.
    pub settled: bool,
}
