//! Reusable `WalletConnect` v2 Sign session handling for EIP-155 wallets.
//!
//! The crate owns URI parsing, relay transport, encrypted envelopes, proposal
//! settlement, approved-scope enforcement, request parsing, and session
//! lifecycle. It never owns wallet keys or policy. Applications implement
//! [`session::SessionHandler`] to decide proposals and handle requests.
//!
//! Nothing in this crate can sign, and nothing in it can widen a policy.
//! The modules split along that line:
//!
//! * [`crypto`] and [`relay`] are transport: confidentiality with one peer over
//!   an untrusted pipe.
//! * [`uri`] and [`protocol`] are parsing: hostile bytes into typed values.
//! * [`session`] owns the conversation and the approved scope, and refuses
//!   anything outside it.
//! * [`request`] translates a dapp's JSON-RPC into the wallet's own vocabulary,
//!   and refuses what that vocabulary cannot faithfully express.
//!
//! Start a session with [`session::Session::connect`]. Relay credentials and
//! wallet metadata are supplied by the embedding application, so this crate
//! contains no Ekubo-specific identity or configuration.

pub mod crypto;
pub mod protocol;
pub mod relay;
pub mod request;
pub mod session;
pub mod uri;

// The ordinary integration surface. The modules remain public for callers
// that need lower-level protocol or request types.
pub use protocol::AppMetadata;
pub use relay::{DEFAULT_RELAY_URL, RelayConfig};
pub use session::{
    ApprovedScope, DappRequest, ProposalDecision, ProposalSummary, RequestOutcome,
    SUPPORTED_EVENTS, ScopeGrant, Session, SessionEvent, SessionHandler,
};
pub use uri::PairingUri;
