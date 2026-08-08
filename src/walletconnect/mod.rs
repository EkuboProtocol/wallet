//! `WalletConnect` v2 (Sign) support: pair with a dapp from a pasted link and
//! serve the requests it proposes.
//!
//! The layering is deliberate and worth reading before changing anything here.
//! A dapp reached this way is exactly as untrusted as an MCP agent is, so it
//! gets exactly the same treatment: it can *propose*, and nothing more. Every
//! transaction it proposes is turned into the same signer-neutral execution
//! plan an agent would have produced, simulated, put to the same policy, and
//! either signed automatically because the policy allows it or queued for the
//! same human review — and every signature request goes to that human review
//! unconditionally, because no policy can evaluate what a signature authorizes.
//!
//! Nothing in this directory can sign, and nothing in it can widen a policy.
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
//! The wiring to the wallet kernel — policy, simulation, custody, the terminal
//! review — lives in `crate::connect`, not here.

pub mod crypto;
pub mod protocol;
pub mod relay;
pub mod request;
pub mod session;
pub mod uri;
