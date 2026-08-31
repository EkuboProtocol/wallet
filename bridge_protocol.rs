//! The bridge↔wallet IPC contract, shared verbatim by both sides.
//!
//! The stdio bridge and the wallet are distributed as one unit but are two
//! processes that can end up at different builds — a wallet updates itself
//! while a harness still holds a bridge started from the previous image. They
//! have to agree on whether to talk to each other.
//!
//! Build identity is the wrong question to ask. The bridge is a transparent
//! proxy: it forwards frames without interpreting tool schemas, arguments, or
//! results, so a wallet that adds a tool, changes a quote path, or fixes a
//! rendering bug stays perfectly compatible with a bridge built before it.
//! Comparing exact build versions rejected every one of those, which made an
//! ordinary wallet update break live agent sessions and made a helper left
//! behind by another build unusable rather than merely stale.
//!
//! What the two processes actually share is this small contract, and only a
//! change to it is a reason to refuse a connection.
//!
//! # Bump [`BRIDGE_PROTOCOL_VERSION`] when any of these changes
//!
//! - The framing: newline-delimited JSON, or the 24 MiB frame ceiling.
//! - The hello frame the bridge sends first, or its `client` values.
//! - The private sentinel request ids the bridge issues on its own behalf.
//! - How `initialize` and `notifications/initialized` are replayed on
//!   reconnect.
//! - **The capability set.** This one is easy to miss because nothing about
//!   it looks like a wire format. The bridge answers `initialize` on its own
//!   when the wallet is down, and a harness records that answer once and
//!   keeps it for the entire session. A bridge that does not claim a
//!   capability the wallet has therefore makes it unreachable for that whole
//!   session, however the wallet answers afterwards. A capability added to
//!   the wallet is a protocol change, and
//!   `the_offline_capabilities_match_the_protocol_version` in the bridge's
//!   tests fails until this constant moves with it.
//!
//! Adding a tool, a resource, a network, or a policy rule is *not* a protocol
//! change. Those travel through frames both sides already forward unchanged.

/// The version of the contract described above.
///
/// Version 1 is every build that also reports it. Wallets that predate the
/// constant publish nothing, and the bridge falls back to comparing exact
/// build versions with them, which is what those wallets expect.
pub const BRIDGE_PROTOCOL_VERSION: u32 = 1;

/// The `_meta` key the wallet publishes [`BRIDGE_PROTOCOL_VERSION`] under in
/// its MCP `initialize` result.
///
/// `_meta` is the field the MCP specification reserves for exactly this: data
/// an implementation needs to carry that the protocol itself does not model.
/// Harnesses receive it and ignore it.
pub const BRIDGE_PROTOCOL_META_KEY: &str = "org.ekubo.bridgeProtocol";
