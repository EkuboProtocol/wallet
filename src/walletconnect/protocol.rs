//! The Sign protocol's wire types, tags, and error codes.
//!
//! Everything a dapp sends arrives here first, so every type in this file is
//! parsing hostile input. Two rules follow from that and are worth stating
//! once rather than repeating at each definition:
//!
//! * No inbound type denies unknown fields. A dapp on a newer SDK will send
//!   fields this wallet has never heard of, and refusing the whole message over
//!   one of them would break pairing for no security gain. Nothing unknown is
//!   ever acted on, which is the property that actually matters.
//! * Every string a dapp controls — its name, its URL, its icons, a namespace
//!   key — is stored exactly as sent and sanitized at the moment it is drawn.
//!   Sanitizing on the way in would mean the wallet displays something other
//!   than what it received.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC version string, which the protocol requires verbatim.
pub const JSONRPC_VERSION: &str = "2.0";

/// How long a settled session lasts before the dapp must extend it: seven
/// days, as the protocol specifies.
pub const SESSION_TTL_SECONDS: i64 = 604_800;

/// Relay publish tags and their time-to-live in seconds.
///
/// The relay reads the tag to decide how to route and how long to retain a
/// message, and rejects a publish whose tag it does not recognize, so these are
/// wire constants rather than local bookkeeping. Request and response carry
/// different tags for the same method.
pub mod tag {
    pub const SESSION_PROPOSE_RESPONSE_APPROVE: u32 = 1101;
    pub const SESSION_PROPOSE_RESPONSE_REJECT: u32 = 1120;
    pub const SESSION_SETTLE_REQUEST: u32 = 1102;
    pub const SESSION_UPDATE_RESPONSE: u32 = 1105;
    pub const SESSION_EXTEND_RESPONSE: u32 = 1107;
    pub const SESSION_REQUEST_RESPONSE: u32 = 1109;
    pub const SESSION_EVENT_RESPONSE: u32 = 1111;
    pub const SESSION_DELETE_REQUEST: u32 = 1112;
    pub const SESSION_DELETE_RESPONSE: u32 = 1113;
    pub const SESSION_PING_RESPONSE: u32 = 1115;
}

/// Time-to-live in seconds for each publish, matching the tag above.
pub mod ttl {
    pub const SESSION_PROPOSE_RESPONSE: u64 = 300;
    pub const SESSION_SETTLE: u64 = 300;
    pub const SESSION_REQUEST_RESPONSE: u64 = 300;
    pub const SESSION_DELETE: u64 = 86_400;
    pub const ONE_DAY: u64 = 86_400;
}

/// The subset of the protocol's error codes this wallet ever sends.
///
/// A dapp shows these to its user, so picking the right one is the difference
/// between "your wallet rejected this" and "your wallet is broken".
pub mod error_code {
    /// The person said no.
    pub const USER_REJECTED: i64 = 5000;
    /// The proposal asked for a chain this wallet has no configuration for.
    pub const UNSUPPORTED_CHAINS: i64 = 5100;
    /// The request named a method this wallet does not implement.
    pub const UNSUPPORTED_METHODS: i64 = 5101;
    /// The proposal asked to subscribe to an event this wallet never emits.
    pub const UNSUPPORTED_EVENTS: i64 = 5102;
    /// The request named an address this session does not sign for.
    pub const UNSUPPORTED_ACCOUNTS: i64 = 5103;
    /// EIP-3326's "the wallet does not have this chain", which is the answer a
    /// dapp knows how to act on when it asks to switch to one.
    pub const CHAIN_NOT_ADDED: i64 = 4902;
    /// The request named a chain outside what this session approved.
    pub const UNAUTHORIZED_CHAIN: i64 = 3005;
    /// The request was well formed but could not be carried out.
    pub const INVALID_METHOD: i64 = 1001;
    /// EIP-5792: the batch asked for a capability this wallet does not
    /// implement and did not mark it optional.
    pub const UNSUPPORTED_CAPABILITY: i64 = 5700;
    /// EIP-5792: the batch named a chain outside this session.
    pub const UNSUPPORTED_CHAIN_ID: i64 = 5710;
    /// EIP-5792: no batch was submitted under that id.
    pub const UNKNOWN_BUNDLE_ID: i64 = 5730;
    /// EIP-5792: more calls than this wallet will put in one batch.
    pub const BUNDLE_TOO_LARGE: i64 = 5740;
    /// The session ended from this side.
    pub const USER_DISCONNECTED: i64 = 6000;
}

/// Sign protocol method names.
pub mod method {
    pub const SESSION_PROPOSE: &str = "wc_sessionPropose";
    pub const SESSION_SETTLE: &str = "wc_sessionSettle";
    pub const SESSION_UPDATE: &str = "wc_sessionUpdate";
    pub const SESSION_EXTEND: &str = "wc_sessionExtend";
    pub const SESSION_REQUEST: &str = "wc_sessionRequest";
    pub const SESSION_EVENT: &str = "wc_sessionEvent";
    pub const SESSION_DELETE: &str = "wc_sessionDelete";
    pub const SESSION_PING: &str = "wc_sessionPing";
}

/// A JSON-RPC message as it arrives, before it is known to be a request or a
/// response.
///
/// The protocol multiplexes both directions over one topic, and a peer is free
/// to answer a request at any point, so deciding which this is has to be part
/// of parsing rather than assumed by the caller.
#[derive(Debug, Deserialize)]
pub struct IncomingMessage {
    pub id: u64,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub params: Option<Value>,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<JsonRpcError>,
}

impl IncomingMessage {
    /// The method name, when this is a request rather than a response.
    #[must_use]
    pub fn as_request(&self) -> Option<(&str, &Value)> {
        match (&self.method, &self.params) {
            (Some(method), Some(params)) => Some((method.as_str(), params)),
            // A request with no params is still a request; the protocol sends
            // `wc_sessionPing` with an empty object, and a peer that omits it
            // entirely means the same thing.
            (Some(method), None) => Some((method.as_str(), &Value::Null)),
            (None, _) => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A JSON-RPC request this wallet sends.
#[derive(Debug, Serialize)]
pub struct OutgoingRequest {
    pub id: u64,
    pub jsonrpc: &'static str,
    pub method: &'static str,
    pub params: Value,
}

impl OutgoingRequest {
    #[must_use]
    pub fn new(id: u64, method: &'static str, params: Value) -> Self {
        Self {
            id,
            jsonrpc: JSONRPC_VERSION,
            method,
            params,
        }
    }
}

/// A JSON-RPC response this wallet sends.
#[derive(Debug, Serialize)]
pub struct OutgoingResponse {
    pub id: u64,
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl OutgoingResponse {
    #[must_use]
    pub const fn result(id: u64, result: Value) -> Self {
        Self {
            id,
            jsonrpc: JSONRPC_VERSION,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub fn error(id: u64, code: i64, message: impl Into<String>) -> Self {
        Self {
            id,
            jsonrpc: JSONRPC_VERSION,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// The relay a message travels over, echoed back to the dapp unchanged.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Relay {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// A dapp's self-description.
///
/// Every field is whatever the dapp typed. `name` and `url` in particular are
/// the two things a person will read to decide whether to connect, and a dapp
/// that wants to be mistaken for another one will simply claim that other one's
/// name. Nothing here is verified, and the review that shows it says so.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AppMetadata {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub icons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Participant {
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(default)]
    pub metadata: AppMetadata,
}

/// One namespace as a proposal asks for it.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProposalNamespace {
    /// Absent when the namespace key already names the chain, as in the
    /// `eip155:1` form; present as a list when the key is bare `eip155`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<Vec<String>>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub events: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionProposeParams {
    #[serde(default)]
    pub relays: Vec<Relay>,
    pub proposer: Participant,
    #[serde(default)]
    pub required_namespaces: std::collections::BTreeMap<String, ProposalNamespace>,
    #[serde(default)]
    pub optional_namespaces: std::collections::BTreeMap<String, ProposalNamespace>,
    #[serde(default)]
    pub expiry_timestamp: Option<i64>,
}

/// One namespace as the wallet settles it: the same shape, plus the accounts
/// actually being exposed.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SettledNamespace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chains: Option<Vec<String>>,
    pub accounts: Vec<String>,
    pub methods: Vec<String>,
    pub events: Vec<String>,
}

/// What a dapp asked the wallet to do, inside a `wc_sessionRequest`.
#[derive(Debug, Deserialize)]
pub struct SessionRequestPayload {
    pub method: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default, rename = "expiryTimestamp")]
    pub expiry_timestamp: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequestParams {
    pub request: SessionRequestPayload,
    pub chain_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SessionDeleteParams {
    #[serde(default)]
    pub code: i64,
    #[serde(default)]
    pub message: String,
}

/// A JSON-RPC id in the form the protocol expects: microseconds since the
/// epoch, plus a small random tail so two calls in the same microsecond differ.
///
/// The shape matters. Some peers sanity-check that an id looks like a recent
/// timestamp, and a bare counter starting at 1 fails that check.
#[must_use]
pub fn request_id(now_millis: i64, salt: u16) -> u64 {
    let micros = u64::try_from(now_millis).unwrap_or(0).saturating_mul(1000);
    micros.saturating_add(u64::from(salt % 1000))
}

#[cfg(test)]
#[path = "protocol_test.rs"]
mod tests;
