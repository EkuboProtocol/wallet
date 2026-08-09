//! EIP-191 `personal_sign` message signing requests.
//!
//! A message signature carries no readable on-chain effect: the bytes are
//! whatever the verifying service decides they mean, so neither simulation nor
//! the policy language can score one. Every request therefore queues for
//! explicit human review, with no automatic path at all — the MCP tool only
//! creates a pending request, and the separate CLI prints the exact bytes,
//! requires terminal approval plus OS owner authentication, and only then
//! signs.
//!
//! Only EIP-191 version `0x45` is supported. The legacy `eth_sign` shape — a
//! signature over a bare, unprefixed 32-byte digest — is refused, because such
//! a digest is indistinguishable from the hash of a transaction, a permit, or
//! an EIP-7702 authorization, and no honest approval screen can be drawn for
//! it. The `0x19` prefix is what makes the human-review promise keepable: a
//! prefixed message can never collide with an RLP transaction preimage.

use crate::{
    policy_store::PolicyStore,
    sanitize::is_bidirectional_control,
    signature_requests::{SignatureQueue, encode_signature, split_decision},
    sql::{Blob, Millis, RowExt},
};
use alloy::primitives::{Address, B256, eip191_hash_message};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use rusqlite::params;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{fmt::Write as _, path::Path, str::FromStr};
use uuid::Uuid;

const QUEUE: SignatureQueue = SignatureQueue {
    table: "pending_messages",
    noun: "message request",
};
/// A human has to read every byte at approval time, so the ceiling sits far
/// below the typed-data limit. An oversized message is refused rather than
/// truncated: what the approver sees is always exactly what is hashed.
pub const MAX_MESSAGE_BYTES: usize = 8_192;

const SIWE_PREAMBLE: &str = " wants you to sign in with your Ethereum account:";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageStatus {
    AwaitingApproval,
    Rejected,
    Signed,
}

impl MessageStatus {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "awaiting_approval" => Ok(Self::AwaitingApproval),
            "rejected" => Ok(Self::Rejected),
            "signed" => Ok(Self::Signed),
            _ => bail!("stored message request has invalid status {value}"),
        }
    }
}

/// How the requester expressed the message. Display metadata only: the stored
/// bytes are what gets hashed either way.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageEncoding {
    Text,
    Hex,
}

impl MessageEncoding {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Hex => "hex",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "text" => Ok(Self::Text),
            "hex" => Ok(Self::Hex),
            _ => bail!("stored message request has invalid encoding {value}"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct PendingMessage {
    pub request_id: Uuid,
    pub wallet_id: String,
    /// Context the requester declared. `personal_sign` binds no chain, so this
    /// is never a property of the signature itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    /// The exact bytes that are hashed, as lowercase `0x`-prefixed hex.
    pub message_hex: String,
    pub encoding: MessageEncoding,
    /// The EIP-191 version `0x45` signing hash of those exact bytes.
    pub digest: String,
    pub status: MessageStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_at: Option<DateTime<Utc>>,
    /// The 65-byte r||s||v signature, present only once signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Who asked for this signature, when the caller knew: a dapp reached
    /// over `WalletConnect` names itself, an MCP agent does not. Recorded when
    /// the row is created rather than supplied to the review afterwards, so
    /// the name the reviewer reads belongs to whoever queued the bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
}

impl PendingMessage {
    pub fn message_bytes(&self) -> Result<Vec<u8>> {
        decode_message_hex(&self.message_hex)
    }
}

fn decode_message_hex(value: &str) -> Result<Vec<u8>> {
    let body = value
        .strip_prefix("0x")
        .context("message hex must start with 0x")?;
    ensure!(
        body.len().is_multiple_of(2),
        "message hex must contain whole bytes"
    );
    hex::decode(body).context("message hex is not valid hexadecimal")
}

/// Validate one requested message and return its exact bytes.
///
/// Exactly one of `text` and `hex` must be present, so a caller can express
/// bytes that are not valid UTF-8 without a lossy round trip through a string.
pub fn parse_message_input(
    text: Option<&str>,
    hex_bytes: Option<&str>,
) -> Result<(Vec<u8>, MessageEncoding)> {
    match (text, hex_bytes) {
        (Some(text), None) => {
            let bytes = text.as_bytes().to_vec();
            validate_message_length(&bytes)?;
            Ok((bytes, MessageEncoding::Text))
        }
        (None, Some(encoded)) => {
            let bytes = decode_message_hex(encoded)?;
            validate_message_length(&bytes)?;
            // The one shape a hex request can express that text cannot: a bare
            // digest. Signing it is the legacy `eth_sign` operation under
            // another name, and there is no rendering that tells a human what
            // it authorizes.
            ensure!(
                bytes.len() != 32,
                "refusing to sign a bare 32-byte value: an unprefixed digest is \
                 indistinguishable from a transaction, permit, or EIP-7702 authorization \
                 hash, and legacy eth_sign is not supported. Pass the message a human can \
                 read as message_text, or use wallet_sign_typed_data for EIP-712."
            );
            Ok((bytes, MessageEncoding::Hex))
        }
        (Some(_), Some(_)) => {
            bail!("pass exactly one of message_text and message_hex, not both")
        }
        (None, None) => bail!("pass exactly one of message_text and message_hex"),
    }
}

fn validate_message_length(message: &[u8]) -> Result<()> {
    ensure!(!message.is_empty(), "message is empty");
    ensure!(
        message.len() <= MAX_MESSAGE_BYTES,
        "message is {} bytes and exceeds the {MAX_MESSAGE_BYTES}-byte maximum a human can \
         review at approval time",
        message.len()
    );
    Ok(())
}

/// The EIP-191 version `0x45` signing hash:
/// `keccak256("\x19Ethereum Signed Message:\n" ‖ len(message) ‖ message)`.
#[must_use]
pub fn message_digest(message: &[u8]) -> B256 {
    eip191_hash_message(message)
}

#[must_use]
pub fn encode_message_hex(message: &[u8]) -> String {
    format!("0x{}", hex::encode(message))
}

/// Everything the approval screen needs to show a message honestly.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct MessageDisplay {
    /// The exact message, present only when the bytes are valid UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The same text with control characters, terminal escape sequences, and
    /// bidirectional controls rendered visibly. Safe to print to a terminal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escaped_text: Option<String>,
    pub byte_length: usize,
    pub line_count: usize,
    /// Reasons the approver should be more careful than usual.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Describe a message for display, flagging everything about it that can make
/// a terminal show the approver something other than what is being signed.
#[must_use]
pub fn describe_message(message: &[u8]) -> MessageDisplay {
    let text = std::str::from_utf8(message).ok();
    let mut warnings = Vec::new();
    match text {
        None => warnings.push(
            "The message is not valid UTF-8; only its exact bytes are shown. Verify them \
             against whatever asked for this signature."
                .into(),
        ),
        Some(text) => {
            if text.chars().any(char::is_control) {
                warnings.push(
                    "The message contains control characters or terminal escape sequences. \
                     They are shown escaped here; printed raw they can repaint the screen \
                     you are reading."
                        .into(),
                );
            }
            if text.chars().any(is_bidirectional_control) {
                warnings.push(
                    "The message contains Unicode bidirectional controls, which reorder \
                     displayed text without changing a byte of what gets signed."
                        .into(),
                );
            }
            if looks_hexadecimal(text) {
                warnings.push(
                    "The message is a bare hexadecimal string. The EIP-191 prefix keeps it \
                     from being a valid transaction signature, but nothing about it tells \
                     you what signing it authorizes."
                        .into(),
                );
            }
        }
    }
    MessageDisplay {
        byte_length: message.len(),
        line_count: text.map_or(1, |text| text.lines().count().max(1)),
        escaped_text: text.map(escape_for_display),
        text: text.map(str::to_owned),
        warnings,
    }
}

fn looks_hexadecimal(text: &str) -> bool {
    let body = text.strip_prefix("0x").unwrap_or(text);
    body.len() >= 32 && body.chars().all(|character| character.is_ascii_hexdigit())
}

fn escape_for_display(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() || is_bidirectional_control(character) {
            // Infallible: writing to a String never fails.
            let _ = write!(escaped, "\\u{{{:04x}}}", character as u32);
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// A recognized Sign-In with Ethereum (ERC-4361) message.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct SiweMessage {
    pub domain: String,
    /// Checksummed, as ERC-4361 requires.
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    pub uri: String,
    pub version: String,
    pub chain_id: String,
    pub nonce: String,
    pub issued_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
}

/// Recognize an ERC-4361 message.
///
/// Recognition is structural: every required field must be present, in the
/// specified order, with a parseable address, version `1`, and a decimal chain
/// ID. A message that merely resembles a login prompt is not recognized and
/// falls through to the generic path, which warns about everything.
#[must_use]
pub fn parse_siwe(message: &str) -> Option<SiweMessage> {
    let message = message.strip_suffix('\n').unwrap_or(message);
    let mut lines = message.split('\n');

    let domain = lines.next()?.strip_suffix(SIWE_PREAMBLE)?;
    if domain.is_empty() {
        return None;
    }
    let address = Address::from_str(lines.next()?).ok()?;
    if !lines.next()?.is_empty() {
        return None;
    }

    let mut heading = lines.next()?;
    let statement = if heading.starts_with("URI: ") {
        None
    } else {
        let statement = heading.to_owned();
        if !lines.next()?.is_empty() {
            return None;
        }
        heading = lines.next()?;
        Some(statement)
    };

    let uri = heading.strip_prefix("URI: ")?.to_owned();
    let version = lines.next()?.strip_prefix("Version: ")?.to_owned();
    let chain_id = lines.next()?.strip_prefix("Chain ID: ")?.to_owned();
    let nonce = lines.next()?.strip_prefix("Nonce: ")?.to_owned();
    let issued_at = lines.next()?.strip_prefix("Issued At: ")?.to_owned();
    if version != "1" || chain_id.parse::<u64>().is_err() || nonce.is_empty() {
        return None;
    }

    let mut expiration_time = None;
    let mut not_before = None;
    let mut request_id = None;
    let mut resources = Vec::new();
    // ERC-4361 fixes the order of these fields and allows each at most once.
    // Accepting them in any order, and letting a later one overwrite an
    // earlier, means one message parses two ways: what this wallet renders for
    // the reviewer, and what the verifier at the other end reads. A second
    // `Expiration Time` that this parser keeps and a stricter verifier
    // rejects — or the reverse — is a signature the owner approved against a
    // description nobody else shares. Refusing is the only reading that cannot
    // disagree with somebody.
    let mut seen = 0_u8;
    while let Some(line) = lines.next() {
        let field = if let Some(value) = line.strip_prefix("Expiration Time: ") {
            expiration_time = Some(value.to_owned());
            1
        } else if let Some(value) = line.strip_prefix("Not Before: ") {
            not_before = Some(value.to_owned());
            2
        } else if let Some(value) = line.strip_prefix("Request ID: ") {
            request_id = Some(value.to_owned());
            3
        } else if line == "Resources:" {
            for resource in lines.by_ref() {
                resources.push(resource.strip_prefix("- ")?.to_owned());
            }
            4
        } else {
            return None;
        };
        // Strictly increasing: equal rejects a repeat, lower rejects a
        // field that has come round again out of order.
        if field <= seen {
            return None;
        }
        seen = field;
    }

    Some(SiweMessage {
        domain: domain.to_owned(),
        address: address.to_checksum(None),
        statement,
        uri,
        version,
        chain_id,
        nonce,
        issued_at,
        expiration_time,
        not_before,
        request_id,
        resources,
    })
}

/// Everything about a recognized login that the approver should be told.
///
/// The address is not checked here: a SIWE message naming a different account
/// is rejected outright before a request is ever created, exactly as a permit
/// whose owner is not the signing wallet is.
#[must_use]
pub fn siwe_warnings(
    siwe: &SiweMessage,
    claimed_chain_id: Option<&str>,
    chain_is_configured: bool,
    now: DateTime<Utc>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Some(claimed) = claimed_chain_id
        && claimed != siwe.chain_id
    {
        warnings.push(format!(
            "The requester declared chain {claimed} but the login message states chain {}. \
             The message is what the site will verify.",
            siwe.chain_id
        ));
    }
    if !chain_is_configured {
        warnings.push(format!(
            "Chain {} in this login message is not a configured network.",
            siwe.chain_id
        ));
    }
    match siwe
        .expiration_time
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
    {
        Some(Ok(expiration)) if expiration.with_timezone(&Utc) <= now => warnings.push(format!(
            "This login expired at {}; signing it now grants nothing.",
            siwe.expiration_time.as_deref().unwrap_or_default()
        )),
        Some(Err(_)) => warnings.push("The Expiration Time is not a valid timestamp.".into()),
        _ => {}
    }
    match siwe.not_before.as_deref().map(DateTime::parse_from_rfc3339) {
        Some(Ok(not_before)) if not_before.with_timezone(&Utc) > now => warnings.push(format!(
            "This login is post-dated and only becomes valid at {}.",
            siwe.not_before.as_deref().unwrap_or_default()
        )),
        Some(Err(_)) => warnings.push("The Not Before field is not a valid timestamp.".into()),
        _ => {}
    }
    if DateTime::parse_from_rfc3339(&siwe.issued_at).is_err() {
        warnings.push("The Issued At field is not a valid timestamp.".into());
    }
    if let Some(host) = uri_authority(&siwe.uri) {
        if host != normalize_domain(&siwe.domain) {
            warnings.push(format!(
                "The message says {} is asking, but its URI points at {host}.",
                siwe.domain
            ));
        }
    } else {
        warnings.push(format!("The URI {} could not be parsed.", siwe.uri));
    }
    if !siwe.resources.is_empty() {
        warnings.push(format!(
            "Signing also authorizes {} listed resource(s): {}.",
            siwe.resources.len(),
            siwe.resources.join(", ")
        ));
    }
    warnings
}

/// The host and, when present, port a SIWE `URI` points at.
fn uri_authority(uri: &str) -> Option<String> {
    let parsed = url::Url::parse(uri).ok()?;
    let host = parsed.host_str()?.to_owned();
    Some(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

/// ERC-4361 allows the domain field to carry a scheme; the authority is what
/// is comparable to the URI.
fn normalize_domain(domain: &str) -> String {
    domain
        .split_once("://")
        .map_or(domain, |(_, authority)| authority)
        .to_owned()
}

pub struct MessageStore {
    database: PolicyStore,
}

impl MessageStore {
    pub fn production(data_dir: &Path) -> Result<Self> {
        Ok(Self {
            database: PolicyStore::production(data_dir)?,
        })
    }

    #[must_use]
    pub const fn new(database: PolicyStore) -> Self {
        Self { database }
    }

    /// Queue one message for human review. An identical message already
    /// awaiting approval for the same wallet and declared chain is reused
    /// rather than stacked.
    pub fn create(
        &mut self,
        wallet_id: &str,
        chain_id: Option<&str>,
        message: &[u8],
        encoding: MessageEncoding,
        requester: Option<&str>,
    ) -> Result<PendingMessage> {
        validate_message_length(message)?;
        let digest = message_digest(message);
        // 0, not NULL, stands for "no chain declared": SQLite treats NULLs as
        // distinct in a unique index, which would silently disable the
        // awaiting-request deduplication in the shared queue. No chain has ID
        // 0, so the sentinel cannot collide with a declared one.
        let chain_id = chain_id
            .map(|declared| declared.parse::<u64>().context("chain ID is not a number"))
            .transpose()?
            .unwrap_or_default();
        let stored_chain_id = i64::try_from(chain_id).context("chain ID out of range")?;
        let requester = requester.unwrap_or_default();
        let request_id = QUEUE.create_or_reuse(
            &mut self.database.connection,
            wallet_id,
            chain_id,
            digest,
            requester,
            |transaction, request_id, now| {
                transaction.execute(
                    "INSERT INTO pending_messages(
                        request_id, wallet_id, chain_id, message, message_encoding, digest,
                        requester, status, created_at, updated_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'awaiting_approval', ?8, ?8)",
                    params![
                        request_id,
                        wallet_id,
                        stored_chain_id,
                        message,
                        encoding.as_str(),
                        Blob(digest),
                        requester,
                        Millis(now),
                    ],
                )?;
                Ok(())
            },
        )?;
        self.get(request_id)
    }

    pub fn get(&self, request_id: Uuid) -> Result<PendingMessage> {
        self.read(request_id)
    }

    pub fn reject(&mut self, request_id: Uuid) -> Result<PendingMessage> {
        let current = self.get(request_id)?;
        ensure!(
            current.status == MessageStatus::AwaitingApproval,
            "message request is not awaiting approval"
        );
        QUEUE.reject(&self.database.connection, request_id)?;
        self.get(request_id)
    }

    /// Atomically record approval and the exact signature. The stored message
    /// must still hash to what the approver reviewed.
    pub fn store_signature(
        &mut self,
        request_id: Uuid,
        signer_wallet_id: &str,
        expected_digest: B256,
        signature: &str,
    ) -> Result<PendingMessage> {
        QUEUE.store_signature(
            &mut self.database.connection,
            request_id,
            signer_wallet_id,
            expected_digest,
            signature,
        )?;
        self.get(request_id)
    }

    pub fn awaiting_approval(&self, wallet_id: Option<&str>) -> Result<Vec<PendingMessage>> {
        QUEUE
            .awaiting_ids(&self.database.connection, wallet_id)?
            .into_iter()
            .map(|id| self.get(id))
            .filter(|result| {
                result.as_ref().map_or(true, |record| {
                    record.status == MessageStatus::AwaitingApproval
                })
            })
            .collect()
    }

    fn read(&self, request_id: Uuid) -> Result<PendingMessage> {
        let row = self
            .database
            .connection
            .query_row(
                "SELECT wallet_id, chain_id, message, message_encoding, digest, status,
                        created_at, updated_at, decided_at, signature, requester
                 FROM pending_messages WHERE request_id = ?1",
                [request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.blob::<B256>(4)?,
                        row.get::<_, String>(5)?,
                        row.time(6)?,
                        row.time(7)?,
                        row.time_opt(8)?,
                        row.blob_opt::<[u8; 65]>(9)?,
                        row.get::<_, String>(10)?,
                    ))
                },
            )
            .with_context(|| format!("unknown message request {request_id}"))?;
        let (
            wallet_id,
            chain_id,
            message,
            encoding,
            digest,
            status,
            created_at,
            updated_at,
            decided_at,
            signature,
            requester,
        ) = row;
        crate::config::validate_wallet_id(&wallet_id)?;
        // Re-derive the digest from the stored bytes so a corrupted or edited
        // row can never present one message while binding a signature to
        // another.
        ensure!(
            message_digest(&message) == digest,
            "stored message digest mismatch"
        );
        let status = MessageStatus::parse(&status)?;
        let (approved_at, rejected_at) =
            split_decision(decided_at, status == MessageStatus::Rejected);
        Ok(PendingMessage {
            request_id,
            wallet_id,
            chain_id: (chain_id != 0).then(|| chain_id.to_string()),
            message_hex: encode_message_hex(&message),
            encoding: MessageEncoding::parse(&encoding)?,
            digest: format!("{digest:#x}"),
            status,
            created_at,
            updated_at,
            approved_at,
            rejected_at,
            signature: signature.map(encode_signature),
            requester: (!requester.is_empty()).then_some(requester),
        })
    }
}

#[cfg(test)]
#[path = "message_test.rs"]
mod tests;
