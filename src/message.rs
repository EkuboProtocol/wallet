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

use crate::policy_store::PolicyStore;
use alloy::primitives::{Address, B256, eip191_hash_message};
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, TimeDelta, Utc};
use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{fmt::Write as _, path::Path, str::FromStr};
use uuid::Uuid;

/// Message approval requests expire exactly like typed-data requests do.
pub const MESSAGE_APPROVAL_EXPIRY_SECONDS: i64 = 900;
const MAX_AWAITING_PER_WALLET: i64 = 64;
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
    Expired,
}

impl MessageStatus {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "awaiting_approval" => Ok(Self::AwaitingApproval),
            "rejected" => Ok(Self::Rejected),
            "signed" => Ok(Self::Signed),
            "expired" => Ok(Self::Expired),
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
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_at: Option<DateTime<Utc>>,
    /// The 65-byte r||s||v signature, present only once signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
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

const fn is_bidirectional_control(character: char) -> bool {
    matches!(
        character,
        '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
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
    while let Some(line) = lines.next() {
        if let Some(value) = line.strip_prefix("Expiration Time: ") {
            expiration_time = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("Not Before: ") {
            not_before = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("Request ID: ") {
            request_id = Some(value.to_owned());
        } else if line == "Resources:" {
            for resource in lines.by_ref() {
                resources.push(resource.strip_prefix("- ")?.to_owned());
            }
        } else {
            return None;
        }
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
    ) -> Result<PendingMessage> {
        crate::config::validate_wallet_id(wallet_id)?;
        validate_message_length(message)?;
        let message_hex = encode_message_hex(message);
        let digest = format!("{:#x}", message_digest(message));
        // The empty string, not NULL, stands for "no chain declared": SQLite
        // treats NULLs as distinct in a unique index, which would silently
        // disable the awaiting-request deduplication below.
        let chain_id = chain_id.unwrap_or_default();
        let created_at = Utc::now();
        let transaction = self.database.connection.transaction()?;
        transaction.execute(
            "UPDATE pending_messages SET status = 'expired', updated_at = ?1
             WHERE status = 'awaiting_approval' AND expires_at <= ?1",
            [created_at.to_rfc3339()],
        )?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT request_id FROM pending_messages
                 WHERE wallet_id = ?1 AND chain_id = ?2 AND digest = ?3
                   AND status = 'awaiting_approval'",
                params![wallet_id, chain_id, digest],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            transaction.commit()?;
            return self.get(Uuid::parse_str(&existing).context("stored request ID is invalid")?);
        }
        let awaiting: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM pending_messages
             WHERE wallet_id = ?1 AND status = 'awaiting_approval'",
            [wallet_id],
            |row| row.get(0),
        )?;
        ensure!(
            awaiting < MAX_AWAITING_PER_WALLET,
            "wallet already has {MAX_AWAITING_PER_WALLET} message requests awaiting approval"
        );

        let request_id = Uuid::new_v4();
        let expires_at = created_at + TimeDelta::seconds(MESSAGE_APPROVAL_EXPIRY_SECONDS);
        transaction.execute(
            "INSERT INTO pending_messages(
                request_id, wallet_id, chain_id, message_hex, message_encoding, digest,
                status, created_at, expires_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'awaiting_approval', ?7, ?8, ?7)",
            params![
                request_id.to_string(),
                wallet_id,
                chain_id,
                message_hex,
                encoding.as_str(),
                digest,
                created_at.to_rfc3339(),
                expires_at.to_rfc3339(),
            ],
        )?;
        transaction.commit()?;
        self.get(request_id)
    }

    pub fn get(&self, request_id: Uuid) -> Result<PendingMessage> {
        let mut record = self.read(request_id)?;
        if record.status == MessageStatus::AwaitingApproval && record.expires_at <= Utc::now() {
            self.database.connection.execute(
                "UPDATE pending_messages SET status = 'expired', updated_at = ?2
                 WHERE request_id = ?1 AND status = 'awaiting_approval'",
                params![request_id.to_string(), Utc::now().to_rfc3339()],
            )?;
            record = self.read(request_id)?;
        }
        Ok(record)
    }

    pub fn reject(&mut self, request_id: Uuid) -> Result<PendingMessage> {
        let current = self.get(request_id)?;
        ensure!(
            current.status == MessageStatus::AwaitingApproval,
            "message request is not awaiting approval"
        );
        let now = Utc::now().to_rfc3339();
        let changed = self.database.connection.execute(
            "UPDATE pending_messages
             SET status = 'rejected', rejected_at = ?2, updated_at = ?2
             WHERE request_id = ?1 AND status = 'awaiting_approval'",
            params![request_id.to_string(), now],
        )?;
        ensure!(changed == 1, "message request changed during rejection");
        self.get(request_id)
    }

    /// Atomically record approval and the exact signature. The stored message
    /// must still hash to what the approver reviewed.
    pub fn store_signature(
        &mut self,
        request_id: Uuid,
        expected_digest: &str,
        signature: &str,
    ) -> Result<PendingMessage> {
        validate_signature_hex(signature)?;
        let transaction = self.database.connection.transaction()?;
        let (digest, status, expires_at): (String, String, String) = transaction
            .query_row(
                "SELECT digest, status, expires_at
                 FROM pending_messages WHERE request_id = ?1",
                [request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .with_context(|| format!("unknown message request {request_id}"))?;
        ensure!(digest == expected_digest, "message request digest mismatch");
        ensure!(
            MessageStatus::parse(&status)? == MessageStatus::AwaitingApproval,
            "message request is not awaiting approval"
        );
        ensure!(
            parse_time(&expires_at)? > Utc::now(),
            "message request expired"
        );
        let now = Utc::now().to_rfc3339();
        transaction.execute(
            "UPDATE pending_messages SET
                status = 'signed', approved_at = ?2, updated_at = ?2, signature = ?3
             WHERE request_id = ?1 AND status = 'awaiting_approval'",
            params![request_id.to_string(), now, signature],
        )?;
        transaction.commit()?;
        self.get(request_id)
    }

    pub fn awaiting_approval(&self, wallet_id: Option<&str>) -> Result<Vec<PendingMessage>> {
        if let Some(wallet_id) = wallet_id {
            crate::config::validate_wallet_id(wallet_id)?;
        }
        let mut statement = self.database.connection.prepare(
            "SELECT request_id FROM pending_messages
             WHERE status = 'awaiting_approval' AND (?1 IS NULL OR wallet_id = ?1)
             ORDER BY created_at DESC",
        )?;
        let request_ids = statement
            .query_map([wallet_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        request_ids
            .into_iter()
            .map(|value| {
                let id = Uuid::parse_str(&value).context("stored request ID is invalid")?;
                self.get(id)
            })
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
                "SELECT wallet_id, chain_id, message_hex, message_encoding, digest, status,
                        created_at, expires_at, updated_at, approved_at, rejected_at, signature
                 FROM pending_messages WHERE request_id = ?1",
                [request_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, Option<String>>(11)?,
                    ))
                },
            )
            .with_context(|| format!("unknown message request {request_id}"))?;
        let (
            wallet_id,
            chain_id,
            message_hex,
            encoding,
            digest,
            status,
            created_at,
            expires_at,
            updated_at,
            approved_at,
            rejected_at,
            signature,
        ) = row;
        crate::config::validate_wallet_id(&wallet_id)?;
        // Re-derive the digest from the stored bytes so a corrupted or edited
        // row can never present one message while binding a signature to
        // another.
        let message = decode_message_hex(&message_hex)?;
        ensure!(
            format!("{:#x}", message_digest(&message)) == digest,
            "stored message digest mismatch"
        );
        if let Some(signature) = &signature {
            validate_signature_hex(signature)?;
        }
        Ok(PendingMessage {
            request_id,
            wallet_id,
            chain_id: (!chain_id.is_empty()).then_some(chain_id),
            message_hex,
            encoding: MessageEncoding::parse(&encoding)?,
            digest,
            status: MessageStatus::parse(&status)?,
            created_at: parse_time(&created_at)?,
            expires_at: parse_time(&expires_at)?,
            updated_at: parse_time(&updated_at)?,
            approved_at: approved_at.as_deref().map(parse_time).transpose()?,
            rejected_at: rejected_at.as_deref().map(parse_time).transpose()?,
            signature,
        })
    }
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .context("stored timestamp is invalid")?
        .with_timezone(&Utc))
}

fn validate_signature_hex(value: &str) -> Result<()> {
    let encoded = value
        .strip_prefix("0x")
        .context("signature must start with 0x")?;
    ensure!(
        encoded.len() == 130 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "signature must be 65 hexadecimal bytes"
    );
    B256::from_str(&format!("0x{}", &encoded[..64])).context("invalid signature encoding")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_store::DatabaseKey;

    pub(crate) fn siwe_payload() -> String {
        [
            "example.com wants you to sign in with your Ethereum account:",
            "0x1111111111111111111111111111111111111111",
            "",
            "Sign in to Example.",
            "",
            "URI: https://example.com/login",
            "Version: 1",
            "Chain ID: 1",
            "Nonce: 32891756",
            "Issued At: 2026-08-04T16:25:24Z",
        ]
        .join("\n")
    }

    fn store() -> (tempfile::TempDir, MessageStore) {
        let directory = tempfile::tempdir().unwrap();
        let database = PolicyStore::open(
            &directory.path().join("policies.db"),
            &DatabaseKey::new([9; 32]),
        )
        .unwrap();
        (directory, MessageStore::new(database))
    }

    #[test]
    fn digest_matches_known_eip191_vectors() {
        // keccak256("\x19Ethereum Signed Message:\n12Hello World")
        assert_eq!(
            format!("{:#x}", message_digest(b"Hello World")),
            "0xa1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
        );
        // The empty message still carries a length prefix of "0".
        assert_eq!(
            format!("{:#x}", message_digest(b"")),
            "0x5f35dce98ba4fba25530a026ed80b2cecdaa31091ba4958b99b52ea1d068adad"
        );
        // Multi-byte UTF-8: the prefix counts bytes, not characters.
        assert_eq!(
            format!("{:#x}", message_digest("é".as_bytes())),
            format!("{:#x}", message_digest(&[0xc3, 0xa9]))
        );
    }

    #[test]
    fn a_real_signature_over_the_digest_recovers_to_the_signer() {
        use alloy::signers::{SignerSync, local::PrivateKeySigner};

        let signer = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x07)).unwrap();
        let digest = message_digest(b"gm");
        let signature = signer.sign_hash_sync(&digest).unwrap();
        assert_eq!(
            signature.recover_address_from_prehash(&digest).unwrap(),
            signer.address()
        );
        // The digest this module builds is exactly what a `personal_sign`
        // signer produces for the same bytes.
        assert_eq!(signer.sign_message_sync(b"gm").unwrap(), signature);
        validate_signature_hex(&format!("0x{}", hex::encode(signature.as_bytes()))).unwrap();
    }

    #[test]
    fn text_and_hex_inputs_describe_the_same_bytes() {
        let (text, encoding) = parse_message_input(Some("gm"), None).unwrap();
        assert_eq!(encoding, MessageEncoding::Text);
        let (bytes, encoding) = parse_message_input(None, Some("0x676d")).unwrap();
        assert_eq!(encoding, MessageEncoding::Hex);
        assert_eq!(text, bytes);
        assert_eq!(message_digest(&text), message_digest(&bytes));
    }

    #[test]
    fn bare_thirty_two_byte_requests_are_refused() {
        let digest_shaped = format!("0x{}", "ab".repeat(32));
        let error = parse_message_input(None, Some(&digest_shaped)).unwrap_err();
        assert!(error.to_string().contains("eth_sign is not supported"));

        // A 32-character sentence is not a digest, and stays signable.
        let sentence = "Please sign in to example.com!!!";
        assert_eq!(sentence.len(), 32);
        assert!(parse_message_input(Some(sentence), None).is_ok());
    }

    #[test]
    fn input_requires_exactly_one_encoding_and_a_reviewable_size() {
        assert!(parse_message_input(None, None).is_err());
        assert!(parse_message_input(Some("gm"), Some("0x676d")).is_err());
        assert!(parse_message_input(Some(""), None).is_err());
        assert!(parse_message_input(None, Some("676d")).is_err());
        assert!(parse_message_input(None, Some("0x6")).is_err());
        assert!(parse_message_input(None, Some("0xzz")).is_err());
        assert!(parse_message_input(Some(&"a".repeat(MAX_MESSAGE_BYTES + 1)), None).is_err());
    }

    #[test]
    fn display_flags_everything_that_can_mislead_a_reader() {
        let plain = describe_message(b"gm");
        assert_eq!(plain.text.as_deref(), Some("gm"));
        assert!(plain.warnings.is_empty());

        let ansi = describe_message(b"safe\x1b[31m\ntext");
        assert_eq!(
            ansi.escaped_text.as_deref(),
            Some("safe\\u{001b}[31m\\u{000a}text")
        );
        assert!(
            ansi.warnings
                .iter()
                .any(|warning| warning.contains("control characters"))
        );

        let bidi = describe_message("send \u{202e}yenom".as_bytes());
        assert!(
            bidi.warnings
                .iter()
                .any(|warning| warning.contains("bidirectional"))
        );
        assert!(bidi.escaped_text.unwrap().contains("\\u{202e}"));

        let hexish = describe_message(format!("0x{}", "cd".repeat(32)).as_bytes());
        assert!(
            hexish
                .warnings
                .iter()
                .any(|warning| warning.contains("bare hexadecimal"))
        );

        let binary = describe_message(&[0xff, 0xfe, 0x00]);
        assert!(binary.text.is_none());
        assert_eq!(binary.byte_length, 3);
        assert!(
            binary
                .warnings
                .iter()
                .any(|warning| warning.contains("not valid UTF-8"))
        );
    }

    #[test]
    fn parses_siwe_with_and_without_a_statement() {
        let siwe = parse_siwe(&siwe_payload()).unwrap();
        assert_eq!(siwe.domain, "example.com");
        assert_eq!(siwe.address, "0x1111111111111111111111111111111111111111");
        assert_eq!(siwe.statement.as_deref(), Some("Sign in to Example."));
        assert_eq!(siwe.uri, "https://example.com/login");
        assert_eq!(siwe.chain_id, "1");
        assert_eq!(siwe.nonce, "32891756");
        assert!(siwe.resources.is_empty());

        let statementless = siwe_payload().replace("Sign in to Example.\n\n", "");
        let siwe = parse_siwe(&statementless).unwrap();
        assert!(siwe.statement.is_none());
        assert_eq!(siwe.uri, "https://example.com/login");
    }

    #[test]
    fn parses_optional_siwe_fields_and_resources() {
        let payload = format!(
            "{}\nExpiration Time: 2026-08-04T17:25:24Z\nRequest ID: abc\nResources:\n- \
             https://example.com/terms\n- ipfs://bafy",
            siwe_payload()
        );
        let siwe = parse_siwe(&payload).unwrap();
        assert_eq!(
            siwe.expiration_time.as_deref(),
            Some("2026-08-04T17:25:24Z")
        );
        assert_eq!(siwe.request_id.as_deref(), Some("abc"));
        assert_eq!(siwe.resources.len(), 2);
    }

    #[test]
    fn near_miss_messages_are_not_recognized_as_siwe() {
        assert!(parse_siwe("gm").is_none());
        // Missing the blank line after the address.
        assert!(parse_siwe(&siwe_payload().replace("1111\n\n", "1111\n")).is_none());
        // Not an address.
        assert!(
            parse_siwe(&siwe_payload().replace("0x1111111111111111111111111111111111111111", "me"))
                .is_none()
        );
        // Unknown version.
        assert!(parse_siwe(&siwe_payload().replace("Version: 1", "Version: 2")).is_none());
        // Non-numeric chain.
        assert!(parse_siwe(&siwe_payload().replace("Chain ID: 1", "Chain ID: mainnet")).is_none());
        // An unexpected trailing field.
        assert!(parse_siwe(&format!("{}\nAlso: everything", siwe_payload())).is_none());
    }

    #[test]
    fn siwe_warnings_cover_chain_time_and_domain_disagreements() {
        let now = DateTime::parse_from_rfc3339("2026-08-04T16:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let siwe = parse_siwe(&siwe_payload()).unwrap();
        assert!(siwe_warnings(&siwe, Some("1"), true, now).is_empty());

        let warnings = siwe_warnings(&siwe, Some("8453"), false, now);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("chain 8453"))
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("not a configured network"))
        );

        let expired = parse_siwe(&format!(
            "{}\nExpiration Time: 2026-08-04T16:29:00Z",
            siwe_payload()
        ))
        .unwrap();
        assert!(
            siwe_warnings(&expired, None, true, now)
                .iter()
                .any(|warning| warning.contains("expired"))
        );

        let postdated = parse_siwe(&format!(
            "{}\nNot Before: 2026-09-04T16:29:00Z",
            siwe_payload()
        ))
        .unwrap();
        assert!(
            siwe_warnings(&postdated, None, true, now)
                .iter()
                .any(|warning| warning.contains("post-dated"))
        );

        let impostor = parse_siwe(&siwe_payload().replace(
            "URI: https://example.com/login",
            "URI: https://phish.example.net/login",
        ))
        .unwrap();
        assert!(
            siwe_warnings(&impostor, None, true, now)
                .iter()
                .any(|warning| warning.contains("phish.example.net"))
        );

        let resourced = parse_siwe(&format!(
            "{}\nResources:\n- https://example.com/everything",
            siwe_payload()
        ))
        .unwrap();
        assert!(
            siwe_warnings(&resourced, None, true, now)
                .iter()
                .any(|warning| warning.contains("listed resource"))
        );
    }

    #[test]
    fn lifecycle_persists_exact_bytes_and_signature() {
        let (_directory, mut store) = store();
        let message = b"gm".to_vec();
        let request = store
            .create("primary", Some("1"), &message, MessageEncoding::Text)
            .unwrap();
        assert_eq!(request.status, MessageStatus::AwaitingApproval);
        assert_eq!(request.message_bytes().unwrap(), message);
        assert_eq!(request.chain_id.as_deref(), Some("1"));
        assert_eq!(request.digest, format!("{:#x}", message_digest(&message)));

        // The identical message reuses the pending request.
        let duplicate = store
            .create("primary", Some("1"), &message, MessageEncoding::Text)
            .unwrap();
        assert_eq!(duplicate.request_id, request.request_id);
        assert_eq!(store.awaiting_approval(None).unwrap().len(), 1);

        let signature = format!("0x{}", "11".repeat(65));
        let signed = store
            .store_signature(request.request_id, &request.digest, &signature)
            .unwrap();
        assert_eq!(signed.status, MessageStatus::Signed);
        assert_eq!(signed.signature.as_deref(), Some(signature.as_str()));
        assert!(signed.approved_at.is_some());
        assert!(store.awaiting_approval(None).unwrap().is_empty());

        // A signed request cannot be re-signed or rejected.
        assert!(
            store
                .store_signature(request.request_id, &request.digest, &signature)
                .is_err()
        );
        assert!(store.reject(request.request_id).is_err());
    }

    #[test]
    fn chainless_requests_deduplicate_and_stay_distinct_from_chained_ones() {
        let (_directory, mut store) = store();
        let message = b"gm".to_vec();
        let first = store
            .create("primary", None, &message, MessageEncoding::Text)
            .unwrap();
        assert!(first.chain_id.is_none());
        let repeated = store
            .create("primary", None, &message, MessageEncoding::Text)
            .unwrap();
        assert_eq!(first.request_id, repeated.request_id);

        let chained = store
            .create("primary", Some("1"), &message, MessageEncoding::Text)
            .unwrap();
        assert_ne!(first.request_id, chained.request_id);
        assert_eq!(store.awaiting_approval(None).unwrap().len(), 2);
    }

    #[test]
    fn rejection_is_terminal_and_digest_is_bound() {
        let (_directory, mut store) = store();
        let request = store
            .create("primary", None, b"gm", MessageEncoding::Text)
            .unwrap();
        assert!(
            store
                .store_signature(
                    request.request_id,
                    &format!("{:#x}", B256::repeat_byte(0xEE)),
                    &format!("0x{}", "22".repeat(65)),
                )
                .is_err()
        );
        assert_eq!(
            store.reject(request.request_id).unwrap().status,
            MessageStatus::Rejected
        );
        assert!(store.reject(request.request_id).is_err());
    }

    #[test]
    fn a_tampered_message_row_never_binds_a_signature_to_other_bytes() {
        let (_directory, mut store) = store();
        let request = store
            .create("primary", None, b"gm", MessageEncoding::Text)
            .unwrap();
        store
            .database
            .connection
            .execute(
                "UPDATE pending_messages SET message_hex = ?2 WHERE request_id = ?1",
                params![
                    request.request_id.to_string(),
                    encode_message_hex(b"send everything")
                ],
            )
            .unwrap();
        assert!(store.get(request.request_id).is_err());
    }
}
