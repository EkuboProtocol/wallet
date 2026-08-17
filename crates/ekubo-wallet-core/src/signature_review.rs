//! Reviewer-facing documents for the two signature requests no policy can
//! ever approve on its own.
//!
//! A transaction review opens with what the wallet will hold afterwards, then
//! the actions that get it there, then the fee envelope. A signature review had
//! none of that: it listed a byte count and a line count and handed over the
//! raw payload, which is the safety floor rather than a reading of it. That
//! asymmetry mattered most where the stakes are closest to a transaction — a
//! permit signature moves tokens exactly as an `approve` call does, one block
//! later and without ever appearing in this wallet's own activity.
//!
//! So both documents are built here, beside the permit interpreter and the
//! token formatting the transaction path already uses, and both lead with the
//! same question that path leads with: what does approving this let someone
//! else do? The exact payload still follows, unaltered and escaped, because a
//! reading is a supplement to the bytes and never a replacement for them.

use crate::approval::{ApprovalKind, ApprovalRequest, ApprovalSectionKind, ReviewDocument};
use crate::approval_summary::{
    TokenMetadata, TokenMetadataMap, format_token_amount, is_effectively_unlimited, token_label,
};
use crate::message::{PendingMessage, SiweMessage, describe_message, parse_siwe};
use crate::typed_data::{
    PendingTypedData, PermitApproval, interpret_permit_approvals, parse_typed_data,
};
use alloy::primitives::{Address, U256};
use std::str::FromStr as _;

/// What a payload's permit interpretation came to.
///
/// The refusal case is a finding, not an error: a permit naming somebody else
/// as the owner is exactly the payload a reviewer most needs to be told about,
/// and hiding the whole review behind an error would leave them deciding from
/// raw JSON. The MCP tool refuses such a payload outright, but a dapp reaching
/// in over `WalletConnect` never passes through that check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PermitInterpretation {
    /// Not a recognized permit shape. The payload means whatever its own types
    /// say, and only the reviewer can judge that.
    Unrecognized,
    Recognized(Vec<PermitApproval>),
    Refused(String),
}

impl PermitInterpretation {
    /// Read the payload as a permit, on behalf of the wallet being asked to
    /// sign it.
    #[must_use]
    pub fn of(typed_data: &serde_json::Value, wallet: Address) -> Self {
        let Ok((typed, _, _)) = parse_typed_data(typed_data) else {
            // An unparseable payload cannot reach a store, so this is only
            // reachable if one already there stopped parsing. Say nothing
            // about permits rather than claiming there are none.
            return Self::Unrecognized;
        };
        match interpret_permit_approvals(&typed, wallet) {
            Ok(Some(approvals)) => Self::Recognized(approvals),
            Ok(None) => Self::Unrecognized,
            Err(error) => Self::Refused(format!("{error:#}")),
        }
    }

    /// The tokens named by a recognized permit, so a caller can load their
    /// display metadata before the document is built.
    #[must_use]
    pub fn tokens(&self) -> Vec<Address> {
        let Self::Recognized(approvals) = self else {
            return Vec::new();
        };
        approvals
            .iter()
            .filter_map(|approval| Address::from_str(&approval.token).ok())
            .collect()
    }
}

/// Build the reviewer's document for an EIP-712 typed-data signature.
///
/// `token_metadata` comes from the owner-confirmed token database and nothing
/// else, exactly as it does for a transaction: a permit's own contract never
/// gets to say what it is called at the moment somebody is deciding about it.
#[must_use]
pub fn typed_data_review_document(
    request: &PendingTypedData,
    interpretation: &PermitInterpretation,
    token_metadata: &TokenMetadataMap,
    exact_payload: String,
    dangerous_display: bool,
) -> ReviewDocument {
    let mut summary = ApprovalRequest::new(
        ApprovalKind::TypedDataSignature,
        "Review typed-data signature",
        "EIP-712 typed data may grant permissions or authorize off-chain actions.",
    )
    .fact("Wallet", request.wallet_id.clone())
    .fact("Signer", format!("{:#x}", request.wallet_address))
    .fact("Chain", request.chain_id.clone())
    .fact(
        "Requester",
        request
            .requester
            .clone()
            .unwrap_or_else(|| "Unknown requester".into()),
    )
    .digest(request.digest.clone());
    summary.id = request.request_id;

    summary = summary.section_kind(ApprovalSectionKind::Effects, "What signing this grants");
    match interpretation {
        PermitInterpretation::Recognized(approvals) => {
            for approval in approvals {
                summary = permit_facts(summary, approval, token_metadata);
            }
            for warning in permit_warnings(approvals, token_metadata) {
                summary = summary.warning(warning);
            }
        }
        PermitInterpretation::Unrecognized => {
            // Saying "nothing" here would be a claim the wallet cannot make.
            // It recognizes permits; everything else is a payload whose
            // meaning lives entirely in the types below.
            summary = summary.fact(
                "Token approvals",
                "None that this wallet recognizes. That is not a promise this payload grants \
                 nothing — read the types and values below and judge what a signature over them \
                 lets the requester do.",
            );
        }
        PermitInterpretation::Refused(reason) => {
            summary = summary.fact(
                "Token approvals",
                format!("This payload is shaped like a permit but was refused: {reason}"),
            );
            summary = summary.warning(format!(
                "This payload has the shape of a token permit but does not check out: {reason}. \
                 A permit that does not name this account as the owner is signed for somebody \
                 else's benefit. Do not approve it unless you know exactly why it is shaped this \
                 way."
            ));
        }
    }

    summary = summary.section_kind(ApprovalSectionKind::Action, "Structured message");
    for (label, value) in structured_message_rows(&request.typed_data) {
        summary = summary.fact(label, value);
    }

    summary = summary.warning(
        "Review every type, domain, and value. Names are untrusted and Unicode may contain \
         confusable or bidirectional characters.",
    );
    if dangerous_display {
        summary = summary.warning(
            "The typed data contains control, bidirectional, invisible, or glyph-changing \
             characters. They are escaped in the exact payload below.",
        );
    }
    ReviewDocument::from_request(summary, vec![exact_payload])
}

/// One permit rendered as the transaction path renders an allowance: the
/// amount with its token, who may draw it, and — separately — how long the
/// signature lives and how long the allowance does.
fn permit_facts(
    summary: ApprovalRequest,
    approval: &PermitApproval,
    token_metadata: &TokenMetadataMap,
) -> ApprovalRequest {
    let token = Address::from_str(&approval.token).ok();
    let display = token
        .and_then(|token| token_metadata.get(&token))
        .cloned()
        .unwrap_or_default();
    let amount = U256::from_str_radix(&approval.amount, 10).ok();
    let mut summary = summary
        .fact("Permit", permit_kind_label(&approval.kind))
        .fact(
            grant_label(&approval.kind),
            match (token, amount) {
                (Some(token), Some(amount)) => permit_amount(amount, token, &display),
                _ => format!("{} of {}", approval.amount, approval.token),
            },
        )
        .fact("To", approval.spender.clone());
    if let Some(expiration) = &approval.expiration {
        summary = summary.fact("Allowance usable until", permit_time(expiration));
    }
    if let Some(deadline) = &approval.deadline {
        summary = summary.fact("Signature usable until", permit_time(deadline));
    }
    summary
}

fn permit_warnings(approvals: &[PermitApproval], token_metadata: &TokenMetadataMap) -> Vec<String> {
    let mut warnings = Vec::new();
    for approval in approvals {
        let Some(token) = Address::from_str(&approval.token).ok() else {
            continue;
        };
        let display = token_metadata.get(&token).cloned().unwrap_or_default();
        let Some(amount) = U256::from_str_radix(&approval.amount, 10).ok() else {
            continue;
        };
        if amount != U256::ZERO && is_effectively_unlimited(amount) {
            warnings.push(format!(
                "Signing this grants an effectively unlimited {} allowance to {}. It can be drawn \
                 at any time, in full, until you revoke it.",
                token_label(token, &display),
                approval.spender
            ));
        }
    }
    if approvals
        .iter()
        .any(|approval| approval.kind == "permit2_signature_transfer")
    {
        warnings.push(
            "This is a Permit2 signature transfer: the signature itself moves the tokens once, to \
             the address named above. It does not need a further transaction from you."
                .into(),
        );
    }
    warnings.push(
        "A permit signature moves tokens exactly as an on-chain approval does, and it is redeemed \
         by whoever holds it rather than by this wallet. It will not appear in this wallet's \
         activity when it is used."
            .into(),
    );
    warnings
}

fn permit_amount(amount: U256, token: Address, display: &TokenMetadata) -> String {
    if is_effectively_unlimited(amount) {
        format!("Unlimited {}", token_label(token, display))
    } else {
        format_token_amount(amount, token, display)
    }
}

fn permit_kind_label(kind: &str) -> &str {
    match kind {
        "erc2612_permit" => "ERC-2612 token permit",
        "dai_permit" => "DAI-style token permit",
        "permit2_permit" => "Permit2 allowance",
        "permit2_signature_transfer" => "Permit2 signature transfer",
        other => other,
    }
}

/// A standing allowance and a one-shot transfer are not the same grant, and
/// the row that names the amount is where that difference is cheapest to say.
fn grant_label(kind: &str) -> &'static str {
    if matches!(kind, "permit2_signature_transfer") {
        "Transfers"
    } else {
        "Allows spending"
    }
}

/// A permit deadline as a readable instant.
///
/// The values are unix seconds, and the sentinels protocols use for "no
/// expiry" — `type(uint48).max`, `type(uint256).max` — are far outside any
/// date a person can read. Printed as digits they are indistinguishable from a
/// deadline minutes away, which is the reading that makes an unbounded grant
/// look bounded.
fn permit_time(seconds: &str) -> String {
    seconds
        .parse::<i64>()
        .ok()
        .and_then(|value| chrono::DateTime::from_timestamp(value, 0))
        .map_or_else(
            || format!("never — {seconds} is beyond any readable date"),
            |moment| moment.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        )
}

/// The domain and the top-level fields of the payload, as rows.
///
/// Nested values are shown as compact JSON rather than flattened: a reviewer
/// comparing a row against the exact payload below should find the same text
/// in both, and a flattening invents a shape the payload never had.
fn structured_message_rows(typed_data: &serde_json::Value) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    if let Some(primary_type) = typed_data
        .get("primaryType")
        .and_then(|value| value.as_str())
    {
        rows.push((
            "Type".to_owned(),
            crate::sanitize::stripped_capped(primary_type, 128),
        ));
    }
    if let Some(domain) = typed_data.get("domain").and_then(|value| value.as_object()) {
        for field in ["name", "version", "chainId", "verifyingContract", "salt"] {
            if let Some(value) = domain.get(field) {
                rows.push((format!("Domain {field}"), scalar_text(value)));
            }
        }
    }
    if let Some(message) = typed_data
        .get("message")
        .and_then(|value| value.as_object())
    {
        for (field, value) in message {
            rows.push((
                crate::sanitize::stripped_capped(field, 64),
                scalar_text(value),
            ));
        }
    }
    rows
}

/// One JSON value as a single reviewable line, sanitized the way every other
/// requester-authored string in a review is.
fn scalar_text(value: &serde_json::Value) -> String {
    let raw = match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => "null".to_owned(),
        other => other.to_string(),
    };
    crate::sanitize::stripped_capped(&raw, 512)
}

/// Build the reviewer's document for an EIP-191 message signature.
#[must_use]
pub fn message_review_document(request: &PendingMessage, message_bytes: &[u8]) -> ReviewDocument {
    let display = describe_message(message_bytes);
    let siwe = display.text.as_deref().and_then(parse_siwe);
    let signer = format!("{:#x}", request.wallet_address);
    let mut summary = ApprovalRequest::new(
        ApprovalKind::MessageSignature,
        "Review message signature",
        "This signature can prove account control. It does not submit a transaction.",
    )
    .fact("Wallet", request.wallet_id.clone())
    .fact("Signer", signer.clone())
    .fact(
        "Chain context",
        request
            .chain_id
            .clone()
            .unwrap_or_else(|| "Not specified".into()),
    )
    .fact("Sent to the wallet as", request.encoding.label())
    .fact("Byte length", display.byte_length.to_string())
    .fact("Line count", display.line_count.to_string())
    .fact(
        "Requester",
        request
            .requester
            .clone()
            .unwrap_or_else(|| "Unknown requester".into()),
    )
    .digest(request.digest.clone());
    summary.id = request.request_id;

    // The transaction review opens with what the wallet holds afterwards. The
    // honest equivalent here is that nothing moves and something is proved,
    // which is the fact a reader most often wants and previously had to infer
    // from a one-line summary.
    summary = summary
        .section_kind(ApprovalSectionKind::Effects, "What signing this does")
        .fact(
            "Balances",
            "Nothing moves. A message signature never transfers a token or submits a transaction.",
        )
        .fact(
            "Proves",
            format!(
                "Control of {signer}. Whoever receives the signature can present it as that proof \
                 to anyone, for as long as they hold it."
            ),
        );
    if let Some(siwe) = &siwe {
        summary = summary.fact(
            "Signs you in to",
            crate::sanitize::stripped_capped(&siwe.domain, 128),
        );
        summary = summary.fact(
            "Session expires",
            siwe.expiration_time.clone().unwrap_or_else(|| {
                "not stated — this login is valid until the site decides otherwise".into()
            }),
        );
    }

    if let Some(siwe) = &siwe {
        summary = siwe_facts(summary, siwe);
        if !siwe
            .address
            .eq_ignore_ascii_case(&request.wallet_address.to_checksum(None))
        {
            summary = summary.warning(format!(
                "This sign-in message names {} but would be signed by {signer}. A login proof for \
                 an account you are not signing as is of no use to you.",
                siwe.address
            ));
        }
    }

    for warning in display.warnings {
        summary = summary.warning(warning);
    }

    let mut payloads = Vec::with_capacity(2);
    if let Some(escaped) = display.escaped_text {
        payloads.push(format!(
            "Visible text (unsafe characters escaped):\n{escaped}"
        ));
    }
    payloads.push(format!("Exact message bytes:\n{}", request.message_hex));
    ReviewDocument::from_request(summary, payloads)
}

/// An ERC-4361 login, field by field.
///
/// These are the terms of the session being opened, and reading them off a
/// wall of plain text is exactly the work a review screen exists to do for
/// somebody. Recognition is structural, so a message that merely resembles a
/// login never reaches here and is never given a login's framing.
fn siwe_facts(summary: ApprovalRequest, siwe: &SiweMessage) -> ApprovalRequest {
    let mut summary = summary
        .section_kind(ApprovalSectionKind::Action, "Sign-in request (ERC-4361)")
        .fact("Site", crate::sanitize::stripped_capped(&siwe.domain, 128))
        .fact("Signing in as", siwe.address.clone())
        .fact("URI", crate::sanitize::stripped_capped(&siwe.uri, 256))
        .fact("Chain ID", siwe.chain_id.clone())
        .fact("Nonce", crate::sanitize::stripped_capped(&siwe.nonce, 128))
        .fact("Issued at", siwe.issued_at.clone());
    if let Some(statement) = &siwe.statement {
        summary = summary.fact(
            "Statement",
            crate::sanitize::stripped_capped(statement, 512),
        );
    }
    if let Some(expiration) = &siwe.expiration_time {
        summary = summary.fact("Expires at", expiration.clone());
    }
    if let Some(not_before) = &siwe.not_before {
        summary = summary.fact("Not valid before", not_before.clone());
    }
    if let Some(request_id) = &siwe.request_id {
        summary = summary.fact(
            "Request ID",
            crate::sanitize::stripped_capped(request_id, 128),
        );
    }
    for resource in &siwe.resources {
        summary = summary.fact("Resource", crate::sanitize::stripped_capped(resource, 256));
    }
    summary
}

/// Escape everything a review payload must never render raw.
///
/// Newlines survive because a payload is read as lines; every other
/// disallowed character becomes its `\u{…}` escape, so what the reviewer sees
/// is the same width and order as what gets signed.
#[must_use]
pub fn escape_review_payload(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character != '\n' && crate::sanitize::is_disallowed(character) {
                character.escape_unicode().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "signature_review_test.rs"]
mod tests;
