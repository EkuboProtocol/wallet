//! Reviewing and signing the two payloads no policy can evaluate: an EIP-191
//! message and an EIP-712 typed-data payload.
//!
//! A transaction's review document is authored in the kernel, by
//! `orchestrator::approve_transaction`, so every caller that approves one gets
//! the same document and the same guard ladder. These two had no such home:
//! they were written inline in the one command that used them. A second caller
//! — a dapp reached over `WalletConnect` proposes exactly these payloads — would
//! have had to copy them, and a copied review is a review that drifts.
//!
//! So this module owns them, and both `review` and `connect` go through it.
//! What each caller keeps is only how it reports the outcome.
//!
//! The ladder here is the same one the transaction path climbs, for the same
//! reasons: the payload is re-derived from the stored record and checked
//! against the digest it was queued under, the reviewer sees the exact bytes,
//! platform owner authentication follows the review, and every mutable input is
//! re-read afterwards — because the review can take as long as a person takes,
//! and the store write at the end repeats the row checks atomically.
//!
//! This module owns only the review. Everything from owner authentication
//! onward — the re-read, the signature, the store write — belongs to
//! `orchestrator::sign_reviewed_message` and its typed-data twin, because those
//! are the steps that must not be skippable. Nothing here can reach key
//! material: `load_matching_signer` is private to the kernel crate, so a
//! signature is obtainable only by calling an entry point that confirms
//! presence first. Drawing a review and then forgetting to authenticate is not
//! a mistake this file is able to make.

use crate::{
    approval::{ApprovalDecision, ApprovalKind, ApprovalRequest},
    config::ConfigStore,
    custody::OsKeyStore,
    human_presence::PlatformHumanPresence,
    message::{
        MessageStatus, MessageStore, PendingMessage, describe_message, message_digest, parse_siwe,
        siwe_warnings,
    },
    typed_data::{
        PendingTypedData, PermitApproval, TypedDataStatus, TypedDataStore,
        interpret_permit_approvals, parse_typed_data,
    },
};
use anyhow::{Result, ensure};
use std::io::{self, Write as _};

/// What a message review decided.
pub enum MessageDecision {
    Rejected(PendingMessage),
    Signed(PendingMessage),
}

/// What a typed-data review decided.
pub enum TypedDataDecision {
    Rejected(PendingTypedData),
    Signed(PendingTypedData),
}

/// Review one queued EIP-191 message and resolve it, either way.
///
/// Who asked is read from the row rather than passed in. A dapp reached over
/// `WalletConnect` names itself when it queues the request; an MCP agent
/// carries no record of which agent. A signature is the one thing here that
/// authorizes something without naming a counterparty in its own bytes, so
/// "who asked for this" is a fact the reviewer otherwise has to supply from
/// memory — and taking it from whichever caller happens to be drawing the
/// review named the wrong dapp for a row another one had queued.
///
/// `no_confirm` skips only the interactive review. Owner authentication still
/// follows, and the transcript is still printed, so the reviewer sees the
/// subject even on the path that answers the question for them.
pub async fn decide_message(
    config: &ConfigStore,
    mut store: MessageStore,
    request: PendingMessage,
    no_confirm: bool,
) -> Result<MessageDecision> {
    ensure!(
        request.status == MessageStatus::AwaitingApproval,
        "message request is not awaiting approval"
    );
    let wallet = config.wallet(&request.wallet_id)?;
    if let Some(chain_id) = &request.chain_id {
        config.network_by_chain_id(chain_id)?;
    }
    let message = request.message_bytes()?;
    let digest = message_digest(&message);
    ensure!(
        format!("{digest:#x}") == request.digest,
        "message request no longer matches its stored bytes"
    );
    let display = describe_message(&message);
    let siwe = display.text.as_deref().and_then(parse_siwe);
    // Re-check the account the login names here too: the request was refused
    // at creation, and nothing may have changed the wallet under it since.
    if let Some(siwe) = &siwe {
        ensure!(
            siwe.address == wallet.address.to_checksum(None),
            "this sign-in message names account {}, but wallet {} is {}",
            siwe.address,
            wallet.id,
            wallet.address.to_checksum(None)
        );
    }

    let mut approval = ApprovalRequest::new(
        ApprovalKind::MessageSignature,
        "Approve message signature",
        "Sign these exact bytes with the wallet key, prefixed as an EIP-191 personal message. \
         The complete message is shown at the end of this review.",
    )
    .fact("Wallet", &request.wallet_id)
    .fact("Signer", wallet.address.to_checksum(None))
    .fact(
        "Asked by",
        request
            .requester
            .as_deref()
            .unwrap_or("an MCP agent; this queue does not record which"),
    )
    .fact(
        "Chain",
        request.chain_id.as_ref().map_or_else(
            || "not stated; a message signature binds no chain".to_owned(),
            |chain_id| format!("{chain_id}, claimed by the requester"),
        ),
    )
    .fact(
        "Size",
        format!(
            "{} bytes, {} line(s), sent as {}",
            display.byte_length,
            display.line_count,
            match request.encoding {
                crate::message::MessageEncoding::Text => "text",
                crate::message::MessageEncoding::Hex => "raw bytes",
            }
        ),
    );

    if let Some(siwe) = &siwe {
        approval = approval
            .fact("Sign in to", &siwe.domain)
            .fact("Account", &siwe.address)
            .fact("URI", &siwe.uri)
            .fact("Chain ID in message", &siwe.chain_id)
            .fact("Nonce", &siwe.nonce)
            .fact("Issued at", &siwe.issued_at);
        if let Some(statement) = &siwe.statement {
            approval = approval.fact("Statement", terminal_safe_excerpt(statement));
        }
        for (label, value) in [
            ("Expires at", siwe.expiration_time.as_deref()),
            ("Not before", siwe.not_before.as_deref()),
            ("Request ID", siwe.request_id.as_deref()),
        ] {
            if let Some(value) = value {
                approval = approval.fact(label, value);
            }
        }
        for (index, resource) in siwe.resources.iter().enumerate() {
            approval = approval.fact(
                format!("Resource {}", index + 1),
                terminal_safe_excerpt(resource),
            );
        }
        for warning in siwe_warnings(
            siwe,
            request.chain_id.as_deref(),
            config.network_by_chain_id(&siwe.chain_id).is_ok(),
            chrono::Utc::now(),
        ) {
            approval = approval.warning(warning);
        }
    } else {
        approval = approval
            .fact(
                "Message",
                display
                    .escaped_text
                    .as_deref()
                    .map_or_else(|| request.message_hex.clone(), terminal_safe_excerpt),
            )
            .warning(
                "This is not a recognized sign-in message. A message signature can authorize an \
                 off-chain order, a delegation, or an account link; verify every byte of the \
                 complete message against whatever asked for it.",
            );
    }
    for warning in &display.warnings {
        approval = approval.warning(warning.clone());
    }
    approval = approval
        .fact("Signing hash", &request.digest)
        .digest(&request.digest);
    approval.id = request.request_id;

    print_review_transcript(&serde_json::json!({
        "approval": approval,
        "message": {
            "hex": request.message_hex,
            "text": display.text,
            "escaped_text": display.escaped_text,
            "byte_length": display.byte_length,
            "encoding": request.encoding,
            "siwe": siwe,
        },
    }))?;
    if !no_confirm
        && !reviewer_approved(
            approval,
            message_payload_lines(&request.message_hex, &display),
        )
        .await?
    {
        return Ok(MessageDecision::Rejected(store.reject(request.request_id)?));
    }

    // Owner authentication, the re-read of every mutable input this review may
    // have raced, and the signature are one step in the kernel: this module
    // draws the review and has no way to reach key material itself.
    Ok(MessageDecision::Signed(
        crate::orchestrator::sign_reviewed_message(
            config,
            &mut store,
            &request,
            &wallet,
            digest,
            &PlatformHumanPresence,
            &OsKeyStore,
        )
        .await?,
    ))
}

/// Review one queued EIP-712 payload and resolve it, either way.
///
/// Who asked is read from the row, on the same terms as [`decide_message`].
pub async fn decide_typed_data(
    config: &ConfigStore,
    mut store: TypedDataStore,
    request: PendingTypedData,
    no_confirm: bool,
) -> Result<TypedDataDecision> {
    ensure!(
        request.status == TypedDataStatus::AwaitingApproval,
        "typed-data request is not awaiting approval"
    );
    let wallet = config.wallet(&request.wallet_id)?;
    config.network_by_chain_id(&request.chain_id)?;
    let (typed, chain_id, digest) = parse_typed_data(&request.typed_data)?;
    ensure!(
        chain_id.to_string() == request.chain_id && format!("{digest:#x}") == request.digest,
        "typed-data request no longer matches its stored payload"
    );
    let permit_approvals = interpret_permit_approvals(&typed, wallet.address)?;

    let mut approval = ApprovalRequest::new(
        ApprovalKind::TypedDataSignature,
        "Approve typed-data signature",
        "Review and sign this exact EIP-712 payload with the wallet key. The complete payload is \
         shown at the end of this review.",
    )
    .fact("Wallet", &request.wallet_id)
    // As the message review already does. A wallet id is a reusable name;
    // the address is what a permit's `owner` field has to be read against,
    // and it is the only way the reviewer can tell that this payload
    // authorizes the account they think it does.
    .fact("Signer", wallet.address.to_checksum(None))
    .fact(
        "Asked by",
        request
            .requester
            .as_deref()
            .unwrap_or("an MCP agent; this queue does not record which"),
    )
    .fact("Chain ID", &request.chain_id)
    .fact("Primary type", &typed.primary_type)
    .fact(
        "Domain",
        format!(
            "name={:?}; version={:?}; verifyingContract={}",
            typed.domain.name.as_deref().unwrap_or("<none>"),
            typed.domain.version.as_deref().unwrap_or("<none>"),
            typed
                .domain
                .verifying_contract
                .map_or_else(|| "<none>".into(), |contract| contract.to_checksum(None)),
        ),
    )
    .fact("Signing hash", &request.digest)
    .digest(&request.digest);
    approval.id = request.request_id;

    // A vendored ERC-7730 descriptor reading, when the domain matches one
    // exactly. Supplemental display only: the printed payload and the permit
    // decode below stay authoritative.
    if let Some(reading) = crate::clear_signing::interpret_typed_data(&request.typed_data).await {
        approval = approval.fact("Reads as", reading.intent);
        for line in reading.fields {
            approval = approval.fact("·", line);
        }
    }

    if let Some(approvals) = &permit_approvals {
        // A standing allowance and a one-time transfer authorization are not
        // the same grant, and the decoder has always known which is which --
        // `kind` says so. The renderer said "allow X to spend up to Y" for
        // both. A SignatureTransfer creates nothing the owner can later
        // inspect or revoke: the spender consumes it once, to a recipient
        // chosen when they execute it, and there is no allowance to go and
        // look at afterwards. Describing that as an allowance tells the reader
        // to expect a thing that will not exist.
        let mut any_transfer = false;
        for (index, permit) in approvals.iter().enumerate() {
            let one_time = permit.kind == "permit2_signature_transfer";
            any_transfer |= one_time;
            let grant = permit_grant_sentence(permit, one_time);
            approval = approval.fact(
                format!("Grants approval {}", index + 1),
                format!(
                    "{grant}{}{}",
                    // Two different clocks, and calling both "deadline" is
                    // what made the shorter one look like the limit. For
                    // Permit2 this one bounds only how long the signature may
                    // be submitted; the allowance it grants then lasts until
                    // `expiration`, which can be far later or maximal.
                    permit
                        .deadline
                        .as_deref()
                        .map_or_else(String::new, |deadline| {
                            if permit.expiration.is_some() {
                                format!("; signature usable until {deadline}")
                            } else {
                                format!("; deadline {deadline}")
                            }
                        }),
                    permit
                        .expiration
                        .as_deref()
                        .map_or_else(String::new, |expiration| format!(
                            "; ALLOWANCE LASTS UNTIL {expiration}"
                        )),
                ),
            );
        }
        if any_transfer {
            approval = approval.warning(
                "A one-time transfer authorization is not an allowance: there is nothing to \
                 inspect or revoke afterwards, and the recipient is chosen by whoever executes \
                 it, not by this signature.",
            );
        }
        approval = approval.warning(
            "Signing grants the token approvals listed above. No policy limits what a signature \
             authorizes, and nothing stops the holder collecting more of them, so approve this \
             only if you expected exactly these approvals now.",
        );
    } else {
        approval = approval.warning(
            "This payload is not a recognized permit. A typed-data signature can authorize \
             transfers, orders, or delegations; verify every field of the printed payload.",
        );
    }

    print_review_transcript(&serde_json::json!({
        "approval": approval,
        "typed_data": request.typed_data,
    }))?;
    if !no_confirm
        && !reviewer_approved(approval, typed_data_payload_lines(&request.typed_data)).await?
    {
        return Ok(TypedDataDecision::Rejected(
            store.reject(request.request_id)?,
        ));
    }

    // As in `decide_message`: presence, re-read, and signature are the
    // kernel's, and this module never holds a signer.
    Ok(TypedDataDecision::Signed(
        crate::orchestrator::sign_reviewed_typed_data(
            config,
            &mut store,
            &request,
            &wallet,
            digest,
            &PlatformHumanPresence,
            &OsKeyStore,
        )
        .await?,
    ))
}

/// Keep one approval fact to a readable length; the complete message always
/// follows at the end of the review document.
#[must_use]
pub fn terminal_safe_excerpt(value: &str) -> String {
    const MAX_FACT_CHARACTERS: usize = 200;
    if value.chars().count() <= MAX_FACT_CHARACTERS {
        return value.to_owned();
    }
    let head: String = value.chars().take(MAX_FACT_CHARACTERS).collect();
    format!("{head}… (complete message below)")
}

/// Write a review transcript to stderr with nothing in it that can redraw the
/// terminal it lands in.
///
/// `serde_json` escapes quotes, backslashes, and C0 control characters, and
/// nothing else. A right-to-left override, an isolate, or a zero-width space —
/// in a token symbol, a message body, a policy label, an RPC error — is
/// perfectly valid JSON and reaches the approver's terminal verbatim. Every
/// other surface that shows a human untrusted text routes through
/// `sanitize`; these transcripts stream straight to a file descriptor and so
/// did not, which is the one place it matters most.
pub fn review_transcript_text(value: &serde_json::Value) -> Result<String> {
    Ok(crate::sanitize::terminal_safe_multiline(
        &serde_json::to_string_pretty(value)?,
    ))
}

pub fn print_review_transcript(value: &serde_json::Value) -> Result<()> {
    let mut stderr = io::stderr().lock();
    stderr.write_all(review_transcript_text(value)?.as_bytes())?;
    stderr.write_all(b"\n")?;
    stderr.flush()?;
    Ok(())
}

/// Ask for a decision and return it, for the queued signing requests where
/// declining has somewhere to be written.
///
/// These reviews run full screen: the complete payload scrolls inside the
/// review itself rather than somewhere above the prompt, and the JSON record
/// printed to the transcript beforehand stays in the scrollback for after
/// the alternate screen closes.
pub async fn reviewer_approved(
    request: ApprovalRequest,
    payload: Vec<crate::fullscreen::Line>,
) -> Result<bool> {
    Ok(
        crate::approve_tui::review_fullscreen(&request, payload).await?
            == ApprovalDecision::Approved,
    )
}

/// How one decoded permit reads in the review.
///
/// A standing allowance and a one-time transfer authorization are not the same
/// grant, and the decoder has always known which is which — `kind` says so.
/// The renderer described both as "allow X to spend up to Y". A Permit2
/// `SignatureTransfer` creates nothing the owner can later inspect or revoke:
/// the spender consumes it once, to a recipient chosen when they execute it.
/// Calling that an allowance tells the reader to expect a thing that will not
/// exist, and to look for a revocation that is not there.
///
/// Separate from the review so both sentences are testable without building a
/// request, a wallet, and a configuration to reach them.
pub(crate) fn permit_grant_sentence(permit: &PermitApproval, one_time: bool) -> String {
    if one_time {
        format!(
            "{}: one-time transfer of up to {} of token {}, which {} may execute once to a \
             recipient it chooses",
            permit.kind, permit.amount, permit.token, permit.spender,
        )
    } else {
        format!(
            "{}: allow {} to spend up to {} of token {}",
            permit.kind, permit.spender, permit.amount, permit.token,
        )
    }
}

/// Payload text for the full-screen review: every control or bidirectional
/// character becomes a visible `\u{..}` escape rather than a silent space,
/// because in a payload being signed the tricky characters are exactly the
/// ones the reviewer needs to see.
fn escape_payload_line(line: &str) -> String {
    use std::fmt::Write as _;
    let mut escaped = String::with_capacity(line.len());
    for character in line.chars() {
        if crate::sanitize::is_disallowed(character) {
            let _ = write!(escaped, "\\u{{{:04x}}}", character as u32);
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// The complete message, line by line, for the scrollable review document.
#[must_use]
pub fn message_payload_lines(
    message_hex: &str,
    display: &crate::message::MessageDisplay,
) -> Vec<crate::fullscreen::Line> {
    use crate::fullscreen::Span;
    use crate::tui::Tone;
    let mut lines = vec![
        Vec::new(),
        vec![Span::toned("Complete message", Tone::Emphasis)],
    ];
    if let Some(text) = &display.text {
        lines.extend(
            text.split('\n')
                .map(|line| vec![Span::plain(escape_payload_line(line))]),
        );
    } else {
        lines.push(vec![Span::toned("Not valid UTF-8.", Tone::Muted)]);
    }
    // Always, not only when the decode failed. The rendering above is not
    // injective: `escape_payload_line` turns a real U+202E into the characters
    // `\u{202e}`, and a message that literally contains those characters
    // renders identically — so the reviewer cannot tell which one they are
    // being asked to sign. Confusables have the same problem in the other
    // direction, a Cyrillic а being indistinguishable from a Latin a. The hex
    // is the only thing on this screen that separates them, and it is what is
    // actually hashed.
    lines.push(Vec::new());
    lines.push(vec![Span::toned("Exact bytes signed", Tone::Emphasis)]);
    lines.extend(
        hex_payload_rows(message_hex)
            .into_iter()
            .map(|row| vec![Span::plain(row)]),
    );
    lines
}

/// Split a 0x-prefixed hex body into fixed-width rows.
///
/// One unbroken line of hex is re-wrapped by the viewport at whatever width
/// the terminal happens to be, so the same message looks different in two
/// windows and neither grouping means anything. Fixed rows of 32 bytes make
/// the layout a property of the message.
fn hex_payload_rows(message_hex: &str) -> Vec<String> {
    const BYTES_PER_ROW: usize = 32;
    let digits = message_hex.strip_prefix("0x").unwrap_or(message_hex);
    if digits.is_empty() {
        return vec!["0x (empty)".to_owned()];
    }
    digits
        .as_bytes()
        .chunks(BYTES_PER_ROW * 2)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect()
}

/// The complete EIP-712 payload, pretty-printed, for the scrollable review
/// document.
#[must_use]
pub fn typed_data_payload_lines(typed_data: &serde_json::Value) -> Vec<crate::fullscreen::Line> {
    use crate::fullscreen::Span;
    use crate::tui::Tone;
    let pretty =
        serde_json::to_string_pretty(typed_data).unwrap_or_else(|_| typed_data.to_string());
    let mut lines = vec![
        Vec::new(),
        vec![Span::toned("Complete EIP-712 payload", Tone::Emphasis)],
    ];
    lines.extend(
        pretty
            .split('\n')
            .map(|line| vec![Span::plain(escape_payload_line(line))]),
    );
    lines
}

#[cfg(test)]
#[path = "signing_review_test.rs"]
mod tests;
