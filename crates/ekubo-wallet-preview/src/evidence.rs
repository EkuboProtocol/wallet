//! Project raw execution evidence into compact neural context. Large hex blobs
//! stay in the source document; selectors and typed ABI readings carry their
//! useful structure without consuming the language window with hex digits.

use crate::{CallSummary, slots::CallEvidence};

#[must_use]
pub fn project(call: &CallSummary) -> CallSummary {
    let mut projected = CallSummary {
        description: call.description.clone(),
        details: call.details.clone(),
        warnings: call.warnings.clone(),
        target: call.target.clone(),
        native_value: call.native_value.clone(),
        evidence: None,
    };
    let Some(evidence) = &call.evidence else {
        return projected;
    };
    let Some(hex) = hex_data(evidence) else {
        projected.warnings.push("Invalid calldata context".into());
        return projected;
    };
    if hex.len() >= 8 {
        projected
            .details
            .push(format!("Calldata selector: 0x{}", &hex[..8]));
    }
    for (address, label) in evidence.tokens.iter().take(16) {
        if address.len() <= 42 && label.len() <= 128 {
            projected
                .details
                .push(format!("Known token {address}: {label}"));
        }
    }
    // A decoded reading takes precedence over public selector guesses.
    for candidate in evidence
        .abi
        .iter()
        .filter(|_| call.description.is_none())
        .take(4)
    {
        let source = if candidate.contract_match {
            "Contract ABI"
        } else {
            "Unverified selector candidate"
        };
        let name = candidate.signature.split('(').next().unwrap_or_default();
        if projected.description.is_none() && !name.is_empty() {
            projected.description = Some(format!("{source}: {}", split_identifier(name)));
        }
        projected
            .details
            .push(format!("{source}: {}", candidate.signature));
        for (name, value) in candidate.arguments.iter().take(16) {
            if value.len() <= 256 {
                projected
                    .details
                    .push(format!("ABI {}: {value}", split_identifier(name)));
            }
        }
    }
    projected
}

pub(crate) fn address(text: &str) -> Option<&str> {
    let start = text.find("0x")?;
    let candidate = text.get(start..start + 42)?;
    candidate[2..]
        .bytes()
        .all(|b| b.is_ascii_hexdigit())
        .then_some(candidate)
}

pub(crate) fn same_address_or_label(first: &str, second: &str) -> bool {
    match (address(first), address(second)) {
        (Some(first), Some(second)) => first.eq_ignore_ascii_case(second),
        _ => !second.trim().is_empty() && first.trim().eq_ignore_ascii_case(second.trim()),
    }
}

/// Recognize canonical ERC-20 approval bytes. The source still must provide
/// token metadata to interpret the integer as a human amount.
pub(crate) fn approval_spender(evidence: &CallEvidence) -> Option<String> {
    if evidence.calldata.len() != 138 {
        return None;
    }
    let hex = hex_data(evidence)?;
    (hex.len() == 136
        && hex[..8].eq_ignore_ascii_case("095ea7b3")
        && hex[8..32].bytes().all(|b| b == b'0'))
    .then(|| format!("0x{}", &hex[32..72]))
}

pub(crate) fn unlimited_approval(evidence: &CallEvidence) -> bool {
    approval_spender(evidence).is_some()
        && hex_data(evidence).is_some_and(|hex| hex[72..].bytes().all(|b| b == b'f' || b == b'F'))
}

fn hex_data(evidence: &CallEvidence) -> Option<&str> {
    let hex = evidence.calldata.strip_prefix("0x")?;
    (hex.len().is_multiple_of(2) && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hex)
}

fn split_identifier(text: &str) -> String {
    let mut words = String::new();
    for (index, character) in text.chars().enumerate() {
        if character == '_' || (index != 0 && character.is_uppercase()) {
            words.push(' ');
        }
        if character != '_' {
            words.extend(character.to_lowercase());
        }
    }
    words
}

#[cfg(test)]
#[path = "evidence_test.rs"]
mod tests;
