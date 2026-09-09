//! Offline selector hints. A byte-exact ABI match is still not contract identity.
//! The immutable snapshot is searched without inflating the whole directory.

use std::{
    collections::VecDeque,
    io::Read as _,
    sync::{Arc, Mutex},
};

use alloy::{dyn_abi::JsonAbiExt, json_abi::Function};
use flate2::read::ZlibDecoder;

use crate::clear_signing::{CalldataCandidate, within_declared_width};

const DATA: &[u8] = include_bytes!("../fourbyte/signatures.bin");
const MAX_BODY: usize = 65_536;
const MAX_BLOCK: usize = 262_144;
const MAX_MATCHES: usize = 4;
const MAX_SIGNATURES: usize = 64;
type Blocks = VecDeque<(usize, Arc<[u8]>)>;
static CACHE: Mutex<Blocks> = Mutex::new(VecDeque::new());

fn word(bytes: &[u8], offset: usize) -> Option<usize> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?) as usize)
}

fn block(index: usize, count: usize) -> Option<Arc<[u8]>> {
    if let Some((_, bytes)) = CACHE.lock().ok()?.iter().find(|(key, _)| *key == index) {
        return Some(Arc::clone(bytes));
    }
    let offset = word(DATA, 12 + index * 12 + 4)?;
    let length = word(DATA, 12 + index * 12 + 8)?;
    let start = 12 + count * 12 + offset;
    let mut bytes = Vec::new();
    ZlibDecoder::new(DATA.get(start..start + length)?)
        .take((MAX_BLOCK + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_BLOCK {
        return None;
    }
    let bytes: Arc<[u8]> = bytes.into();
    let mut cache = CACHE.lock().ok()?;
    // A small FIFO bounds resident decompressed data even across many plans.
    if cache.len() >= 64 {
        cache.pop_front();
    }
    cache.push_back((index, Arc::clone(&bytes)));
    Some(bytes)
}

fn signatures(selector: [u8; 4]) -> Option<Vec<String>> {
    let key = u32::from_be_bytes(selector) as usize;
    let count = word(DATA, 8)?;
    let mut low = 0;
    let mut high = count;
    while low < high {
        let middle = low + (high - low) / 2;
        if word(DATA, 12 + middle * 12)? <= key {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    let bytes = block(low.checked_sub(1)?, count)?;
    let rows = word(&bytes, 0)?;
    for row in 0..rows {
        if word(&bytes, 4 + row * 12)? != key {
            continue;
        }
        let start = 4 + rows * 12 + word(&bytes, 8 + row * 12)?;
        let length = word(&bytes, 12 + row * 12)?;
        let text = std::str::from_utf8(bytes.get(start..start + length)?).ok()?;
        return Some(
            text.split(';')
                .take(MAX_SIGNATURES)
                .map(str::to_owned)
                .collect(),
        );
    }
    None
}

/// Candidate functions for otherwise undecoded calldata. Callers must prefer
/// successful clear signing and standard decoding. No match establishes safety.
#[must_use]
pub fn calldata_candidates(calldata: &[u8]) -> Vec<CalldataCandidate> {
    let Some((selector, body)) = calldata.split_at_checked(4) else {
        return Vec::new();
    };
    if body.len() > MAX_BODY || !body.len().is_multiple_of(32) {
        return Vec::new();
    }
    let selector: [u8; 4] = selector.try_into().expect("four-byte split");
    signatures(selector)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|signature| decode_candidate(&signature, selector, body))
        .take(MAX_MATCHES)
        .collect()
}

fn decode_candidate(signature: &str, selector: [u8; 4], body: &[u8]) -> Option<CalldataCandidate> {
    // Bound parser nesting and string allocation before touching public data.
    if signature.len() > 1024
        || signature
            .bytes()
            .filter(|b| *b == b'(' || *b == b'[')
            .count()
            > 32
    {
        return None;
    }
    let function = Function::parse(signature).ok()?;
    if function.selector().as_slice() != selector {
        return None;
    }
    let values = function.abi_decode_input(body).ok()?;
    if !values.iter().all(within_declared_width)
        || function.abi_encode_input_raw(&values).ok()? != body
    {
        return None;
    }
    let arguments = values
        .iter()
        .take(16)
        .enumerate()
        .map(|(index, value)| {
            // Nested data stays typed; the display projection has a separate cap.
            (
                format!("arg{index}"),
                crate::sanitize::stripped_capped(&format!("{value:?}"), 256),
            )
        })
        .collect();
    Some(CalldataCandidate {
        signature: function.signature(),
        contract_match: false,
        arguments,
    })
}

/// Supplemental review lines keep ambiguity visible and never replace the
/// authoritative target/calldata or the unrecognized-call status.
#[must_use]
pub fn details(candidates: &[CalldataCandidate]) -> Vec<String> {
    candidates
        .iter()
        .flat_map(|candidate| {
            let mut lines = vec![format!(
                "Possible function: {}",
                crate::sanitize::stripped_capped(&candidate.signature, 180)
            )];
            lines.extend(
                candidate
                    .arguments
                    .iter()
                    .map(|(name, value)| format!("{name}: {value}")),
            );
            lines
        })
        .collect()
}

#[cfg(test)]
#[path = "fourbyte_test.rs"]
mod tests;
