//! Translating a dapp's JSON-RPC parameters into the wallet's own vocabulary.
//!
//! Pure parsing: no chain access, no wallet state, no signing. It is separate
//! from the session so that the awkward parts — and every one of these methods
//! has an awkward part — can be pinned down by tests directly.
//!
//! The rule this module follows throughout is that an ambiguity is refused
//! rather than guessed at. A quantity that is not a `0x` hex string is not
//! silently read as decimal, and a transaction field this wallet would have to
//! ignore is named in the refusal instead of being dropped quietly. The one
//! place it deliberately does guess is argument *order*, where the ecosystem
//! never settled on one and both orders are unambiguous to detect.

use alloy::primitives::{Address, Bytes, U256};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

/// A transaction a dapp asked to send, reduced to what an execution plan can
/// carry.
#[derive(Debug)]
pub struct TransactionRequest {
    pub from: Address,
    pub to: Address,
    pub data: Bytes,
    pub value: U256,
    /// The gas limit the dapp suggested, if any. Advisory: the wallet
    /// simulates and prepares its own, and this is shown to the reviewer only
    /// so a wild suggestion is visible.
    pub suggested_gas: Option<U256>,
    /// Fields the dapp sent that this wallet decides for itself. Surfaced in
    /// the review rather than dropped in silence, because the dapp asked for
    /// something specific and did not get it.
    pub overridden: Vec<String>,
}

/// Parse `eth_sendTransaction`.
pub fn parse_send_transaction(params: &Value) -> Result<TransactionRequest> {
    let object = params
        .as_array()
        .and_then(|array| array.first())
        .and_then(Value::as_object)
        .context("eth_sendTransaction takes an array holding one transaction object")?;

    let from = object
        .get("from")
        .and_then(Value::as_str)
        .context("the transaction has no `from` address")?;
    let from = Address::parse_checksummed(from, None)
        .or_else(|_| from.parse::<Address>())
        .context("the transaction's `from` is not a 20-byte address")?;

    // A plan step always has a target. Contract creation — `to` absent or null
    // — is a real transaction shape this wallet's plan model cannot express, so
    // it is refused by name rather than turned into a transfer to the zero
    // address, which is what dropping the field would amount to.
    let to = match object.get("to") {
        None | Some(Value::Null) => bail!(
            "this request deploys a contract, which this wallet cannot represent as an execution \
             plan. Deploy from a tool that signs its own transactions."
        ),
        Some(value) => {
            let to = value
                .as_str()
                .context("the transaction's `to` is not a string")?;
            Address::parse_checksummed(to, None)
                .or_else(|_| to.parse::<Address>())
                .context("the transaction's `to` is not a 20-byte address")?
        }
    };

    // `data` is the standard spelling and `input` the newer one; a dapp that
    // sends both and disagrees with itself is refused rather than resolved.
    let data = match (object.get("data"), object.get("input")) {
        (Some(data), Some(input)) if data != input => bail!(
            "the transaction sets both `data` and `input` to different values, so what it wants \
             executed is ambiguous"
        ),
        (Some(value), _) | (None, Some(value)) => parse_bytes(value)?,
        (None, None) => Bytes::new(),
    };

    let value = match object.get("value") {
        None | Some(Value::Null) => U256::ZERO,
        Some(value) => parse_quantity(value).context("the transaction's `value` is malformed")?,
    };

    let suggested_gas = match object.get("gas") {
        None | Some(Value::Null) => None,
        Some(value) => Some(parse_quantity(value).context("the transaction's `gas` is malformed")?),
    };

    // Everything the wallet decides for itself. Nonce comes from the chain at
    // signing time, fees from the simulation, and the chain from the session's
    // approved scope; honoring a dapp's opinion on any of them would let it
    // move a signature onto a different chain or ahead of a queued one.
    let mut overridden = Vec::new();
    for field in [
        "nonce",
        "gasPrice",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "chainId",
        "type",
    ] {
        if object.get(field).is_some_and(|value| !value.is_null()) {
            overridden.push(field.to_owned());
        }
    }

    Ok(TransactionRequest {
        from,
        to,
        data,
        value,
        suggested_gas,
        overridden,
    })
}

/// Parse `personal_sign`.
///
/// The parameter order is `[message, address]`, and enough dapps send
/// `[address, message]` that every production wallet accepts both. Detecting
/// which is which is unambiguous — one of them parses as a 20-byte address and
/// a message that also does is a 20-byte message, which `personal_sign` is
/// never used for — so this accepts both rather than failing on half the
/// ecosystem.
///
/// The message itself is hex when it is `0x`-prefixed and validly hex, and
/// literal UTF-8 otherwise. That is the de-facto rule every wallet implements.
/// It is ambiguous in principle, and the ambiguity is handled where it belongs:
/// the approval screen shows the exact bytes being hashed, so what is signed is
/// what was displayed.
/// Returns the bytes, the signer, and whether the dapp sent the message as hex
/// — the last only so the review can say how it arrived.
pub fn parse_personal_sign(params: &Value) -> Result<(Vec<u8>, Address, bool)> {
    let array = params
        .as_array()
        .context("personal_sign takes an array of two parameters")?;
    ensure!(
        array.len() >= 2,
        "personal_sign takes a message and an address"
    );
    let first = array[0].as_str().unwrap_or_default();
    let second = array[1].as_str().unwrap_or_default();

    let (message, address) = match (address_of(first), address_of(second)) {
        (_, Some(address)) => (first, address),
        (Some(address), None) => (second, address),
        (None, None) => bail!("neither personal_sign parameter is a 20-byte address"),
    };
    let (bytes, was_hex) = decode_message(message);
    Ok((bytes, address, was_hex))
}

/// Parse `eth_signTypedData`, `_v3`, and `_v4`.
///
/// Parameters are `[address, typedData]`, where the payload may arrive as a
/// JSON string or as an object — both are common — and the order is again
/// sometimes reversed.
pub fn parse_sign_typed_data(params: &Value) -> Result<(Address, Value)> {
    let array = params
        .as_array()
        .context("eth_signTypedData takes an array of two parameters")?;
    ensure!(
        array.len() >= 2,
        "eth_signTypedData takes an address and a typed-data payload"
    );

    let (address, payload) = match (
        array[0].as_str().and_then(address_of),
        array[1].as_str().and_then(address_of),
    ) {
        (Some(address), _) => (address, &array[1]),
        (None, Some(address)) => (address, &array[0]),
        (None, None) => bail!("neither eth_signTypedData parameter is a 20-byte address"),
    };

    let typed_data = match payload {
        Value::String(text) => serde_json::from_str::<Value>(text)
            .context("the typed-data payload is a string that is not valid JSON")?,
        other => other.clone(),
    };
    ensure!(
        typed_data.is_object(),
        "the typed-data payload is not a JSON object"
    );
    Ok((address, typed_data))
}

/// Parse `wallet_switchEthereumChain`, which carries a hex chain id.
pub fn parse_switch_chain(params: &Value) -> Result<u64> {
    let chain_id = params
        .as_array()
        .and_then(|array| array.first())
        .and_then(|value| value.get("chainId"))
        .context("wallet_switchEthereumChain takes an array holding one `{chainId}` object")?;
    let chain_id = chain_id
        .as_str()
        .context("the requested chainId is not a string")?;
    let value = parse_quantity(&Value::String(chain_id.to_owned()))
        .context("the requested chainId is not a hex quantity")?;
    u64::try_from(value).context("the requested chainId does not fit in 64 bits")
}

/// A 20-byte address, or nothing.
fn address_of(value: &str) -> Option<Address> {
    Address::parse_checksummed(value, None)
        .or_else(|_| value.parse::<Address>())
        .ok()
}

/// The bytes a `personal_sign` message denotes.
///
/// Hex when it is `0x`-prefixed with an even number of hex digits, literal
/// UTF-8 otherwise — including a `0x` string that is not really hex, which is
/// a message that happens to start with those two characters.
fn decode_message(message: &str) -> (Vec<u8>, bool) {
    if let Some(body) = message.strip_prefix("0x")
        && body.len() % 2 == 0
        && body.bytes().all(|byte| byte.is_ascii_hexdigit())
        && let Ok(bytes) = hex::decode(body)
    {
        return (bytes, true);
    }
    (message.as_bytes().to_vec(), false)
}

/// A JSON-RPC quantity: `0x`-prefixed hex, and nothing else.
///
/// Decimal strings and JSON numbers are refused. `"100"` means 256 to a hex
/// reader and 100 to a decimal one, and there is no way to tell which the
/// sender meant — for a transaction value, guessing wrong is a 2.5x error in
/// the amount being sent.
fn parse_quantity(value: &Value) -> Result<U256> {
    let text = value
        .as_str()
        .context("must be a `0x`-prefixed hex string, not a number")?;
    let body = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .context("must be `0x`-prefixed hex")?;
    ensure!(!body.is_empty(), "is an empty hex quantity");
    U256::from_str_radix(body, 16).context("is not a valid hex quantity")
}

/// Calldata: `0x`-prefixed hex, or the empty string for none.
fn parse_bytes(value: &Value) -> Result<Bytes> {
    if value.is_null() {
        return Ok(Bytes::new());
    }
    let text = value
        .as_str()
        .context("the transaction's calldata is not a string")?;
    if text.is_empty() || text == "0x" {
        return Ok(Bytes::new());
    }
    let body = text
        .strip_prefix("0x")
        .context("the transaction's calldata is not `0x`-prefixed")?;
    let bytes = hex::decode(body).context("the transaction's calldata is not valid hex")?;
    Ok(Bytes::from(bytes))
}

#[cfg(test)]
#[path = "request_test.rs"]
mod tests;
