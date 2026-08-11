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

use alloy_primitives::{Address, Bytes, U256};
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
/// `[address, message]` that every production wallet accepts both. Usually
/// exactly one of the two parses as a 20-byte address, which settles it.
///
/// Not always, though: a 20-byte message is a perfectly good EIP-191 input,
/// and one that happens to be address-shaped makes both parameters parse.
/// This used to claim that could not happen and take the second as the signer
/// regardless, so `[wallet, address_shaped_message]` — a legitimate request in
/// the order half the ecosystem sends — read the *message* as the signer, and
/// the foreign-signer check then refused it. Deterministically, every time.
///
/// `controlled` breaks the tie, because the tie has an answer: the signer is
/// an account this session signs for and the message is not. When neither
/// parameter is that account the ambiguity does not matter — the request is
/// refused either way — so the old reading stands and the refusal names the
/// second one.
///
/// The message itself is hex when it is `0x`-prefixed and validly hex, and
/// literal UTF-8 otherwise. That is the de-facto rule every wallet implements.
/// It is ambiguous in principle, and the ambiguity is handled where it belongs:
/// the approval screen shows the exact bytes being hashed, so what is signed is
/// what was displayed.
/// Returns the bytes, the signer, and whether the dapp sent the message as hex
/// — the last only so the review can say how it arrived.
pub fn parse_personal_sign(
    params: &Value,
    controlled: Address,
) -> Result<(Vec<u8>, Address, bool)> {
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
        // Both address-shaped: the one this session controls is the signer,
        // and if neither is, either reading is refused downstream.
        (Some(leading), Some(trailing)) if leading == controlled && trailing != controlled => {
            (second, leading)
        }
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

/// The `wallet_sendCalls` version this wallet answers.
///
/// `1.0.0` returned a bare string id where `2.0.0` returns an object, so a
/// wallet cannot serve both from one response shape. Refusing the older one by
/// name beats answering it in a shape its caller will not understand.
pub const SEND_CALLS_VERSION: &str = "2.0.0";

/// One call out of an EIP-5792 batch.
#[derive(Debug)]
pub struct ProposedCall {
    pub to: Address,
    pub data: Bytes,
    pub value: U256,
}

/// A batch a dapp asked to execute, from `wallet_sendCalls`.
#[derive(Debug)]
pub struct SendCallsRequest {
    /// Optional in EIP-5792 — a dapp may leave the account to the wallet — so
    /// `None` means "the connected one" rather than "unspecified".
    pub from: Option<Address>,
    pub chain_id: u64,
    /// Whether the dapp requires all-or-nothing execution. This wallet always
    /// executes a batch atomically, so it is recorded rather than acted on.
    pub atomic_required: bool,
    pub calls: Vec<ProposedCall>,
    /// Capabilities the dapp asked for and did not mark optional. Anything
    /// here is refused by name: the spec's answer to a capability the wallet
    /// does not implement is an error, not a silent best effort.
    pub required_capabilities: Vec<String>,
}

/// Parse `wallet_sendCalls`.
///
/// The dapp's own `id`, if it sent one, is deliberately not carried out of
/// here. This wallet answers with the id of the record the batch became —
/// which is what `ekubo-wallet transaction show` and cancellation use — and
/// EIP-5792 has the dapp query whatever id the response returned.
pub fn parse_send_calls(params: &Value) -> Result<SendCallsRequest> {
    let object = params
        .as_array()
        .and_then(|array| array.first())
        .and_then(Value::as_object)
        .context("wallet_sendCalls takes an array holding one request object")?;

    let version = object
        .get("version")
        .and_then(Value::as_str)
        .context("the batch has no `version`")?;
    ensure!(
        version == SEND_CALLS_VERSION,
        "this wallet implements wallet_sendCalls {SEND_CALLS_VERSION}, not {version}"
    );

    let from = match object.get("from") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let from = value
                .as_str()
                .context("the batch's `from` is not a string")?;
            Some(
                Address::parse_checksummed(from, None)
                    .or_else(|_| from.parse::<Address>())
                    .context("the batch's `from` is not a 20-byte address")?,
            )
        }
    };

    let chain_id = object
        .get("chainId")
        .and_then(Value::as_str)
        .context("the batch has no `chainId`")?;
    let chain_id = parse_quantity(&Value::String(chain_id.to_owned()))
        .context("the batch's `chainId` is not a hex quantity")?;
    let chain_id =
        u64::try_from(chain_id).context("the batch's `chainId` does not fit in 64 bits")?;

    // Required by the spec, and load-bearing: a dapp that sends `false` is
    // saying it can cope with a partial result, and one that sends `true` is
    // saying it cannot. Neither is a default worth inventing.
    let atomic_required = object
        .get("atomicRequired")
        .and_then(Value::as_bool)
        .context("the batch has no `atomicRequired` boolean")?;

    let calls = object
        .get("calls")
        .and_then(Value::as_array)
        .context("the batch has no `calls` array")?;
    ensure!(!calls.is_empty(), "the batch holds no calls");

    let mut required_capabilities = required_capability_names(object.get("capabilities"))?;
    let mut parsed = Vec::with_capacity(calls.len());
    for (index, call) in calls.iter().enumerate() {
        let call = call
            .as_object()
            .with_context(|| format!("call {} is not an object", index + 1))?;
        // Same rule as `eth_sendTransaction`: a plan step always has a target,
        // and a deployment is refused by name rather than turned into a
        // transfer to the zero address.
        let to = match call.get("to") {
            None | Some(Value::Null) => bail!(
                "call {} deploys a contract, which this wallet cannot represent as an execution \
                 plan step. Deploy from a tool that signs its own transactions.",
                index + 1
            ),
            Some(value) => {
                let to = value
                    .as_str()
                    .with_context(|| format!("call {}'s `to` is not a string", index + 1))?;
                Address::parse_checksummed(to, None)
                    .or_else(|_| to.parse::<Address>())
                    .with_context(|| {
                        format!("call {}'s `to` is not a 20-byte address", index + 1)
                    })?
            }
        };
        let data = match call.get("data") {
            None | Some(Value::Null) => Bytes::new(),
            Some(value) => parse_bytes(value)
                .with_context(|| format!("call {}'s `data` is malformed", index + 1))?,
        };
        let value = match call.get("value") {
            None | Some(Value::Null) => U256::ZERO,
            Some(value) => parse_quantity(value)
                .with_context(|| format!("call {}'s `value` is malformed", index + 1))?,
        };
        required_capabilities.extend(required_capability_names(call.get("capabilities"))?);
        parsed.push(ProposedCall { to, data, value });
    }
    required_capabilities.sort_unstable();
    required_capabilities.dedup();

    Ok(SendCallsRequest {
        from,
        chain_id,
        atomic_required,
        calls: parsed,
        required_capabilities,
    })
}

/// The names in a `capabilities` object that the dapp did not mark optional.
///
/// A capability is required unless it says otherwise, so an unrecognized key
/// with no `optional: true` is one this wallet has to refuse rather than
/// quietly not honor.
fn required_capability_names(capabilities: Option<&Value>) -> Result<Vec<String>> {
    let Some(capabilities) = capabilities else {
        return Ok(Vec::new());
    };
    if capabilities.is_null() {
        return Ok(Vec::new());
    }
    let capabilities = capabilities
        .as_object()
        .context("`capabilities` is not an object")?;
    Ok(capabilities
        .iter()
        .filter(|(_, value)| value.get("optional").and_then(Value::as_bool) != Some(true))
        .map(|(name, _)| name.clone())
        .collect())
}

/// Parse `wallet_getCallsStatus`, which carries one batch id.
pub fn parse_get_calls_status(params: &Value) -> Result<String> {
    let id = params
        .as_array()
        .and_then(|array| array.first())
        .and_then(Value::as_str)
        .context("wallet_getCallsStatus takes an array holding one batch id")?;
    ensure!(!id.is_empty(), "the batch id is empty");
    Ok(id.to_owned())
}

/// Parse `wallet_getCapabilities`: an address, and optionally the chains the
/// dapp cares about.
///
/// An absent or empty chain list means "all of them", which is what the spec
/// asks a wallet to answer when the dapp does not narrow the question.
pub fn parse_get_capabilities(params: &Value) -> Result<(Address, Vec<u64>)> {
    let array = params
        .as_array()
        .context("wallet_getCapabilities takes an array of parameters")?;
    let address = array
        .first()
        .and_then(Value::as_str)
        .context("wallet_getCapabilities takes an address")?;
    let address = Address::parse_checksummed(address, None)
        .or_else(|_| address.parse::<Address>())
        .context("the requested address is not a 20-byte address")?;

    let chains = match array.get(1) {
        None | Some(Value::Null) => Vec::new(),
        Some(value) => {
            let listed = value
                .as_array()
                .context("the requested chain list is not an array")?;
            let mut chains = Vec::with_capacity(listed.len());
            for chain in listed {
                let quantity =
                    parse_quantity(chain).context("a requested chain id is not a hex quantity")?;
                chains.push(
                    u64::try_from(quantity)
                        .context("a requested chain id does not fit in 64 bits")?,
                );
            }
            chains
        }
    };
    Ok((address, chains))
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
