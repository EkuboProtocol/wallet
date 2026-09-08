//! Corpus synthesis: teaching the model from the interpreter it will run beside.
//!
//! Every training example is produced by the same code path that will render
//! the review. A spec entry names a chain, a contract, and a function
//! signature the vendored registry claims; this synthesizes typed arguments
//! for it, ABI-encodes them, and hands the result to
//! `ekubo_wallet_core::clear_signing::interpret`. What comes back is the
//! actual descriptor reading a reviewer would see.
//!
//! An entry whose reading comes back empty is *counted and dropped*, never
//! guessed at. That is what makes the generator self-checking: the signature
//! canonicalization, the include resolution, and the deployment addresses all
//! have to be right for a reading to appear at all, so a mistake in any of
//! them shows up as coverage this reports rather than as a corpus of examples
//! the engine would never actually produce.
//!
//! Compiled only under the `train` feature. Nothing here ships.

use crate::slots::{CallSummary, PlanDocument};
use alloy::{
    dyn_abi::{DynSolType, DynSolValue, JsonAbiExt, Specifier as _},
    json_abi::Function,
    primitives::{Address, Bytes, I256, U256},
};
use ekubo_wallet_core::approval_summary::{OwnAccounts, TokenMetadata, TokenMetadataMap};
use rand::{Rng, RngExt as _, seq::IndexedRandom as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One call the registry claims it can interpret, as
/// `scripts/preview-corpus-spec.py` writes it.
#[derive(Clone, Debug, Deserialize)]
pub struct CallSpec {
    pub descriptor: String,
    pub protocol: String,
    pub chain_id: u64,
    pub address: String,
    pub signature: String,
    /// The signature with parameter names stripped, ready for an ABI parser.
    pub canonical: String,
    pub intent: Option<String>,
}

/// A synthesized token, plausible enough that the renderer treats it the way
/// it treats a real one.
struct SynthToken {
    address: Address,
    symbol: &'static str,
    decimals: u8,
}

/// Symbols drawn from the assets a wallet actually holds. The point is not
/// realism for its own sake: `format_token_amount` renders differently for a
/// six-decimal token than an eighteen-decimal one, and a model trained only on
/// one shape would read the other wrong.
const SYMBOLS: &[(&str, u8)] = &[
    ("USDC", 6),
    ("USDT", 6),
    ("WBTC", 8),
    ("WETH", 18),
    ("DAI", 18),
    ("stETH", 18),
    ("wstETH", 18),
    ("LINK", 18),
    ("UNI", 18),
    ("AAVE", 18),
    ("EKUBO", 18),
    ("GHO", 18),
];

/// The synthesized world one example is generated against.
pub struct Fixtures {
    tokens: Vec<SynthToken>,
    others: Vec<Address>,
    pub own: OwnAccounts,
    pub sender: Address,
}

impl Fixtures {
    /// Build the addresses and metadata a run draws from.
    pub fn new(rng: &mut impl Rng) -> Self {
        let tokens = SYMBOLS
            .iter()
            .map(|(symbol, decimals)| SynthToken {
                address: random_address(rng),
                symbol,
                decimals: *decimals,
            })
            .collect();
        let sender = random_address(rng);
        let mut own = OwnAccounts::new();
        own.insert(sender, "main".to_owned());
        own.insert(random_address(rng), "savings".to_owned());
        Self {
            tokens,
            others: (0..24).map(|_| random_address(rng)).collect(),
            own,
            sender,
        }
    }

    /// Display metadata for the tokens one call names.
    ///
    /// `referenced` comes from the same `token_references` call the
    /// orchestrator makes before a review: a descriptor names its tokens
    /// through constants and parameter paths, and a wallet resolves exactly
    /// those against its database. Feeding the corpus anything else would
    /// train the model on a rendering production never produces -- a
    /// `tokenAmount` field whose token went unresolved reads as a bare
    /// integer, not as an amount with a symbol.
    ///
    /// A fraction is still withheld. An unlisted token renders by address in
    /// base units, which is a shape the model has to recognize, and a corpus
    /// where every token resolves would never contain it.
    pub fn metadata(&self, referenced: &[Address], rng: &mut impl Rng) -> TokenMetadataMap {
        let mut metadata: TokenMetadataMap = self
            .tokens
            .iter()
            .map(|token| {
                (
                    token.address,
                    TokenMetadata {
                        symbol: Some(token.symbol.to_owned()),
                        decimals: Some(token.decimals),
                    },
                )
            })
            .collect();
        for address in referenced {
            // Deterministic in the address, so the same token reads the same
            // way everywhere in one plan.
            let seed = address
                .as_slice()
                .iter()
                .map(|byte| *byte as usize)
                .sum::<usize>();
            let (symbol, decimals) = SYMBOLS[seed % SYMBOLS.len()];
            metadata.entry(*address).or_insert(TokenMetadata {
                symbol: Some(symbol.to_owned()),
                decimals: Some(decimals),
            });
        }
        metadata.retain(|_, _| rng.random_range(0..100) >= 12);
        metadata
    }

    /// An address for a parameter: usually a token, sometimes one of the
    /// owner's own accounts, sometimes a stranger.
    fn address(&self, rng: &mut impl Rng) -> Address {
        match rng.random_range(0..10) {
            0..=5 => self
                .tokens
                .choose(rng)
                .map_or(Address::ZERO, |token| token.address),
            6 => self
                .own
                .keys()
                .copied()
                .collect::<Vec<_>>()
                .choose(rng)
                .copied()
                .unwrap_or(self.sender),
            _ => self.others.choose(rng).copied().unwrap_or(Address::ZERO),
        }
    }
}

fn random_address(rng: &mut impl Rng) -> Address {
    let mut bytes = [0_u8; 20];
    rng.fill(&mut bytes);
    Address::from(bytes)
}

/// Synthesize one value of an ABI type.
///
/// Magnitudes are drawn on a log scale rather than uniformly, because a
/// uniform `uint256` is a 77-digit number that no real call carries and that
/// would teach the model nothing about how an amount reads. Unlimited
/// allowances are sampled deliberately: they are the case the review most
/// needs to say out loud, so the corpus has to contain them.
fn synth(kind: &DynSolType, fixtures: &Fixtures, rng: &mut impl Rng, depth: usize) -> DynSolValue {
    match kind {
        DynSolType::Address => DynSolValue::Address(fixtures.address(rng)),
        DynSolType::Bool => DynSolValue::Bool(rng.random()),
        DynSolType::Uint(bits) => DynSolValue::Uint(synth_uint(*bits, rng), *bits),
        DynSolType::Int(bits) => {
            let magnitude = synth_uint((*bits).min(63), rng);
            let signed = I256::try_from(magnitude.to::<u64>()).unwrap_or(I256::ZERO);
            DynSolValue::Int(if rng.random() { -signed } else { signed }, *bits)
        }
        DynSolType::FixedBytes(size) => {
            let mut bytes = [0_u8; 32];
            rng.fill(&mut bytes[..*size]);
            DynSolValue::FixedBytes(bytes.into(), *size)
        }
        DynSolType::Bytes => {
            let length = rng.random_range(0..48);
            DynSolValue::Bytes((0..length).map(|_| rng.random()).collect())
        }
        DynSolType::String => DynSolValue::String(
            ["ekubo", "vault", "position", "order", "market"]
                .choose(rng)
                .unwrap_or(&"item")
                .to_string(),
        ),
        DynSolType::Array(inner) => DynSolValue::Array(synth_many(inner, fixtures, rng, depth)),
        DynSolType::FixedArray(inner, size) => DynSolValue::FixedArray(
            (0..*size)
                .map(|_| synth(inner, fixtures, rng, depth + 1))
                .collect(),
        ),
        DynSolType::Tuple(kinds) => DynSolValue::Tuple(
            kinds
                .iter()
                .map(|kind| synth(kind, fixtures, rng, depth + 1))
                .collect(),
        ),
        DynSolType::Function => DynSolValue::Function(alloy::primitives::Function::ZERO),
        DynSolType::CustomStruct { .. } => DynSolValue::Tuple(Vec::new()),
    }
}

/// A short array. Nesting is capped so a recursive type cannot make one
/// example arbitrarily large.
fn synth_many(
    inner: &DynSolType,
    fixtures: &Fixtures,
    rng: &mut impl Rng,
    depth: usize,
) -> Vec<DynSolValue> {
    let length = if depth >= 2 {
        1
    } else {
        rng.random_range(1..4)
    };
    (0..length)
        .map(|_| synth(inner, fixtures, rng, depth + 1))
        .collect()
}

/// An unsigned magnitude, log-scaled, with the sentinels a wallet must read.
fn synth_uint(bits: usize, rng: &mut impl Rng) -> U256 {
    if bits >= 128 && rng.random_range(0..12) == 0 {
        // The unlimited-allowance sentinels. `approval_summary` treats
        // anything at or above `type(uint128).max` as unlimited, and the
        // review has to say so, so the corpus carries all three in use.
        let sentinel = [
            U256::MAX,
            U256::MAX >> 1,
            (U256::from(1) << 128) - U256::from(1),
        ];
        return sentinel.choose(rng).copied().unwrap_or(U256::MAX);
    }
    let width = rng.random_range(1..=bits.min(80));
    let ceiling = U256::from(1) << width;
    U256::from(rng.random::<u64>()) % ceiling.max(U256::from(1))
}

/// Build one interpreted call for a spec entry, or `None` when the descriptor
/// engine declined to read the synthesized calldata.
pub fn synthesize(spec: &CallSpec, fixtures: &Fixtures, rng: &mut impl Rng) -> Option<CallSummary> {
    let function = Function::parse(&spec.canonical).ok()?;
    let kinds: Vec<DynSolType> = function
        .inputs
        .iter()
        .map(|input| input.resolve().ok())
        .collect::<Option<_>>()?;
    let values: Vec<DynSolValue> = kinds
        .iter()
        .map(|kind| synth(kind, fixtures, rng, 0))
        .collect();
    let calldata = Bytes::from(function.abi_encode_input(&values).ok()?);
    let to = spec.address.parse::<Address>().ok()?;
    let envelope = || ekubo_wallet_core::clear_signing::CallEnvelope {
        from: fixtures.sender,
        to,
    };
    // The same two-pass resolution the orchestrator performs: ask the
    // descriptor which tokens it names, resolve those, then render.
    let referenced = futures::executor::block_on(
        ekubo_wallet_core::clear_signing::token_references(spec.chain_id, envelope(), &calldata),
    );
    let metadata = fixtures.metadata(&referenced, rng);
    let value = if matches!(
        function.state_mutability,
        alloy::json_abi::StateMutability::Payable
    ) && rng.random_range(0..3) == 0
    {
        synth_uint(64, rng)
    } else {
        U256::ZERO
    };
    let reading = futures::executor::block_on(ekubo_wallet_core::clear_signing::interpret(
        spec.chain_id,
        envelope(),
        &calldata,
        value,
        &metadata,
        &fixtures.own,
    ))?;
    Some(CallSummary {
        description: Some(reading.intent),
        details: reading.fields,
        warnings: reading.warnings,
        target: target_label(to, &metadata),
        native_value: native_value(value),
    })
}

/// How the orchestrator labels a call's target: by symbol when the token
/// database knows it, by checksum otherwise.
fn target_label(to: Address, metadata: &TokenMetadataMap) -> String {
    metadata
        .get(&to)
        .and_then(|entry| entry.symbol.as_deref())
        .map_or_else(
            || to.to_checksum(None),
            |symbol| format!("{symbol} ({})", to.to_checksum(None)),
        )
}

/// How the orchestrator renders a native value: eighteen decimals and a ticker.
fn native_value(value: U256) -> String {
    format!(
        "{} ETH",
        ekubo_wallet_core::approval_summary::format_fixed_point(&value.to_string(), 18)
    )
}

/// One generated plan, with everything the labeling and training steps need.
#[derive(Clone, Debug, Serialize)]
pub struct Example {
    /// The `(descriptor, canonical signature)` pairs this plan was built from,
    /// in call order. This is the key a template is looked up by.
    pub formats: Vec<String>,
    pub protocols: Vec<String>,
    /// The tokenized model input, as vocabulary pieces.
    pub input_pieces: Vec<String>,
    /// What each lifted slot holds, so a label can be written against the
    /// shapes the renderer actually produced.
    pub slot_kinds: Vec<String>,
    pub slot_calls: Vec<usize>,
    /// The verbatim slot texts. Read by the trainer to render a sample, and
    /// deliberately *not* read by the vocabulary builder -- see
    /// `scripts/build-preview-vocab.py`.
    pub slot_texts: Vec<String>,
    /// The decoded lines, kept so a human labeling a format can see what a
    /// reviewer would see.
    pub lines: Vec<String>,
}

/// Turn a synthesized plan into the record the corpus stores.
#[must_use]
pub fn record(document: &PlanDocument, formats: Vec<String>, protocols: Vec<String>) -> Example {
    let slotized = crate::slots::slotize(document);
    let mut lines = Vec::new();
    for call in &document.calls {
        if let Some(description) = &call.description {
            lines.push(description.clone());
        }
        lines.extend(call.details.iter().cloned());
    }
    Example {
        formats,
        protocols,
        input_pieces: slotized
            .tokens
            .iter()
            .filter_map(|token| crate::vocab::piece_of(*token))
            .map(str::to_owned)
            .collect(),
        slot_kinds: slotized
            .slots
            .iter()
            .map(|slot| slot.kind.tag().to_owned())
            .collect(),
        slot_calls: slotized.slots.iter().map(|slot| slot.call).collect(),
        slot_texts: slotized
            .slots
            .iter()
            .map(|slot| slot.text.clone())
            .collect(),
        lines,
    }
}

/// Group spec entries so each distinct interpretable call is generated once
/// per requested sample, rather than once per deployment.
///
/// A descriptor deployed on nine chains is the same reading nine times. Left
/// alone it would weight those formats nine times as heavily as a
/// single-chain one, which teaches the model about deployment counts.
#[must_use]
pub fn deduplicate(specs: Vec<CallSpec>) -> Vec<CallSpec> {
    let mut unique: BTreeMap<(String, String), CallSpec> = BTreeMap::new();
    for spec in specs {
        unique
            .entry((spec.descriptor.clone(), spec.canonical.clone()))
            .or_insert(spec);
    }
    unique.into_values().collect()
}
