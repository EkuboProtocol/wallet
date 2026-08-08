//! The one predicate language every policy rule is written in.
//!
//! A rule is a set of extractor → [`Predicate`] slots, and this module holds
//! the predicate half. There is exactly one predicate type, applied to exactly
//! one value domain ([`DynSolValue`]), so the same vocabulary that constrains a
//! call's `to` address also constrains a decoded argument nested three levels
//! inside its calldata. Nesting is composition rather than machinery: a
//! `bytes[]` argument reached by [`Predicate::Each`] whose element predicate is
//! [`Predicate::Selector`] matches a batched inner call, and no part of this
//! module knows what a multicall is.
//!
//! Three properties are load-bearing and deliberately not negotiable:
//!
//! * **A predicate never errors at match time.** Anything that would be an
//!   error — calldata too short, a decode that fails, a literal that does not
//!   parse as the value's type — is a non-match. Combined with the rule set's
//!   default-deny, an unanswerable question therefore denies rather than
//!   admits.
//! * **A matched call is canonically encoded.** `abi_decode_input` alone
//!   ignores trailing bytes and accepts dirty address padding, so
//!   [`Predicate::Selector`] re-encodes what it decoded and requires the bytes
//!   back. That rejects trailing garbage, non-canonical offsets, and unclean
//!   words in one comparison, which means a rule cannot be satisfied by an
//!   alternate encoding that a target contract's decoder would read differently.
//! * **Failing that check is doubt, not denial.** The two above nearly
//!   cancelled each other out. Reporting a non-canonical call as a plain
//!   non-match is right for an `allow` and wrong for everything else: a `deny`
//!   naming the selector stopped firing, so one appended byte carried a
//!   denied call through whatever broader `allow` sat beside it, and a `not`
//!   around the same predicate inverted into a positive match. So there are
//!   three answers, not two — see [`Match`] — and an `allow` requires
//!   certainty while a `deny` needs only suspicion.

use alloy::{
    dyn_abi::{DynSolType, DynSolValue, JsonAbiExt},
    json_abi::Function,
    primitives::{Address, I256, U256},
};
use anyhow::{Context, Result, bail, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

/// The answer a predicate gives about one value.
///
/// Two answers are not enough. A selector predicate that meets its own
/// function, encoded in a form this policy cannot decode, is not answering
/// "no" — it is answering "this is my subject and I cannot read it". Those
/// collapse safely for an `allow`, which must refuse both, and unsafely for
/// everything else: reported as a non-match, a `deny` naming that selector
/// stops firing while a broader `allow` still admits the call, and a `not`
/// around it turns the unreadable call into a positive match. Doubt is
/// therefore its own answer and it propagates, so that it can fail closed in
/// both directions rather than in only one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Match {
    Yes,
    No,
    /// The predicate's own subject, in an encoding it cannot decide. Satisfies
    /// no `allow` and triggers every `deny` that could have named it.
    Unreadable,
}

impl Match {
    #[must_use]
    const fn of(value: bool) -> Self {
        if value { Self::Yes } else { Self::No }
    }

    /// Conjunction. A definite `No` settles it; otherwise doubt survives.
    #[must_use]
    pub(crate) const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Unreadable, _) | (_, Self::Unreadable) => Self::Unreadable,
            (Self::Yes, Self::Yes) => Self::Yes,
        }
    }

    /// Disjunction. A definite `Yes` settles it; otherwise doubt survives.
    #[must_use]
    const fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Yes, _) | (_, Self::Yes) => Self::Yes,
            (Self::Unreadable, _) | (_, Self::Unreadable) => Self::Unreadable,
            (Self::No, Self::No) => Self::No,
        }
    }

    #[must_use]
    const fn negate(self) -> Self {
        match self {
            Self::Yes => Self::No,
            Self::No => Self::Yes,
            Self::Unreadable => Self::Unreadable,
        }
    }

    /// Whether this answer may satisfy an `allow`. Only certainty does.
    #[must_use]
    pub const fn is_match(self) -> bool {
        matches!(self, Self::Yes)
    }

    /// Whether this answer must trigger a `deny`. Doubt does: a rule written
    /// to stop a call cannot be escaped by encoding that call unreadably.
    #[must_use]
    pub const fn is_suspected(self) -> bool {
        matches!(self, Self::Yes | Self::Unreadable)
    }
}

/// Everything a predicate may consult beyond the call itself.
///
/// One address, and deliberately nothing else. Evaluation is a pure function of
/// data — no I/O, no locks, and nothing the RPC reports can reach a policy
/// decision — and the smaller this type is, the less there is to keep true.
/// The `$self` literal is the only thing that reads it.
///
/// It used to carry the confirmed-token and address-book sets, for `is_token`
/// and `is_address_book`. Those are gone. Both stores exist to tell a person
/// what they are looking at, and reading them into an authorization decision
/// meant a row written to improve a label also widened what could be signed:
/// the two uses could not be told apart afterwards, and the safer of them was
/// paying for the other. Token and address-book metadata now only ever reaches
/// the review display.
#[derive(Clone, Copy, Debug, Default)]
pub struct PolicyContext {
    pub wallet: Address,
}

/// A four-byte-selector-and-arguments predicate over a `bytes` value.
///
/// The signature is the authority: the selector is derived from it rather than
/// stated alongside it, so a policy can never allowlist four bytes whose
/// meaning it does not know, and a reviewer reads `approve(address,uint256)`
/// instead of `0x095ea7b3`.
#[derive(Clone, Debug)]
pub struct SelectorPredicate {
    /// Canonical `name(type name, …)` form, re-emitted from the parsed
    /// signature so two spellings of one function cannot produce two digests.
    signature: String,
    function: Function,
    args: BTreeMap<String, Predicate>,
}

impl SelectorPredicate {
    pub fn new(abi: &str, args: BTreeMap<String, Predicate>) -> Result<Self> {
        let function = Function::parse(abi)
            .map_err(|error| anyhow::anyhow!("invalid function signature {abi:?}: {error}"))?;
        ensure!(
            function.inputs.iter().all(|input| !input.name.is_empty()),
            "every parameter in {abi:?} must be named so rules can refer to it"
        );
        let mut names = BTreeSet::new();
        for input in &function.inputs {
            ensure!(
                names.insert(input.name.clone()),
                "parameter {} appears twice in {abi:?}",
                input.name
            );
        }
        for (name, predicate) in &args {
            let input = function
                .inputs
                .iter()
                .find(|input| &input.name == name)
                .with_context(|| format!("{abi:?} has no parameter named {name:?}"))?;
            let resolved = DynSolType::parse(&input.selector_type())
                .with_context(|| format!("parameter {name:?} of {abi:?} has an unusable type"))?;
            predicate.check_applicable(&resolved).with_context(|| {
                format!("predicate on parameter {name:?} of {abi:?} is not applicable")
            })?;
        }
        Ok(Self {
            signature: canonical_signature(&function),
            function,
            args,
        })
    }

    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }

    #[must_use]
    pub fn args(&self) -> &BTreeMap<String, Predicate> {
        &self.args
    }

    /// Whether `data` is a canonically encoded call to this signature whose
    /// named arguments all satisfy their predicates.
    ///
    /// The selector decides the subject and the body decides the answer. Once
    /// the four bytes match, this call *is* the function named here, so a body
    /// that will not decode or will not round-trip is [`Match::Unreadable`]
    /// rather than [`Match::No`]: the arguments are unknown, not absent.
    fn evaluate(&self, data: &[u8], context: &PolicyContext) -> Match {
        if data.len() < 4 || data[..4] != self.function.selector()[..] {
            return Match::No;
        }
        let body = &data[4..];
        let Ok(values) = self.function.abi_decode_input(body) else {
            return Match::Unreadable;
        };
        // Canonical-form check: see the module comment. `abi_decode_input`
        // alone ignores trailing bytes and accepts dirty padding, so a call a
        // target contract would execute can decode here into arguments that
        // are not the ones it will act on.
        let Ok(reencoded) = self.function.abi_encode_input_raw(&values) else {
            return Match::Unreadable;
        };
        if reencoded != body {
            return Match::Unreadable;
        }
        // Round-tripping is not the whole of being canonical. A narrow type
        // keeps its entire 32-byte word through decode and encode alike, so
        // both halves of the comparison above carry the same dirty bits and
        // agree — see [`within_declared_width`] for what that lets through.
        if !values.iter().all(within_declared_width) {
            return Match::Unreadable;
        }
        self.args
            .iter()
            .fold(Match::Yes, |answer, (name, predicate)| {
                answer.and(
                    self.function
                        .inputs
                        .iter()
                        .position(|input| &input.name == name)
                        .and_then(|index| values.get(index))
                        .map_or(Match::No, |value| predicate.evaluate(value, context)),
                )
            })
    }
}

impl PartialEq for SelectorPredicate {
    fn eq(&self, other: &Self) -> bool {
        self.signature == other.signature && self.args == other.args
    }
}

impl Eq for SelectorPredicate {}

/// `name(type name, …)` rebuilt from the parsed signature, so whitespace and
/// spelling differences in the source document collapse to one form.
fn canonical_signature(function: &Function) -> String {
    let params = function
        .inputs
        .iter()
        .map(|input| format!("{} {}", input.selector_type(), input.name))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{}({params})", function.name)
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SelectorPredicateWire {
    abi: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    args: BTreeMap<String, Predicate>,
}

impl<'de> Deserialize<'de> for SelectorPredicate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SelectorPredicateWire::deserialize(deserializer)?;
        Self::new(&wire.abi, wire.args).map_err(serde::de::Error::custom)
    }
}

impl Serialize for SelectorPredicate {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SelectorPredicateWire {
            abi: self.signature.clone(),
            args: self.args.clone(),
        }
        .serialize(serializer)
    }
}

impl JsonSchema for SelectorPredicate {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SelectorPredicate".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        SelectorPredicateWire::json_schema(generator)
    }
}

/// One predicate over one value.
///
/// Externally tagged, so a document reads `{"in": ["0x…"]}`, `"any_value"`, or
/// `{"each": {"selector": {"abi": "…"}}}`.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Predicate {
    /// Matches every value, including one this policy cannot decode. The only
    /// way to write an unconstrained slot explicitly.
    AnyValue,
    /// Equal to one literal, which may be the `$self` variable standing for
    /// this wallet's own address.
    Eq(String),
    /// Equal to one of a set of literals, any of which may be `$self`.
    In(BTreeSet<String>),
    Selector(Box<SelectorPredicate>),
    /// Every element of an array satisfies the inner predicate. An empty array
    /// satisfies it vacuously.
    Each(Box<Predicate>),
    /// At least one of these predicates matches. An empty list never matches.
    Any(Vec<Predicate>),
    /// All of these predicates match. An empty list matches vacuously.
    All(Vec<Predicate>),
    Not(Box<Predicate>),
    /// The element count of an array, or the byte length of a `bytes` or
    /// `string`, satisfies the inner predicate as a `uint256`.
    Length(Box<Predicate>),
}

impl Predicate {
    /// Whether this predicate can ever be satisfied by a value of type `ty`.
    ///
    /// Run when the policy document is parsed, against the types the rule's own
    /// signature declares, so a predicate that could only ever fail is refused
    /// at install time instead of silently never matching at signing time.
    pub fn check_applicable(&self, ty: &DynSolType) -> Result<()> {
        match self {
            Self::AnyValue => Ok(()),
            Self::Eq(literal) => check_literal(literal, ty),
            Self::In(literals) => {
                ensure!(!literals.is_empty(), "an `in` predicate needs a value");
                literals
                    .iter()
                    .try_for_each(|literal| check_literal(literal, ty))
            }
            Self::Selector(_) => {
                ensure!(
                    matches!(ty, DynSolType::Bytes),
                    "a selector predicate needs `bytes`, not {ty:?}"
                );
                Ok(())
            }
            Self::Each(inner) => match element_type(ty) {
                Some(element) => inner.check_applicable(element),
                None => bail!("an `each` predicate needs an array, not {ty:?}"),
            },
            Self::Any(inner) => {
                ensure!(!inner.is_empty(), "an `any` predicate needs a branch");
                inner.iter().try_for_each(|item| item.check_applicable(ty))
            }
            Self::All(inner) => inner.iter().try_for_each(|item| item.check_applicable(ty)),
            Self::Not(inner) => inner.check_applicable(ty),
            Self::Length(inner) => {
                ensure!(
                    element_type(ty).is_some()
                        || matches!(ty, DynSolType::Bytes | DynSolType::String),
                    "a `length` predicate needs an array, bytes, or string, not {ty:?}"
                );
                inner.check_applicable(&DynSolType::Uint(256))
            }
        }
    }

    /// How `value` answers this predicate. Never errors: an unanswerable
    /// question is [`Match::No`] or [`Match::Unreadable`], and the rule set
    /// denies by default, so uncertainty never admits.
    ///
    /// The two differ in what else they do. `No` says the predicate's subject
    /// is not here; `Unreadable` says it is here in a form that cannot be
    /// decided, which additionally trips any `deny` written over it.
    #[must_use]
    pub fn evaluate(&self, value: &DynSolValue, context: &PolicyContext) -> Match {
        match self {
            Self::AnyValue => Match::Yes,
            Self::Eq(literal) => Match::of(render(value).is_some_and(|rendered| {
                value
                    .as_type()
                    .and_then(|ty| resolve_literal(literal, &ty, context).ok())
                    .is_some_and(|canonical| canonical == rendered)
            })),
            Self::In(literals) => Match::of(render(value).is_some_and(|rendered| {
                value.as_type().is_some_and(|ty| {
                    literals
                        .iter()
                        .filter_map(|literal| resolve_literal(literal, &ty, context).ok())
                        .any(|canonical| canonical == rendered)
                })
            })),
            Self::Selector(selector) => match value {
                DynSolValue::Bytes(data) => selector.evaluate(data, context),
                _ => Match::No,
            },
            Self::Each(inner) => match elements(value) {
                Some(items) => items.iter().fold(Match::Yes, |answer, item| {
                    answer.and(inner.evaluate(item, context))
                }),
                None => Match::No,
            },
            Self::Any(inner) => inner.iter().fold(Match::No, |answer, item| {
                answer.or(item.evaluate(value, context))
            }),
            Self::All(inner) => inner.iter().fold(Match::Yes, |answer, item| {
                answer.and(item.evaluate(value, context))
            }),
            Self::Not(inner) => inner.evaluate(value, context).negate(),
            Self::Length(inner) => length_of(value).map_or(Match::No, |length| {
                inner.evaluate(&DynSolValue::Uint(U256::from(length), 256), context)
            }),
        }
    }

    /// True when `value` definitely satisfies this predicate — the question an
    /// `allow` asks. Doubt answers no.
    #[must_use]
    pub fn matches(&self, value: &DynSolValue, context: &PolicyContext) -> bool {
        self.evaluate(value, context).is_match()
    }

    /// Whether this predicate is exactly as permissive as, or narrower than,
    /// `other` — used to render an honest permission diff and to spot rules a
    /// policy already covers. Deliberately conservative: `false` means "cannot
    /// prove it", never "definitely broader". Regex and `not` are opaque to
    /// this, which is why a diff reports them rather than reasoning about them.
    /// Matches every value of its type, whatever that value is. `all` of
    /// nothing asserts nothing, so it is the widest predicate there is, and an
    /// `any` containing a universally true branch is too.
    #[must_use]
    fn is_universally_true(&self) -> bool {
        match self {
            Self::AnyValue => true,
            Self::All(items) => items.iter().all(Self::is_universally_true),
            Self::Any(items) => items.iter().any(Self::is_universally_true),
            _ => false,
        }
    }

    /// Matches nothing at all — `any` of no branches, or an `all` with a
    /// branch that never matches. Such a predicate is narrower than everything.
    #[must_use]
    fn is_universally_false(&self) -> bool {
        match self {
            Self::Any(items) => items.iter().all(Self::is_universally_false),
            Self::All(items) => items.iter().any(Self::is_universally_false),
            _ => false,
        }
    }

    #[must_use]
    pub fn is_narrower_than(&self, other: &Self) -> bool {
        // Settle the degenerate ends first. Deciding these structurally would
        // mean depending on the order of the match arms below, and an `any`
        // wrapping an empty `all` is already enough to make that go wrong.
        if other.is_universally_true() || self.is_universally_false() {
            return true;
        }
        if self.structurally_narrower_than(other) {
            return true;
        }
        // Each branch strictly shrinks one side, so this terminates. They are
        // ORed rather than matched in sequence because more than one can apply.
        let from_left = match self {
            Self::Any(left) => {
                !left.is_empty() && left.iter().all(|item| item.is_narrower_than(other))
            }
            Self::All(left) => left.iter().any(|item| item.is_narrower_than(other)),
            _ => false,
        };
        let from_right = match other {
            Self::All(right) => {
                !right.is_empty() && right.iter().all(|item| self.is_narrower_than(item))
            }
            Self::Any(right) => right.iter().any(|item| self.is_narrower_than(item)),
            _ => false,
        };
        from_left || from_right
    }

    fn structurally_narrower_than(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Eq(left), Self::Eq(right)) => left == right,
            (Self::Eq(left), Self::In(right)) => right.contains(left),
            (Self::In(left), Self::In(right)) => left.is_subset(right),
            (Self::In(left), Self::Eq(right)) => left.len() == 1 && left.contains(right),
            (Self::Each(left), Self::Each(right)) => left.is_narrower_than(right),
            // Containment reverses under negation: every value `not A` admits
            // is admitted by `not B` exactly when B admits everything A does.
            // Comparing these the same way round as the others would claim a
            // widening was a narrowing, which is the one error a permission
            // diff must never make.
            (Self::Not(left), Self::Not(right)) => right.is_narrower_than(left),
            (Self::Selector(left), Self::Selector(right)) => {
                left.signature == right.signature
                    && right.args.iter().all(|(name, right_arg)| {
                        left.args
                            .get(name)
                            .is_some_and(|left_arg| left_arg.is_narrower_than(right_arg))
                    })
            }
            _ => false,
        }
    }

    /// Every literal this predicate compares against, at the level it applies
    /// to. Recurses through the boolean combinators, which do not change what
    /// is being compared, but not into `selector` arguments or array elements,
    /// which describe a different value than the one this predicate names.
    ///
    /// Display only: callers use it to decide which token balances to pre-query
    /// for the approval review. No policy decision reads it. A `$self` travels
    /// unresolved — there is no wallet here to resolve it against — and the
    /// callers that want addresses drop what does not parse as one.
    pub fn literals(&self, into: &mut BTreeSet<String>) {
        match self {
            Self::Eq(literal) => {
                into.insert(literal.clone());
            }
            Self::In(literals) => into.extend(literals.iter().cloned()),
            Self::Any(inner) | Self::All(inner) => {
                for item in inner {
                    item.literals(into);
                }
            }
            Self::Not(inner) => inner.literals(into),
            Self::AnyValue | Self::Selector(_) | Self::Each(_) | Self::Length(_) => {}
        }
    }

    /// One line of plain English, for the permission diff and the approval
    /// review. An unconstrained `bytes` slot says so out loud: a rule allowing
    /// a batching function with no constraint on its payload grants everything
    /// that payload can reach, and the reviewer has to be told that.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::AnyValue => "anything".into(),
            Self::Eq(literal) => match Variable::parse(literal).ok().flatten() {
                Some(variable) => variable.describe().to_string(),
                None => format!("exactly {literal}"),
            },
            Self::In(literals) => {
                let mut items = literals.iter().cloned().collect::<Vec<_>>();
                items.sort();
                let described = items
                    .iter()
                    .map(|literal| describe_literal(literal))
                    .collect::<Vec<_>>();
                format!("one of {}", described.join(", "))
            }
            Self::Selector(selector) => {
                if selector.args.is_empty() {
                    format!(
                        "a call to {} with unconstrained arguments",
                        selector.signature
                    )
                } else {
                    let mut args = selector
                        .args
                        .iter()
                        .map(|(name, predicate)| format!("{name} is {}", predicate.describe()))
                        .collect::<Vec<_>>();
                    args.sort();
                    format!(
                        "a call to {} where {}",
                        selector.signature,
                        args.join(" and ")
                    )
                }
            }
            Self::Each(inner) => format!("every element is {}", inner.describe()),
            Self::Any(inner) => inner
                .iter()
                .map(Self::describe)
                .collect::<Vec<_>>()
                .join(" or "),
            Self::All(inner) => inner
                .iter()
                .map(Self::describe)
                .collect::<Vec<_>>()
                .join(" and "),
            Self::Not(inner) => format!("not {}", inner.describe()),
            Self::Length(inner) => format!("length is {}", inner.describe()),
        }
    }
}

fn element_type(ty: &DynSolType) -> Option<&DynSolType> {
    match ty {
        DynSolType::Array(inner) | DynSolType::FixedArray(inner, _) => Some(inner),
        _ => None,
    }
}

fn elements(value: &DynSolValue) -> Option<&[DynSolValue]> {
    match value {
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) => Some(items),
        _ => None,
    }
}

fn length_of(value: &DynSolValue) -> Option<usize> {
    match value {
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) => Some(items.len()),
        DynSolValue::Bytes(data) => Some(data.len()),
        DynSolValue::String(text) => Some(text.len()),
        _ => None,
    }
}

/// Whether every word in a decoded value carries only the bits its declared
/// width can hold.
///
/// The re-encode in [`SelectorPredicate::evaluate`] was doing this job and
/// could not: a narrow type is decoded by taking the whole 32-byte word and
/// remembering the declared width beside it, and encoding writes that same
/// word back. `uint8` given `0x…ff01` decodes to 65281 and re-encodes to the
/// bytes it came from, and `bytes4` keeps whatever 28 bytes follow it. Both
/// pass a comparison that reads as "this is canonically encoded".
///
/// What the target sees is not that. solc's decoder reverts on a `uintN` whose
/// word does not fit and masks a `bytesN` down to its width, so those bits
/// reach nothing — while the policy reasons about them, and in the direction
/// that matters: [`render`] prints the full integer, so `deny amount == 1`
/// does not fire on the word a masking target reads as exactly 1. The padding
/// on a `bytesN` is worse still for being invisible, since `render` truncates
/// it away and the rule matches while 28 attacker-chosen bytes ride along into
/// what gets signed.
///
/// So the width is checked directly, and a value that fails is `Unreadable`
/// like every other unanswerable question here: refused for an `allow`,
/// suspected for a `deny`.
fn within_declared_width(value: &DynSolValue) -> bool {
    match value {
        DynSolValue::Uint(word, bits) => *bits >= 256 || *word < (U256::from(1) << *bits),
        // Two's complement, so the range is asymmetric. Whether the codec
        // sign-extended a short word or reinterpreted it whole, a word that is
        // not a valid `intN` lands outside this and is caught either way.
        DynSolValue::Int(word, bits) => {
            *bits >= 256 || (*word >= min_int(*bits) && *word <= max_int(*bits))
        }
        DynSolValue::FixedBytes(word, size) => word[*size..].iter().all(|byte| *byte == 0),
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) | DynSolValue::Tuple(items) => {
            items.iter().all(within_declared_width)
        }
        _ => true,
    }
}

/// The largest `intN`, as an [`I256`].
fn max_int(bits: usize) -> I256 {
    I256::try_from((U256::from(1) << (bits - 1)) - U256::from(1)).unwrap_or(I256::MAX)
}

/// The smallest `intN`, as an [`I256`].
fn min_int(bits: usize) -> I256 {
    max_int(bits).wrapping_neg().wrapping_sub(I256::ONE)
}

/// The canonical text of a value: lowercase `0x` hex for anything byte-shaped,
/// decimal for integers. Both sides of a comparison go through this, so a
/// literal spelled `0xABC…` and a decoded address compare equal.
fn render(value: &DynSolValue) -> Option<String> {
    Some(match value {
        DynSolValue::Address(address) => format!("{address:#x}"),
        DynSolValue::Bool(flag) => flag.to_string(),
        DynSolValue::Bytes(data) => format!("0x{}", hex::encode(data)),
        DynSolValue::FixedBytes(word, size) => format!("0x{}", hex::encode(&word[..*size])),
        DynSolValue::Int(value, _) => value.to_string(),
        DynSolValue::String(text) => text.clone(),
        DynSolValue::Uint(value, _) => value.to_string(),
        _ => return None,
    })
}

/// Every literal in a policy document is written one of exactly two ways: hex
/// with a `0x` prefix, or decimal with no prefix. Bare hex is refused rather
/// than guessed at, because `10` is a legal spelling of both sixteen and ten
/// and a policy that means one while reading like the other is the kind of
/// mistake this whole format exists to prevent.
fn decode_hex_literal(literal: &str) -> Result<Vec<u8>> {
    let digits = literal
        .strip_prefix("0x")
        .with_context(|| format!("{literal:?} must be hex with a 0x prefix"))?;
    ensure!(
        digits.len() % 2 == 0,
        "{literal:?} has an odd number of hex digits"
    );
    hex::decode(digits).with_context(|| format!("{literal:?} is not valid hex"))
}

/// The literal standing for the wallet a policy governs, rather than for
/// something written out in the document.
///
/// This is what makes a rule portable — "the proceeds must come back to me"
/// without naming an address. It is a literal rather than a predicate of its
/// own so that it composes with everything literals already compose with:
/// `{"in": ["$self", "0x…"]}` says "me or my cold wallet" in vocabulary the
/// reader already has, which a dedicated predicate could not do without an
/// `any` wrapped around it.
pub const SELF_LITERAL: &str = "$self";

/// A literal naming something the wallet resolves instead of spelling out.
///
/// `$` introduces one, and it cannot collide with the two ways every other
/// literal is written — 0x-prefixed hex, or unprefixed decimal — so an
/// unrecognised `$name` is an error rather than a literal. A typo therefore
/// fails the install instead of quietly becoming a value that never matches.
///
/// The cost is that a `string` argument whose text really does begin with `$`
/// can no longer be named by a policy, and there is deliberately no escape for
/// it. A document that means a variable but reads as text, or the reverse, is
/// exactly the mistake this literal format exists to prevent, and refusing
/// outright is the only reading that cannot be wrong in silence.
#[derive(Clone, Copy, Debug)]
enum Variable {
    /// `$self`: the address of the wallet this policy governs.
    SelfAddress,
}

impl Variable {
    /// Which variable a literal names, if it names one at all.
    fn parse(literal: &str) -> Result<Option<Self>> {
        if !literal.starts_with('$') {
            return Ok(None);
        }
        match literal {
            SELF_LITERAL => Ok(Some(Self::SelfAddress)),
            other => bail!("{other:?} is not a variable; the only one is {SELF_LITERAL:?}"),
        }
    }

    /// Whether this variable can ever be compared against a value of type
    /// `ty`, so a policy that could only ever fail is refused at install time.
    fn check_applicable(self, ty: &DynSolType) -> Result<()> {
        match self {
            Self::SelfAddress => ensure!(
                matches!(ty, DynSolType::Address),
                "{SELF_LITERAL} is an address and cannot be compared against {ty:?}"
            ),
        }
        Ok(())
    }

    /// What this variable stands for, in the same canonical text [`render`]
    /// produces, so the two compare directly.
    fn resolve(self, ty: &DynSolType, context: &PolicyContext) -> Result<String> {
        self.check_applicable(ty)?;
        match self {
            Self::SelfAddress => Ok(format!("{:#x}", context.wallet)),
        }
    }

    /// How this variable reads to someone approving the rule. The one place
    /// the wording lives, so a variable cannot be added and rendered as its
    /// own syntax in half the diff.
    const fn describe(self) -> &'static str {
        match self {
            Self::SelfAddress => "this wallet",
        }
    }
}

/// Check a literal against the type it will be compared to, at install time,
/// where there is no wallet to resolve a variable against and an error is the
/// whole point.
fn check_literal(literal: &str, ty: &DynSolType) -> Result<()> {
    match Variable::parse(literal)? {
        Some(variable) => variable.check_applicable(ty),
        None => parse_literal(literal, ty).map(|_| ()),
    }
}

/// The canonical text a literal compares against, resolving a variable through
/// the context. An error here is a non-match rather than a failure —
/// [`Predicate::evaluate`] discards it — and [`check_literal`] has already
/// refused the document that could produce one.
fn resolve_literal(literal: &str, ty: &DynSolType, context: &PolicyContext) -> Result<String> {
    match Variable::parse(literal)? {
        Some(variable) => variable.resolve(ty, context),
        None => parse_literal(literal, ty),
    }
}

/// How a literal reads in the permission diff and the approval review: a
/// variable by what it means, so a reviewer sees "this wallet" and not `$self`.
fn describe_literal(literal: &str) -> String {
    match Variable::parse(literal).ok().flatten() {
        Some(variable) => variable.describe().to_string(),
        None => literal.to_string(),
    }
}

/// Parse a policy literal the way the value it will be compared against is
/// typed, and return its canonical text. Type-directed, so a document says
/// `{"eq": "0"}` for an integer and `{"eq": "0x…"}` for an address without
/// having to declare which it meant.
fn parse_literal(literal: &str, ty: &DynSolType) -> Result<String> {
    match ty {
        DynSolType::Address => {
            let bytes = decode_hex_literal(literal)?;
            ensure!(
                bytes.len() == 20,
                "{literal:?} is {} bytes; an address is 20",
                bytes.len()
            );
            Ok(format!("{:#x}", Address::from_slice(&bytes)))
        }
        DynSolType::Bool => match literal {
            "true" | "false" => Ok(literal.to_string()),
            _ => bail!("{literal:?} is not a boolean"),
        },
        // The declared width is part of the type, so a literal outside it is
        // not a narrow rule but an unsatisfiable one: no canonical `uint8`
        // call can carry 256. Left unchecked it installed quietly and then
        // never fired, which is a silently absent `deny` — and while dirty
        // words could still round-trip past the canonical-form check, it was
        // a `deny` that failed to fire on calldata a masking target read as
        // the value the rule named. Refused here, where the number is written
        // and the author can still see what they meant.
        DynSolType::Uint(bits) => {
            let value = if literal.starts_with("0x") {
                U256::from_be_slice(&decode_hex_literal(literal)?)
            } else {
                ensure!(
                    !literal.is_empty() && literal.bytes().all(|byte| byte.is_ascii_digit()),
                    "{literal:?} must be decimal digits or 0x-prefixed hex"
                );
                U256::from_str(literal)
                    .with_context(|| format!("{literal:?} does not fit an unsigned integer"))?
            };
            ensure!(
                *bits >= 256 || value < (U256::from(1) << *bits),
                "{literal:?} does not fit uint{bits}"
            );
            Ok(value.to_string())
        }
        DynSolType::Int(bits) => {
            let (sign, digits) = literal
                .strip_prefix('-')
                .map_or(("", literal), |rest| ("-", rest));
            ensure!(
                !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()),
                "{literal:?} must be decimal digits, optionally signed"
            );
            let value = I256::from_str(&format!("{sign}{digits}"))
                .with_context(|| format!("{literal:?} does not fit a signed integer"))?;
            ensure!(
                *bits >= 256 || (value >= min_int(*bits) && value <= max_int(*bits)),
                "{literal:?} does not fit int{bits}"
            );
            Ok(value.to_string())
        }
        DynSolType::Bytes => Ok(format!("0x{}", hex::encode(decode_hex_literal(literal)?))),
        DynSolType::FixedBytes(size) => {
            let bytes = decode_hex_literal(literal)?;
            ensure!(
                bytes.len() == *size,
                "{literal:?} is {} bytes; this parameter is bytes{size}",
                bytes.len()
            );
            Ok(format!("0x{}", hex::encode(bytes)))
        }
        DynSolType::String => Ok(literal.to_string()),
        other => bail!("values of type {other:?} cannot be compared to a literal"),
    }
}

#[cfg(test)]
#[path = "predicate_test.rs"]
mod tests;
