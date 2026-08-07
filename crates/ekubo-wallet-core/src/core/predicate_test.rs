//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default.
//!
//! The property tests at the bottom carry most of the weight. Three of them
//! encode the invariants the whole engine rests on — that matching never
//! panics, that a matched call is canonically encoded, and that
//! `is_narrower_than` never claims a widening is a narrowing — and they are
//! the reason to trust the hand-written cases above them rather than the other
//! way round.

use super::*;
use alloy::primitives::address;
use proptest::prelude::*;

const WALLET: Address = address!("1111111111111111111111111111111111111111");
const TOKEN: Address = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
const FRIEND: Address = address!("2222222222222222222222222222222222222222");
const STRANGER: Address = address!("3333333333333333333333333333333333333333");

fn context() -> PolicyContext {
    PolicyContext { wallet: WALLET }
}

fn predicate(json: serde_json::Value) -> Predicate {
    serde_json::from_value(json).expect("predicate parses")
}

fn selector(abi: &str, args: &serde_json::Value) -> Predicate {
    predicate(serde_json::json!({ "selector": { "abi": abi, "args": args } }))
}

/// Encode a call the way an honest producer would.
fn encode(abi: &str, values: &[DynSolValue]) -> Vec<u8> {
    let function = Function::parse(abi).expect("signature parses");
    function.abi_encode_input(values).expect("values encode")
}

fn bytes(data: Vec<u8>) -> DynSolValue {
    DynSolValue::Bytes(data)
}

// ---------------------------------------------------------------- literals

#[test]
fn addresses_must_be_hex_with_an_0x_prefix() {
    let ty = DynSolType::Address;
    assert!(parse_literal("0x1111111111111111111111111111111111111111", &ty).is_ok());
    // Bare hex is refused rather than guessed at.
    assert!(parse_literal("1111111111111111111111111111111111111111", &ty).is_err());
    assert!(parse_literal("0x11", &ty).is_err(), "wrong width");
    assert!(parse_literal("0xzz11111111111111111111111111111111111111", &ty).is_err());
}

#[test]
fn integers_are_decimal_without_a_prefix() {
    let ty = DynSolType::Uint(256);
    assert_eq!(parse_literal("0", &ty).unwrap(), "0");
    assert_eq!(parse_literal("1000", &ty).unwrap(), "1000");
    // 0x-prefixed hex is the other legal spelling and canonicalizes to decimal,
    // so the two forms of one number compare equal.
    assert_eq!(parse_literal("0x10", &ty).unwrap(), "16");
    assert!(parse_literal("ten", &ty).is_err());
    assert!(parse_literal("1_000", &ty).is_err());
    assert!(parse_literal("", &ty).is_err());
}

#[test]
fn a_literal_is_canonicalized_before_comparison() {
    // Mixed-case hex in the document still matches a decoded address.
    let mixed = Predicate::Eq("0xA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48".into());
    assert!(mixed.matches(&DynSolValue::Address(TOKEN), &context()));
}

#[test]
fn fixed_bytes_literals_must_match_the_declared_width() {
    assert!(parse_literal("0x1234", &DynSolType::FixedBytes(2)).is_ok());
    assert!(
        parse_literal("0x1234", &DynSolType::FixedBytes(32)).is_err(),
        "a bytes32 rule that can never match is refused at parse time"
    );
}

#[test]
fn odd_length_hex_is_refused() {
    assert!(parse_literal("0x123", &DynSolType::Bytes).is_err());
}

// -------------------------------------------------------------- predicates

#[test]
fn the_only_thing_a_predicate_reads_beyond_the_call_is_the_wallet() {
    let ctx = context();
    let is_self = predicate(serde_json::json!({ "eq": SELF_LITERAL }));
    assert!(is_self.matches(&DynSolValue::Address(WALLET), &ctx));
    assert!(!is_self.matches(&DynSolValue::Address(FRIEND), &ctx));
}

#[test]
fn self_composes_with_the_literals_around_it() {
    // The reason `$self` is a literal and not a predicate of its own: "me or
    // one named address" is an ordinary `in`, with no `any` wrapped around it.
    let ctx = context();
    let me_or_friend = predicate(serde_json::json!({
        "in": [SELF_LITERAL, format!("{FRIEND:#x}")]
    }));
    assert!(me_or_friend.matches(&DynSolValue::Address(WALLET), &ctx));
    assert!(me_or_friend.matches(&DynSolValue::Address(FRIEND), &ctx));
    assert!(!me_or_friend.matches(&DynSolValue::Address(STRANGER), &ctx));
}

#[test]
fn self_resolves_against_the_wallet_being_asked_not_the_one_it_was_written_for() {
    // What portability means: the same document, two wallets, two answers.
    let is_self = predicate(serde_json::json!({ "eq": SELF_LITERAL }));
    let theirs = PolicyContext { wallet: FRIEND };
    assert!(is_self.matches(&DynSolValue::Address(FRIEND), &theirs));
    assert!(!is_self.matches(&DynSolValue::Address(WALLET), &theirs));
}

#[test]
fn an_unknown_variable_is_refused_rather_than_read_as_a_literal() {
    // A typo that parsed as an ordinary literal would be an address that never
    // matches anything, which is a rule silently doing nothing. Every literal
    // is 0x-hex or decimal, so nothing legitimate begins with `$` and refusing
    // the whole prefix costs nothing.
    for unknown in ["$slef", "$wallet", "$", "$SELF"] {
        assert!(
            check_literal(unknown, &DynSolType::Address).is_err(),
            "{unknown} must not parse as a literal"
        );
    }
    assert!(check_literal(SELF_LITERAL, &DynSolType::Address).is_ok());
}

#[test]
fn self_is_an_address_and_is_refused_anywhere_else() {
    for ty in [
        DynSolType::Uint(256),
        DynSolType::Bool,
        DynSolType::Bytes,
        DynSolType::String,
    ] {
        assert!(
            check_literal(SELF_LITERAL, &ty).is_err(),
            "{SELF_LITERAL} must not be applicable to {ty:?}"
        );
    }
}

#[test]
fn the_retired_is_wallet_spelling_no_longer_parses() {
    // `$self` replaced it. A document still saying `is_wallet` is refused
    // rather than guessed at: the two mean the same thing, but a policy that
    // silently rewrites itself is a policy whose permission diff shows the
    // owner something they did not write.
    let error = serde_json::from_value::<Predicate>(serde_json::json!("is_wallet"))
        .expect_err("the variant must not parse");
    assert!(error.to_string().contains("unknown variant"), "{error}");
}

#[test]
fn a_variable_reads_as_what_it_means_in_the_permission_diff() {
    // A reviewer approving a rule sees the authority, not the syntax.
    assert_eq!(
        predicate(serde_json::json!({ "eq": SELF_LITERAL })).describe(),
        "this wallet"
    );
    // Ordering follows the literals, so it does not move when the wording does.
    assert_eq!(
        predicate(serde_json::json!({ "in": [SELF_LITERAL, format!("{FRIEND:#x}")] })).describe(),
        format!("one of this wallet, {FRIEND:#x}")
    );
}

#[test]
fn the_metadata_predicates_are_gone_from_the_language() {
    // `is_token` and `is_address_book` let a row written to improve a label
    // widen what could be signed. A document naming either is refused rather
    // than parsed into something weaker, so a policy that relied on one fails
    // closed and visibly instead of quietly admitting less than it says.
    for removed in ["is_token", "is_address_book"] {
        let error = serde_json::from_value::<Predicate>(serde_json::json!(removed))
            .expect_err("the variant must not parse");
        assert!(error.to_string().contains("unknown variant"), "{error}");
    }
}

#[test]
fn an_empty_any_never_matches_and_an_empty_all_always_does() {
    let ctx = context();
    let value = DynSolValue::Address(WALLET);
    assert!(!Predicate::Any(Vec::new()).matches(&value, &ctx));
    assert!(Predicate::All(Vec::new()).matches(&value, &ctx));
}

#[test]
fn each_over_an_empty_array_is_vacuously_true() {
    let ctx = context();
    let empty = DynSolValue::Array(Vec::new());
    assert!(predicate(serde_json::json!({ "each": { "eq": SELF_LITERAL } })).matches(&empty, &ctx));
}

#[test]
fn each_requires_every_element() {
    let ctx = context();
    let all_known = DynSolValue::Array(vec![
        DynSolValue::Address(TOKEN),
        DynSolValue::Address(TOKEN),
    ]);
    let one_unknown = DynSolValue::Array(vec![
        DynSolValue::Address(TOKEN),
        DynSolValue::Address(STRANGER),
    ]);
    let each_token = Predicate::Each(Box::new(Predicate::Eq(format!("{TOKEN:#x}"))));
    assert!(each_token.matches(&all_known, &ctx));
    assert!(!each_token.matches(&one_unknown, &ctx));
}

#[test]
fn a_predicate_applied_to_the_wrong_shape_is_a_non_match_not_a_panic() {
    let ctx = context();
    // `each` over a scalar, an address literal over an integer, `$self` over a
    // bool: all unanswerable, all false.
    assert!(
        !predicate(serde_json::json!({ "each": { "eq": SELF_LITERAL } }))
            .matches(&DynSolValue::Address(TOKEN), &ctx)
    );
    assert!(
        !Predicate::Eq(format!("{TOKEN:#x}")).matches(&DynSolValue::Uint(U256::from(1), 256), &ctx)
    );
    assert!(
        !predicate(serde_json::json!({ "eq": SELF_LITERAL }))
            .matches(&DynSolValue::Bool(true), &ctx)
    );
}

// ------------------------------------------------------------ selector/ABI

#[test]
fn a_selector_predicate_matches_a_well_formed_call() {
    let ctx = context();
    let data = encode(
        "approve(address spender, uint256 amount)",
        &[
            DynSolValue::Address(FRIEND),
            DynSolValue::Uint(U256::from(500), 256),
        ],
    );
    let rule = selector(
        "approve(address spender, uint256 amount)",
        &serde_json::json!({ "spender": { "in": ["0x2222222222222222222222222222222222222222"] } }),
    );
    assert!(rule.matches(&bytes(data), &ctx));
}

#[test]
fn the_selector_is_derived_from_the_signature() {
    // keccak("approve(address,uint256)")[..4]
    let function = Function::parse("approve(address spender, uint256 amount)").unwrap();
    assert_eq!(hex::encode(function.selector()), "095ea7b3");
}

#[test]
fn a_different_function_with_the_same_argument_shape_does_not_match() {
    let ctx = context();
    let transfer = encode(
        "transfer(address to, uint256 amount)",
        &[
            DynSolValue::Address(FRIEND),
            DynSolValue::Uint(U256::from(1), 256),
        ],
    );
    let approve_rule = selector(
        "approve(address spender, uint256 amount)",
        &serde_json::json!({}),
    );
    assert!(
        !approve_rule.matches(&bytes(transfer), &ctx),
        "identical argument types, different selector"
    );
}

#[test]
fn trailing_bytes_break_the_canonical_form_check() {
    let ctx = context();
    let mut data = encode(
        "approve(address spender, uint256 amount)",
        &[
            DynSolValue::Address(FRIEND),
            DynSolValue::Uint(U256::from(1), 256),
        ],
    );
    let rule = selector(
        "approve(address spender, uint256 amount)",
        &serde_json::json!({}),
    );
    assert!(rule.matches(&bytes(data.clone()), &ctx));
    // alloy's decoder ignores trailing data; re-encoding is what catches it.
    data.push(0xff);
    assert!(!rule.matches(&bytes(data), &ctx));
}

#[test]
fn dirty_address_padding_breaks_the_canonical_form_check() {
    let ctx = context();
    let mut data = encode(
        "approve(address spender, uint256 amount)",
        &[
            DynSolValue::Address(FRIEND),
            DynSolValue::Uint(U256::from(1), 256),
        ],
    );
    // Byte 4 is the first byte of the spender word's zero padding. A decoder
    // that masks would still read FRIEND here; the round-trip refuses it, so a
    // rule cannot be satisfied by an encoding a contract might read otherwise.
    data[4] = 0x01;
    let rule = selector(
        "approve(address spender, uint256 amount)",
        &serde_json::json!({ "spender": { "eq": "0x2222222222222222222222222222222222222222" } }),
    );
    assert!(!rule.matches(&bytes(data), &ctx));
}

#[test]
fn truncated_calldata_is_a_non_match() {
    let ctx = context();
    let full = encode(
        "approve(address spender, uint256 amount)",
        &[
            DynSolValue::Address(FRIEND),
            DynSolValue::Uint(U256::from(1), 256),
        ],
    );
    let rule = selector(
        "approve(address spender, uint256 amount)",
        &serde_json::json!({}),
    );
    for length in 0..full.len() {
        assert!(
            !rule.matches(&bytes(full[..length].to_vec()), &ctx),
            "prefix of length {length} must not match"
        );
    }
}

#[test]
fn empty_calldata_is_expressed_as_an_eq_literal() {
    let ctx = context();
    let empty = Predicate::Eq("0x".into());
    assert!(empty.matches(&bytes(Vec::new()), &ctx));
    assert!(!empty.matches(&bytes(vec![0x00]), &ctx));
}

#[test]
fn nested_calls_fall_out_of_each_plus_selector() {
    let ctx = context();
    let inner_ok = encode(
        "transfer(address to, uint256 amount)",
        &[
            DynSolValue::Address(FRIEND),
            DynSolValue::Uint(U256::from(5), 256),
        ],
    );
    let inner_bad = encode(
        "transfer(address to, uint256 amount)",
        &[
            DynSolValue::Address(STRANGER),
            DynSolValue::Uint(U256::from(5), 256),
        ],
    );
    let rule = selector(
        "multicall(bytes[] data)",
        &serde_json::json!({
            "data": { "each": { "selector": {
                "abi": "transfer(address to, uint256 amount)",
                "args": { "to": { "in": ["0x2222222222222222222222222222222222222222"] } }
            }}}
        }),
    );
    let good = encode(
        "multicall(bytes[] data)",
        &[DynSolValue::Array(vec![
            DynSolValue::Bytes(inner_ok.clone()),
            DynSolValue::Bytes(inner_ok.clone()),
        ])],
    );
    let bad = encode(
        "multicall(bytes[] data)",
        &[DynSolValue::Array(vec![
            DynSolValue::Bytes(inner_ok),
            DynSolValue::Bytes(inner_bad),
        ])],
    );
    assert!(rule.matches(&bytes(good), &ctx));
    assert!(!rule.matches(&bytes(bad), &ctx));
}

#[test]
fn length_constrains_arrays() {
    let ctx = context();
    let rule = selector(
        "multicall(bytes[] data)",
        &serde_json::json!({ "data": { "length": { "eq": "1" } } }),
    );
    let one = encode(
        "multicall(bytes[] data)",
        &[DynSolValue::Array(vec![DynSolValue::Bytes(vec![1, 2, 3])])],
    );
    let two = encode(
        "multicall(bytes[] data)",
        &[DynSolValue::Array(vec![
            DynSolValue::Bytes(vec![1]),
            DynSolValue::Bytes(vec![2]),
        ])],
    );
    assert!(rule.matches(&bytes(one), &ctx));
    assert!(!rule.matches(&bytes(two), &ctx));
}

// ------------------------------------------------------- parse-time checks

#[test]
fn a_signature_must_name_every_parameter() {
    assert!(
        SelectorPredicate::new("approve(address,uint256)", BTreeMap::new()).is_err(),
        "rules refer to arguments by name, so names are mandatory"
    );
    assert!(SelectorPredicate::new("poke()", BTreeMap::new()).is_ok());
}

#[test]
fn a_predicate_on_an_unknown_parameter_is_refused() {
    let args = BTreeMap::from([(
        "recipient".to_string(),
        Predicate::Eq(SELF_LITERAL.to_string()),
    )]);
    assert!(SelectorPredicate::new("approve(address spender, uint256 amount)", args).is_err());
}

#[test]
fn a_predicate_that_could_never_match_its_type_is_refused_at_parse_time() {
    // an address literal on a uint, `each` on a scalar, `selector` on a non-bytes:
    // each of these would silently never match at signing time.
    for (abi, args) in [
        (
            "approve(address spender, uint256 amount)",
            serde_json::json!({ "amount": { "eq": SELF_LITERAL } }),
        ),
        (
            "approve(address spender, uint256 amount)",
            serde_json::json!({ "spender": { "each": { "eq": SELF_LITERAL } } }),
        ),
        (
            "approve(address spender, uint256 amount)",
            serde_json::json!({ "spender": { "eq": "$nonesuch" } }),
        ),
        (
            "approve(address spender, uint256 amount)",
            serde_json::json!({ "spender": { "selector": { "abi": "poke()" } } }),
        ),
        (
            "approve(address spender, uint256 amount)",
            serde_json::json!({ "spender": { "eq": "12" } }),
        ),
    ] {
        let parsed: Result<SelectorPredicate, _> = serde_json::from_value(serde_json::json!({
            "abi": abi, "args": args
        }));
        assert!(parsed.is_err(), "{abi} with {args} should be refused");
    }
}

#[test]
fn an_empty_in_set_is_refused() {
    assert!(
        Predicate::In(BTreeSet::new())
            .check_applicable(&DynSolType::Address)
            .is_err()
    );
}

#[test]
fn the_canonical_signature_collapses_spelling_differences() {
    let spaced =
        SelectorPredicate::new("approve(address spender, uint256 amount)", BTreeMap::new());
    let tight = SelectorPredicate::new("approve(address spender,uint256 amount)", BTreeMap::new());
    assert_eq!(
        spaced.unwrap().signature(),
        tight.unwrap().signature(),
        "one function must have one digest"
    );
}

// ------------------------------------------------------------- subsumption

#[test]
fn subsumption_recognizes_the_obvious_cases() {
    let one = Predicate::Eq("0x2222222222222222222222222222222222222222".into());
    let pair = predicate(serde_json::json!({ "in": [
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333"
    ]}));
    assert!(one.is_narrower_than(&pair));
    assert!(!pair.is_narrower_than(&one));
    assert!(pair.is_narrower_than(&Predicate::AnyValue));
    assert!(!Predicate::AnyValue.is_narrower_than(&pair));
}

#[test]
fn subsumption_reverses_under_negation() {
    let narrow = Predicate::Eq("0x2222222222222222222222222222222222222222".into());
    let wide = predicate(serde_json::json!({ "in": [
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333"
    ]}));
    let not_narrow = Predicate::Not(Box::new(narrow.clone()));
    let not_wide = Predicate::Not(Box::new(wide.clone()));
    // `not wide` admits fewer addresses than `not narrow`.
    assert!(not_wide.is_narrower_than(&not_narrow));
    assert!(!not_narrow.is_narrower_than(&not_wide));
}

#[test]
fn a_selector_rule_is_narrower_when_it_constrains_more() {
    let loose = selector(
        "approve(address spender, uint256 amount)",
        &serde_json::json!({}),
    );
    let tight = selector(
        "approve(address spender, uint256 amount)",
        &serde_json::json!({ "spender": { "in": ["0x2222222222222222222222222222222222222222"] } }),
    );
    assert!(tight.is_narrower_than(&loose));
    assert!(!loose.is_narrower_than(&tight));
}

// ---------------------------------------------------------------- fuzzing

/// The literals an address slot may compare against, including the variable —
/// `$self` is one of these rather than a strategy of its own precisely because
/// it is a literal, so `eq` and `in` exercise it exactly as they do the rest.
///
/// `WALLET` is in here alongside `$self`, which under [`context`] resolves to
/// it. That the two are indistinguishable by evaluation and distinguishable by
/// `is_narrower_than` is intended: subsumption may be incomplete, and a policy
/// naming an address outright is not the same authority as one that follows
/// whichever wallet it is installed on.
fn address_literals() -> Vec<String> {
    vec![
        SELF_LITERAL.to_string(),
        format!("{WALLET:#x}"),
        format!("{TOKEN:#x}"),
        format!("{FRIEND:#x}"),
        format!("{STRANGER:#x}"),
    ]
}

/// The non-combinator predicates over an address-typed value.
fn address_leaf_predicate() -> impl Strategy<Value = Predicate> {
    let addresses = prop::sample::select(address_literals());
    prop_oneof![
        Just(Predicate::AnyValue),
        addresses.clone().prop_map(Predicate::Eq),
        prop::collection::btree_set(addresses, 1..4).prop_map(Predicate::In),
    ]
}

/// Predicates over an address-typed value, for the soundness properties.
fn address_predicate() -> impl Strategy<Value = Predicate> {
    let addresses = prop::sample::select(address_literals());
    let leaf = prop_oneof![
        Just(Predicate::AnyValue),
        addresses.clone().prop_map(Predicate::Eq),
        prop::collection::btree_set(addresses, 1..4).prop_map(Predicate::In),
    ];
    leaf.prop_recursive(3, 12, 3, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 1..3).prop_map(Predicate::Any),
            prop::collection::vec(inner.clone(), 0..3).prop_map(Predicate::All),
            inner.prop_map(|item| Predicate::Not(Box::new(item))),
        ]
    })
}

fn sample_addresses() -> Vec<Address> {
    vec![WALLET, TOKEN, FRIEND, STRANGER, Address::ZERO]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The property the whole default-deny design rests on: an unanswerable
    /// question is a non-match, never a panic and never an error.
    #[test]
    fn matching_arbitrary_bytes_never_panics(data in prop::collection::vec(any::<u8>(), 0..600)) {
        let ctx = context();
        for rule in [
            selector("approve(address spender, uint256 amount)", &serde_json::json!({})),
            selector(
                "multicall(bytes[] data)",
                &serde_json::json!({ "data": { "each": { "selector": {
                    "abi": "transfer(address to, uint256 amount)",
                    "args": { "to": { "eq": SELF_LITERAL } }
                }}}}),
            ),
            Predicate::Eq("0x".into()),
            Predicate::Length(Box::new(Predicate::Eq("4".into()))),
        ] {
            let _ = rule.matches(&bytes(data.clone()), &ctx);
        }
    }

    /// Any honestly encoded call matches a rule that pins every argument, and
    /// the selector predicate agrees with alloy about what those arguments are.
    #[test]
    fn honest_encodings_match_a_fully_pinned_rule(
        spender in prop::sample::select(sample_addresses()),
        amount in any::<u128>(),
    ) {
        let ctx = context();
        let data = encode(
            "approve(address spender, uint256 amount)",
            &[
                DynSolValue::Address(spender),
                DynSolValue::Uint(U256::from(amount), 256),
            ],
        );
        let rule = selector(
            "approve(address spender, uint256 amount)",
            &serde_json::json!({
                "spender": { "eq": format!("{spender:#x}") },
                "amount": { "eq": amount.to_string() },
            }),
        );
        prop_assert!(rule.matches(&bytes(data), &ctx));
    }

    /// Flipping any single byte of a canonical encoding must break a rule that
    /// pins every argument: either the decode fails, or the round-trip fails,
    /// or some argument now differs. This is what stops an attacker reshaping
    /// calldata into something a rule still admits but a contract reads
    /// differently.
    #[test]
    fn single_byte_mutations_never_survive_a_fully_pinned_rule(
        index in 0usize..68,
        delta in 1u8..=255,
    ) {
        let ctx = context();
        let spender = FRIEND;
        let amount = 12_345_u64;
        let mut data = encode(
            "approve(address spender, uint256 amount)",
            &[
                DynSolValue::Address(spender),
                DynSolValue::Uint(U256::from(amount), 256),
            ],
        );
        let rule = selector(
            "approve(address spender, uint256 amount)",
            &serde_json::json!({
                "spender": { "eq": format!("{spender:#x}") },
                "amount": { "eq": amount.to_string() },
            }),
        );
        prop_assert!(rule.matches(&bytes(data.clone()), &ctx));
        data[index] = data[index].wrapping_add(delta);
        prop_assert!(!rule.matches(&bytes(data), &ctx), "mutation at {index} survived");
    }

    /// `is_narrower_than` may be incomplete, but it must never be wrong: if it
    /// says A is narrower than B, then every value A admits, B admits too. A
    /// false claim here would render a widening as a narrowing in the diff a
    /// human approves.
    #[test]
    fn subsumption_never_claims_a_widening_is_a_narrowing(
        left in address_predicate(),
        right in address_predicate(),
    ) {
        let ctx = context();
        if left.is_narrower_than(&right) {
            for candidate in sample_addresses() {
                let value = DynSolValue::Address(candidate);
                if left.matches(&value, &ctx) {
                    prop_assert!(
                        right.matches(&value, &ctx),
                        "{left:?} claimed narrower than {right:?}, but {candidate} escapes"
                    );
                }
            }
        }
    }

    /// Subsumption is reflexive, which is the cheapest sanity check that the
    /// structural cases line up with the evaluator.
    #[test]
    fn subsumption_is_reflexive(rule in address_predicate()) {
        prop_assert!(rule.is_narrower_than(&rule));
    }

    /// A leaf predicate the type check rejects for a type must never match a
    /// value of that type — that is what makes parse-time rejection a real
    /// guard rather than a style rule. It is deliberately only claimed for
    /// leaves: `any` is rejected when *some* branch is inapplicable, while
    /// another branch may still legitimately match.
    #[test]
    fn rejected_leaf_predicates_never_match(rule in address_leaf_predicate()) {
        let ctx = context();
        if rule.check_applicable(&DynSolType::Uint(256)).is_err() {
            prop_assert!(!rule.matches(&DynSolValue::Uint(U256::from(7), 256), &ctx));
        }
    }
}

// ------------------------------------------- fuzzing across dynamic ABI types
//
// The properties above use one static signature. Dynamic types are where ABI
// encoding actually gets interesting — a `bytes` or an array is reached through
// an offset word, so a decoder that trusted the head would read the wrong
// thing. These generate whole calls across several shapes.

/// One generated call: a signature and values that fit it.
#[derive(Clone, Debug)]
struct Shape {
    abi: &'static str,
    values: Vec<DynSolValue>,
}

impl Shape {
    fn calldata(&self) -> Vec<u8> {
        encode(self.abi, &self.values)
    }

    /// A predicate pinning every argument to the value it was built from.
    fn fully_pinned(&self) -> Predicate {
        let function = Function::parse(self.abi).expect("signature parses");
        let args = function
            .inputs
            .iter()
            .zip(&self.values)
            .filter_map(|(input, value)| {
                render(value).map(|text| (input.name.clone(), Predicate::Eq(text)))
            })
            .collect::<BTreeMap<_, _>>();
        Predicate::Selector(Box::new(
            SelectorPredicate::new(self.abi, args).expect("pinned predicate builds"),
        ))
    }
}

fn any_address() -> impl Strategy<Value = Address> {
    prop::array::uniform20(any::<u8>()).prop_map(Address::from)
}

/// Shapes whose every argument is a scalar, so all of them can be pinned with
/// `eq`. Includes `bytes` and `string`, which are dynamically encoded.
fn pinnable_shape() -> impl Strategy<Value = Shape> {
    prop_oneof![
        (any_address(), any::<u128>()).prop_map(|(to, amount)| Shape {
            abi: "transfer(address to, uint256 amount)",
            values: vec![
                DynSolValue::Address(to),
                DynSolValue::Uint(U256::from(amount), 256)
            ],
        }),
        (any_address(), any::<bool>()).prop_map(|(operator, approved)| Shape {
            abi: "setApprovalForAll(address operator, bool approved)",
            values: vec![DynSolValue::Address(operator), DynSolValue::Bool(approved)],
        }),
        (
            prop::collection::vec(any::<u8>(), 0..70),
            "[a-z ]{0,40}".prop_map(String::from)
        )
            .prop_map(|(payload, memo)| Shape {
                abi: "submit(bytes payload, string memo)",
                values: vec![DynSolValue::Bytes(payload), DynSolValue::String(memo)],
            }),
    ]
}

/// Shapes including arrays, which cannot be pinned with `eq` but still have to
/// decode and round-trip correctly.
fn array_shape() -> impl Strategy<Value = Shape> {
    prop_oneof![
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..40), 0..4).prop_map(|calls| {
            Shape {
                abi: "multicall(bytes[] data)",
                values: vec![DynSolValue::Array(
                    calls.into_iter().map(DynSolValue::Bytes).collect(),
                )],
            }
        }),
        (
            any::<u64>(),
            prop::collection::vec(any_address(), 0..5),
            any_address()
        )
            .prop_map(|(amount_in, path, to)| Shape {
                abi: "swap(uint256 amountIn, address[] path, address to)",
                values: vec![
                    DynSolValue::Uint(U256::from(amount_in), 256),
                    DynSolValue::Array(path.into_iter().map(DynSolValue::Address).collect()),
                    DynSolValue::Address(to),
                ],
            }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Whatever the shape, an honestly encoded call matches a bare selector
    /// predicate for its own signature — dynamic offsets and all.
    #[test]
    fn any_shape_matches_its_own_signature(
        shape in prop_oneof![pinnable_shape(), array_shape()]
    ) {
        let ctx = context();
        let rule = selector(shape.abi, &serde_json::json!({}));
        prop_assert!(rule.matches(&bytes(shape.calldata()), &ctx));
    }

    /// ...and never matches a different signature.
    #[test]
    fn any_shape_is_rejected_by_a_different_signature(
        shape in prop_oneof![pinnable_shape(), array_shape()]
    ) {
        let ctx = context();
        let other = if shape.abi == "transfer(address to, uint256 amount)" {
            "approve(address spender, uint256 amount)"
        } else {
            "transfer(address to, uint256 amount)"
        };
        let rule = selector(other, &serde_json::json!({}));
        prop_assert!(!rule.matches(&bytes(shape.calldata()), &ctx));
    }

    /// The general form of the mutation property, across dynamic encodings: no
    /// single-byte change to a canonical call can leave every decoded argument
    /// where it was. This is what stops calldata being reshaped into something
    /// a rule still admits but a contract reads differently.
    #[test]
    fn no_single_byte_mutation_preserves_every_argument(
        shape in pinnable_shape(),
        seed in any::<usize>(),
        delta in 1u8..=255,
    ) {
        let ctx = context();
        let rule = shape.fully_pinned();
        let mut data = shape.calldata();
        prop_assert!(rule.matches(&bytes(data.clone()), &ctx), "honest call must match");
        let index = seed % data.len();
        data[index] = data[index].wrapping_add(delta);
        prop_assert!(
            !rule.matches(&bytes(data), &ctx),
            "mutation at byte {} survived a fully pinned rule",
            index
        );
    }

    /// Truncation at any length is a non-match, for every shape.
    #[test]
    fn no_prefix_of_any_shape_matches(
        shape in prop_oneof![pinnable_shape(), array_shape()],
        seed in any::<usize>(),
    ) {
        let ctx = context();
        let rule = selector(shape.abi, &serde_json::json!({}));
        let data = shape.calldata();
        let length = seed % data.len();
        prop_assert!(!rule.matches(&bytes(data[..length].to_vec()), &ctx));
    }

    /// Appending anything to a canonical call breaks it, whatever the shape.
    #[test]
    fn no_shape_tolerates_trailing_bytes(
        shape in prop_oneof![pinnable_shape(), array_shape()],
        tail in prop::collection::vec(any::<u8>(), 1..8),
    ) {
        let ctx = context();
        let rule = selector(shape.abi, &serde_json::json!({}));
        let mut data = shape.calldata();
        data.extend_from_slice(&tail);
        prop_assert!(!rule.matches(&bytes(data), &ctx));
    }
}

// ------------------------------------------------- unreadable encodings

const APPROVE: &str = "approve(address spender, uint256 amount)";

fn approve_body() -> Vec<u8> {
    encode(
        APPROVE,
        &[
            DynSolValue::Address(FRIEND),
            DynSolValue::Uint(U256::from(1), 256),
        ],
    )
}

#[test]
fn an_illegible_body_is_unreadable_rather_than_absent() {
    // The distinction the engine rests on: "not my subject" and "my subject,
    // in an encoding I cannot certify" are different answers. Only the first
    // is a plain `No`.
    let ctx = context();
    let rule = selector(APPROVE, &serde_json::json!({}));
    let honest = approve_body();
    assert_eq!(rule.evaluate(&bytes(honest.clone()), &ctx), Match::Yes);

    let other = encode(
        "transfer(address to, uint256 amount)",
        &[
            DynSolValue::Address(FRIEND),
            DynSolValue::Uint(U256::from(1), 256),
        ],
    );
    assert_eq!(rule.evaluate(&bytes(other), &ctx), Match::No);

    let mut trailing = honest.clone();
    trailing.push(0x00);
    assert_eq!(rule.evaluate(&bytes(trailing), &ctx), Match::Unreadable);

    let truncated = honest[..honest.len() - 1].to_vec();
    assert_eq!(rule.evaluate(&bytes(truncated), &ctx), Match::Unreadable);
}

#[test]
fn doubt_survives_negation_and_composition() {
    let ctx = context();
    let mut data = approve_body();
    data.push(0x00);

    let negated = predicate(serde_json::json!({ "not": { "selector": { "abi": APPROVE } } }));
    assert_eq!(
        negated.evaluate(&bytes(data.clone()), &ctx),
        Match::Unreadable,
        "negating doubt must not manufacture certainty"
    );
    assert!(!negated.matches(&bytes(data.clone()), &ctx));

    let any = predicate(serde_json::json!({ "any": [{ "selector": { "abi": APPROVE } }] }));
    assert_eq!(any.evaluate(&bytes(data.clone()), &ctx), Match::Unreadable);
    let all = predicate(serde_json::json!({ "all": [{ "selector": { "abi": APPROVE } }] }));
    assert_eq!(all.evaluate(&bytes(data.clone()), &ctx), Match::Unreadable);

    // A definite answer still settles a composition that also holds doubt.
    let certain = predicate(serde_json::json!({ "any": [
        { "any_value": null },
        { "selector": { "abi": APPROVE } }
    ]}));
    assert_eq!(certain.evaluate(&bytes(data), &ctx), Match::Yes);
}
