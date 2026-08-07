//! Every shipped example policy, exercised against real calls.
//!
//! `shipped_assets.rs` proves the examples parse. This proves they *do what
//! their labels say*, which is the part a reader actually relies on: an
//! example that parses but permits something its label disclaims is worse
//! than no example, because it is quoted as a pattern.
//!
//! Each case states the call and the verdict it must get. Denials are as
//! load-bearing as grants here — most of these files exist to show something
//! being refused.

use alloy::{
    dyn_abi::{DynSolValue, JsonAbiExt},
    json_abi::Function,
    primitives::{Address, U256, address},
};
use ekubo_wallet::core::{
    execution_plan::ExecutionPlan,
    policy::{PolicyOutcome, WalletPolicy, evaluate_policy, policy_allows, policy_outcome},
    predicate::PolicyContext,
};
use serde_json::json;
use std::{fs, path::PathBuf};

/// Deliberately not the router: `$self` and the router's own `eq` must be
/// distinguishable, or a rule requiring proceeds to come back here would pass
/// for proceeds sent to the router instead.
const WALLET: Address = address!("9999999999999999999999999999999999999999");
/// The address the swap and batching examples name as their router.
const ROUTER: Address = address!("1111111111111111111111111111111111111111");
const USDC: Address = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
const WETH: Address = address!("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
/// The recipient the examples name outright.
const FRIEND: Address = address!("2222222222222222222222222222222222222222");
/// Named by no example, so nothing should admit it.
const STRANGER: Address = address!("3333333333333333333333333333333333333333");

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn example(name: &str) -> WalletPolicy {
    let path = repository_root().join("examples/policies").join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|_| panic!("{name} is readable"));
    let value = serde_json::from_str(&text).unwrap_or_else(|_| panic!("{name} is JSON"));
    WalletPolicy::parse(value).unwrap_or_else(|error| panic!("{name} is a valid policy: {error:#}"))
}

/// Everything a policy may consult beyond the plan: the signing wallet.
fn context() -> PolicyContext {
    PolicyContext { wallet: WALLET }
}

fn encode(abi: &str, values: &[DynSolValue]) -> String {
    let function = Function::parse(abi).expect("signature parses");
    format!(
        "0x{}",
        hex::encode(function.abi_encode_input(values).expect("values encode"))
    )
}

fn uint(value: u128) -> DynSolValue {
    DynSolValue::Uint(U256::from(value), 256)
}

/// A one-step plan on `chain_id`.
fn plan(chain_id: &str, to: Address, data: &str, value: &str) -> ExecutionPlan {
    ExecutionPlan::parse(json!({
        "schema_version": "1",
        "chain_id": chain_id,
        "caip2_chain_id": format!("eip155:{chain_id}"),
        "sender": format!("{WALLET:#x}"),
        "ordered_steps": [{
            "step": 1,
            "kind": "execution",
            "transaction": {
                "chain_id": chain_id,
                "from": format!("{WALLET:#x}"),
                "to": format!("{to:#x}"),
                "data": data,
                "value": value
            }
        }]
    }))
    .expect("plan parses")
}

fn allows(policy: &WalletPolicy, plan: &ExecutionPlan) -> bool {
    policy_allows(&evaluate_policy(plan, policy, &context()))
}

fn outcome(policy: &WalletPolicy, plan: &ExecutionPlan) -> PolicyOutcome {
    policy_outcome(&evaluate_policy(plan, policy, &context()))
}

/// Assert a verdict and say which example and which call produced it.
#[track_caller]
fn check(name: &str, policy: &WalletPolicy, plan: &ExecutionPlan, expected: bool, case: &str) {
    let findings = evaluate_policy(plan, policy, &context());
    let actual = policy_allows(&findings);
    assert_eq!(
        actual,
        expected,
        "{name}: {case} should be {}, findings: {:?}",
        if expected { "allowed" } else { "denied" },
        findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>()
    );
}

fn transfer(to: Address, amount: u128) -> String {
    encode(
        "transfer(address to, uint256 amount)",
        &[DynSolValue::Address(to), uint(amount)],
    )
}

fn approve(spender: Address, amount: u128) -> String {
    encode(
        "approve(address spender, uint256 amount)",
        &[DynSolValue::Address(spender), uint(amount)],
    )
}

fn set_approval_for_all(operator: Address, approved: bool) -> String {
    encode(
        "setApprovalForAll(address operator, bool approved)",
        &[DynSolValue::Address(operator), DynSolValue::Bool(approved)],
    )
}

// ------------------------------------------------------------------ examples

#[test]
fn transfers_to_address_book_permits_only_named_recipients() {
    let name = "transfers-to-named-addresses.json";
    let policy = example(name);
    check(
        name,
        &policy,
        &plan("1", USDC, &transfer(FRIEND, 1_000_000), "0"),
        true,
        "confirmed token to a named recipient",
    );
    check(
        name,
        &policy,
        &plan("1", USDC, &transfer(STRANGER, 1), "0"),
        false,
        "confirmed token to an unnamed recipient",
    );
    check(
        name,
        &policy,
        &plan("1", STRANGER, &transfer(FRIEND, 1), "0"),
        false,
        "unconfirmed token, even to a named recipient",
    );
    check(
        name,
        &policy,
        &plan("1", USDC, &approve(FRIEND, 1), "0"),
        false,
        "approve is a different function and matches no rule",
    );
    // The label promises no amount ceiling, and there is none.
    check(
        name,
        &policy,
        &plan("1", USDC, &transfer(FRIEND, u128::MAX), "0"),
        true,
        "any amount, because a rule bounds which calls not how much",
    );
}

#[test]
fn revoke_only_lets_an_agent_clean_up_but_never_grant() {
    let name = "revoke-approvals-only.json";
    let policy = example(name);
    check(
        name,
        &policy,
        &plan("1", USDC, &approve(ROUTER, 0), "0"),
        true,
        "approve to zero is a revocation",
    );
    check(
        name,
        &policy,
        &plan("1", USDC, &approve(ROUTER, 1), "0"),
        false,
        "approve to one is a grant",
    );
    check(
        name,
        &policy,
        &plan("1", USDC, &set_approval_for_all(ROUTER, false), "0"),
        true,
        "revoking an operator",
    );
    check(
        name,
        &policy,
        &plan("1", USDC, &set_approval_for_all(ROUTER, true), "0"),
        false,
        "granting an operator",
    );
    // The wildcard chain entry means this holds off mainnet too.
    check(
        name,
        &policy,
        &plan("8453", USDC, &approve(ROUTER, 0), "0"),
        true,
        "the wildcard chain covers Base",
    );
}

#[test]
fn swap_example_requires_confirmed_hops_and_proceeds_to_self() {
    let name = "swap-proceeds-to-self.json";
    let policy = example(name);
    let abi = "swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)";
    let swap = |path: Vec<Address>, recipient: Address| {
        encode(
            abi,
            &[
                uint(1),
                uint(1),
                DynSolValue::Array(path.into_iter().map(DynSolValue::Address).collect()),
                DynSolValue::Address(recipient),
                uint(0),
            ],
        )
    };
    check(
        name,
        &policy,
        &plan("1", ROUTER, &swap(vec![USDC, WETH], WALLET), "0"),
        true,
        "confirmed hops paying back to this wallet",
    );
    check(
        name,
        &policy,
        &plan("1", ROUTER, &swap(vec![USDC, STRANGER], WALLET), "0"),
        false,
        "one unconfirmed hop fails `each`",
    );
    check(
        name,
        &policy,
        &plan("1", ROUTER, &swap(vec![USDC, WETH], FRIEND), "0"),
        false,
        "proceeds to someone else fail `$self`",
    );
    check(
        name,
        &policy,
        &plan("1", USDC, &approve(ROUTER, u128::MAX), "0"),
        true,
        "approving the named router for a confirmed token",
    );
    check(
        name,
        &policy,
        &plan("1", USDC, &approve(STRANGER, 1), "0"),
        false,
        "approving anyone else",
    );
}

#[test]
fn a_deny_rule_beats_a_blanket_allow() {
    let name = "deny-blanket-operators.json";
    let policy = example(name);
    check(
        name,
        &policy,
        &plan("1", STRANGER, "0xdeadbeef", "0"),
        true,
        "the blanket allow covers unremarkable calls",
    );
    check(
        name,
        &policy,
        &plan("1", USDC, &set_approval_for_all(ROUTER, true), "0"),
        false,
        "the deny rule wins over the blanket allow",
    );
    check(
        name,
        &policy,
        &plan("1", USDC, &set_approval_for_all(ROUTER, false), "0"),
        true,
        "revocation is not what the deny rule names",
    );
    check(
        name,
        &policy,
        &plan(
            "1",
            USDC,
            &encode(
                "increaseAllowance(address spender, uint256 addedValue)",
                &[DynSolValue::Address(ROUTER), uint(1)],
            ),
            "0",
        ),
        false,
        "increaseAllowance is denied by the `any` branch",
    );
}

#[test]
fn native_sends_example_permits_plain_sends_and_nothing_else() {
    let name = "native-sends-only.json";
    let policy = example(name);
    check(
        name,
        &policy,
        &plan("1", FRIEND, "0x", "1000000000000000000"),
        true,
        "plain send to a named address",
    );
    check(
        name,
        &policy,
        &plan("1", STRANGER, "0x", "1"),
        false,
        "plain send to an unnamed address",
    );
    check(
        name,
        &policy,
        &plan("1", FRIEND, &transfer(FRIEND, 1), "0"),
        false,
        "calldata to a named address is not a plain send",
    );
}

#[test]
fn the_batching_example_constrains_what_the_payload_may_carry() {
    let name = "batched-calls.json";
    let policy = example(name);
    let multicall = |inner: Vec<String>| {
        encode(
            "multicall(bytes[] data)",
            &[DynSolValue::Array(
                inner
                    .into_iter()
                    .map(|hex_string| {
                        DynSolValue::Bytes(
                            hex::decode(hex_string.trim_start_matches("0x")).expect("hex"),
                        )
                    })
                    .collect(),
            )],
        )
    };
    check(
        name,
        &policy,
        &plan(
            "1",
            ROUTER,
            &multicall(vec![transfer(FRIEND, 1), transfer(FRIEND, 2)]),
            "0",
        ),
        true,
        "every nested call is a transfer to a named address",
    );
    check(
        name,
        &policy,
        &plan(
            "1",
            ROUTER,
            &multicall(vec![transfer(FRIEND, 1), transfer(STRANGER, 2)]),
            "0",
        ),
        false,
        "one nested call escapes the address book",
    );
    check(
        name,
        &policy,
        &plan(
            "1",
            ROUTER,
            &multicall(vec![approve(STRANGER, u128::MAX)]),
            "0",
        ),
        false,
        "a nested approve is not a nested transfer",
    );
    // `each` over an empty array is vacuously true, so an empty batch is
    // permitted. It also does nothing, which is why that is the right answer.
    check(
        name,
        &policy,
        &plan("1", ROUTER, &multicall(Vec::new()), "0"),
        true,
        "an empty batch carries nothing to object to",
    );
}

#[test]
fn the_edge_case_example_shows_each_corner_of_the_language() {
    let name = "predicate-edge-cases.json";
    let policy = example(name);
    check(
        name,
        &policy,
        &plan("1", USDC, &transfer(FRIEND, 1), "0"),
        true,
        "`all`: named recipient that is not the zero address",
    );
    check(
        name,
        &policy,
        &plan("1", USDC, &transfer(WALLET, 1), "0"),
        true,
        "`$self` sits in the same `in` set as the named address",
    );
    check(
        name,
        &policy,
        &plan("1", USDC, &transfer(STRANGER, 1), "0"),
        false,
        "and admits nobody else",
    );
    check(
        name,
        &policy,
        &plan("1", STRANGER, &transfer(FRIEND, 1), "0"),
        false,
        "`not`: an unlisted target is denied outright",
    );
    check(
        name,
        &policy,
        &plan("1", ROUTER, &encode("poke()", &[]), "0"),
        true,
        "`any`: the second branch matches a no-argument call",
    );
    check(
        name,
        &policy,
        &plan("1", ROUTER, &encode("poke()", &[]), "1000000000000000000"),
        true,
        "the native_value guard lists this exact amount",
    );
    check(
        name,
        &policy,
        &plan("1", ROUTER, &encode("poke()", &[]), "5"),
        false,
        "an amount the native_value guard does not list",
    );
}

#[test]
fn the_three_outcomes_are_distinguishable() {
    // The whole reason `deny` and "no rule matched" are separate outcomes: one
    // is the owner having answered, the other is nobody having asked. They get
    // opposite treatment downstream, so they must be told apart here.
    let denying = example("deny-blanket-operators.json");
    assert_eq!(
        outcome(&denying, &plan("1", STRANGER, "0xdeadbeef", "0")),
        PolicyOutcome::Allowed,
        "an allow rule matched: this signs with no prompt"
    );
    assert_eq!(
        outcome(
            &denying,
            &plan("1", USDC, &set_approval_for_all(ROUTER, true), "0")
        ),
        PolicyOutcome::Rejected,
        "a deny rule matched: refused outright, never queued, no approval path"
    );

    let narrow = example("transfers-to-named-addresses.json");
    assert_eq!(
        outcome(&narrow, &plan("1", STRANGER, "0xdeadbeef", "0")),
        PolicyOutcome::RequiresApproval,
        "no rule matched: the owner has not spoken, so a human still may"
    );
    assert_eq!(
        outcome(&narrow, &plan("1", USDC, &transfer(FRIEND, 1), "0")),
        PolicyOutcome::Allowed,
    );
}

#[test]
fn a_deny_rule_outranks_an_allow_that_also_matches() {
    // Both rules match the same call. Deny-precedence decides, and the outcome
    // is the hard one: a plan like this must not reach an approval prompt.
    let policy = WalletPolicy::parse(json!({
        "version": 1,
        "chains": { "1": { "rules": [
            { "effect": "allow", "label": "anything to this token" },
            { "effect": "deny", "label": "but never an operator grant",
              "calldata": { "selector": {
                  "abi": "setApprovalForAll(address operator, bool approved)",
                  "args": { "approved": { "eq": "true" } } } } },
        ]}},
    }))
    .expect("policy parses");
    assert_eq!(
        outcome(
            &policy,
            &plan("1", USDC, &set_approval_for_all(ROUTER, true), "0")
        ),
        PolicyOutcome::Rejected,
    );
}

// --------------------------------------------------------------- the defaults

#[test]
fn an_unmatched_call_is_denied_and_says_why() {
    // The property every example above rests on: silence denies.
    let policy = example("transfers-to-named-addresses.json");
    let findings = evaluate_policy(&plan("1", STRANGER, "0xdeadbeef", "0"), &policy, &context());
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect::<Vec<_>>(),
        ["call_not_allowed"],
        "an unmatched call is refused by the default, and the finding names it"
    );
}

#[test]
fn a_chain_the_example_does_not_configure_is_refused() {
    // These examples key on chain 1 with no wildcard, so nothing else applies.
    for name in [
        "transfers-to-named-addresses.json",
        "swap-proceeds-to-self.json",
        "native-sends-only.json",
        "batched-calls.json",
        "predicate-edge-cases.json",
    ] {
        let policy = example(name);
        assert!(
            !allows(&policy, &plan("8453", USDC, &transfer(FRIEND, 1), "0")),
            "{name} must not govern a chain it never mentions"
        );
    }
}

#[test]
fn every_example_refuses_a_call_it_never_describes() {
    // A blanket sanity net: no example may permit an arbitrary call to an
    // unknown contract, except the two that exist to allow everything.
    for name in [
        "transfers-to-named-addresses.json",
        "revoke-approvals-only.json",
        "swap-proceeds-to-self.json",
        "native-sends-only.json",
        "batched-calls.json",
        "predicate-edge-cases.json",
        "token-budget.template.json",
        "approval-wildcards.template.json",
        "deny-all.json",
    ] {
        let policy = example(name);
        assert!(
            !allows(&policy, &plan("1", STRANGER, "0xdeadbeef", "0")),
            "{name} permitted an arbitrary call to an unknown contract"
        );
    }
}
