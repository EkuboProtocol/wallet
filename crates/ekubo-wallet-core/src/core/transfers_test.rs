//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use std::str::FromStr as _;

fn chain() -> DecimalU256 {
    DecimalU256::new("1").unwrap()
}

fn sender() -> Address {
    Address::repeat_byte(0x11)
}

fn token() -> Address {
    Address::from_str("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48").unwrap()
}

/// The native leg is refused, and it is refused by the plan rather than here.
///
/// The check used to sit in `transfer_plan`, which only `wallet_send_transfers`
/// reaches. `wallet_send_execution_plan` reaches the same send with a plan any
/// producer authored, so the check covered the honest door and left the general
/// one open. It is on `ExecutionPlan::validate` now; this test stays to prove
/// the transfer path still gets the refusal through it.
#[test]
fn a_native_transfer_to_the_zero_address_is_refused() {
    let native = transfer_plan(
        &chain(),
        sender(),
        vec![Transfer {
            token: Address::ZERO,
            to: Address::ZERO,
            amount: DecimalU256::new("1000").unwrap(),
        }],
    );
    let error = format!("{:#}", native.unwrap_err());
    assert!(error.contains("cannot be undone"), "{error}");

    // One bad recipient in a batch refuses the batch: the plan is signed as a
    // unit, so admitting the others would sign the destruction alongside them.
    let batch = transfer_plan(
        &chain(),
        sender(),
        vec![
            Transfer {
                token: Address::ZERO,
                to: Address::repeat_byte(0x22),
                amount: DecimalU256::new("1").unwrap(),
            },
            Transfer {
                token: Address::ZERO,
                to: Address::ZERO,
                amount: DecimalU256::new("1").unwrap(),
            },
        ],
    );
    assert!(batch.is_err());
}

/// And an ERC-20 transfer naming zero is *not* refused, which is a deliberate
/// narrowing rather than an oversight.
///
/// Its recipient rides in calldata; the transaction's `to` is the token. A
/// plan-level check sees the token and nothing else, and decoding every
/// `transfer(address,uint256)` to find a recipient is a different feature from
/// checking where a transaction is addressed.
///
/// What that gives up is small. The destructive case is native value: sent to
/// `0x0` it is gone and nothing can undo it. An ERC-20 `transfer` to zero
/// reverts on `OpenZeppelin` and on most implementations, so the token refuses it
/// without help -- the original claim that "a great many burn the amount" was
/// stronger than the evidence for it.
#[test]
fn an_erc20_transfer_naming_zero_is_left_to_the_token() {
    let erc20 = transfer_plan(
        &chain(),
        sender(),
        vec![Transfer {
            token: token(),
            to: Address::ZERO,
            amount: DecimalU256::new("1000").unwrap(),
        }],
    )
    .expect("the transaction is addressed to the token, which is a real recipient");
    assert_eq!(erc20.ordered_steps[0].transaction.to, token());
}

/// And an ordinary recipient still builds the plan it always did, so the check
/// is a refusal of one address rather than of transfers.
#[test]
fn an_ordinary_recipient_still_builds_its_plan() {
    let recipient = Address::repeat_byte(0x22);
    let plan = transfer_plan(
        &chain(),
        sender(),
        vec![
            Transfer {
                token: Address::ZERO,
                to: recipient,
                amount: DecimalU256::new("1000").unwrap(),
            },
            Transfer {
                token: token(),
                to: recipient,
                amount: DecimalU256::new("5").unwrap(),
            },
        ],
    )
    .unwrap();
    assert_eq!(plan.ordered_steps.len(), 2);
    assert_eq!(plan.ordered_steps[0].transaction.to, recipient);
    assert_eq!(
        plan.ordered_steps[0].transaction.value.as_str(),
        "1000",
        "a native transfer carries its value to the recipient"
    );
    assert_eq!(
        plan.ordered_steps[1].transaction.to,
        token(),
        "and a token transfer goes to the token, with the recipient in calldata"
    );
}
