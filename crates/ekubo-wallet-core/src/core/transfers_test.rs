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

/// The zero address is not a recipient. Sending the native token there
/// destroys it, and a great many ERC-20s burn the amount rather than refusing
/// the call -- so whether the value survives depends on which contract was
/// named, which is not a thing to leave to chance in a signed plan.
///
/// Refused here rather than left to the policy, because no policy rule speaks
/// about it: an ordinary allowlist for the token authorizes this plan, and
/// `ExecutionPlan::validate` checks calldata bounds, step ordering, chain, and
/// sender -- everything about the shape of the request except where the value
/// is going.
#[test]
fn a_transfer_to_the_zero_address_is_refused() {
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

    let erc20 = transfer_plan(
        &chain(),
        sender(),
        vec![Transfer {
            token: token(),
            to: Address::ZERO,
            amount: DecimalU256::new("1000").unwrap(),
        }],
    );
    assert!(
        erc20.is_err(),
        "an ERC-20 transfer to zero burns on many contracts and is refused too"
    );

    // One bad recipient in a batch refuses the batch: the plan is signed as a
    // unit, so admitting the others would sign the destruction alongside them.
    let batch = transfer_plan(
        &chain(),
        sender(),
        vec![
            Transfer {
                token: token(),
                to: Address::repeat_byte(0x22),
                amount: DecimalU256::new("1").unwrap(),
            },
            Transfer {
                token: token(),
                to: Address::ZERO,
                amount: DecimalU256::new("1").unwrap(),
            },
        ],
    );
    assert!(batch.is_err());
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
