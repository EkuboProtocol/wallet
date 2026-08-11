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

/// The zero address is a valid EVM destination. A policy can refuse it like any
/// other recipient; plan validation does not override an intentional burn.
#[test]
fn a_native_transfer_to_the_zero_address_is_represented_exactly() {
    let plan = transfer_plan(
        &chain(),
        sender(),
        vec![Transfer {
            token: Address::ZERO,
            to: Address::ZERO,
            amount: DecimalU256::new("1000").unwrap(),
        }],
    )
    .unwrap();
    assert_eq!(plan.ordered_steps[0].transaction.to, Address::ZERO);
    assert_eq!(plan.ordered_steps[0].transaction.value.as_str(), "1000");
}

/// An ERC-20 recipient rides in calldata, while the transaction is addressed
/// to the token contract.
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
