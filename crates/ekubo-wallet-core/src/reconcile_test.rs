//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

const fn receipt(succeeded: bool) -> ReceiptStatus {
    ReceiptStatus {
        succeeded,
        block_number: 100,
        gas_used: 21_000,
        effective_gas_price: 1_000_000_000,
    }
}

#[test]
fn a_receipt_settles_the_envelope_regardless_of_nonce() {
    assert_eq!(
        classify(5, 6, Some(receipt(true))),
        ChainObservation::Mined(receipt(true))
    );
    assert_eq!(
        classify(5, 5, Some(receipt(false))),
        ChainObservation::Mined(receipt(false))
    );
}

#[test]
fn a_consumed_nonce_without_a_receipt_is_a_replacement() {
    assert_eq!(classify(5, 6, None), ChainObservation::Replaced);
    assert_eq!(classify(0, 3, None), ChainObservation::Replaced);
}

#[test]
fn an_unconsumed_nonce_without_a_receipt_is_still_pending() {
    assert_eq!(classify(5, 5, None), ChainObservation::StillPending);
    assert_eq!(classify(5, 0, None), ChainObservation::StillPending);
}
