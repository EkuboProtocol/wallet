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

#[test]
fn a_lease_stamped_in_the_future_is_not_a_lease() {
    // `updated_at` is a durable wall-clock value with no plausibility bound in
    // the schema or the row decoding. A row stamped in the future -- a clock
    // that jumped and came back, a database copied between machines, a
    // restored backup -- gives a negative age, which compared only against the
    // lease interval reads as a lease with time still to run.
    //
    // `submitting` holds the wallet's one in-flight slot for that chain, so
    // the wallet stays frozen there until wall time catches up to the stamp
    // and *then* the lease elapses. Nothing short of a SQL prompt shortens it.
    assert!(
        lease_expired(TimeDelta::seconds(-1)),
        "a lease that has not started yet is not one this wallet has to wait out"
    );
    assert!(lease_expired(TimeDelta::days(-365)));

    // The ordinary rule is unchanged.
    assert!(!lease_expired(TimeDelta::zero()));
    assert!(!lease_expired(TimeDelta::seconds(
        SUBMISSION_LEASE_SECONDS - 1
    )));
    assert!(lease_expired(TimeDelta::seconds(SUBMISSION_LEASE_SECONDS)));
    assert!(lease_expired(TimeDelta::seconds(
        SUBMISSION_LEASE_SECONDS + 1
    )));
}
