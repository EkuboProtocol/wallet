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
        block_hash: alloy::primitives::B256::ZERO,
        head_block_number: 100,
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

mod cancellation_configuration_tests {
    //! A cancellation is priced and sent through the configuration that is
    //! live when it runs, or not at all.

    /// The caller resolves the wallet and the network before the await, and
    /// that snapshot then decides endpoint selection, chain-ID validation, fee
    /// estimation, the gas ceiling, and where the envelope goes. Configuration
    /// writes replace the whole document atomically while readers hold
    /// independent snapshots, so another owner task or the MCP server can replace the
    /// profile while this runs -- and this is the one signing path with no
    /// policy and no review behind it.
    ///
    /// Read from the source because reaching the check needs a live endpoint:
    /// what is checkable is that the configuration is consulted before
    /// anything is priced, and that the record re-read it sits beside was
    /// never enough on its own.
    #[test]
    fn cancellation_rereads_the_configuration_before_pricing() {
        let source = include_str!("reconcile.rs");
        let body = source
            .split_once("pub async fn attempt_cancellation")
            .expect("the entry point exists")
            .1;
        let wallet = body
            .find("config.wallet(&record.wallet_id)?")
            .expect("it re-reads the wallet");
        let network = body
            .find("config.network_by_chain_id(&record.chain_id)?")
            .expect("it re-reads the network");
        let priced = body
            .find("sign_cancellation(")
            .expect("and then prices a cancellation");
        assert!(
            wallet < priced && network < priced,
            "the configuration must be checked before anything is signed"
        );
    }

    /// And the refusal points at retrying rather than at repair.
    ///
    /// This asks whether the configuration changed underneath, not which
    /// profile is allowed. Running the command again picks up whatever is
    /// current and succeeds, so nothing an owner might legitimately want is
    /// refused -- which matters here more than on `transaction discard`,
    /// because being unable to cancel is the failure this path exists to
    /// prevent.
    #[test]
    fn the_refusal_tells_the_owner_to_run_it_again() {
        let source = include_str!("reconcile.rs");
        let body = source
            .split_once("pub async fn attempt_cancellation")
            .expect("the entry point exists")
            .1;
        // Collapse the layout before matching: these messages wrap across
        // string continuations, and a needle carrying one matches nothing.
        // The same mistake shipped once already in this pass and was caught by
        // CI on Windows rather than locally.
        // The backslash of a string continuation survives `split_whitespace`
        // as its own token, so it goes first. Collapsing layout without
        // removing it matches nothing and reads as "the message is missing".
        let prose = body
            .replace('\\', " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            prose.matches("Run the command again.").count(),
            2,
            "both refusals name the remedy, and the remedy is a retry"
        );
        assert!(
            !body[..body.find("sign_cancellation(").unwrap()].contains("network_for_record("),
            // A call, not a mention: the doc comment above names the function
            // to explain why it is deliberately not used here.
            "a cancellation must not refuse because a profile was replaced earlier; that rule \
             belongs to `transaction discard`, where refusing costs nothing"
        );
    }
}
