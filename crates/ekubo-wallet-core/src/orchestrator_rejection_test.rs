//! Tests for [`super::record_rejection`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::{core::policy::WalletPolicy, policy_store::DatabaseKey, policy_store::PolicyStore};
use serde_json::json;

fn plan() -> crate::core::execution_plan::ExecutionPlan {
    crate::core::execution_plan::ExecutionPlan::parse(json!({
        "schema_version": "1",
        "chain_id": "1",
        "caip2_chain_id": "eip155:1",
        "sender": "0x1111111111111111111111111111111111111111",
        "ordered_steps": [{
            "step": 1,
            "kind": "execution",
            "transaction": {
                "chain_id": "1",
                "from": "0x1111111111111111111111111111111111111111",
                "to": "0x2222222222222222222222222222222222222222",
                "data": "0x",
                "value": "1"
            }
        }]
    }))
    .unwrap()
}

fn pending() -> (tempfile::TempDir, Mutex<PendingStore>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("policies.db");
    let mut database = PolicyStore::open(&path, &DatabaseKey::new([9; 32])).unwrap();
    database
        .put_for_wallet(
            "primary",
            plan().sender,
            &WalletPolicy::allow_anything(),
            None,
        )
        .unwrap();
    (directory, Mutex::new(PendingStore::new(database)))
}

/// `reject` commits and *then* re-reads, so a failure in that read reports an
/// error for a rejection that did land. Reported as an error, the caller
/// concludes the request is still pending -- when it is not -- and the
/// distinction matters in the other direction too: a rejection that genuinely
/// did not commit leaves a refused request that `store_signed` will still
/// accept and sign.
///
/// Both halves are decided by asking the row. A second rejection stands in for
/// the read that failed: `reject` refuses it, because the row is no longer
/// awaiting approval, and the row says `Rejected`, so the owner's decision is
/// recorded and that is what matters.
#[test]
fn a_rejection_already_recorded_is_a_success_not_an_error() {
    let (_directory, pending) = pending();
    let request = lock(&pending)
        .unwrap()
        .create("primary", "ethereum", &plan(), None, 1)
        .unwrap();

    let rejected = record_rejection(&pending, request.request_id).unwrap();
    assert_eq!(rejected.status, PendingStatus::Rejected);

    // The raw call fails now, which is exactly the shape of the post-commit
    // read failure this has to survive.
    assert!(
        lock(&pending).unwrap().reject(request.request_id).is_err(),
        "the store itself refuses a row that is not awaiting approval"
    );
    let again = record_rejection(&pending, request.request_id)
        .expect("a decision already written down is not a failure to write it down");
    assert_eq!(again.status, PendingStatus::Rejected);
}

/// The other half: when the row really is still awaiting approval, the failure
/// is reported, and it says the thing the owner needs to know -- that what
/// their terminal told them is not what the wallet will do.
#[test]
fn a_rejection_that_did_not_land_says_the_request_can_still_be_signed() {
    let (_directory, pending) = pending();
    let request = lock(&pending)
        .unwrap()
        .create("primary", "ethereum", &plan(), None, 1)
        .unwrap();
    // Reject a request that is not this one, so the store errors while the
    // real row stays `AwaitingApproval`.
    let missing = uuid::Uuid::new_v4();
    let error = format!("{:#}", record_rejection(&pending, missing).unwrap_err());
    assert!(error.contains("still awaiting approval"), "{error}");
    assert!(error.contains("can still be signed"), "{error}");
    assert!(
        error.contains("open that review") && error.contains("reject it again"),
        "{error}"
    );

    assert_eq!(
        lock(&pending)
            .unwrap()
            .get(request.request_id)
            .unwrap()
            .status,
        PendingStatus::AwaitingApproval,
        "and the untouched request is exactly where it was"
    );
}
