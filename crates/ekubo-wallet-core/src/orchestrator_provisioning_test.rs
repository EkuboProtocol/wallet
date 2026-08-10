//! Tests for [`super::require_provisioned_wallet`] and the two reviewed
//! signers that call it.
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::{
    config::WalletSource,
    core::policy::WalletPolicy,
    custody::{Deletion, PrivateKeyMaterial},
    human_presence::HumanPresenceError,
    message::MessageEncoding,
    policy_store::DatabaseKey,
};
use alloy::primitives::Address;
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};

/// Reached only if the guard let the request through, and it says so. Owner
/// authentication is the step a half-provisioned wallet must never get to ask
/// for: a prompt on the owner's screen is the wallet asserting that what
/// follows is a thing it is prepared to do.
struct RecordingPresence(AtomicBool);

impl crate::sealed::SealedHumanPresence for RecordingPresence {}

#[async_trait]
impl HumanPresence for RecordingPresence {
    async fn confirm(&self, _request: &PresenceRequest) -> Result<(), HumanPresenceError> {
        self.0.store(true, Ordering::SeqCst);
        Err(HumanPresenceError::Denied("stub".into()))
    }
}

/// Any use at all is a failure: the key must not be touched for a wallet whose
/// authority was never described.
struct UnusableKeys;

impl crate::sealed::SealedKeyStore for UnusableKeys {}

impl KeyStore for UnusableKeys {
    fn insert_new(&self, _wallet_id: &str, _key: &PrivateKeyMaterial) -> Result<()> {
        panic!("a policyless wallet reached the key store");
    }
    fn load(&self, _wallet_id: &str) -> Result<PrivateKeyMaterial> {
        panic!("a policyless wallet reached the key store");
    }
    fn address_of(&self, _wallet_id: &str) -> Result<Option<Address>> {
        panic!("a policyless wallet reached the key store");
    }
    fn delete_matching(&self, _wallet_id: &str, _expected: Address) -> Result<Deletion> {
        panic!("a policyless wallet reached the key store");
    }
}

/// A wallet in `config.json` whose policy initialization did not happen —
/// exactly what `account create` and `account import` leave behind when the
/// second half of provisioning fails.
struct HalfProvisioned {
    directory: tempfile::TempDir,
    config: ConfigStore,
    policies: PolicyStore,
    wallet: WalletMetadata,
}

/// The one key every handle in a fixture opens the database with. Explicit
/// rather than `production`, which reads the real OS credential store.
const KEY: DatabaseKey = DatabaseKey::new([7; 32]);

impl HalfProvisioned {
    /// A second connection to the same encrypted database, because the request
    /// stores take a `PolicyStore` by value and the guard needs one of its own.
    fn handle(&self) -> PolicyStore {
        PolicyStore::open(&self.directory.path().join("policies.db"), &KEY).unwrap()
    }
}

fn half_provisioned(with_policy: bool) -> HalfProvisioned {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigStore::new(directory.path());
    // The wallet metadata is built here rather than through custody: every
    // assertion below stops at or before owner authentication, which is ahead
    // of the point either signer compares this against `config.json`.
    let wallet = WalletMetadata {
        id: "primary".into(),
        address: Address::repeat_byte(0x11),
        created_at: chrono::Utc::now(),
        source: WalletSource::Imported,
        exported_at: None,
    };

    let mut policies = PolicyStore::open(&directory.path().join("policies.db"), &KEY).unwrap();
    if with_policy {
        policies
            .put(
                "primary",
                &WalletPolicy::require_approval_for_everything(),
                None,
            )
            .unwrap();
    }
    HalfProvisioned {
        directory,
        config,
        policies,
        wallet,
    }
}

/// The invariant itself, asked directly. A wallet is provisioned or it is not;
/// this is not a question about what the policy permits.
#[test]
fn a_wallet_with_no_policy_is_not_provisioned() {
    let missing = half_provisioned(false);
    let error = format!(
        "{:#}",
        require_provisioned_wallet(&missing.policies, "primary").unwrap_err()
    );
    assert!(error.contains("has no policy"), "{error}");
    assert!(
        error.contains("policy require-approval primary"),
        "the refusal has to name the repair: {error}"
    );

    let present = half_provisioned(true);
    require_provisioned_wallet(&present.policies, "primary")
        .expect("a provisioned wallet signs as it always did");
}

/// The startup loop in `WalletMcpServer::new` walked the wallets that existed
/// when the process began. Wallets appear afterwards, and this one did. The
/// refusal has to come from the signer rather than from the startup that never
/// saw it.
#[tokio::test]
async fn a_policyless_wallet_cannot_have_a_message_signed() {
    let fixture = half_provisioned(false);
    let mut store = MessageStore::new(fixture.handle());
    let request = store
        .create("primary", None, b"hello", MessageEncoding::Text, None)
        .unwrap();
    let digest = crate::message::message_digest(b"hello");

    let presence = RecordingPresence(AtomicBool::new(false));
    let error = format!(
        "{:#}",
        sign_reviewed_message(
            &fixture.config,
            &fixture.policies,
            &mut store,
            &request,
            &fixture.wallet,
            digest,
            &presence,
            &UnusableKeys,
        )
        .await
        .expect_err("a wallet with no policy has nothing that may be signed")
    );
    assert!(error.contains("has no policy"), "{error}");
    assert!(
        !presence.0.load(Ordering::SeqCst),
        "the owner must not be asked to authenticate a signature the wallet will refuse"
    );

    // And the request is still awaiting approval rather than quietly resolved,
    // so installing a policy and reviewing again is the whole repair.
    assert_eq!(
        store.get(request.request_id).unwrap().status,
        MessageStatus::AwaitingApproval
    );
}

/// The twin, and the one with teeth: a typed-data payload is a permit, an
/// order, or a delegation that its recipient exercises later. There is no
/// simulation and no policy grading behind it -- the human review was the
/// whole gate, and the human was told this wallet was inert.
#[tokio::test]
async fn a_policyless_wallet_cannot_have_typed_data_signed() {
    let fixture = half_provisioned(false);
    let mut store = TypedDataStore::new(fixture.handle());
    let typed = serde_json::json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"}
            ],
            "Message": [{"name": "value", "type": "uint256"}]
        },
        "primaryType": "Message",
        "domain": {"name": "Test", "chainId": 1},
        "message": {"value": "1"}
    });
    let (_, chain_id, digest) = crate::typed_data::parse_typed_data(&typed).unwrap();
    let request = store
        .create("primary", chain_id, &typed, digest, None)
        .unwrap();

    let presence = RecordingPresence(AtomicBool::new(false));
    let error = format!(
        "{:#}",
        sign_reviewed_typed_data(
            &fixture.config,
            &fixture.policies,
            &mut store,
            &request,
            &fixture.wallet,
            digest,
            &presence,
            &UnusableKeys,
        )
        .await
        .expect_err("a wallet with no policy has nothing that may be signed")
    );
    assert!(error.contains("has no policy"), "{error}");
    assert!(
        !presence.0.load(Ordering::SeqCst),
        "the owner must not be asked to authenticate a signature the wallet will refuse"
    );
}

/// The positive control, without which the two above would pass on a signer
/// that refused everything. A provisioned wallet gets past the guard and on to
/// owner authentication, which is where it is supposed to stop.
#[tokio::test]
async fn a_provisioned_wallet_still_reaches_owner_authentication() {
    let fixture = half_provisioned(true);
    let mut store = MessageStore::new(fixture.handle());
    let request = store
        .create("primary", None, b"hello", MessageEncoding::Text, None)
        .unwrap();
    let digest = crate::message::message_digest(b"hello");

    let presence = RecordingPresence(AtomicBool::new(false));
    let error = format!(
        "{:#}",
        sign_reviewed_message(
            &fixture.config,
            &fixture.policies,
            &mut store,
            &request,
            &fixture.wallet,
            digest,
            &presence,
            &UnusableKeys,
        )
        .await
        .expect_err("the presence stub denies")
    );
    assert!(
        presence.0.load(Ordering::SeqCst),
        "the guard must not be refusing wallets that are provisioned"
    );
    assert!(!error.contains("has no policy"), "{error}");
}
