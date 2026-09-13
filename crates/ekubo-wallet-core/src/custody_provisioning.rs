//! Fresh, empty v2 enrollment. Keys are generated inside the protected service.
//! No caller-supplied key, account inventory, or source database is accepted.
use crate::{
    custody_envelope::{CustodyBinding, CustodyEnrollment, WrappedDataKey, WrappingKey},
    custody_staging::{CredentialStagingStore, ServiceCredentialRecord},
    database_staging::DatabaseStagingStore,
    pending_profile::{PendingProfileStore, ProfileRecord},
    policy_store::{DatabaseKey, PolicyStore},
};
use anyhow::Result;
use rand::TryRng as _;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const INSTALLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// A single live setup attempt. Dropping it loses the relay; retry must never
/// replace its records. An interrupted unused pending profile requires explicit
/// privileged cleanup, while an installed profile can never be re-enrolled.
pub fn enroll(
    store: &(impl CredentialStagingStore + DatabaseStagingStore + PendingProfileStore),
) -> Result<WrappedDataKey> {
    let (owner, service, profile) = store.identity();
    let generation = Uuid::new_v4();
    let wrapping = random_key()?;
    let database = random_key()?;
    let key = WrappingKey::from_material(wrapping.clone());
    let (cipher, relay) =
        key.enroll(CustodyBinding::new(&owner, &service, profile, generation)?)?;
    let enrollment = serde_json::to_vec(&CustodyEnrollment::new(generation, &relay)?)?;
    // create-new publication refuses every second attempt, even if its predecessor
    // crashed before returning ciphertext. No credential-store reads occur here.
    store.prepare_record(ProfileRecord::credential(
        ServiceCredentialRecord::WrappingKey,
        wrapping.as_slice(),
    ))?;
    store.prepare_record(ProfileRecord::credential(
        ServiceCredentialRecord::Enrollment,
        &enrollment,
    ))?;
    store.prepare_record(ProfileRecord::credential(
        ServiceCredentialRecord::DatabaseKey,
        &cipher.seal_database_key(&database)?,
    ))?;
    let candidate = store.create_canonical_database(profile)?;
    let database_key = DatabaseKey::new(*database);
    let db = PolicyStore::open_with(
        candidate.path(),
        &database_key,
        crate::policy_store::SeedDefaults::Yes,
    )?;
    db.assert_schema_current()?;
    drop(db);
    candidate.publish()?;
    // Native publication targets wallet.db directly; there is no received,
    // canonical, or runtime copy of an existing database.
    CustodyEnrollment::from_bytes(&enrollment)?.unlock(&key, &owner, &service, profile, &relay)?;
    store.prepare_record(ProfileRecord::marker(profile.to_string().as_bytes()))?;
    Ok(relay)
}

fn random_key() -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    rand::rngs::SysRng
        .try_fill_bytes(key.as_mut())
        .map_err(|_| anyhow::anyhow!("operating-system randomness is unavailable"))?;
    Ok(key)
}
