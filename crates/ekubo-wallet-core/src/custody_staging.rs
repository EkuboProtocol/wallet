//! Immutable native storage primitives. Platform stores validate live handles
//! and identities and durably publish each create-new record. Fresh enrollment
//! generates its own material; these primitives perform no credential import.
use anyhow::{Result, ensure};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Closed record names shared by Linux and Windows service custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServiceCredentialRecord {
    WrappingKey,
    Enrollment,
    DatabaseKey,
    AccountKey(Uuid),
}

impl ServiceCredentialRecord {
    #[must_use]
    pub fn file_name(self) -> String {
        match self {
            Self::WrappingKey => "wrapping.key".into(),
            Self::Enrollment => "custody.json".into(),
            Self::DatabaseKey => "key-database".into(),
            Self::AccountKey(instance) => format!("key-account-{instance}"),
        }
    }
}

#[derive(Clone, Copy)]
pub enum StagedRecord {
    Credential(ServiceCredentialRecord),
    Complete,
}
impl StagedRecord {
    pub fn file_name(self, stage: Uuid) -> Result<String> {
        ensure!(!stage.is_nil(), "invalid custody stage identity");
        let suffix = match self {
            Self::Credential(ServiceCredentialRecord::AccountKey(instance)) => {
                ensure!(!instance.is_nil(), "invalid staged account instance");
                format!("key-account-{instance}")
            }
            Self::Credential(record) => record.file_name(),
            Self::Complete => "complete.json".into(),
        };
        Ok(format!("custody-stage-{stage}-{suffix}"))
    }
}

/// Implementing this interface grants no OS authority. Production callers use
/// only the protected native service roots; test stores may be in memory.
pub trait CredentialStagingStore {
    fn identity(&self) -> (String, String, Uuid);
    fn create_new(&self, stage: Uuid, record: StagedRecord, bytes: &[u8]) -> Result<()>;
    fn read(&self, stage: Uuid, record: StagedRecord) -> Result<Zeroizing<Vec<u8>>>;
}
