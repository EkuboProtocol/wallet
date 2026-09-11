//! Immutable staging only. A completed stage is not activation authority or a
//! receipt authorizing deletion of a legacy key. Platform stores validate live
//! handles and identities and must durably publish each create-new record.
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
    /// Verified migration candidate, published after the canonical database.
    /// This is staging evidence, never an activation or deletion receipt.
    Candidate,
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
            Self::Candidate => "candidate.json".into(),
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

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialStage {
    pub(crate) version: u8,
    pub(crate) stage: Uuid,
    pub(crate) records: u64,
    pub(crate) digest: [u8; 32],
}
impl CredentialStage {
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.stage
    }
}
