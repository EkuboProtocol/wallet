//! Explicit owner-directed first-run move. Never called by fresh enrollment.
//! The source database is read-only and kept under the old application/lifecycle
//! locks. Retirement is bound to the durable installed-service receipt.
use crate::{
    config::WalletMetadata,
    human_presence::{OwnerAuthorizationScope, authorize_owner},
    policy_store::{DatabaseKey, legacy_move_database as database},
};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context as _, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::File,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(target_os = "windows")]
#[path = "legacy_move_native.rs"]
mod native;
#[path = "legacy_move_retirement.rs"]
mod retirement;
pub use retirement::Identity as RetirementIdentity;
#[path = "legacy_move_transport.rs"]
mod transport;

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct Secret(Vec<u8>);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountMaterial {
    instance: Uuid,
    key: Secret,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transfer {
    snapshot: database::Snapshot,
    keys: Vec<AccountMaterial>,
    binding: MoveBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoveBinding {
    pub profile: Uuid,
    pub source: PathBuf,
    pub preserved_profiles: Vec<PathBuf>,
    pub retained_shared_accounts: Vec<Uuid>,
    #[serde(default)]
    pub retirement: Option<RetirementIdentity>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum MoveStatus {
    Unavailable,
    Baseline,
    PendingCleanup {
        digest: [u8; 32],
        binding: MoveBinding,
    },
    Complete {
        binding: MoveBinding,
        shared_database_credential_retained: bool,
    },
}

impl MoveStatus {
    #[must_use]
    pub const fn pending(&self) -> bool {
        matches!(self, Self::PendingCleanup { .. })
    }
}

/// Only the already-authenticated owner dispatcher may route these requests.
/// Core additionally authenticates the owner before accepting an import.
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceCommand {
    AuthorizeSource {
        nonce: Uuid,
        source: PathBuf,
        preserved_profiles: Vec<PathBuf>,
    },
    Inspect {
        nonce: Uuid,
    },
    Import {
        payload: String,
    },
    Verify {
        digest: [u8; 32],
        nonce: Uuid,
        binding: MoveBinding,
    },
    Complete {
        digest: [u8; 32],
        nonce: Uuid,
        binding: MoveBinding,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptPhase {
    SourceAuthorized,
    Inspected,
    Imported,
    Verified,
    Complete,
}

impl ServiceCommand {
    fn phase(&self) -> ReceiptPhase {
        match self {
            Self::AuthorizeSource { .. } => ReceiptPhase::SourceAuthorized,
            Self::Inspect { .. } => ReceiptPhase::Inspected,
            Self::Import { .. } => ReceiptPhase::Imported,
            Self::Verify { .. } => ReceiptPhase::Verified,
            Self::Complete { .. } => ReceiptPhase::Complete,
        }
    }
}
impl Drop for ServiceCommand {
    fn drop(&mut self) {
        if let Self::Import { payload } = self {
            zeroize::Zeroize::zeroize(payload);
        }
    }
}

/// Wire shape of the shared owner protocol's `Request::LegacyMove(ServiceCommand)`.
/// Kept below the client dependency boundary so core authenticates its own peer.
#[cfg(any(target_os = "windows", test))]
#[derive(Serialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
enum OwnerRequest<'a> {
    LegacyMove(&'a ServiceCommand),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    phase: ReceiptPhase,
    selection_digest: Option<[u8; 32]>,
    digest: [u8; 32],
    nonce: Uuid,
    accounts: Vec<Uuid>,
    profile: Uuid,
    binding: Option<MoveBinding>,
    wallets: Vec<WalletMetadata>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MoveSummary {
    pub source: PathBuf,
    pub accounts: Vec<WalletMetadata>,
    pub tables: Vec<(String, usize)>,
    pub retained_shared_accounts: Vec<Uuid>,
    pub preserved_profiles: Vec<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct CleanupReport {
    pub deleted_account_credentials: Vec<Uuid>,
    pub already_absent: Vec<Uuid>,
    pub retained_shared_accounts: Vec<Uuid>,
    pub shared_database_credential_retained: bool,
}

struct Frozen {
    connection: Option<rusqlite::Connection>,
    // SQLite closes before any other descriptor for its inode is closed.
    pin: File,
    _locks: Vec<File>,
    root: PathBuf,
    digest: [u8; 32],
}

pub struct LegacySource {
    authorized_profile: Uuid,
    frozen: Vec<Frozen>,
    summary: MoveSummary,
    snapshot: Option<database::Snapshot>,
    digest: [u8; 32],
    retirement: retirement::Identity,
}

/// An owner-reviewed inventory, not an automatically discovered list. If the
/// owner cannot identify the other profiles, automatic retirement is refused.
pub enum ProfileInventory {
    ReviewedComplete { preserve_profiles: Vec<PathBuf> },
    Unknown,
}

/// Suggest the released 1.x path only when the owner explicitly opens the move
/// flow. This is never a v2 data-root fallback and performs no credential access.
pub fn suggested_legacy_root() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("EKUBO_WALLET_HOME") {
        let path = PathBuf::from(path);
        ensure!(
            path.is_absolute(),
            "select the absolute legacy profile path explicitly"
        );
        return Ok(path);
    }
    let base = directories::BaseDirs::new().context("cannot determine legacy profile path")?;
    #[cfg(target_os = "linux")]
    return Ok(std::env::var_os("XDG_STATE_HOME")
        .map_or_else(|| base.home_dir().join(".local/state"), PathBuf::from)
        .join("ekubo-wallet"));
    #[cfg(target_os = "windows")]
    return Ok(base.data_local_dir().join("Ekubo/wallet"));
}

impl LegacySource {
    /// Must be an explicit first-run choice. The reviewed inventory includes all
    /// known custom profiles which must remain usable. 1.x has no global profile
    /// registry: the UI must ask about custom profiles rather than claim discovery
    /// is exhaustive. Shared account entries in this inventory are not removed.
    pub async fn review(source: PathBuf, inventory: ProfileInventory) -> Result<Self> {
        let ProfileInventory::ReviewedComplete { preserve_profiles } = inventory else {
            anyhow::bail!(
                "cannot retire legacy credentials without an explicitly reviewed complete profile inventory"
            );
        };
        ensure!(
            source.is_absolute() && preserve_profiles.iter().all(|path| path.is_absolute()),
            "legacy profile paths must be explicit absolute paths"
        );
        ensure!(
            preserve_profiles.len() <= 32,
            "this bounded move supports at most 32 preserved profiles; do not omit profiles to bypass the limit"
        );
        let source = source.canonicalize()?;
        let preserve_profiles = preserve_profiles
            .into_iter()
            .map(|path| path.canonicalize())
            .collect::<std::io::Result<BTreeSet<_>>>()?
            .into_iter()
            .collect::<Vec<_>>();
        #[cfg(target_os = "linux")]
        {
            let authorization = authorize_owner(OwnerAuthorizationScope::LegacyMove).await?;
            authorization.require(OwnerAuthorizationScope::LegacyMove)?;
        }
        let mut peer = transport::Peer::connect().await?;
        let authorized_profile = peer.profile();
        let nonce = Uuid::new_v4();
        #[cfg(target_os = "windows")]
        let receipt = peer
            .call(&ServiceCommand::AuthorizeSource {
                nonce,
                source: source.clone(),
                preserved_profiles: preserve_profiles.clone(),
            })
            .await?;
        #[cfg(target_os = "linux")]
        let receipt = peer.call(&ServiceCommand::Inspect { nonce }).await?;
        ensure!(receipt.nonce == nonce, "stale move inspection");
        tokio::task::spawn_blocking(move || {
            ensure!(
                source.canonicalize()? == source
                    && preserve_profiles
                        .iter()
                        .all(|path| path.canonicalize().is_ok_and(|current| current == *path)),
                "authorized source selection changed before reading legacy credentials"
            );
            let mut reviewed = if let Some(binding) = &receipt.binding {
                let source = source.canonicalize()?;
                let preserved = preserve_profiles
                    .into_iter()
                    .map(|p| p.canonicalize())
                    .collect::<std::io::Result<BTreeSet<_>>>()?;
                ensure!(
                    source == binding.source
                        && preserved.into_iter().collect::<Vec<_>>() == binding.preserved_profiles,
                    "resume requires the exact destination-bound source inventory"
                );
                Self::resume(receipt)?
            } else {
                Self::open(&source, preserve_profiles)?
            };
            reviewed.authorized_profile = authorized_profile;
            Ok(reviewed)
        })
        .await?
    }

    fn open(source: &Path, preserve_profiles: Vec<PathBuf>) -> Result<Self> {
        require_legacy_owner()?;
        let source = source.canonicalize()?;
        let v2 = crate::config::default_data_dir()?;
        ensure!(
            source != v2.canonicalize().unwrap_or(v2),
            "source is the v2 profile"
        );
        let mut paths = preserve_profiles
            .into_iter()
            .map(|path| path.canonicalize().map_err(anyhow::Error::from))
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            !paths.contains(&source),
            "source cannot also be an unmigrated profile"
        );
        paths.insert(source.clone());
        let raw = Zeroizing::new(
            crate::credential_store::legacy_entry("org.ekubo.wallet.db", "default")?
                .get_secret()?,
        );
        let retirement_key = retirement::hash(&raw);
        let key = DatabaseKey::new(
            raw.as_slice()
                .try_into()
                .context("invalid legacy database credential")?,
        );
        let mut frozen = Vec::new();
        for path in paths {
            frozen.push(Frozen::open(path, &key)?);
        }
        let source_index = frozen
            .iter()
            .position(|item| item.root == source)
            .expect("source was included");
        let selected = frozen.remove(source_index);
        frozen.insert(0, selected);
        let accounts = database::wallets(frozen[0].connection.as_ref().expect("open source"))?;
        let mut preserved_accounts = Vec::new();
        for other in &frozen[1..] {
            preserved_accounts.extend(database::wallets(
                other.connection.as_ref().expect("open source"),
            )?);
        }
        let snapshot =
            database::capture(frozen[0].connection.as_ref().expect("open source"), false)?;
        let retirement = retirement::Identity {
            database_key_hash: retirement_key,
            source_file_hash: retirement::file_hash(&frozen[0].pin)?,
        };
        let digest = snapshot.digest()?;
        let summary = MoveSummary {
            source,
            retained_shared_accounts: shared_accounts(&accounts, &preserved_accounts),
            accounts,
            tables: snapshot
                .tables
                .iter()
                .map(|table| (table.name.clone(), table.rows.len()))
                .collect(),
            preserved_profiles: frozen[1..]
                .iter()
                .map(|profile| profile.root.clone())
                .collect(),
        };
        Ok(Self {
            authorized_profile: Uuid::nil(),
            frozen,
            summary,
            snapshot: Some(snapshot),
            digest,
            retirement,
        })
    }

    #[must_use]
    pub fn summary(&self) -> &MoveSummary {
        &self.summary
    }

    /// Import and re-open/verify the durable protected destination over a native
    /// authenticated connection. No caller-supplied success flag/receipt can
    /// authorize source cleanup. A failure leaves source credentials in place.
    pub async fn move_and_cleanup(mut self) -> Result<CleanupReport> {
        self.revalidate()?;
        let mut peer = transport::Peer::connect().await?;
        ensure!(
            peer.profile() == self.authorized_profile,
            "installed destination changed since source authorization"
        );
        let binding = MoveBinding {
            profile: peer.profile(),
            source: self.summary.source.clone(),
            preserved_profiles: self.summary.preserved_profiles.clone(),
            retained_shared_accounts: self.summary.retained_shared_accounts.clone(),
            retirement: Some(self.retirement.clone()),
        };
        if let Some(snapshot) = self.snapshot.take() {
            let mut keys = Vec::new();
            for wallet in &self.summary.accounts {
                if let Some(key) = legacy_key(wallet)? {
                    keys.push(AccountMaterial {
                        instance: wallet.instance_id,
                        key: Secret(key.to_vec()),
                    });
                }
            }
            let transfer = Transfer {
                snapshot,
                keys,
                binding: binding.clone(),
            };
            let bytes = Zeroizing::new(serde_json::to_vec(&transfer)?);
            ensure!(
                bytes.len() <= database::MAX_BYTES,
                "legacy move exceeds bounded transfer size; no source credentials were deleted"
            );
            let command = ServiceCommand::Import {
                payload: STANDARD.encode(bytes.as_slice()),
            };
            let imported = peer.call(&command).await?;
            ensure!(
                imported.digest == self.digest,
                "destination import identity mismatch"
            );
        }
        // Authentication is renewed immediately before destructive cleanup. The
        // same locks and exact source identity remain alive through the prompt.
        #[cfg(target_os = "linux")]
        {
            let authorization = authorize_owner(OwnerAuthorizationScope::LegacyMove).await?;
            authorization.require(OwnerAuthorizationScope::LegacyMove)?;
        }
        let nonce = Uuid::new_v4();
        let verified = peer
            .call(&ServiceCommand::Verify {
                digest: self.digest,
                nonce,
                binding: binding.clone(),
            })
            .await?;
        let expected: BTreeSet<_> = self
            .summary
            .accounts
            .iter()
            .map(|wallet| wallet.instance_id)
            .collect();
        ensure!(
            verified.digest == self.digest
                && verified.nonce == nonce
                && verified.accounts.len() == expected.len()
                && verified.accounts.into_iter().collect::<BTreeSet<_>>() == expected,
            "destination did not freshly verify every moved account"
        );
        // Moving snapshot above intentionally prevents retaining another copy of
        // its sensitive cells. Revalidation uses the retained source connections.
        for profile in &self.frozen {
            profile.revalidate()?;
        }
        retirement::check_database_key(
            &self.retirement,
            self.frozen[0].connection.is_some() || !self.summary.preserved_profiles.is_empty(),
        )?;
        self.frozen[0].retire(&binding)?;
        let mut report = tokio::task::block_in_place(|| cleanup(&self.summary))?;
        report.shared_database_credential_retained = retirement::retire_database_key(
            &self.retirement,
            !self.summary.preserved_profiles.is_empty(),
        )?;
        // A crash here leaves the durable receipt pending. Explicit resume can
        // verify the destination keys even when old keys are already absent.
        let nonce = Uuid::new_v4();
        let completed = peer
            .call(&ServiceCommand::Complete {
                digest: self.digest,
                nonce,
                binding,
            })
            .await?;
        ensure!(
            completed.digest == self.digest
                && completed.nonce == nonce
                && completed.accounts.len() == expected.len()
                && completed.accounts.into_iter().collect::<BTreeSet<_>>() == expected,
            "cleanup completion receipt did not match the reviewed move"
        );
        Ok(report)
    }

    fn revalidate(&self) -> Result<()> {
        for profile in &self.frozen {
            profile.revalidate()?;
        }
        Ok(())
    }
}

impl Frozen {
    fn open(root: PathBuf, key: &DatabaseKey) -> Result<Self> {
        let mut locks = Vec::new();
        for name in ["application.lock", "lifecycle.lock"] {
            let file = open_legacy_file(&root.join(name), true)?;
            fs2::FileExt::try_lock_exclusive(&file)
                .context("close the 1.x application before moving its profile")?;
            locks.push(file);
        }
        let pin = open_legacy_file(&root.join("wallet.db"), false)?;
        ensure!(
            pin.metadata()?.len() <= 64 * 1024 * 1024,
            "legacy database exceeds the bounded move size"
        );
        let connection = database::open_source(&root.join("wallet.db"), key)?;
        database::require_quiescent(&connection)?;
        let digest = database::capture(&connection, false)?.digest()?;
        let result = Self {
            connection: Some(connection),
            pin,
            _locks: locks,
            root,
            digest,
        };
        result.revalidate()?;
        Ok(result)
    }
    fn revalidate(&self) -> Result<()> {
        let current = std::fs::symlink_metadata(self.root.join("wallet.db"))?;
        ensure!(
            current.is_file() && !current.file_type().is_symlink(),
            "legacy database path changed"
        );
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt as _;
            let pinned = self.pin.metadata()?;
            ensure!(
                (current.dev(), current.ino()) == (pinned.dev(), pinned.ino()),
                "legacy database inode changed"
            );
        }
        #[cfg(target_os = "windows")]
        ensure!(
            native::identity(&open_legacy_file(&self.root.join("wallet.db"), false)?)?
                == native::identity(&self.pin)?,
            "legacy database file changed"
        );
        if let Some(connection) = &self.connection {
            ensure!(
                database::capture(connection, false)?.digest()? == self.digest,
                "legacy database changed during move"
            );
        }
        Ok(())
    }
}

fn open_legacy_file(path: &Path, write: bool) -> Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(write);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)
                .bits()
                .cast_signed(),
        );
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.share_mode(3).custom_flags(0x0020_0000); // no delete sharing; OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "legacy source object is not a regular file"
    );
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt as _;
        ensure!(
            file.metadata()?.uid() == rustix::process::geteuid().as_raw(),
            "legacy profile belongs to another owner"
        );
        ensure!(
            file.metadata()?.nlink() == 1,
            "legacy source has multiple hard links"
        );
    }
    #[cfg(target_os = "windows")]
    native::identity(&file)?;
    Ok(file)
}

fn require_legacy_owner() -> Result<()> {
    #[cfg(target_os = "linux")]
    ensure!(
        crate::service_storage::data_dir().is_none()
            && rustix::process::getuid().as_raw() != 0
            && rustix::process::getuid() == rustix::process::geteuid(),
        "legacy move requires the actual login owner"
    );
    #[cfg(target_os = "windows")]
    {
        ensure!(
            crate::windows_service_custody::data_dir().is_none(),
            "service cannot read legacy credentials"
        );
        crate::windows_service_config::validate_owner_component(
            crate::windows_service_identity::current_process_identity()?.user_sid(),
        )?;
    }
    Ok(())
}

fn shared_accounts(source: &[WalletMetadata], preserved: &[WalletMetadata]) -> Vec<Uuid> {
    let instances: BTreeSet<_> = preserved.iter().map(|wallet| wallet.instance_id).collect();
    let addresses: BTreeSet<_> = preserved.iter().map(|wallet| wallet.address).collect();
    source
        .iter()
        .filter(|wallet| {
            instances.contains(&wallet.instance_id) || addresses.contains(&wallet.address)
        })
        .map(|wallet| wallet.instance_id)
        .collect()
}

fn legacy_key(wallet: &WalletMetadata) -> Result<Option<Zeroizing<Vec<u8>>>> {
    tokio::task::block_in_place(|| {
        match crate::credential_store::legacy_entry(
            "org.ekubo.wallet.private-key.instance",
            &wallet.instance_id.to_string(),
        )?
        .get_secret()
        {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                verify_key(wallet, &bytes)?;
                Ok(Some(bytes))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.into()),
        }
    })
}
fn verify_key(wallet: &WalletMetadata, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() == 32 && PrivateKeySigner::from_slice(bytes)?.address() == wallet.address,
        "account credential does not match its reviewed legacy identity"
    );
    Ok(())
}

fn cleanup(summary: &MoveSummary) -> Result<CleanupReport> {
    require_legacy_owner()?;
    cleanup_with(summary, legacy_key, |wallet, expected| {
        let entry = crate::credential_store::legacy_entry(
            "org.ekubo.wallet.private-key.instance",
            &wallet.instance_id.to_string(),
        )?;
        let current = Zeroizing::new(entry.get_secret()?);
        ensure!(
            current.as_slice() == expected,
            "legacy credential changed before deletion"
        );
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error.into()),
        }
    })
}

fn cleanup_with(
    summary: &MoveSummary,
    mut read: impl FnMut(&WalletMetadata) -> Result<Option<Zeroizing<Vec<u8>>>>,
    mut remove: impl FnMut(&WalletMetadata, &[u8]) -> Result<()>,
) -> Result<CleanupReport> {
    // Check all identities before the first deletion, then re-read each exact key
    // immediately before deleting it. Legacy keyrings have no compare-and-delete
    // primitive: application/lifecycle exclusion covers cooperating 1.x writers,
    // not a hostile same-user process that already controls 1.x credentials.
    for wallet in &summary.accounts {
        if let Some(key) = read(wallet)? {
            verify_key(wallet, &key)?;
        }
    }
    let mut report = CleanupReport {
        deleted_account_credentials: Vec::new(),
        already_absent: Vec::new(),
        retained_shared_accounts: summary.retained_shared_accounts.clone(),
        shared_database_credential_retained: true,
    };
    for wallet in &summary.accounts {
        if summary
            .retained_shared_accounts
            .contains(&wallet.instance_id)
        {
            continue;
        }
        let Some(expected) = read(wallet)? else {
            report.already_absent.push(wallet.instance_id);
            continue;
        };
        verify_key(wallet, &expected)?;
        remove(wallet, &expected)?;
        ensure!(
            read(wallet)?.is_none(),
            "legacy credential deletion was not confirmed; cleanup remains incomplete"
        );
        report.deleted_account_credentials.push(wallet.instance_id);
    }
    Ok(report)
}

/// Called inside the authenticated owner native context. Import authorization is
/// checked in core, while verification returns only public identity evidence.
pub async fn service_command(command: ServiceCommand) -> Result<Receipt> {
    let root = crate::config::default_data_dir()?;
    #[cfg(target_os = "linux")]
    ensure!(
        crate::service_storage::data_dir().is_some(),
        "legacy import requires protected v2 custody"
    );
    #[cfg(target_os = "windows")]
    ensure!(
        crate::windows_service_custody::data_dir().is_some(),
        "legacy import requires protected v2 custody"
    );
    let mut receipt = match &command {
        ServiceCommand::AuthorizeSource {
            nonce,
            source,
            preserved_profiles,
        } => {
            ensure!(
                !nonce.is_nil(),
                "source authorization requires a fresh nonce"
            );
            let selection = selection_digest(service_profile()?, source, preserved_profiles)?;
            let auth = authorize_owner(OwnerAuthorizationScope::LegacyMove).await?;
            auth.require(OwnerAuthorizationScope::LegacyMove)?;
            let mut receipt = inspected_receipt(&root, *nonce)?;
            if let Some(binding) = &receipt.binding {
                ensure!(
                    binding.source == *source && binding.preserved_profiles == *preserved_profiles,
                    "source authorization differs from pending destination binding"
                );
            }
            receipt.selection_digest = Some(selection);
            Ok(receipt)
        }
        ServiceCommand::Inspect { nonce } => {
            ensure!(!nonce.is_nil(), "inspection requires a fresh nonce");
            inspected_receipt(&root, *nonce)
        }
        ServiceCommand::Import { payload } => {
            ensure!(
                payload.len() <= database::MAX_BYTES.div_ceil(3) * 4,
                "legacy payload is oversized"
            );
            let bytes = Zeroizing::new(STANDARD.decode(payload)?);
            ensure!(
                bytes.len() <= database::MAX_BYTES,
                "legacy payload is oversized"
            );
            let transfer: Transfer = serde_json::from_slice(&bytes)?;
            ensure!(
                transfer.binding.retirement.is_some(),
                "new imports require resumable retirement identity"
            );
            let binding = validated_binding(&transfer.binding)?;
            let auth = authorize_owner(OwnerAuthorizationScope::LegacyMove).await?;
            auth.require(OwnerAuthorizationScope::LegacyMove)?;
            let config = crate::config::ConfigStore::production()?;
            config.with_lifecycle_lock(|| {
                let digest =
                    database::import_bound(&root, &transfer.snapshot, &binding, |wallets| {
                        prepare_keys(wallets, &transfer.keys)
                    })?;
                verified_receipt(&root, digest, Uuid::nil())
            })
        }
        ServiceCommand::Verify {
            digest,
            nonce,
            binding,
        } => {
            ensure!(!nonce.is_nil(), "verification requires a fresh nonce");
            let binding = validated_binding(binding)?;
            // Windows authorization must execute inside the service's sealed
            // authenticated owner-call task-local, never in the desktop process.
            #[cfg(target_os = "windows")]
            {
                let auth = authorize_owner(OwnerAuthorizationScope::LegacyMove).await?;
                auth.require(OwnerAuthorizationScope::LegacyMove)?;
            }
            let config = crate::config::ConfigStore::production()?;
            config.with_lifecycle_lock(|| {
                database::verify_binding(&root, &binding)?;
                verified_receipt(&root, *digest, *nonce)
            })
        }
        ServiceCommand::Complete {
            digest,
            nonce,
            binding,
        } => {
            ensure!(!nonce.is_nil(), "completion requires a fresh nonce");
            let binding = validated_binding(binding)?;
            let auth = authorize_owner(OwnerAuthorizationScope::LegacyMove).await?;
            auth.require(OwnerAuthorizationScope::LegacyMove)?;
            let config = crate::config::ConfigStore::production()?;
            config.with_lifecycle_lock(|| {
                database::verify_binding(&root, &binding)?;
                let receipt = verified_receipt(&root, *digest, *nonce)?;
                database::finish_cleanup(&root, *digest, &binding)?;
                Ok(receipt)
            })
        }
    }?;
    receipt.phase = command.phase();
    Ok(receipt)
}

fn inspected_receipt(root: &Path, nonce: Uuid) -> Result<Receipt> {
    match move_status()? {
        MoveStatus::PendingCleanup { digest, .. } => verified_receipt(root, digest, nonce),
        MoveStatus::Baseline => Ok(Receipt {
            phase: ReceiptPhase::Inspected,
            selection_digest: None,
            digest: [0; 32],
            nonce,
            accounts: vec![],
            profile: service_profile()?,
            binding: None,
            wallets: vec![],
        }),
        _ => anyhow::bail!("destination is not available for a move"),
    }
}

fn selection_digest(profile: Uuid, source: &Path, preserved: &[PathBuf]) -> Result<[u8; 32]> {
    ensure!(
        source.is_absolute()
            && preserved.len() <= 32
            && preserved
                .iter()
                .all(|path| path.is_absolute() && path != source)
            && preserved.windows(2).all(|pair| pair[0] < pair[1]),
        "invalid source authorization selection"
    );
    let bytes = serde_json::to_vec(&(
        "legacy_move.authorize_source.v1",
        profile,
        source,
        preserved,
    ))?;
    ensure!(
        bytes.len() <= 256 * 1024,
        "source authorization selection is oversized"
    );
    Ok(retirement::hash(&bytes))
}

fn prepare_keys(wallets: &[WalletMetadata], keys: &[AccountMaterial]) -> Result<()> {
    let instances: BTreeSet<_> = keys.iter().map(|key| key.instance).collect();
    ensure!(
        instances.len() == keys.len()
            && instances
                .iter()
                .all(|id| wallets.iter().any(|wallet| wallet.instance_id == *id)),
        "unexpected or duplicate moved account keys"
    );
    for wallet in wallets {
        let entry = crate::credential_store::entry(
            crate::custody::KEYRING_SERVICE,
            &wallet.instance_id.to_string(),
        )?;
        let supplied = keys.iter().find(|key| key.instance == wallet.instance_id);
        match entry.get_secret() {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                verify_key(wallet, &bytes)?;
                if let Some(key) = supplied {
                    ensure!(
                        bytes.as_slice() == key.key.0.as_slice(),
                        "existing destination key differs"
                    );
                }
            }
            Err(keyring::Error::NoEntry) => {
                let key = supplied
                    .context("missing account credential; no verified destination copy exists")?;
                verify_key(wallet, &key.key.0)?;
                entry.set_secret(&key.key.0)?;
                let bytes = Zeroizing::new(entry.get_secret()?);
                ensure!(
                    bytes.as_slice() == key.key.0.as_slice(),
                    "destination key readback mismatch"
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn verified_receipt(root: &Path, digest: [u8; 32], nonce: Uuid) -> Result<Receipt> {
    let wallets = database::verify(root, digest)?;
    prepare_keys(&wallets, &[])?;
    let profile = service_profile()?;
    Ok(Receipt {
        phase: ReceiptPhase::Verified,
        selection_digest: None,
        digest,
        nonce,
        accounts: wallets.iter().map(|wallet| wallet.instance_id).collect(),
        profile,
        binding: database::move_state(root)?
            .binding
            .map(|value| serde_json::from_str(&value))
            .transpose()?,
        wallets,
    })
}

fn service_profile() -> Result<Uuid> {
    #[cfg(target_os = "linux")]
    return crate::service_storage::profile_id().context("missing service profile");
    #[cfg(target_os = "windows")]
    return crate::windows_service_custody::profile_id().context("missing service profile");
}

fn validated_binding(binding: &MoveBinding) -> Result<String> {
    ensure!(
        binding.profile == service_profile()?
            && binding.source.is_absolute()
            && binding.preserved_profiles.len() <= 32
            && binding
                .preserved_profiles
                .iter()
                .all(|path| path.is_absolute() && path != &binding.source)
            && binding
                .preserved_profiles
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && binding.retained_shared_accounts.len() <= 512
            && (!binding.preserved_profiles.is_empty()
                || binding.retained_shared_accounts.is_empty()),
        "invalid move source/destination binding"
    );
    let encoded = serde_json::to_string(binding)?;
    ensure!(
        encoded.len() <= 256 * 1024,
        "move identity metadata is oversized"
    );
    Ok(encoded)
}

/// Public metadata only. A pending receipt must stop startup before any normal
/// desktop work, even after account credentials have already been imported.
pub fn move_status() -> Result<MoveStatus> {
    let profile = service_profile()?;
    let state = database::move_state(&crate::config::default_data_dir()?)?;
    if let Some(digest) = state.receipt {
        let encoded = state.binding.context(
            "legacy move cleanup is pending without bound source metadata; keep the wallet paused",
        )?;
        ensure!(
            encoded.len() <= 256 * 1024,
            "move identity metadata is oversized"
        );
        let binding: MoveBinding = serde_json::from_str(&encoded)?;
        ensure!(
            binding.profile == profile,
            "move receipt belongs to another destination"
        );
        return Ok(if state.complete {
            let retained = !binding.preserved_profiles.is_empty() || binding.retirement.is_none();
            MoveStatus::Complete {
                binding,
                shared_database_credential_retained: retained,
            }
        } else {
            MoveStatus::PendingCleanup { digest, binding }
        });
    }
    Ok(if state.baseline {
        MoveStatus::Baseline
    } else {
        MoveStatus::Unavailable
    })
}

/// Service-side backstop: no desktop can activate execution while cleanup is
/// pending, including a client that skips the first-run screen.
pub fn require_cleanup_finished(root: &Path) -> Result<()> {
    let state = database::move_state(root)?;
    ensure!(
        state.receipt.is_none() || state.complete,
        "legacy move cleanup is pending; resume its exact source review before starting the wallet"
    );
    Ok(())
}

pub(crate) fn initialize_baseline(root: &Path) -> Result<()> {
    database::initialize_baseline(root)
}

#[cfg(test)]
#[path = "legacy_move_test.rs"]
mod tests;
