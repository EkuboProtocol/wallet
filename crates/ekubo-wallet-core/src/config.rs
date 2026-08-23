#[cfg(any(test, feature = "test-hooks"))]
use crate::policy_store::{DATABASE_FILE, DatabaseKey};
use crate::{
    desktop_store::DesktopStore,
    human_presence::{OwnerAuthorization, OwnerAuthorizationScope},
};
use alloy::primitives::Address;
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use directories::BaseDirs;
use fs2::FileExt;
use rusqlite::{OptionalExtension as _, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "test-hooks"))]
use std::sync::Arc;
use std::{
    collections::BTreeSet,
    env,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};
use url::Url;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WalletSource {
    Created,
    Imported,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WalletMetadata {
    /// Immutable identity for this one local custody lifecycle.
    ///
    /// Re-importing the same private key creates a new instance. Names and
    /// addresses can both repeat after retirement, so neither is an authority
    /// boundary.
    pub instance_id: Uuid,
    pub id: String,
    #[schemars(with = "String")]
    pub address: Address,
    pub created_at: DateTime<Utc>,
    pub source: WalletSource,
    /// When this tool first handed out a copy of the private key.
    ///
    /// A timestamp is a sound positive: `account export` definitely revealed
    /// the key. Its absence is not the corresponding negative. The key sits in
    /// the OS credential store, which the owner can read with their login
    /// credential and anything running as them can reach, so a copy can leave
    /// without this process ever observing it. Nothing in the policy, signing,
    /// or approval path reads this field; it is provenance a human can consult,
    /// never a control.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exported_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeCurrency {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct NetworkConfig {
    pub name: String,
    /// Disabled profiles remain inspectable and editable but are excluded
    /// from ordinary wallet activity until the owner enables them again.
    pub disabled: bool,
    /// Test networks are hidden from owner-facing data unless testnet mode is
    /// enabled. This classification travels with the configured network so
    /// custom networks and reviewed agent proposals cannot lose it.
    pub testnet: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub chain_id: u64,
    /// Every endpoint this network may be reached through, in preference
    /// order. Never empty.
    ///
    /// A public RPC is a shared, rate-limited, individually unreliable
    /// service, and the wallet cannot simulate — and therefore cannot sign —
    /// while the one it holds is refusing requests. Carrying several means a
    /// single healthy endpoint anywhere in the list is enough, and the order
    /// is the order they are tried in.
    #[schemars(with = "Vec<String>")]
    #[serde(deserialize_with = "deserialize_rpc_urls")]
    pub rpc_urls: Vec<Url>,
    /// Whether endpoints are tried in configured or fresh random order.
    #[serde(default, skip_serializing_if = "RpcStrategy::is_default")]
    pub rpc_strategy: RpcStrategy,
    /// Receipts remain provisional, and keep the wallet/chain signing slot,
    /// until they are this many blocks deep.
    #[serde(
        default = "default_finality_confirmations",
        skip_serializing_if = "is_default_finality_confirmations"
    )]
    pub finality_confirmations: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_currency: Option<NativeCurrency>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub block_explorer_url: Option<Url>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub documentation_url: Option<Url>,
}

/// How deep a receipt must be before the wallet will sign the next
/// transaction on the same chain.
///
/// This is a latency setting far more than a safety one: nothing is undone by
/// a reorg that the wallet could have prevented by waiting, and the only
/// thing waiting buys is that a receipt already reported is less likely to be
/// re-mined at another position. Twelve blocks — the old value, inherited
/// from proof-of-work exchange practice — held the signing slot for about
/// two and a half minutes of Ethereum mainnet before an agent could send
/// anything else, which read as the wallet having hung. Three keeps the
/// reorg window covered on every chain the registry ships while leaving the
/// wallet usable, and any network that wants to be more careful can say so
/// per network in its own configuration.
pub const DEFAULT_FINALITY_CONFIRMATIONS: u16 = 3;

const fn default_finality_confirmations() -> u16 {
    DEFAULT_FINALITY_CONFIRMATIONS
}

// Serde's `skip_serializing_if` callback receives a reference even for Copy
// fields, so this signature is fixed by the derive contract.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_default_finality_confirmations(value: &u16) -> bool {
    *value == DEFAULT_FINALITY_CONFIRMATIONS
}

fn deserialize_rpc_urls<'de, D>(deserializer: D) -> std::result::Result<Vec<Url>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let urls = Vec::<Url>::deserialize(deserializer)?;
    if urls.is_empty() {
        return Err(serde::de::Error::custom(
            "a network must contain at least one RPC URL",
        ));
    }
    Ok(urls)
}

/// How a network's endpoints are ordered for one request.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RpcStrategy {
    /// Try endpoints in configured order and take the first answer. The
    /// cheapest strategy, and the one that trusts whichever endpoint happens
    /// to be first.
    #[default]
    Ordered,
    /// Try endpoints in a fresh random order per request.
    ///
    /// Costs exactly what `ordered` costs. What it buys is that no single
    /// operator sees the whole of a wallet's activity, and that an operator
    /// deciding whether to lie about a particular request cannot know it will
    /// be asked — which is weaker than being checked, but is not nothing, and
    /// it spreads load off whichever endpoint would otherwise be first.
    Random,
}

impl RpcStrategy {
    /// Whether every request should visit the endpoints in a fresh order.
    #[must_use]
    pub fn shuffles(self) -> bool {
        matches!(self, Self::Random)
    }

    /// Serialization skips the default to keep the configuration concise.
    #[must_use]
    pub fn is_default(&self) -> bool {
        *self == Self::Ordered
    }
}

impl std::fmt::Display for RpcStrategy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ordered => formatter.write_str("ordered"),
            Self::Random => formatter.write_str("random"),
        }
    }
}

impl std::str::FromStr for RpcStrategy {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ordered" => Ok(Self::Ordered),
            "random" => Ok(Self::Random),
            _ => anyhow::bail!("unknown RPC strategy {value}; use ordered or random"),
        }
    }
}

impl NetworkConfig {
    /// What this network is called, for a person reading it.
    ///
    /// `name` is the internal handle an agent types, and `aliases` exist so a
    /// person can abbreviate in conversation — neither is the network's name.
    /// Anything a human reads says "Robinhood Chain", not "robinhood".
    #[must_use]
    pub fn display_label(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.name)
    }

    /// What this network's balances and values are denominated in.
    ///
    /// The stored field is optional — a row may predate it, or have been
    /// written by hand — and a network without one showed balances in wei and
    /// approvals in "native units", on Ethereum, to an owner who had chosen
    /// nothing unusual. The compiled-in registry already knows what every
    /// chain this build ships calls its currency, so a configuration that does
    /// not say falls back to that, by chain id.
    ///
    /// Only the registry answers. Nothing an agent or a peer can reach
    /// contributes to it, because these decimals are what an approval screen
    /// formats an amount with, and a wrong answer there is an owner reading a
    /// number that is not the one being signed. A chain the registry does not
    /// carry still has no currency, and the raw units it falls back to are
    /// honest about that.
    #[must_use]
    pub fn resolved_native_currency(&self) -> Option<NativeCurrency> {
        self.native_currency.clone().or_else(|| {
            crate::networks::known_network(self.chain_id)
                .and_then(|profile| profile.config.native_currency.clone())
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WalletConfig {
    pub version: u8,
    pub wallets: Vec<WalletMetadata>,
    pub networks: Vec<NetworkConfig>,
}

const WALLET_CONFIGURATION_SETTING: &str = "wallet_configuration";

#[derive(Clone)]
pub struct ConfigStore {
    data_dir: PathBuf,
    database: ConfigDatabase,
}

#[derive(Clone)]
enum ConfigDatabase {
    Production,
    #[cfg(any(test, feature = "test-hooks"))]
    Explicit(Arc<DatabaseKey>),
}

impl ConfigStore {
    /// Open an isolated encrypted configuration store for tests.
    ///
    /// Production always obtains its key from the platform credential store
    /// through [`Self::production`]. This constructor is absent from release
    /// builds so a caller cannot accidentally put a database key beside or in
    /// application code.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self::open(data_dir, DatabaseKey::new([0x43; 32]))
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn open(data_dir: impl Into<PathBuf>, key: DatabaseKey) -> Self {
        Self {
            data_dir: data_dir.into(),
            database: ConfigDatabase::Explicit(Arc::new(key)),
        }
    }

    pub fn production() -> Result<Self> {
        Ok(Self {
            data_dir: default_data_dir()?,
            database: ConfigDatabase::Production,
        })
    }

    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    fn database(&self) -> Result<DesktopStore> {
        match &self.database {
            ConfigDatabase::Production => DesktopStore::production(&self.data_dir),
            #[cfg(any(test, feature = "test-hooks"))]
            ConfigDatabase::Explicit(key) => {
                DesktopStore::open(&self.data_dir.join(DATABASE_FILE), key)
            }
        }
    }

    /// Open the shared security database through the same production or
    /// explicit test key as this configuration store.
    pub(crate) fn policy_store(&self) -> Result<crate::policy_store::PolicyStore> {
        match &self.database {
            ConfigDatabase::Production => {
                crate::policy_store::PolicyStore::production(&self.data_dir)
            }
            #[cfg(any(test, feature = "test-hooks"))]
            ConfigDatabase::Explicit(key) => {
                crate::policy_store::PolicyStore::open(&self.data_dir.join(DATABASE_FILE), key)
            }
        }
    }

    pub fn load(&self) -> Result<WalletConfig> {
        let mut database = self.database()?;
        let Some(config) = database.setting::<WalletConfig>(WALLET_CONFIGURATION_SETTING)? else {
            let config = WalletConfig {
                version: 3,
                wallets: Vec::new(),
                networks: default_networks(),
            };
            validate_config(&config)?;
            database.set_setting(WALLET_CONFIGURATION_SETTING, &config)?;
            return Ok(config);
        };
        validate_config(&config)?;
        Ok(config)
    }

    /// Write the configuration into the encrypted database, without taking
    /// the inter-process read-modify-write lock.
    ///
    /// Private on purpose. `update` is the only correct way to change a
    /// configuration, because a read-modify-write that does not hold the lock
    /// silently discards whatever another owner or MCP task wrote in between.
    /// That rule used to live in a doc comment while the compiler allowed
    /// anything; now the only caller that can reach this is `update` itself.
    fn save(&self, config: &WalletConfig) -> Result<()> {
        validate_config(config)?;
        let encoded = serde_json::to_vec(config)?;
        ensure!(
            encoded.len() <= MAX_CONFIG_BYTES,
            "wallet configuration exceeds {MAX_CONFIG_BYTES} bytes"
        );
        self.database()?
            .set_setting(WALLET_CONFIGURATION_SETTING, config)
    }

    /// Update the configuration while holding an inter-process lock.
    ///
    /// Every read-modify-write operation must use this method so two owner or
    /// MCP tasks cannot silently discard each other's changes.
    pub(crate) fn update<T>(
        &self,
        update: impl FnOnce(&mut WalletConfig) -> Result<T>,
    ) -> Result<T> {
        create_private_dir(&self.data_dir)?;
        let lock_path = self.data_dir.join("config.lock");
        let lock = open_private_file(&lock_path)
            .with_context(|| format!("failed to open {}", lock_path.display()))?;
        lock.lock_exclusive()
            .with_context(|| format!("failed to lock {}", lock_path.display()))?;

        let result = (|| {
            let mut config = self.load()?;
            let value = update(&mut config)?;
            self.save(&config)?;
            Ok(value)
        })();
        // The work's own answer is the only one reported, in both directions.
        //
        // Propagating an unlock failure over a *failure* replaces "the
        // database key is wrong" with "failed to unlock a lock file", which
        // tells the owner nothing about why their wallet did not open.
        // Propagating it over a *success* is worse: the configuration has
        // already been replaced, so the caller undoes a write that happened.
        //
        // Discarding it costs nothing. The lock is released when this process
        // exits, and an unlock that fails while the process is alive leaves a
        // lock this process still holds — which is what it held a moment ago.
        let _ = FileExt::unlock(&lock);
        result
    }

    /// Test-only access for constructing representative encrypted state.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn update_for_test<T>(
        &self,
        update: impl FnOnce(&mut WalletConfig) -> Result<T>,
    ) -> Result<T> {
        self.update(update)
    }

    /// Run a whole wallet-lifecycle operation as one cross-process step.
    ///
    /// [`Self::update`] serializes a single read-modify-write of the
    /// configuration, which is the wrong granularity for creating or removing
    /// a wallet: those touch the credential store *and* the configuration, and
    /// between the two another process could complete an entire lifecycle of
    /// its own. That is what let two creations of the same id both write a
    /// credential, and what let a replacement wallet be created in the gap
    /// between a removal deleting a row and deleting the key it named.
    ///
    /// A separate lock file, not `config.lock`: `update` is called from inside
    /// this section, and `flock` on a second descriptor for the same file
    /// deadlocks against the descriptor this process already holds.
    pub fn with_lifecycle_lock<T>(&self, body: impl FnOnce() -> Result<T>) -> Result<T> {
        create_private_dir(&self.data_dir)?;
        let lock_path = self.data_dir.join("lifecycle.lock");
        let lock = open_private_file(&lock_path)
            .with_context(|| format!("failed to open {}", lock_path.display()))?;
        lock.lock_exclusive()
            .with_context(|| format!("failed to lock {}", lock_path.display()))?;
        let result = body();
        // Discarded for the same reason `update` discards it: the work's own
        // answer is the only one worth reporting, and the lock is released
        // when this process exits regardless.
        let _ = FileExt::unlock(&lock);
        result
    }

    /// Add or replace a network after core-verified owner authorization.
    pub fn install_network(
        &self,
        network: NetworkConfig,
        authorization: &OwnerAuthorization,
    ) -> Result<()> {
        authorization.require(OwnerAuthorizationScope::NetworkSettings)?;
        self.update(|config| replace_configured_network(&mut config.networks, network))
    }

    /// Install and consume the exact network proposal the owner reviewed.
    ///
    /// The active configuration and proposal queue share one `SQLCipher`
    /// database. Keeping both mutations in this transaction prevents a
    /// replacement proposal from being consumed after the reviewed profile
    /// has already been installed, and prevents an installed profile from
    /// leaving its stale proposal behind.
    pub fn install_network_proposal(
        &self,
        reviewed: &NetworkConfig,
        authorization: &OwnerAuthorization,
    ) -> Result<()> {
        authorization.require(OwnerAuthorizationScope::NetworkSettings)?;
        validate_network(reviewed)?;

        create_private_dir(&self.data_dir)?;
        let lock_path = self.data_dir.join("config.lock");
        let lock = open_private_file(&lock_path)
            .with_context(|| format!("failed to open {}", lock_path.display()))?;
        lock.lock_exclusive()
            .with_context(|| format!("failed to lock {}", lock_path.display()))?;

        let result = (|| {
            let mut database = self.database()?;
            let transaction = database.connection.transaction()?;
            let reviewed_json = serde_json::to_string(reviewed)?;
            let stored_proposal: Option<String> = transaction
                .query_row(
                    "SELECT profile_json FROM network_proposals WHERE chain_id = ?1",
                    [i64::try_from(reviewed.chain_id).context("chain ID out of range")?],
                    |row| row.get(0),
                )
                .optional()?;
            ensure!(
                stored_proposal.as_deref() == Some(reviewed_json.as_str()),
                "the network proposal changed during confirmation; review it again"
            );

            let encoded: Option<String> = transaction
                .query_row(
                    "SELECT value_json FROM application_settings WHERE key = ?1",
                    [WALLET_CONFIGURATION_SETTING],
                    |row| row.get(0),
                )
                .optional()?;
            let mut config = encoded.map_or_else(
                || {
                    Ok::<_, anyhow::Error>(WalletConfig {
                        version: 3,
                        wallets: Vec::new(),
                        networks: default_networks(),
                    })
                },
                |value| serde_json::from_str(&value).context("invalid encrypted app setting"),
            )?;
            validate_config(&config)?;
            replace_configured_network(&mut config.networks, reviewed.clone())?;
            validate_config(&config)?;
            let encoded = serde_json::to_string(&config)?;
            ensure!(
                encoded.len() <= MAX_CONFIG_BYTES,
                "wallet configuration exceeds {MAX_CONFIG_BYTES} bytes"
            );
            transaction.execute(
                "INSERT INTO application_settings(key, value_json, updated_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET
                     value_json = excluded.value_json,
                     updated_at = excluded.updated_at",
                params![
                    WALLET_CONFIGURATION_SETTING,
                    encoded,
                    crate::sql::Millis(Utc::now())
                ],
            )?;
            let removed = transaction.execute(
                "DELETE FROM network_proposals WHERE chain_id = ?1 AND profile_json = ?2",
                params![
                    i64::try_from(reviewed.chain_id).context("chain ID out of range")?,
                    reviewed_json
                ],
            )?;
            ensure!(
                removed == 1,
                "the network proposal changed during installation; nothing was installed"
            );
            transaction.commit()?;
            Ok(())
        })();
        let _ = FileExt::unlock(&lock);
        result
    }

    /// Add a genuinely new network after core-verified owner authorization.
    ///
    /// The desktop's Create affordance must not inherit upsert semantics: a
    /// chain appearing while the owner is authenticating is a conflict to
    /// review, not a row the stale form may silently replace.
    pub fn add_network(
        &self,
        network: NetworkConfig,
        authorization: &OwnerAuthorization,
    ) -> Result<()> {
        authorization.require(OwnerAuthorizationScope::NetworkSettings)?;
        self.update(|config| add_configured_network(&mut config.networks, network))
    }

    /// Replace the exact network row an owner opened in the desktop editor.
    ///
    /// The complete old row is the optimistic revision: RPC URLs are
    /// security-sensitive simulation inputs, so a stale editor may not
    /// overwrite a newer owner decision. Removing the reviewed row and adding
    /// the replacement happen in the same encrypted-database transaction.
    pub fn replace_network(
        &self,
        reviewed: &NetworkConfig,
        replacement: NetworkConfig,
        authorization: &OwnerAuthorization,
    ) -> Result<()> {
        authorization.require(OwnerAuthorizationScope::NetworkSettings)?;
        validate_network(&replacement)?;
        self.update(|config| {
            let index = config
                .networks
                .iter()
                .position(|network| network.chain_id == reviewed.chain_id)
                .with_context(|| {
                    format!(
                        "network {} (chain {}) no longer exists",
                        reviewed.name, reviewed.chain_id
                    )
                })?;
            ensure!(
                config.networks[index] == *reviewed,
                "network {} changed while it was being edited; review the current settings",
                reviewed.name
            );
            let mut networks = config.networks.clone();
            networks.remove(index);
            add_configured_network(&mut networks, replacement)?;
            config.networks = networks;
            Ok(())
        })
    }

    /// Replace every configured network with the exact built-in defaults.
    ///
    /// This intentionally discards custom RPC URLs and network rows, so the
    /// owner authorization is enforced here at the encrypted persistence
    /// boundary rather than being trusted to a desktop confirmation alone.
    pub fn reset_networks_to_defaults(
        &self,
        reviewed_networks: &[NetworkConfig],
        authorization: &OwnerAuthorization,
    ) -> Result<Vec<NetworkConfig>> {
        authorization.require(OwnerAuthorizationScope::NetworkSettings)?;
        let defaults = default_networks();
        self.update(|config| {
            ensure!(
                config.networks == reviewed_networks,
                "network configuration changed during reset review"
            );
            config.networks.clone_from(&defaults);
            Ok(())
        })?;
        Ok(defaults)
    }

    /// Disable without friction because it only removes attack surface. Enabling
    /// restores signing and RPC authority and therefore requires core-verified
    /// owner authorization.
    pub fn set_network_disabled(
        &self,
        reviewed: &NetworkConfig,
        disabled: bool,
        authorization: Option<&OwnerAuthorization>,
    ) -> Result<NetworkConfig> {
        if !disabled {
            authorization
                .context("enabling a network requires owner authorization")?
                .require(OwnerAuthorizationScope::NetworkSettings)?;
        }
        self.update(|config| {
            let network = config
                .networks
                .iter_mut()
                .find(|network| network.chain_id == reviewed.chain_id)
                .with_context(|| {
                    format!(
                        "network {} (chain {}) no longer exists",
                        reviewed.name, reviewed.chain_id
                    )
                })?;
            ensure!(
                *network == *reviewed,
                "network {} changed while the enable setting was being authenticated; review the current settings",
                reviewed.name
            );
            network.disabled = disabled;
            Ok(network.clone())
        })
    }

    pub fn wallet(&self, id: &str) -> Result<WalletMetadata> {
        self.load()?
            .wallets
            .into_iter()
            .find(|wallet| wallet.id == id)
            .with_context(|| format!("unknown wallet {id}"))
    }

    pub fn network(&self, requested: &str) -> Result<NetworkConfig> {
        let networks = self.load()?.networks;
        networks
            .iter()
            .find(|network| !network.disabled && network.name == requested)
            .or_else(|| {
                networks.iter().find(|network| {
                    !network.disabled && network.aliases.iter().any(|alias| alias == requested)
                })
            })
            .cloned()
            .with_context(|| format!("unknown network {requested}"))
    }

    /// The network a pending transaction belongs to, refusing a profile that
    /// has been replaced since the envelope was signed.
    ///
    /// One profile is configured per chain id, and `replace_configured_network`
    /// takes a chain over: the endpoints behind a chain id can be swapped
    /// wholesale while every pending row keeps pointing at that id. A chain id
    /// is not an identity for a *node set* -- a stale, isolated, or forked
    /// endpoint reports the same number -- so a lifecycle decision resolved
    /// this way can be made against endpoints that never saw the transaction
    /// they are being asked about.
    ///
    /// The row already records the name it was signed under, and nothing was
    /// comparing it. Comparing it is not proof the endpoints are the same ones
    /// -- nothing local can prove that -- but it catches the case the wallet
    /// can see, and it fails closed: a caller is told the profile changed
    /// rather than being given an answer from somewhere else.
    ///
    /// Aliases count, so renaming a network through an alias it already
    /// carried is not treated as a replacement.
    pub fn network_for_record(&self, chain_id: &str, network_name: &str) -> Result<NetworkConfig> {
        let network = self.network_by_chain_id(chain_id)?;
        ensure!(
            network.name == network_name
                || network.aliases.iter().any(|alias| alias == network_name),
            "this transaction was signed against network `{network_name}`, but chain {chain_id} \
             is now configured as `{}`. Its endpoints may never have seen the transaction, so \
             nothing here can decide its fate. Restore the profile it was signed against, or \
             cancel it on chain.",
            network.name
        );
        Ok(network)
    }

    pub fn network_by_chain_id(&self, chain_id: &str) -> Result<NetworkConfig> {
        ensure!(
            !chain_id.is_empty()
                && !chain_id.starts_with('0')
                && chain_id.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid decimal chain ID {chain_id}"
        );
        let chain_id = chain_id.parse::<u64>().context("unsupported chain ID")?;
        self.load()?
            .networks
            .into_iter()
            .find(|network| !network.disabled && network.chain_id == chain_id)
            .with_context(|| format!("no configured network for chain {chain_id}"))
    }
}

pub fn default_data_dir() -> Result<PathBuf> {
    if let Some(explicit) = env::var_os("EKUBO_WALLET_HOME") {
        ensure!(!explicit.is_empty(), "EKUBO_WALLET_HOME cannot be empty");
        return Ok(PathBuf::from(explicit));
    }
    let base = BaseDirs::new().context("could not determine the user home directory")?;
    #[cfg(target_os = "macos")]
    return Ok(base
        .home_dir()
        .join("Library/Application Support/org.ekubo.wallet"));
    #[cfg(target_os = "windows")]
    return Ok(base.data_local_dir().join("Ekubo/wallet"));
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    Ok(env::var_os("XDG_STATE_HOME")
        .map_or_else(|| base.home_dir().join(".local/state"), PathBuf::from)
        .join("ekubo-wallet"))
}

/// The networks a fresh configuration starts with.
///
/// Re-exported from [`crate::networks`], which is where they and every other
/// chain the wallet knows about now live. It stays here because every caller
/// in the tree already imports it from `config`, and because "what a new
/// configuration contains" is a configuration question.
pub use crate::networks::default_networks;

pub fn validate_config(config: &WalletConfig) -> Result<()> {
    ensure!(config.version == 3, "unsupported configuration version");
    let mut wallet_ids = BTreeSet::new();
    let mut instance_ids = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    for wallet in &config.wallets {
        validate_wallet_id(&wallet.id)?;
        ensure!(
            !wallet.instance_id.is_nil(),
            "wallet {} has an invalid nil instance UUID",
            wallet.id
        );
        ensure!(
            wallet_ids.insert(&wallet.id),
            "duplicate wallet {}",
            wallet.id
        );
        ensure!(
            instance_ids.insert(wallet.instance_id),
            "duplicate wallet instance {}",
            wallet.instance_id
        );
        ensure!(
            addresses.insert(wallet.address),
            "address {:#x} is already active",
            wallet.address
        );
    }
    ensure!(
        config.networks.len() <= MAX_CONFIGURED_NETWORKS,
        "a configuration may hold at most {MAX_CONFIGURED_NETWORKS} networks"
    );
    let mut chain_ids = BTreeSet::new();
    let mut identifiers = BTreeSet::new();
    for network in &config.networks {
        validate_network(network)?;
        ensure!(
            chain_ids.insert(network.chain_id),
            "duplicate chain ID {}",
            network.chain_id
        );
        for identifier in std::iter::once(&network.name).chain(network.aliases.iter()) {
            ensure!(
                identifiers.insert(identifier),
                "duplicate network name or alias {identifier}"
            );
        }
    }
    Ok(())
}

pub fn validate_wallet_id(id: &str) -> Result<()> {
    let valid = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    ensure!(
        valid,
        "wallet id must use 1-64 letters, numbers, underscores, or hyphens"
    );
    Ok(())
}

/// The largest configuration document this build will parse.
///
/// A wallet entry and a network profile are each well under a kilobyte, and
/// the counts below cap how many of each there can be, so this sits an order
/// of magnitude above any honest file. It exists because `load` runs on every
/// command and the file it reads is not trusted.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// Gas every transaction costs before executing a single opcode. A configured
/// ceiling below this describes a network on which nothing can be sent.
pub const INTRINSIC_GAS: u64 = 21_000;

/// Networks one configuration may hold.
///
/// Raised from 64 when the defaults grew to cover every EVM mainnet Alchemy
/// serves: 64 left an owner barely a dozen slots of their own, and a cap that
/// the shipped defaults nearly fill is a cap on the owner rather than on
/// abuse. It is still a cap, because every `load` reads and validates the
/// whole list, and a file naming thousands of networks is an accident or an
/// attempt either way.
pub const MAX_CONFIGURED_NETWORKS: usize = 192;

/// Aliases one network may answer to. Enough for a canonical name, a short
/// form, and the spellings people actually type.
pub const MAX_NETWORK_ALIASES: usize = 8;

/// Endpoints one network may list.
///
/// Failover walks this list in order, so its length is also the worst case a
/// caller waits through before hearing that a request failed: every endpoint
/// ahead of the working one costs its own timeout. Enough entries that a
/// public chain keeps working when several providers are down at once, few
/// enough that the wait when they are *all* down stays bounded.
pub const MAX_NETWORK_RPC_URLS: usize = 8;

pub fn validate_network(network: &NetworkConfig) -> Result<()> {
    validate_network_identifier(&network.name, "network name")?;
    ensure!(
        network.aliases.len() <= MAX_NETWORK_ALIASES,
        "a network may have at most {MAX_NETWORK_ALIASES} aliases"
    );
    let mut identifiers = BTreeSet::from([&network.name]);
    for alias in &network.aliases {
        validate_network_identifier(alias, "network alias")?;
        ensure!(
            identifiers.insert(alias),
            "duplicate network name or alias {alias}"
        );
    }
    ensure!(network.chain_id > 0, "network chain ID must be positive");
    ensure!(
        (1..=1_000).contains(&network.finality_confirmations),
        "network finality confirmations must be between 1 and 1000"
    );
    ensure!(
        !network.rpc_urls.is_empty(),
        "a network must have at least one RPC URL"
    );
    ensure!(
        network.rpc_urls.len() <= MAX_NETWORK_RPC_URLS,
        "a network may have at most {MAX_NETWORK_RPC_URLS} RPC URLs"
    );
    let mut endpoints = BTreeSet::new();
    for rpc_url in &network.rpc_urls {
        ensure!(
            matches!(rpc_url.scheme(), "http" | "https"),
            "RPC URL must use http:// or https://"
        );
        // Userinfo is a credential written in the one part of a URL that does
        // not have to look like one. The owner-only editor may show complete
        // endpoints, while agent and error surfaces use the core's redacted
        // label. Userinfo is still refused because standard URL renderers and
        // transport errors can surface it unexpectedly. Refuse without
        // echoing the URL, since the message that named it would publish the
        // thing it is complaining about. Checked before the duplicate test
        // below, which does echo.
        ensure!(
            rpc_url.username().is_empty() && rpc_url.password().is_none(),
            "an RPC URL for network {} carries a username or password; credentials in URL \
             userinfo can be exposed by transport errors and standard URL renderers. Remove it \
             from the URL.",
            network.name
        );
        // A list that names one endpoint twice is shorter than it looks: the
        // second attempt reaches the service that just failed, so the network
        // has fewer real fallbacks than its owner believes.
        ensure!(
            endpoints.insert(rpc_url),
            "duplicate RPC URL {rpc_url} in network {}",
            network.name
        );
    }
    if let Some(display_name) = &network.display_name {
        ensure!(
            !display_name.trim().is_empty()
                && display_name.len() <= 128
                && !display_name.chars().any(crate::sanitize::is_disallowed),
            "network display name must contain 1-128 characters and no control, \
             bidirectional, or zero-width characters"
        );
    }
    if let Some(currency) = &network.native_currency {
        ensure!(
            !currency.name.trim().is_empty()
                && currency.name.len() <= 64
                && !currency.name.chars().any(crate::sanitize::is_disallowed),
            "native currency name must contain 1-64 characters and no control, \
             bidirectional, or zero-width characters"
        );
        // The symbol sits beside an amount on the approval screen, which is
        // the one place a right-to-left override buys something: it can move
        // the digits it is next to.
        ensure!(
            !currency.symbol.trim().is_empty()
                && currency.symbol.len() <= 32
                && !currency.symbol.chars().any(crate::sanitize::is_disallowed),
            "native currency symbol must contain 1-32 characters and no control, \
             bidirectional, or zero-width characters"
        );
    }
    for (label, url) in [
        ("block explorer URL", network.block_explorer_url.as_ref()),
        ("documentation URL", network.documentation_url.as_ref()),
    ] {
        if let Some(url) = url {
            ensure!(
                matches!(url.scheme(), "http" | "https"),
                "{label} must use http:// or https://"
            );
            // Neither of these is ever fetched; GPUI hands them to the
            // platform's URL opener. This is an agent-supplied string that
            // crosses that platform boundary, so it is worth being narrow at
            // the door as well.
            //
            // A base is a base: `explorer_transaction_url` appends
            // `/tx/{hash}`, so anything after a `?` or `#` would be discarded
            // or produce nonsense anyway, and refusing them removes the
            // ordinary place an `&` can legitimately appear.
            ensure!(
                url.query().is_none() && url.fragment().is_none(),
                "{label} must be a base URL with no query string or fragment; the transaction \
                 path is appended to it"
            );
            ensure!(
                !url.as_str().chars().any(crate::sanitize::is_disallowed),
                "{label} must not contain control, bidirectional, or zero-width characters"
            );
        }
    }
    Ok(())
}

fn validate_network_identifier(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        "{label} must use 1-64 letters, numbers, underscores, or hyphens"
    );
    Ok(())
}

fn validate_known_network_classification(network: &NetworkConfig) -> Result<()> {
    if let Some(known) = crate::networks::known_network(network.chain_id) {
        ensure!(
            network.testnet == known.config.testnet,
            "chain {} is classified as {} by the built-in registry",
            network.chain_id,
            if known.config.testnet {
                "a testnet"
            } else {
                "a mainnet"
            }
        );
    }
    Ok(())
}

pub fn add_configured_network(
    networks: &mut Vec<NetworkConfig>,
    next: NetworkConfig,
) -> Result<()> {
    validate_network(&next)?;
    validate_known_network_classification(&next)?;
    if let Some(existing) = networks
        .iter()
        .find(|network| network.chain_id == next.chain_id)
    {
        bail!(
            "chain {} is already configured as {}",
            next.chain_id,
            existing.name
        );
    }
    let identifiers = std::iter::once(&next.name)
        .chain(next.aliases.iter())
        .collect::<BTreeSet<_>>();
    if let Some(existing) = networks.iter().find(|network| {
        std::iter::once(&network.name)
            .chain(network.aliases.iter())
            .any(|identifier| identifiers.contains(identifier))
    }) {
        bail!(
            "network name or alias conflicts with configured network {}",
            existing.name
        );
    }
    networks.push(next);
    Ok(())
}

/// Replace whatever already describes this network — the entry with the same
/// name, and the entry holding the same chain ID — while rejecting identifier
/// collisions with the networks that survive.
///
/// A chain ID identifies a network more firmly than a name does, and the
/// configuration allows one profile per chain ID, so someone who names a chain
/// ID that is already configured is saying which network they mean rather than
/// asking to configure a second copy of it. Naming a preset's chain under a
/// different name therefore takes that chain over instead of failing and
/// sending the user off to `network remove` first.
pub fn replace_configured_network(
    networks: &mut Vec<NetworkConfig>,
    next: NetworkConfig,
) -> Result<()> {
    validate_network(&next)?;
    validate_known_network_classification(&next)?;
    let identifiers = std::iter::once(&next.name)
        .chain(next.aliases.iter())
        .collect::<BTreeSet<_>>();
    // The chain being taken over is exempt from the identifier check: reusing
    // the name and aliases of the profile being replaced is not a collision
    // with it. Nothing else is exempt — matching by name as well meant a
    // candidate for a *new* chain that reused a configured chain's name
    // silently deleted that chain, whose profile the reviewer was never shown.
    if let Some(existing) = networks.iter().find(|network| {
        network.chain_id != next.chain_id
            && std::iter::once(&network.name)
                .chain(network.aliases.iter())
                .any(|identifier| identifiers.contains(identifier))
    }) {
        bail!(
            "network name or alias conflicts with configured network {} (chain {})",
            existing.name,
            existing.chain_id
        );
    }
    // Nothing here has to survive a replacement any more. A fee or gas ceiling
    // used to live on the network profile, so replacing the profile deleted a
    // bound the owner never asked to change and this function carried it
    // forward by hand. Those ceilings are policy rules now, in a separate store
    // with its own revision, and a network edit cannot touch them.
    networks.retain(|network| network.chain_id != next.chain_id);
    networks.push(next);
    Ok(())
}

pub(crate) fn create_private_dir(path: &Path) -> Result<()> {
    // Created private, rather than created and then narrowed. `create_dir_all`
    // followed by `set_permissions` leaves the directory readable for the
    // window between the two calls, which is when the wallet's own files are
    // about to appear in it. `DirBuilder` applies the mode as it creates, so
    // there is no window and no separate `set_permissions` following a symlink
    // somebody swapped in.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        // `symlink_metadata` rather than `exists`/`metadata`: both of those
        // resolve the name, so a symlink planted at `path` answered for its
        // target and the mode below was applied to whatever the link pointed
        // at. Asking about the link itself is the only question with a stable
        // answer, and a data directory reached through a link is refused
        // outright rather than hardened in place — the wallet cannot promise
        // 0700 on a directory whose identity another process chooses.
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "{} is a symbolic link; the wallet data directory must be a real directory it \
                     can keep private",
                    path.display()
                );
            }
            Ok(metadata) => {
                ensure!(
                    metadata.is_dir(),
                    "{} exists and is not a directory",
                    path.display()
                );
                // An existing directory may predate this rule, or have been
                // restored from a backup that widened it.
                let mode = metadata.permissions().mode();
                if mode & 0o077 != 0 {
                    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(path)?;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
            }
        }
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path)?;
    Ok(())
}

/// Open a file that only this owner may read, refusing to follow a symlink
/// planted in its place, and return the handle that names the inode.
///
/// There is deliberately no by-path counterpart. `fs::set_permissions` and
/// `File::open` each resolve the name independently, so a caller that opens a
/// file and then narrows it by name has asked the filesystem the same question
/// twice and may be answered differently each time — the second answer being a
/// link the mode is then applied to. Handing back the handle means the caller
/// cannot reintroduce that gap: it already holds the only reference it needs.
pub(crate) fn open_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW fails with ELOOP rather than opening a link's target, so
        // the handle below refers to the name itself or to nothing.
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    set_private_handle_permissions(&file)?;
    Ok(file)
}

/// Narrow the file this handle already refers to, rather than whatever its
/// name refers to now.
///
/// `fs::set_permissions` resolves a path and follows symlinks, so a caller
/// that opens a file and then narrows it by name is naming the same thing
/// twice and can be answered differently each time — the second answer being
/// a link the mode is then applied to. Every one of these callers is holding
/// the open handle already, so there is no reason to ask twice.
pub(crate) fn set_private_handle_permissions(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let _ = file;
    Ok(())
}

#[cfg(test)]
#[path = "config_test.rs"]
mod tests;
