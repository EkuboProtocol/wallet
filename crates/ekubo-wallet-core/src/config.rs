use alloy::primitives::Address;
use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use directories::BaseDirs;
use fs2::FileExt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    env,
    fs::{self, File, OpenOptions},
    io::{BufReader, Read as _, Write},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use url::Url;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WalletSource {
    Created,
    Imported,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WalletMetadata {
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

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct NetworkConfig {
    pub name: String,
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
    pub rpc_urls: Vec<Url>,
    /// How those endpoints are used: in order, in a random order, or several
    /// at once with their answers compared.
    #[serde(default, skip_serializing_if = "RpcStrategy::is_default")]
    pub rpc_strategy: RpcStrategy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_gas_limit: Option<String>,
    /// The most this wallet will ever sign as `maxFeePerGas`, in wei.
    ///
    /// The fee fields of an automatic transaction come from an RPC and reach
    /// the signature unchanged: no policy rule speaks about them, and nobody
    /// reviews them, because the whole point of an automatic transaction is
    /// that nobody is asked. `gas_limit × max_fee_per_gas` is what the owner
    /// can lose to a single endpoint that answers dishonestly, and the block
    /// gas limit already bounds the first factor. This bounds the second.
    ///
    /// Unset means unbounded, which is what it was, and is the right default
    /// only because a number chosen here for every chain would be wrong on
    /// most of them. An owner running automatic transactions against one
    /// public endpoint should set it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_currency: Option<NativeCurrency>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub block_explorer_url: Option<Url>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub documentation_url: Option<Url>,
}

/// How a network's endpoints are used for one request.
///
/// Failover already answers availability: any healthy endpoint will do. This
/// answers a different question — how much the answer is worth. A single
/// public RPC is an unaccountable third party that sees every address this
/// wallet asks about and can answer anything it likes, and for a simulation
/// that means it decides what the approval screen says a transaction will do
/// and what it will cost. Nothing downstream can catch a *coherent* lie: the
/// wallet checks that a response is internally consistent and linked to the
/// block it pinned, not that it is true.
///
/// The defence against a lie is a second opinion from an unrelated operator.
/// That is what [`RpcStrategy::MOfN`] buys, and what it costs is one more
/// copy of the most expensive request the wallet makes.
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
    /// Ask several endpoints and use the answer only if `agree` of them
    /// return the same one.
    ///
    /// This is the only strategy that reduces what a single RPC operator can
    /// do to a signature. Endpoints are drawn from the configured list until
    /// `agree` of them return matching answers; one that fails or refuses is
    /// an unavailable witness rather than a disagreement, so it is skipped.
    /// A genuine disagreement fails closed: the wallet refuses the answer
    /// rather than picking a side, because there is no basis on which it
    /// could choose correctly.
    MOfN { agree: usize },
}

impl RpcStrategy {
    /// The number of endpoints whose answers must match. One, except under
    /// [`RpcStrategy::MOfN`].
    #[must_use]
    pub fn required_agreement(self) -> usize {
        match self {
            Self::Ordered | Self::Random => 1,
            Self::MOfN { agree } => agree,
        }
    }

    /// Whether every request should visit the endpoints in a fresh order.
    #[must_use]
    pub fn shuffles(self) -> bool {
        matches!(self, Self::Random)
    }

    /// Serialization skips the default, so a configuration written before
    /// this setting existed round-trips unchanged.
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
            Self::MOfN { agree } => write!(formatter, "m_of_n({agree})"),
        }
    }
}

impl std::str::FromStr for RpcStrategy {
    type Err = anyhow::Error;

    /// Accepts `ordered`, `random`, and `m_of_n(2)`; the parenthesised count
    /// may also be written `m_of_n:2` or `m-of-n 2`, because this is typed at
    /// a prompt and a shell eats parentheses.
    fn from_str(value: &str) -> Result<Self> {
        let normalized = value.trim().to_ascii_lowercase().replace(['-', ' '], "_");
        match normalized.as_str() {
            "ordered" => return Ok(Self::Ordered),
            "random" => return Ok(Self::Random),
            _ => {}
        }
        let count = normalized
            .strip_prefix("m_of_n")
            .map(|rest| rest.trim_matches(|character| matches!(character, '(' | ')' | ':' | '_')))
            .filter(|rest| !rest.is_empty())
            .with_context(|| {
                format!("unknown RPC strategy {value}; use ordered, random, or m_of_n(2)")
            })?;
        let agree = count
            .parse::<usize>()
            .with_context(|| format!("m_of_n needs a count, as in m_of_n(2); got {value}"))?;
        Ok(Self::MOfN { agree })
    }
}

impl NetworkConfig {
    /// The endpoint tried first, and the one shown wherever a single endpoint
    /// identifies the network. Every constructor and the deserializer refuse
    /// an empty list, so this cannot fail on a value that exists.
    #[must_use]
    pub fn primary_rpc_url(&self) -> &Url {
        self.rpc_urls
            .first()
            .expect("a network config always carries at least one RPC URL")
    }
}

/// The on-disk shape of a network, which still accepts the single `rpc_url`
/// that every release through 1.0.0-rc.0 wrote.
///
/// Fallbacks turned the one endpoint into a list, and a configuration written
/// before that change names exactly one. Reading it as a one-element list is
/// the whole migration: the endpoint keeps working, and the next write records
/// it in the new shape.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredNetwork {
    name: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    chain_id: u64,
    #[serde(default)]
    rpc_url: Option<Url>,
    #[serde(default)]
    rpc_urls: Vec<Url>,
    #[serde(default)]
    rpc_strategy: RpcStrategy,
    #[serde(default)]
    max_gas_limit: Option<String>,
    #[serde(default)]
    max_fee_per_gas: Option<String>,
    #[serde(default)]
    native_currency: Option<NativeCurrency>,
    #[serde(default)]
    block_explorer_url: Option<Url>,
    #[serde(default)]
    documentation_url: Option<Url>,
}

// Written by hand rather than derived through `#[serde(try_from)]`: the
// derive would make the published JSON schema the *stored* shape, advertising
// a legacy `rpc_url` alongside `rpc_urls` to every MCP caller reading the
// schema. What this type accepts and what it documents are allowed to differ,
// and here they must.
impl<'de> Deserialize<'de> for NetworkConfig {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Self::try_from(StoredNetwork::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<StoredNetwork> for NetworkConfig {
    type Error = anyhow::Error;

    fn try_from(stored: StoredNetwork) -> Result<Self> {
        // Both spellings at once is a file edited by hand into a state no
        // build produces, and the two can disagree about which endpoint is
        // primary. Refuse it rather than pick one.
        ensure!(
            stored.rpc_url.is_none() || stored.rpc_urls.is_empty(),
            "network {} sets both rpc_url and rpc_urls; keep only rpc_urls",
            stored.name
        );
        let rpc_urls = match stored.rpc_url {
            Some(single) => vec![single],
            None => stored.rpc_urls,
        };
        ensure!(
            !rpc_urls.is_empty(),
            "network {} has no RPC URL",
            stored.name
        );
        Ok(Self {
            name: stored.name,
            display_name: stored.display_name,
            aliases: stored.aliases,
            chain_id: stored.chain_id,
            rpc_urls,
            rpc_strategy: stored.rpc_strategy,
            max_gas_limit: stored.max_gas_limit,
            max_fee_per_gas: stored.max_fee_per_gas,
            native_currency: stored.native_currency,
            block_explorer_url: stored.block_explorer_url,
            documentation_url: stored.documentation_url,
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

/// The on-disk shape, which still accepts the `custody` enum that 0.1.0
/// through 0.3.0-rc.0 wrote.
///
/// That enum held no information `source` and `exported_at` do not already
/// carry, and held it less precisely: an imported key that was later exported
/// collapsed to `exported` and lost the fact that it arrived externally known.
/// It is therefore folded into those two fields on load and never written
/// again. Reading the file through a dedicated type keeps `WalletMetadata`
/// free of a field that exists only for compatibility.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredConfig {
    version: u8,
    wallets: Vec<StoredWallet>,
    networks: Vec<NetworkConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredWallet {
    id: String,
    address: Address,
    created_at: DateTime<Utc>,
    source: WalletSource,
    #[serde(default)]
    custody: Option<LegacyCustodyStatus>,
    #[serde(default)]
    exported_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum LegacyCustodyStatus {
    Sealed,
    ExternallyKnown,
    Exported,
}

impl TryFrom<StoredWallet> for WalletMetadata {
    type Error = anyhow::Error;

    fn try_from(stored: StoredWallet) -> Result<Self> {
        // Every released build set `custody` and `exported_at` inside one
        // atomic configuration update, so the two can only disagree in a file
        // edited by hand. Refuse that file rather than resolve it: silently
        // trusting `exported_at` would downgrade a wallet whose key is
        // recorded as copied into one that reads as never exported, which is
        // the one direction this record must never fail in.
        if let Some(custody) = stored.custody {
            ensure!(
                (custody == LegacyCustodyStatus::Exported) == stored.exported_at.is_some(),
                "wallet {} records custody {:?} but {}; the two disagree, \
                 so correct the configuration by hand before continuing",
                stored.id,
                custody,
                if stored.exported_at.is_some() {
                    "carries an export timestamp"
                } else {
                    "carries no export timestamp"
                },
            );
        }
        Ok(Self {
            id: stored.id,
            address: stored.address,
            created_at: stored.created_at,
            source: stored.source,
            exported_at: stored.exported_at,
        })
    }
}

impl TryFrom<StoredConfig> for WalletConfig {
    type Error = anyhow::Error;

    fn try_from(stored: StoredConfig) -> Result<Self> {
        Ok(Self {
            version: stored.version,
            wallets: stored
                .wallets
                .into_iter()
                .map(WalletMetadata::try_from)
                .collect::<Result<Vec<_>>>()?,
            networks: stored.networks,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ConfigStore {
    data_dir: PathBuf,
    file: PathBuf,
}

impl ConfigStore {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let file = data_dir.join("config.json");
        Self { data_dir, file }
    }

    pub fn production() -> Result<Self> {
        Ok(Self::new(default_data_dir()?))
    }

    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    #[must_use]
    pub fn file(&self) -> &Path {
        &self.file
    }

    pub fn load(&self) -> Result<WalletConfig> {
        // Only a genuine absence starts from defaults. `Path::exists` answers
        // false for every stat failure — a permission error on the directory,
        // a symlink loop, an exhausted descriptor table — so an unreadable
        // configuration used to load as an empty one, and the next `update`
        // would write that empty one back over the file that was there all
        // along, taking the wallet roster and every configured RPC with it.
        // Failing to read is not the same as having nothing to read.
        let file = match File::open(&self.file) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(WalletConfig {
                    version: 2,
                    wallets: Vec::new(),
                    networks: default_networks(),
                });
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to open {}", self.file.display()));
            }
        };
        // Read with a ceiling rather than streaming straight into serde. The
        // filesystem is untrusted and `load` runs on essentially every command
        // and every MCP call, so an oversized file would be parsed into memory
        // each time. Nothing legitimate approaches this: the cap is far above
        // a configuration holding the maximum wallets and networks.
        // Narrow an existing file that is readable by anyone. `save` writes
        // 0600, but a file restored from a backup, copied by an older build, or
        // unpacked from an archive arrives with whatever mode it was given.
        // Repairing on read means it is fixed the first time anything looks at
        // it rather than the next time something writes.
        // Applied to the handle just opened, not to the name it came from: the
        // two need not still be the same file.
        set_private_handle_permissions(&file)?;
        let mut reader = BufReader::new(file).take(MAX_CONFIG_BYTES as u64 + 1);
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .with_context(|| format!("failed to read {}", self.file.display()))?;
        ensure!(
            bytes.len() <= MAX_CONFIG_BYTES,
            "{} exceeds {MAX_CONFIG_BYTES} bytes",
            self.file.display()
        );
        let reader = bytes.as_slice();
        let stored: StoredConfig = serde_json::from_reader(reader)
            .with_context(|| format!("failed to parse {}", self.file.display()))?;
        let config = WalletConfig::try_from(stored)
            .with_context(|| format!("failed to load {}", self.file.display()))?;
        validate_config(&config)?;
        Ok(config)
    }

    /// Write the configuration, without taking the inter-process lock.
    ///
    /// Private on purpose. `update` is the only correct way to change a
    /// configuration, because a read-modify-write that does not hold the lock
    /// silently discards whatever another CLI or MCP process wrote in between.
    /// That rule used to live in a doc comment while the compiler allowed
    /// anything; now the only caller that can reach this is `update` itself.
    fn save(&self, config: &WalletConfig) -> Result<()> {
        validate_config(config)?;
        create_private_dir(&self.data_dir)?;
        let mut temporary = NamedTempFile::new_in(&self.data_dir)
            .context("failed to create temporary configuration")?;
        set_private_handle_permissions(temporary.as_file())?;
        serde_json::to_writer_pretty(&mut temporary, config)?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.file)
            .map_err(|error| error.error)
            .with_context(|| format!("failed to replace {}", self.file.display()))?;
        // Past this point the new configuration is the configuration, so
        // nothing here may report failure: a caller that hears "the update
        // failed" about a write that committed rolls back something that
        // happened. `custody::add` deleting the only copy of a private key is
        // that mistake in its worst form.
        //
        // The mode is already right: the temporary was narrowed through its own
        // handle before anything was written to it, and a rename carries the
        // mode with the inode. Re-narrowing by name here bought nothing and was
        // the one permission change in this file that resolved a path instead
        // of a handle — on the configuration, immediately after publishing it.
        //
        // `sync_parent` stays best-effort: the durability it buys is bounded by
        // what the platform offers anyway.
        let _ = sync_parent(&self.data_dir);
        Ok(())
    }

    /// Update the configuration while holding an inter-process lock.
    ///
    /// Reads are safe without the lock because saves replace the complete JSON
    /// document atomically. Every read-modify-write operation must use this
    /// method so two CLI or MCP processes cannot silently discard each other's
    /// changes.
    pub fn update<T>(&self, update: impl FnOnce(&mut WalletConfig) -> Result<T>) -> Result<T> {
        create_private_dir(&self.data_dir)?;
        let lock_path = self.data_dir.join("config.lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("failed to open {}", lock_path.display()))?;
        set_private_handle_permissions(&lock)?;
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
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("failed to open {}", lock_path.display()))?;
        set_private_handle_permissions(&lock)?;
        lock.lock_exclusive()
            .with_context(|| format!("failed to lock {}", lock_path.display()))?;
        let result = body();
        // Discarded for the same reason `update` discards it: the work's own
        // answer is the only one worth reporting, and the lock is released
        // when this process exits regardless.
        let _ = FileExt::unlock(&lock);
        result
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
            .find(|network| network.name == requested)
            .or_else(|| {
                networks
                    .iter()
                    .find(|network| network.aliases.iter().any(|alias| alias == requested))
            })
            .cloned()
            .with_context(|| format!("unknown network {requested}"))
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
            .find(|network| network.chain_id == chain_id)
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
    ensure!(config.version == 2, "unsupported configuration version");
    let mut wallet_ids = BTreeSet::new();
    for wallet in &config.wallets {
        validate_wallet_id(&wallet.id)?;
        ensure!(
            wallet_ids.insert(&wallet.id),
            "duplicate wallet {}",
            wallet.id
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
        !network.rpc_urls.is_empty(),
        "a network must have at least one RPC URL"
    );
    ensure!(
        network.rpc_urls.len() <= MAX_NETWORK_RPC_URLS,
        "a network may have at most {MAX_NETWORK_RPC_URLS} RPC URLs"
    );
    // An agreement threshold the network cannot reach would refuse every
    // request, and refusing to sign is exactly what an unusable configuration
    // should not be able to cause silently at signing time. Checked where the
    // number is entered, so the message names the number that is wrong.
    if let RpcStrategy::MOfN { agree } = network.rpc_strategy {
        ensure!(
            agree >= 2,
            "m_of_n needs at least 2 agreeing endpoints; use ordered for a single answer"
        );
        ensure!(
            agree <= network.rpc_urls.len(),
            "m_of_n({agree}) needs {agree} endpoints but {} has {}",
            network.name,
            network.rpc_urls.len()
        );
    }
    let mut endpoints = BTreeSet::new();
    for rpc_url in &network.rpc_urls {
        ensure!(
            matches!(rpc_url.scheme(), "http" | "https"),
            "RPC URL must use http:// or https://"
        );
        // Userinfo is a credential written in the one part of a URL that does
        // not have to look like one, and this wallet quotes its endpoints back
        // verbatim: `wallet_list` hands them to the agent, `network show`
        // prints them, and the disclosure text names them. A field repeated on
        // every read cannot hold a secret, so it is refused here rather than
        // redacted at each of the places it would otherwise surface — and
        // refused without echoing the URL, since the message that named it
        // would publish the thing it is complaining about. Checked before the
        // duplicate test below, which does echo.
        ensure!(
            rpc_url.username().is_empty() && rpc_url.password().is_none(),
            "an RPC URL for network {} carries a username or password; this wallet repeats its \
             endpoints verbatim to the agent and on screen, so a credential there would be \
             disclosed. Remove it from the URL.",
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
    if let Some(limit) = &network.max_gas_limit {
        ensure!(
            !limit.starts_with('0') && limit.bytes().all(|byte| byte.is_ascii_digit()),
            "max gas limit must be a canonical positive decimal integer"
        );
        let limit = limit
            .parse::<u64>()
            .context("max gas limit must fit uint64")?;
        // Intrinsic gas, not merely positive. A transaction costs 21,000 gas
        // before it does anything at all, so a cap below that admits no
        // transaction on this network — and the refusal surfaces later, from
        // `effective_gas_limit` at simulation time, as "effective simulation
        // gas limit is below intrinsic gas". Rejecting it where the number is
        // entered says which number is wrong while the person still has it in
        // front of them.
        ensure!(
            limit >= INTRINSIC_GAS,
            "max gas limit must be at least {INTRINSIC_GAS}, the intrinsic cost of any \
             transaction; a lower cap would refuse every transaction on this network"
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

pub fn add_configured_network(
    networks: &mut Vec<NetworkConfig>,
    next: NetworkConfig,
) -> Result<()> {
    validate_network(&next)?;
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
    // The owner's fee ceiling survives a replacement it did not ask to change.
    //
    // Both constructors of a candidate profile leave `max_fee_per_gas` as
    // `None` and say why: the MCP one because "an agent does not choose the
    // owner's fee ceiling", the CLI form because a ceiling is a judgement
    // about what the owner's transactions are worth rather than a property of
    // the chain. Both are right about intent and both achieved the opposite,
    // because this function replaces the whole profile — so a routine endpoint
    // edit deleted the ceiling, and an absent ceiling is unbounded. Nothing
    // downstream notices: no policy rule speaks about fees, no reviewer sees
    // them, and `capped_fee` returns an endpoint's estimate unchanged when
    // there is nothing to check it against.
    //
    // Carried rather than required, because `None` here has only ever meant
    // "not specified". Nothing in the CLI or MCP surface sets a ceiling at
    // all; the owner writes one into the configuration by hand, and the
    // owner's own `network edit` path clones the existing profile, so a
    // deliberate change arrives as `Some`. A future affordance for *removing*
    // one needs to say so explicitly rather than by omission.
    let inherited = networks
        .iter()
        .find(|network| network.chain_id == next.chain_id)
        .and_then(|existing| existing.max_fee_per_gas.clone());
    let next = NetworkConfig {
        max_fee_per_gas: next.max_fee_per_gas.or(inherited),
        ..next
    };
    networks.retain(|network| network.chain_id != next.chain_id);
    networks.push(next);
    Ok(())
}

pub fn remove_configured_network(
    networks: &mut Vec<NetworkConfig>,
    requested: &str,
) -> Result<NetworkConfig> {
    let index = networks
        .iter()
        .position(|network| network.name == requested)
        .or_else(|| {
            networks
                .iter()
                .position(|network| network.aliases.iter().any(|alias| alias == requested))
        })
        .with_context(|| format!("unknown network {requested}"))?;
    Ok(networks.remove(index))
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

/// Flush the directory entry so a rename survives a crash.
///
/// Unix only, and deliberately not emulated elsewhere: Windows offers no
/// portable handle to a directory that `sync_all` accepts, and the alternative
/// — `FlushFileBuffers` on a volume handle — needs privileges this process does
/// not have and flushes far more than this file. `NamedTempFile::persist` uses
/// `MoveFileEx`, which is atomic with respect to readers, so a crash there
/// loses the write rather than corrupting the file. The residual on Windows is
/// that a power loss immediately after saving can leave the previous
/// configuration in place; the file is never torn.
fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    let _ = path;
    Ok(())
}

#[cfg(test)]
#[path = "config_test.rs"]
mod tests;
