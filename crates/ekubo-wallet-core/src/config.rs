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
    /// A timestamp is a sound positive: `wallet export` definitely revealed
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
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub chain_id: u64,
    #[schemars(with = "String")]
    pub rpc_url: Url,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_gas_limit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_currency: Option<NativeCurrency>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub block_explorer_url: Option<Url>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub documentation_url: Option<Url>,
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
        // unpacked from an archive arrives with whatever mode it was given —
        // and this one holds RPC URLs, which can carry provider credentials.
        // Repairing on read means it is fixed the first time anything looks at
        // it rather than the next time something writes.
        set_private_file_permissions(&self.file)?;
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
        set_private_file_permissions(temporary.path())?;
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
        // Neither step is load-bearing on its own. `load` re-narrows an
        // over-permissive file every time it reads one, and the durability
        // `sync_parent` buys is bounded by what the platform offers anyway.
        let _ = set_private_file_permissions(&self.file);
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
        set_private_file_permissions(&lock_path)?;
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

/// The built-in network profiles.
///
/// Each RPC is an endpoint its own chain or its operator publishes for wallet
/// use, chosen so it is documented somewhere a user can read rather than
/// aggregated from a directory. Each was checked against `eth_simulateV1` —
/// without which this wallet cannot simulate and therefore cannot sign
/// automatically — and the endpoints that do not answer it are called out
/// inline below. They are public, shared, and rate-limited: a funded wallet
/// should be pointed at a dedicated provider with `ekubo-wallet network add`.
#[must_use]
pub fn default_networks() -> Vec<NetworkConfig> {
    vec![
        network(
            "ethereum",
            "Ethereum Mainnet",
            &["mainnet", "eth"],
            1,
            "https://rpc.mevblocker.io",
            "16777216",
            "Ether",
            "ETH",
            "https://etherscan.io",
            "https://mevblocker.io",
        ),
        network(
            "base",
            "Base",
            &["base-mainnet"],
            8453,
            "https://mainnet.base.org",
            "16777216",
            "Ether",
            "ETH",
            "https://basescan.org",
            "https://docs.base.org/base-chain/quickstart/connecting-to-base",
        ),
        network(
            "arbitrum",
            "Arbitrum One",
            &["arbitrum-one", "arb", "arb1"],
            42161,
            "https://arb1.arbitrum.io/rpc",
            "32000000",
            "Ether",
            "ETH",
            "https://arbiscan.io",
            "https://support.arbitrum.io/hc/en-gb/articles/19479729907483-How-can-I-add-Arbitrum-network-to-my-wallet",
        ),
        network(
            "robinhood",
            "Robinhood Chain",
            &["robinhood-chain", "hood"],
            4663,
            "https://rpc.mainnet.chain.robinhood.com",
            "32000000",
            "Ether",
            "ETH",
            "https://robinhoodchain.blockscout.com",
            "https://docs.robinhood.com/chain/connecting/",
        ),
        // The published Monad RPC does not answer `eth_simulateV1`, so
        // simulation-gated automatic signing fails on this network until the
        // operator adds it or the user configures an endpoint that has it.
        network(
            "monad",
            "Monad",
            &["monad-mainnet"],
            143,
            "https://rpc.monad.xyz",
            "30000000",
            "Monad",
            "MON",
            "https://monadvision.com",
            "https://docs.monad.xyz/developer-essentials/network-information",
        ),
        network(
            "ink",
            "Ink",
            &["ink-mainnet"],
            57073,
            "https://rpc-gel.inkonchain.com",
            "16777216",
            "Ether",
            "ETH",
            "https://explorer.inkonchain.com",
            "https://docs.inkonchain.com/general/connect-wallet",
        ),
        network(
            "optimism",
            "OP Mainnet",
            &["op", "op-mainnet"],
            10,
            "https://mainnet.optimism.io",
            "16777216",
            "Ether",
            "ETH",
            "https://explorer.optimism.io",
            "https://docs.optimism.io/op-mainnet/network-information/connecting-to-op",
        ),
        network(
            "gnosis",
            "Gnosis",
            &["gnosis-mainnet", "xdai"],
            100,
            "https://rpc.gnosischain.com",
            "16777216",
            "xDai",
            "xDAI",
            "https://gnosisscan.io",
            "https://docs.gnosischain.com/about/networks/mainnet",
        ),
        network(
            "berachain",
            "Berachain",
            &["bera"],
            80094,
            "https://rpc.berachain.com",
            "16777216",
            "BERA",
            "BERA",
            "https://berascan.com",
            "https://docs.berachain.com/general/introduction/connect-to-berachain",
        ),
        // The published MegaETH RPC does not answer `eth_simulateV1` yet, so
        // simulation-gated automatic signing fails on this network until the
        // operator adds it or the user configures an endpoint that has it.
        network(
            "megaeth",
            "MegaETH",
            &["megaeth-mainnet", "mega"],
            4326,
            "https://mainnet.megaeth.com/rpc",
            "10000000000",
            "Ether",
            "ETH",
            "https://megaexplorer.xyz",
            "https://docs.megaeth.com",
        ),
    ]
}

fn network(
    name: &str,
    display_name: &str,
    aliases: &[&str],
    chain_id: u64,
    rpc_url: &str,
    max_gas_limit: &str,
    currency_name: &str,
    currency_symbol: &str,
    explorer: &str,
    documentation: &str,
) -> NetworkConfig {
    NetworkConfig {
        name: name.into(),
        display_name: Some(display_name.into()),
        aliases: aliases.iter().map(ToString::to_string).collect(),
        chain_id,
        rpc_url: rpc_url.parse().expect("static RPC URL"),
        max_gas_limit: Some(max_gas_limit.into()),
        native_currency: Some(NativeCurrency {
            name: currency_name.into(),
            symbol: currency_symbol.into(),
            decimals: 18,
        }),
        block_explorer_url: Some(explorer.parse().expect("static explorer URL")),
        documentation_url: Some(documentation.parse().expect("static documentation URL")),
    }
}

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

/// Networks one configuration may hold. A wallet talks to a handful of chains;
/// a list longer than this is an accident or an attempt, and either way every
/// subsequent `load` pays for it.
pub const MAX_CONFIGURED_NETWORKS: usize = 64;

/// Aliases one network may answer to. Enough for a canonical name, a short
/// form, and the spellings people actually type.
pub const MAX_NETWORK_ALIASES: usize = 8;

pub(crate) fn validate_network(network: &NetworkConfig) -> Result<()> {
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
        matches!(network.rpc_url.scheme(), "http" | "https"),
        "RPC URL must use http:// or https://"
    );
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
        if !path.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)?;
        }
        // An existing directory may predate this rule, or have been restored
        // from a backup that widened it.
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path)?;
    Ok(())
}

pub(crate) fn set_private_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    let _ = path;
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
