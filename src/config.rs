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
    io::{BufReader, Write},
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CustodyStatus {
    Sealed,
    ExternallyKnown,
    Exported,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WalletMetadata {
    pub id: String,
    #[schemars(with = "String")]
    pub address: Address,
    pub created_at: DateTime<Utc>,
    pub source: WalletSource,
    #[serde(default = "legacy_custody_status")]
    pub custody: CustodyStatus,
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
        if !self.file.exists() {
            return Ok(WalletConfig {
                version: 2,
                wallets: Vec::new(),
                networks: default_networks(),
            });
        }
        let reader = BufReader::new(
            File::open(&self.file)
                .with_context(|| format!("failed to open {}", self.file.display()))?,
        );
        let config: WalletConfig = serde_json::from_reader(reader)
            .with_context(|| format!("failed to parse {}", self.file.display()))?;
        validate_config(&config)?;
        Ok(config)
    }

    pub fn save(&self, config: &WalletConfig) -> Result<()> {
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
        set_private_file_permissions(&self.file)?;
        sync_parent(&self.data_dir)?;
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
        FileExt::unlock(&lock)
            .with_context(|| format!("failed to unlock {}", lock_path.display()))?;
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
        .join("Library/Application Support/org.ekubo.wallet-mcp"));
    #[cfg(target_os = "windows")]
    return Ok(base.data_local_dir().join("Ekubo/wallet-mcp"));
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    Ok(env::var_os("XDG_STATE_HOME")
        .map_or_else(|| base.home_dir().join(".local/state"), PathBuf::from)
        .join("ekubo-wallet-mcp"))
}

#[must_use]
pub fn default_networks() -> Vec<NetworkConfig> {
    vec![
        network(
            "ethereum",
            "Ethereum Mainnet",
            &["mainnet", "eth"],
            1,
            "https://ethereum-rpc.publicnode.com",
            "16777216",
            "Ether",
            "ETH",
            "https://etherscan.io",
            "https://chainlist.org/chain/1",
        ),
        network(
            "base",
            "Base",
            &["base-mainnet"],
            8453,
            "https://base.gateway.tenderly.co",
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
            "polygon",
            "Polygon Mainnet",
            &["polygon-mainnet", "polygon-pos", "matic"],
            137,
            "https://polygon.drpc.org",
            "32000000",
            "POL",
            "POL",
            "https://polygonscan.com",
            "https://docs.polygon.technology/pos/reference/rpc-endpoints",
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
        ensure!(
            wallet.exported_at.is_none() || wallet.custody == CustodyStatus::Exported,
            "wallet {} has an export timestamp without exported custody status",
            wallet.id
        );
    }
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

fn validate_network(network: &NetworkConfig) -> Result<()> {
    validate_network_identifier(&network.name, "network name")?;
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
        ensure!(limit > 0, "max gas limit must be positive");
    }
    if let Some(display_name) = &network.display_name {
        ensure!(
            !display_name.trim().is_empty()
                && display_name.len() <= 128
                && !display_name.chars().any(char::is_control),
            "network display name must contain 1-128 printable characters"
        );
    }
    if let Some(currency) = &network.native_currency {
        ensure!(
            !currency.name.trim().is_empty()
                && currency.name.len() <= 64
                && !currency.name.chars().any(char::is_control),
            "native currency name must contain 1-64 printable characters"
        );
        ensure!(
            !currency.symbol.trim().is_empty()
                && currency.symbol.len() <= 32
                && !currency.symbol.chars().any(char::is_control),
            "native currency symbol must contain 1-32 printable characters"
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

/// Replace a network with the same canonical name, while rejecting chain-ID
/// or identifier collisions with every other configured network.
pub fn replace_configured_network(
    networks: &mut Vec<NetworkConfig>,
    next: NetworkConfig,
) -> Result<()> {
    validate_network(&next)?;
    if let Some(existing) = networks
        .iter()
        .find(|network| network.name != next.name && network.chain_id == next.chain_id)
    {
        bail!(
            "chain {} is already configured as {}; remove it before adding {}",
            next.chain_id,
            existing.name,
            next.name
        );
    }
    let identifiers = std::iter::once(&next.name)
        .chain(next.aliases.iter())
        .collect::<BTreeSet<_>>();
    if let Some(existing) = networks.iter().find(|network| {
        network.name != next.name
            && std::iter::once(&network.name)
                .chain(network.aliases.iter())
                .any(|identifier| identifiers.contains(identifier))
    }) {
        bail!(
            "network name or alias conflicts with configured network {}",
            existing.name
        );
    }
    networks.retain(|network| network.name != next.name);
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

fn legacy_custody_status() -> CustodyStatus {
    CustodyStatus::ExternallyKnown
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    let _ = path;
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_networks_have_unique_chain_ids_and_identifiers() {
        validate_config(&WalletConfig {
            version: 2,
            wallets: vec![],
            networks: default_networks(),
        })
        .unwrap();
    }

    #[test]
    fn round_trips_private_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(directory.path());
        let config = store.load().unwrap();
        store.save(&config).unwrap();
        assert_eq!(store.load().unwrap(), config);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(store.file()).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn cli_replacement_is_name_scoped_and_rejects_cross_network_collisions() {
        let mut networks = default_networks();
        let mut ethereum = networks
            .iter()
            .find(|network| network.name == "ethereum")
            .unwrap()
            .clone();
        ethereum.rpc_url = "https://rpc.example.invalid".parse().unwrap();
        replace_configured_network(&mut networks, ethereum.clone()).unwrap();
        assert_eq!(
            networks
                .iter()
                .find(|network| network.name == "ethereum")
                .unwrap()
                .rpc_url,
            ethereum.rpc_url
        );

        let mut conflicting = ethereum;
        conflicting.name = "custom".into();
        assert!(replace_configured_network(&mut networks, conflicting).is_err());
        assert_eq!(
            remove_configured_network(&mut networks, "eth")
                .unwrap()
                .name,
            "ethereum"
        );
    }

    #[test]
    fn network_identifiers_cannot_inject_terminal_or_completion_controls() {
        let mut candidate = default_networks().remove(0);
        candidate.aliases.push("bad\nvalue".into());
        assert!(validate_network(&candidate).is_err());
    }
}
