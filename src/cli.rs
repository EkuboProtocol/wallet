use crate::{
    VERSION,
    address_book::AddressBookStore,
    approval::{ApprovalDecision, ApprovalKind, ApprovalRequest, ApprovalUi, TerminalApprovalUi},
    approval_summary::{
        TokenMetadataMap, interpret_steps, plan_token_metadata, render_balance_changes,
    },
    config::{
        ConfigStore, NativeCurrency, NetworkConfig, default_networks, remove_configured_network,
        replace_configured_network,
    },
    core::policy::{FindingSeverity, WalletPolicy},
    custody::{CustodyService, KeyStore, OsKeyStore, PrivateKeyMaterial},
    execution::{PreparedExecution, SigningOverrides, prepare_execution, sign_prepared_execution},
    human_presence::{HumanPresence, PlatformHumanPresence, PresenceAction, PresenceRequest},
    legal::{self, LegalDocument, LegalStore},
    pending::{PendingStatus, PendingStore, PendingTransaction},
    policy_store::PolicyStore,
    rpc::verify_chain_id,
    simulation::{SimulationResult, simulate_execution},
    typed_data::{
        PendingTypedData, TypedDataStatus, TypedDataStore, interpret_permit_approvals,
        parse_typed_data,
    },
};
use alloy::{primitives::Address, signers::SignerSync};
use anyhow::{Context, Result, ensure};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use directories::BaseDirs;
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};
use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use tempfile::NamedTempFile;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Parser)]
#[command(
    name = "ekubo-wallet",
    version = VERSION,
    about = "Policy-enforced local EVM wallet and MCP server"
)]
pub struct Cli {
    /// Override the platform data directory.
    #[arg(long, global = true, env = "EKUBO_WALLET_HOME")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the stdio MCP server.
    Server,
    /// Print the server version.
    Version,
    /// Manage local wallets.
    Wallet(WalletArgs),
    /// List configured EVM networks.
    Network(Box<NetworkArgs>),
    /// Set and inspect local wallet policies.
    Policy(PolicyArgs),
    /// Inspect transactions signed or broadcast by this wallet server.
    #[command(alias = "tx")]
    Transaction(TransactionArgs),
    /// Inspect the local token database.
    Token(TokenArgs),
    /// Manage per-chain address aliases used for agent lookups.
    #[command(name = "address-book")]
    AddressBook(AddressBookArgs),
    /// Read legal documents and record their acceptance.
    Legal(LegalArgs),
    /// List exceptional requests, or review and sign one locally.
    Approve {
        request_id: Option<Uuid>,
        /// Skip the terminal yes/no prompt; platform owner authentication is still required.
        #[arg(long)]
        no_confirm: bool,
    },
    /// List exceptional requests, or reject one locally.
    Reject { request_id: Option<Uuid> },
    /// Print a shell completion script, including local dynamic candidates.
    Completion { shell: Shell },
    /// Print dynamic completion candidates.
    #[command(name = "__complete", hide = true)]
    Complete { value_kind: String },
    /// Configure a supported agent integration.
    #[command(name = "__configure-agent", hide = true)]
    ConfigureAgent(ConfigureAgentArgs),
}

#[derive(Debug, Args)]
struct WalletArgs {
    #[command(subcommand)]
    command: WalletCommand,
}

#[derive(Debug, Subcommand)]
enum WalletCommand {
    /// List wallet metadata. Never returns private keys.
    List,
    /// Generate a new key directly in the platform credential store.
    Create { wallet_id: String },
    /// Import an existing private key from a hidden interactive prompt.
    Import { wallet_id: String },
    /// Export a private key after terminal confirmation and owner authentication.
    Export { wallet_id: String },
    /// Remove a wallet and key after terminal confirmation and owner authentication.
    Remove { wallet_id: String },
}

#[derive(Debug, Args)]
struct NetworkArgs {
    #[command(subcommand)]
    command: NetworkCommand,
}

#[derive(Debug, Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Print the active encrypted policy and revision.
    Show { wallet_id: String },
    /// Replace a wallet policy from a JSON file after owner authentication.
    Set {
        wallet_id: String,
        policy_file: PathBuf,
    },
    /// Install the wildcard automatic policy after owner authentication.
    AllowAll { wallet_id: String },
    /// Install the policy that queues every transaction for explicit approval.
    RequireApproval { wallet_id: String },
    /// Parse and summarize a policy file without changing any wallet.
    Validate { policy_file: PathBuf },
    /// Print the JSON Schema describing a policy document.
    Schema,
}

#[derive(Debug, Subcommand)]
enum NetworkCommand {
    /// List configured networks, including their complete RPC URLs.
    List,
    /// Print the built-in public network presets.
    Presets,
    /// Replace configured networks with the built-in presets.
    Reset,
    /// Add or update a preset, or configure a complete custom network.
    Add(Box<NetworkAddArgs>),
    /// Remove a configured network by name or alias.
    #[command(alias = "delete")]
    Remove { name: String },
}

#[derive(Debug, Args)]
struct NetworkAddArgs {
    name: String,
    chain_id: Option<u64>,
    #[arg(long)]
    rpc_url: Option<Url>,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long = "alias")]
    aliases: Vec<String>,
    #[arg(long)]
    native_currency_name: Option<String>,
    #[arg(long)]
    native_currency_symbol: Option<String>,
    #[arg(long)]
    native_currency_decimals: Option<u8>,
    #[arg(long)]
    max_gas_limit: Option<String>,
    #[arg(long)]
    block_explorer_url: Option<Url>,
    #[arg(long)]
    documentation_url: Option<Url>,
}

#[derive(Debug, Args)]
struct ConfigureAgentArgs {
    #[command(subcommand)]
    command: ConfigureAgentCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigureAgentCommand {
    /// Add this server to ~/.cursor/mcp.json without replacing other entries.
    Cursor {
        server_command: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        server_args: Vec<String>,
    },
}

#[derive(Debug, Args)]
struct TransactionArgs {
    #[command(subcommand)]
    command: TransactionCommand,
}

#[derive(Debug, Args)]
struct TokenArgs {
    #[command(subcommand)]
    command: TokenCommand,
}

#[derive(Debug, Args)]
struct AddressBookArgs {
    #[command(subcommand)]
    command: AddressBookCommand,
}

#[derive(Debug, Subcommand)]
enum AddressBookCommand {
    /// Print address book entries as JSON, optionally scoped to one network.
    List {
        /// Network name, alias, or decimal chain ID.
        network: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Add or update one alias after owner authentication.
    Add {
        /// Network name, alias, or decimal chain ID.
        network: String,
        alias: String,
        address: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Remove one alias after owner authentication.
    #[command(alias = "delete")]
    Remove {
        /// Network name, alias, or decimal chain ID.
        network: String,
        alias: String,
    },
}

#[derive(Debug, Args)]
struct LegalArgs {
    #[command(subcommand)]
    command: LegalCommand,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum LegalDocumentArg {
    Terms,
    Privacy,
    Licenses,
}

impl LegalDocumentArg {
    const fn document(self) -> LegalDocument {
        match self {
            Self::Terms => LegalDocument::TermsOfService,
            Self::Privacy => LegalDocument::PrivacyPolicy,
            Self::Licenses => LegalDocument::ThirdPartyLicenses,
        }
    }
}

#[derive(Debug, Subcommand)]
enum LegalCommand {
    /// Print acceptance status for the terms of service and privacy policy.
    Status,
    /// Print the complete text of one legal document.
    Show { document: LegalDocumentArg },
    /// Review and accept the terms of service and privacy policy.
    ///
    /// Each document is acknowledged separately. Signing (transactions and
    /// typed data) stays disabled until both are accepted.
    Accept,
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    /// Print stored tokens as JSON, optionally filtered by decimal chain ID.
    List {
        chain_id: Option<u64>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
}

#[derive(Debug, Subcommand)]
enum TransactionCommand {
    /// Print recorded transaction lifecycle rows as JSON.
    List {
        wallet_id: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u16,
    },
    /// Print one row, including exact signed bytes, by request ID or transaction hash.
    Show { identifier: String },
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        let config = match self.data_dir {
            Some(path) => ConfigStore::new(path),
            None => ConfigStore::production()?,
        };
        match self.command {
            Command::Server => crate::mcp::serve(config).await,
            Command::Version => {
                println!("ekubo-wallet {VERSION}");
                Ok(())
            }
            Command::Wallet(args) => run_wallet(config, args.command).await,
            Command::Network(args) => run_network(&config, args.command).await,
            Command::Policy(args) => run_policy(config, args.command).await,
            Command::Transaction(args) => run_transaction(&config, args.command),
            Command::Token(args) => run_token(&config, &args.command),
            Command::AddressBook(args) => run_address_book(&config, args.command).await,
            Command::Legal(args) => run_legal(&config, &args.command),
            Command::Approve {
                request_id,
                no_confirm,
            } => run_approve(&config, request_id, no_confirm).await,
            Command::Reject { request_id } => run_reject(&config, request_id),
            Command::Completion { shell } => print_completion_script(shell),
            Command::Complete { value_kind } => print_completion_values(&config, &value_kind),
            Command::ConfigureAgent(args) => run_configure_agent(args.command),
        }
    }
}

async fn run_wallet(config: ConfigStore, command: WalletCommand) -> Result<()> {
    let custody = CustodyService::new(
        config.clone(),
        Arc::new(OsKeyStore),
        Arc::new(PlatformHumanPresence),
    );
    match command {
        WalletCommand::List => print_json(&config.load()?.wallets),
        WalletCommand::Create { wallet_id } => {
            // A freshly generated key holds nothing until the user funds it,
            // so the automatic profile is a safe starting point; the README
            // still directs replacing it before funding.
            let wallet = custody.create(&wallet_id)?;
            initialize_wallet_policy(&config, &wallet.id, &WalletPolicy::allow_all_with_approval())
                .with_context(|| {
                    format!(
                        "wallet {} was created but policy initialization failed; signing will fail closed",
                        wallet.id
                    )
                })?;
            print_json(&wallet)
        }
        WalletCommand::Import { wallet_id } => {
            require_interactive("wallet import")?;
            cliclack::intro("Import an existing wallet")?;
            let mut input = cliclack::password("Private key")
                .mask('•')
                .interact()
                .context("failed to read private key")?;
            let key = PrivateKeyMaterial::from_hex(&input)?;
            input.zeroize();

            let progress = cliclack::spinner();
            progress.start("Saving the key in the platform credential store");
            let result = custody.import(&wallet_id, key);
            match result {
                Ok(wallet) => {
                    // An imported key usually already controls funds, so
                    // nothing signs automatically until the user deliberately
                    // installs a more permissive policy.
                    initialize_wallet_policy(
                        &config,
                        &wallet.id,
                        &WalletPolicy::require_approval_for_everything(),
                    )
                    .with_context(|| {
                        format!(
                            "wallet {} was imported but policy initialization failed; signing will fail closed",
                            wallet.id
                        )
                    })?;
                    progress.stop("Wallet imported");
                    cliclack::outro(
                        "Imported wallets start with the require-approval policy: nothing signs \
                         automatically until you install a more permissive policy.",
                    )?;
                    print_json(&wallet)
                }
                Err(error) => {
                    progress.error("Wallet import failed");
                    Err(error)
                }
            }
        }
        WalletCommand::Export { wallet_id } => {
            let wallet = config.wallet(&wallet_id)?;
            require_approval(
                ApprovalRequest::new(
                    ApprovalKind::ExportPrivateKey,
                    "Export private key",
                    "Reveal the raw private key for this wallet.",
                )
                .fact("Wallet", &wallet.id)
                .fact("Address", format!("{:#x}", wallet.address))
                .warning(
                    "Export permanently ends the wallet's exclusive-policy guarantee. Anyone with the key can bypass this service.",
                ),
            )
            .await?;

            let progress = cliclack::spinner();
            progress.start("Waiting for owner authentication");
            let result = custody.export(&wallet_id).await;
            let key = match result {
                Ok(key) => {
                    progress.stop("Owner authenticated; custody state updated");
                    key
                }
                Err(error) => {
                    progress.error("Private key export failed");
                    return Err(error);
                }
            };
            let mut stdout = io::stdout().lock();
            stdout.write_all(key.as_bytes())?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
            Ok(())
        }
        WalletCommand::Remove { wallet_id } => {
            let wallet = config.wallet(&wallet_id)?;
            require_approval(
                ApprovalRequest::new(
                    ApprovalKind::RemoveWallet,
                    "Remove wallet",
                    "Delete this wallet's platform credential and local metadata.",
                )
                .fact("Wallet", &wallet.id)
                .fact("Address", format!("{:#x}", wallet.address))
                .warning("This operation cannot be undone unless a separate key backup exists."),
            )
            .await?;

            let progress = cliclack::spinner();
            progress.start("Waiting for owner authentication");
            let result = custody.remove(&wallet_id).await;
            match result {
                Ok(wallet) => {
                    let mut policies = PolicyStore::production(config.data_dir())?;
                    if let Some(policy) = policies.get(&wallet.id)? {
                        policies.delete(&wallet.id, policy.revision)?;
                    }
                    progress.stop("Wallet removed");
                    print_json(&wallet)
                }
                Err(error) => {
                    progress.error("Wallet removal failed");
                    Err(error)
                }
            }
        }
    }
}

fn initialize_wallet_policy(
    config: &ConfigStore,
    wallet_id: &str,
    policy: &WalletPolicy,
) -> Result<()> {
    let mut policies = PolicyStore::production(config.data_dir())?;
    ensure!(
        policies.get(wallet_id)?.is_none(),
        "policy state already exists for wallet {wallet_id}"
    );
    policies.put(wallet_id, policy, None)?;
    Ok(())
}

fn run_token(config: &ConfigStore, command: &TokenCommand) -> Result<()> {
    match command {
        TokenCommand::List {
            chain_id,
            limit,
            offset,
        } => {
            let (chain_id, limit, offset) = (*chain_id, *limit, *offset);
            let store = crate::token_store::TokenStore::production(config.data_dir())?;
            print_json(&serde_json::json!({
                "total": store.count(chain_id)?,
                "tokens": store.list(chain_id, limit, offset)?,
            }))
        }
    }
}

/// Resolve a network by name, alias, or canonical decimal chain ID.
fn resolve_network(config: &ConfigStore, requested: &str) -> Result<NetworkConfig> {
    if !requested.is_empty() && requested.bytes().all(|byte| byte.is_ascii_digit()) {
        config.network_by_chain_id(requested)
    } else {
        config.network(requested)
    }
}

async fn run_address_book(config: &ConfigStore, command: AddressBookCommand) -> Result<()> {
    match command {
        AddressBookCommand::List {
            network,
            limit,
            offset,
        } => {
            let chain_id = network
                .as_deref()
                .map(|requested| resolve_network(config, requested))
                .transpose()?
                .map(|network| network.chain_id);
            let store = AddressBookStore::production(config.data_dir())?;
            print_json(&serde_json::json!({
                "total": store.count(chain_id)?,
                "entries": store.list(chain_id, limit, offset)?,
            }))
        }
        AddressBookCommand::Add {
            network,
            alias,
            address,
            note,
        } => {
            require_interactive("address book changes")?;
            crate::address_book::validate_alias(&alias)?;
            let network = resolve_network(config, &network)?;
            let address =
                Address::from_str(&address).context("address must be a 20-byte EVM address")?;
            let existing =
                AddressBookStore::production(config.data_dir())?.get(network.chain_id, &alias)?;
            let digest = configuration_digest(&serde_json::json!({
                "operation": "upsert",
                "chain_id": network.chain_id.to_string(),
                "alias": alias,
                "address": format!("{address:#x}"),
                "note": note,
            }))?;
            let mut request = ApprovalRequest::new(
                ApprovalKind::AddressBookChange,
                "Add address book entry",
                "Store this alias for agent lookups. Aliases carry no signing authority, but an \
                 agent will resolve payments to this address when the user names the alias.",
            )
            .fact("Network", &network.name)
            .fact("Chain ID", network.chain_id.to_string())
            .fact("Alias", &alias)
            .fact("Address", address.to_checksum(None))
            .digest(&digest);
            if let Some(note) = &note {
                request = request.fact("Note", note);
            }
            if let Some(existing) = &existing {
                request = request.warning(format!(
                    "This replaces the existing entry for {alias}, currently {}.",
                    existing.address
                ));
            }
            require_approval(request).await?;
            PlatformHumanPresence
                .confirm(&PresenceRequest {
                    action: PresenceAction::ModifyAddressBook,
                    wallet_id: format!("alias {alias} on chain {}", network.chain_id),
                    operation_digest: Some(digest),
                })
                .await?;
            let entry = AddressBookStore::production(config.data_dir())?.upsert(
                network.chain_id,
                &alias,
                address,
                note.as_deref(),
            )?;
            print_json(&entry)
        }
        AddressBookCommand::Remove { network, alias } => {
            require_interactive("address book changes")?;
            let network = resolve_network(config, &network)?;
            let existing = AddressBookStore::production(config.data_dir())?
                .get(network.chain_id, &alias)?
                .with_context(|| {
                    format!(
                        "no address book entry {alias} on chain {}",
                        network.chain_id
                    )
                })?;
            let digest = configuration_digest(&serde_json::json!({
                "operation": "remove",
                "chain_id": network.chain_id.to_string(),
                "alias": alias,
                "address": existing.address,
            }))?;
            require_approval(
                ApprovalRequest::new(
                    ApprovalKind::AddressBookChange,
                    "Remove address book entry",
                    "Remove this alias from agent lookups.",
                )
                .fact("Network", &network.name)
                .fact("Chain ID", network.chain_id.to_string())
                .fact("Alias", &alias)
                .fact("Address", &existing.address)
                .digest(&digest),
            )
            .await?;
            PlatformHumanPresence
                .confirm(&PresenceRequest {
                    action: PresenceAction::ModifyAddressBook,
                    wallet_id: format!("alias {alias} on chain {}", network.chain_id),
                    operation_digest: Some(digest),
                })
                .await?;
            let removed = AddressBookStore::production(config.data_dir())?
                .remove(network.chain_id, &alias)?;
            print_json(&serde_json::json!({
                "removed": removed,
            }))
        }
    }
}

fn run_legal(config: &ConfigStore, command: &LegalCommand) -> Result<()> {
    let store = LegalStore::new(config.data_dir());
    match command {
        LegalCommand::Status => print_json(&store.status()?),
        LegalCommand::Show { document } => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(document.document().text().as_bytes())?;
            stdout.flush()?;
            Ok(())
        }
        LegalCommand::Accept => {
            require_interactive("legal acceptance")?;
            let accept = |document: LegalDocument, prompt: &str| -> Result<bool> {
                let text = document.text();
                let digest = document.digest();
                cliclack::note(document.title(), terminal_note_safe(&text))?;
                cliclack::log::info(format!("Document digest: {digest}"))?;
                let accepted = cliclack::confirm(prompt).initial_value(false).interact()?;
                if accepted {
                    store.record_acceptance(document, &digest)?;
                }
                Ok(accepted)
            };
            cliclack::intro("Ekubo Wallet legal acceptance")?;
            ensure!(
                accept(
                    LegalDocument::TermsOfService,
                    "Do you accept these Terms of Service?",
                )?,
                "the Terms of Service were not accepted; signing stays disabled"
            );
            ensure!(
                accept(
                    LegalDocument::PrivacyPolicy,
                    "Do you separately acknowledge this Privacy Policy?",
                )?,
                "the Privacy Policy was not acknowledged; signing stays disabled"
            );
            cliclack::outro("Recorded. Signing is now enabled for this installation.")?;
            print_json(&store.status()?)
        }
    }
}

/// Legal texts are trusted compile-time strings, but they pass through the
/// same control-character stripping as every other terminal output.
fn terminal_note_safe(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() && character != '\n' {
                ' '
            } else {
                character
            }
        })
        .collect()
}

async fn run_policy(config: ConfigStore, command: PolicyCommand) -> Result<()> {
    match command {
        PolicyCommand::Show { wallet_id } => {
            config.wallet(&wallet_id)?;
            let stored = PolicyStore::production(config.data_dir())?
                .get(&wallet_id)?
                .with_context(|| format!("wallet {wallet_id} has no local policy"))?;
            print_json(&serde_json::json!({
                "wallet_id": stored.wallet_id,
                "revision": stored.revision,
                "updated_at": stored.updated_at,
                "policy": stored.policy,
            }))
        }
        PolicyCommand::Set {
            wallet_id,
            policy_file,
        } => {
            let bytes = fs::read(&policy_file)
                .with_context(|| format!("failed to read {}", policy_file.display()))?;
            let value = serde_json::from_slice(&bytes)
                .with_context(|| format!("failed to parse {}", policy_file.display()))?;
            let policy = WalletPolicy::parse(value)?;
            replace_policy(&config, &wallet_id, policy, Some(&policy_file)).await
        }
        PolicyCommand::AllowAll { wallet_id } => {
            replace_policy(
                &config,
                &wallet_id,
                WalletPolicy::allow_all_with_approval(),
                None,
            )
            .await
        }
        PolicyCommand::RequireApproval { wallet_id } => {
            replace_policy(
                &config,
                &wallet_id,
                WalletPolicy::require_approval_for_everything(),
                None,
            )
            .await
        }
        // Validation reads a file and writes nothing, so it needs neither a
        // configured wallet, the encrypted database, nor owner authentication.
        PolicyCommand::Validate { policy_file } => {
            let bytes = fs::read(&policy_file)
                .with_context(|| format!("failed to read {}", policy_file.display()))?;
            let value = serde_json::from_slice(&bytes)
                .with_context(|| format!("failed to parse {}", policy_file.display()))?;
            let policy = WalletPolicy::parse(value)?;
            let canonical = serde_json::to_vec(&policy)?;
            print_json(&serde_json::json!({
                "valid": true,
                "policy_file": policy_file.display().to_string(),
                "digest": format!("0x{}", hex::encode(Keccak256::digest(&canonical))),
                "version": policy.version,
                "require_simulation": policy.require_simulation,
                "approval_expiry_seconds": policy.approval_expiry_seconds,
                "chains": policy.chains.keys().collect::<Vec<_>>(),
                "policy": policy,
            }))
        }
        PolicyCommand::Schema => print_json(&policy_json_schema()),
    }
}

/// The schema is derived from the same types the wallet enforces, so a document
/// that validates here cannot drift from what `policy set` will accept.
fn policy_json_schema() -> serde_json::Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(WalletPolicy))
        .expect("policy schema serializes");
    if let Some(object) = schema.as_object_mut() {
        object.insert(
            "title".into(),
            serde_json::Value::String("Ekubo Wallet policy".into()),
        );
        object.insert(
            "description".into(),
            serde_json::Value::String(
                "Stateless per-transaction signing policy. Amounts are decimal strings in the \
                 asset's smallest unit. There are no daily limits, rolling windows, or spend \
                 counters."
                    .into(),
            ),
        );
    }
    schema
}

fn run_transaction(config: &ConfigStore, command: TransactionCommand) -> Result<()> {
    let pending = PendingStore::production(config.data_dir())?;
    match command {
        TransactionCommand::List { wallet_id, limit } => {
            if let Some(wallet_id) = wallet_id.as_deref() {
                config.wallet(wallet_id)?;
            }
            print_json(&serde_json::json!({
                "transactions": pending.list(wallet_id.as_deref(), limit)?,
            }))
        }
        TransactionCommand::Show { identifier } => {
            print_json(&pending.get_by_identifier(&identifier)?)
        }
    }
}

fn list_pending_approvals(config: &ConfigStore) -> Result<()> {
    let pending = PendingStore::production(config.data_dir())?;
    let awaiting = pending.awaiting_approval(None)?;
    let awaiting_typed_data =
        TypedDataStore::production(config.data_dir())?.awaiting_approval(None)?;
    if awaiting.is_empty() && awaiting_typed_data.is_empty() {
        eprintln!("No requests are awaiting approval.");
    } else {
        eprintln!(
            "{} request(s) awaiting approval. Review one with `ekubo-wallet approve <request-id>`; \
             unapproved requests expire at their listed expires_at.",
            awaiting.len() + awaiting_typed_data.len()
        );
    }
    print_json(&serde_json::json!({
        "pending_approvals": awaiting,
        "pending_typed_data": awaiting_typed_data,
    }))
}

fn run_reject(config: &ConfigStore, request_id: Option<Uuid>) -> Result<()> {
    let Some(request_id) = request_id else {
        return list_pending_approvals(config);
    };
    let request = match PendingStore::production(config.data_dir())?.reject(request_id) {
        Ok(request) => request,
        Err(transaction_error) => {
            let mut typed_data = TypedDataStore::production(config.data_dir())?;
            let Ok(request) = typed_data.reject(request_id) else {
                return Err(transaction_error);
            };
            eprintln!(
                "Rejected. An MCP agent waiting on this typed-data request sees the rejection \
                 automatically."
            );
            return print_json(&serde_json::json!({
                "rejected": request.request_id,
                "digest": request.digest,
                "rejected_at": request.rejected_at,
            }));
        }
    };
    eprintln!("Rejected. An MCP agent waiting on this request sees the rejection automatically.");
    print_json(&serde_json::json!({
        "rejected": request.request_id,
        "digest": request.digest,
        "rejected_at": request.rejected_at,
    }))
}

async fn run_approve(
    config: &ConfigStore,
    request_id: Option<Uuid>,
    no_confirm: bool,
) -> Result<()> {
    let Some(request_id) = request_id else {
        return list_pending_approvals(config);
    };
    require_interactive("transaction approval")?;
    legal::require_current_acceptance(config.data_dir())?;
    let mut pending = PendingStore::production(config.data_dir())?;
    let request = match pending.get(request_id) {
        Ok(request) => request,
        Err(transaction_error) => {
            drop(pending);
            let typed_data = TypedDataStore::production(config.data_dir())?;
            let Ok(request) = typed_data.get(request_id) else {
                return Err(transaction_error);
            };
            return approve_typed_data(config, typed_data, request, no_confirm).await;
        }
    };
    ensure!(
        request.approval_required,
        "transaction did not require approval"
    );
    ensure!(
        request.status == PendingStatus::AwaitingApproval,
        "pending request is not awaiting approval"
    );
    let wallet = config.wallet(&request.wallet_id)?;
    let network = config.network(&request.network_name)?;
    ensure!(
        network.chain_id.to_string() == request.chain_id,
        "pending request network chain changed"
    );
    ensure!(
        request.execution_plan.sender == wallet.address,
        "pending request sender no longer matches wallet"
    );
    let stored_policy = PolicyStore::production(config.data_dir())?
        .get(&wallet.id)?
        .with_context(|| format!("wallet {} has no local policy", wallet.id))?;
    ensure!(
        stored_policy.revision == request.policy_revision,
        "active policy changed while approval was pending"
    );

    let simulation =
        simulate_execution(&wallet, &network, &request.execution_plan, &stored_policy).await?;
    let overrides = SigningOverrides {
        allow_policy_override: true,
        allow_simulation_failure: true,
    };
    let prepared = prepare_execution(
        &wallet,
        &network,
        &request.execution_plan,
        &simulation,
        overrides,
    )
    .await?;
    // Display metadata only. A failed or slow lookup degrades the review text to
    // exact base units; it never blocks or alters the approval decision.
    let token_metadata = plan_token_metadata(&network, &request.execution_plan.ordered_steps).await;
    let approval =
        transaction_approval_request(&request, &simulation, &prepared, &network, &token_metadata)?;
    print_approval_review(&approval, &simulation)?;
    if !no_confirm {
        require_approval(approval).await?;
    }

    let review_digest = prepared.review_digest();
    PlatformHumanPresence
        .confirm(&PresenceRequest {
            action: PresenceAction::ApprovePolicyException,
            wallet_id: wallet.id.clone(),
            operation_digest: Some(review_digest.clone()),
        })
        .await?;

    // Re-read all mutable local authority after the potentially long human
    // review. Signing below is synchronous and performs no RPC requests. The
    // final SQL write repeats the pending/policy checks atomically, so a race
    // cannot put a stale signature into the submission queue.
    let current = pending.get(request_id)?;
    ensure!(
        current.status == PendingStatus::AwaitingApproval,
        "pending request changed during approval"
    );
    ensure!(
        current.digest == request.digest,
        "pending request digest changed during approval"
    );
    ensure!(
        config.wallet(&request.wallet_id)? == wallet,
        "wallet configuration changed during approval"
    );
    ensure!(
        config.network(&request.network_name)? == network,
        "network configuration changed during approval"
    );
    let current_policy = PolicyStore::production(config.data_dir())?
        .get(&wallet.id)?
        .with_context(|| format!("wallet {} has no local policy", wallet.id))?;
    ensure!(
        current_policy.revision == request.policy_revision
            && current_policy.policy == stored_policy.policy,
        "active policy changed during approval"
    );
    ensure!(
        prepared.review_digest() == review_digest,
        "prepared transaction changed during approval"
    );
    let signed = sign_prepared_execution(
        &wallet,
        &network,
        &request.execution_plan,
        &simulation,
        &prepared,
        &OsKeyStore,
        overrides,
    )?;
    let approved = pending.store_signed(
        request_id,
        &request.digest,
        &review_digest,
        &signed.serialized_transaction,
        &signed.transaction_hash,
    )?;
    eprintln!(
        "Approved and signed. An MCP agent waiting on this request detects the approval and \
         submits automatically; nothing further is needed here."
    );
    print_json(&serde_json::json!({
        "approved": approved.request_id,
        "digest": approved.digest,
        "transaction_hash": approved.signed_transaction_hash,
        "approved_at": approved.approved_at,
    }))
}

async fn approve_typed_data(
    config: &ConfigStore,
    mut store: TypedDataStore,
    request: PendingTypedData,
    no_confirm: bool,
) -> Result<()> {
    ensure!(
        request.status == TypedDataStatus::AwaitingApproval,
        "typed-data request is not awaiting approval"
    );
    let wallet = config.wallet(&request.wallet_id)?;
    config.network_by_chain_id(&request.chain_id)?;
    let (typed, chain_id, digest) = parse_typed_data(&request.typed_data)?;
    ensure!(
        chain_id.to_string() == request.chain_id && format!("{digest:#x}") == request.digest,
        "typed-data request no longer matches its stored payload"
    );
    let permit_approvals = interpret_permit_approvals(&typed, wallet.address)?;

    let mut approval = ApprovalRequest::new(
        ApprovalKind::TypedDataSignature,
        "Approve typed-data signature",
        "Review and sign this exact EIP-712 payload with the wallet key. The complete payload is \
         printed above this summary.",
    )
    .fact("Wallet", &request.wallet_id)
    .fact("Chain ID", &request.chain_id)
    .fact("Primary type", &typed.primary_type)
    .fact(
        "Domain",
        format!(
            "name={:?}; version={:?}; verifyingContract={}",
            typed.domain.name.as_deref().unwrap_or("<none>"),
            typed.domain.version.as_deref().unwrap_or("<none>"),
            typed
                .domain
                .verifying_contract
                .map_or_else(|| "<none>".into(), |contract| contract.to_checksum(None)),
        ),
    )
    .fact("Signing hash", &request.digest)
    .digest(&request.digest);
    approval.id = request.request_id;
    approval.expires_at = request.expires_at;

    if let Some(approvals) = &permit_approvals {
        for (index, permit) in approvals.iter().enumerate() {
            approval = approval.fact(
                format!("Grants approval {}", index + 1),
                format!(
                    "{}: allow {} to spend up to {} of token {}{}",
                    permit.kind,
                    permit.spender,
                    permit.amount,
                    permit.token,
                    permit
                        .deadline
                        .as_deref()
                        .map_or_else(String::new, |deadline| format!("; deadline {deadline}")),
                ),
            );
        }
        approval = approval.warning(
            "Signing grants the token approvals listed above; the active policy did not authorize \
             them automatically.",
        );
        let stored_policy = PolicyStore::production(config.data_dir())?
            .get(&wallet.id)?
            .with_context(|| format!("wallet {} has no local policy", wallet.id))?;
        let tuples = approvals
            .iter()
            .map(crate::typed_data::PermitApproval::tuple)
            .collect::<Result<Vec<_>>>()?;
        for finding in crate::core::policy::evaluate_permit_approvals(
            &stored_policy.policy,
            &request.chain_id,
            &tuples,
        ) {
            if finding.severity != FindingSeverity::Info {
                approval = approval.warning(format!("{}: {}", finding.code, finding.message));
            }
        }
    } else {
        approval = approval.warning(
            "This payload is not a recognized permit. A typed-data signature can authorize \
             transfers, orders, or delegations; verify every field of the printed payload.",
        );
    }

    let mut stderr = io::stderr().lock();
    serde_json::to_writer_pretty(
        &mut stderr,
        &serde_json::json!({
            "approval": approval,
            "typed_data": request.typed_data,
        }),
    )?;
    stderr.write_all(b"\n")?;
    stderr.flush()?;
    drop(stderr);
    if !no_confirm {
        require_approval(approval).await?;
    }

    PlatformHumanPresence
        .confirm(&PresenceRequest {
            action: PresenceAction::SignTypedData,
            wallet_id: wallet.id.clone(),
            operation_digest: Some(request.digest.clone()),
        })
        .await?;

    // Re-read mutable local authority after the potentially long human
    // review; the final SQL write repeats the pending checks atomically.
    let current = store.get(request.request_id)?;
    ensure!(
        current.status == TypedDataStatus::AwaitingApproval && current.digest == request.digest,
        "typed-data request changed during approval"
    );
    ensure!(
        config.wallet(&request.wallet_id)? == wallet,
        "wallet configuration changed during approval"
    );
    let material = OsKeyStore.load(&wallet.id)?;
    let signer = material.signer();
    ensure!(
        signer.address() == wallet.address,
        "credential-store private key does not match wallet metadata"
    );
    let signature = signer
        .sign_hash_sync(&digest)
        .context("failed to sign typed data")?;
    let stored = store.store_signature(
        request.request_id,
        &request.digest,
        &format!("0x{}", hex::encode(signature.as_bytes())),
    )?;
    eprintln!(
        "Approved and signed. An MCP agent waiting on this request reads the signature \
         automatically; nothing further is needed here."
    );
    print_json(&serde_json::json!({
        "approved": stored.request_id,
        "digest": stored.digest,
        "signature": stored.signature,
        "approved_at": stored.approved_at,
    }))
}

fn transaction_approval_request(
    pending: &PendingTransaction,
    simulation: &SimulationResult,
    prepared: &PreparedExecution,
    network: &NetworkConfig,
    token_metadata: &TokenMetadataMap,
) -> Result<ApprovalRequest> {
    let total_native = pending
        .execution_plan
        .ordered_steps
        .iter()
        .map(|step| BigUint::from_str(step.transaction.value.as_str()))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<BigUint>();
    let mut request = ApprovalRequest::new(
        ApprovalKind::PolicyException,
        "Approve policy exception",
        "Review and sign this exact execution plan despite policy or simulation findings.",
    )
    .fact("Wallet", &pending.wallet_id)
    .fact("Network", &pending.network_name)
    .fact("Chain ID", &pending.chain_id)
    .fact("Sender", format!("{:#x}", pending.execution_plan.sender))
    .fact(
        "Ordered calls",
        pending.execution_plan.ordered_steps.len().to_string(),
    )
    .fact("Total native value", total_native.to_string())
    .fact("Policy revision", pending.policy_revision.to_string())
    .fact("Plan digest", &pending.digest)
    .fact("Simulation parent block", &simulation.block_number)
    .fact("Transaction type", prepared.transaction_type())
    .fact("Transaction nonce", prepared.nonce().to_string())
    .fact("Gas limit", prepared.gas_limit().to_string())
    .fact(
        "Max fee per gas (wei)",
        prepared.max_fee_per_gas().to_string(),
    )
    .fact(
        "Max priority fee per gas (wei)",
        prepared.max_priority_fee_per_gas().to_string(),
    )
    .fact("Maximum transaction fee (wei)", prepared.maximum_fee_wei())
    .digest(prepared.review_digest());
    request.id = pending.request_id;
    request.expires_at = pending.expires_at;
    let interpretations = interpret_steps(&pending.execution_plan.ordered_steps, token_metadata);
    for (step, interpretation) in pending
        .execution_plan
        .ordered_steps
        .iter()
        .zip(&interpretations)
    {
        let calldata = step.transaction.data.as_ref();
        let selector = if calldata.is_empty() {
            "none".into()
        } else {
            format!("0x{}", hex::encode(&calldata[..calldata.len().min(4)]))
        };
        request = request.fact(
            format!("Call {}", step.step),
            format!(
                "kind={:?}; condition={:?}; target={:#x}; value={} wei; selector={selector}; calldata={} bytes",
                step.kind,
                step.submit_condition,
                step.transaction.to,
                step.transaction.value,
                calldata.len(),
            ),
        );
        // The exact fields above are authoritative; these lines are a
        // supplemental reading from a vendored ERC-7730 descriptor or from
        // recognized standard calldata.
        request = request.fact(
            format!("Call {} reads as", step.step),
            interpretation.description.clone().unwrap_or_else(|| {
                "no matching descriptor or standard token operation; verify the target and selector directly"
                    .into()
            }),
        );
        for detail in &interpretation.details {
            request = request.fact(format!("Call {} ·", step.step), detail);
        }
    }
    let balance_changes = render_balance_changes(simulation, network, token_metadata);
    if balance_changes.is_empty() {
        request = request.fact(
            "Simulated net balance changes",
            if simulation.simulation.success {
                "none detected"
            } else {
                "unavailable because simulation failed"
            },
        );
    } else {
        for (index, line) in balance_changes.iter().enumerate() {
            request = request.fact(
                if index == 0 {
                    "Simulated net balance change (excludes live gas)".to_string()
                } else {
                    format!("Simulated net balance change {}", index + 1)
                },
                line,
            );
        }
    }
    if let Some(authorization_nonce) = prepared.authorization_nonce() {
        request = request.fact(
            "EIP-7702 authorization",
            format!(
                "implementation={}; nonce={authorization_nonce}",
                simulation.implementation.as_deref().unwrap_or("missing")
            ),
        );
    }
    if let Some(replaced) = &simulation.replaces_delegated_implementation {
        request = request.warning(format!(
            "This replaces the wallet's current EIP-7702 delegation to {replaced}."
        ));
    }
    for warning in interpretations
        .iter()
        .flat_map(|interpretation| &interpretation.warnings)
    {
        request = request.warning(warning);
    }
    for finding in &simulation.policy_findings {
        if finding.severity != FindingSeverity::Info {
            request = request.warning(format!(
                "{}: {}{}",
                finding.code,
                finding.message,
                finding
                    .step
                    .map_or_else(String::new, |step| format!(" (step {step})"))
            ));
        }
    }
    if let Some(failure) = &simulation.simulation.failure {
        request = request.warning(format!(
            "Simulation {:?}: {} Recommended action: {:?}.",
            failure.category, failure.message, failure.recommended_action
        ));
    }
    Ok(request)
}

fn print_approval_review(approval: &ApprovalRequest, simulation: &SimulationResult) -> Result<()> {
    let mut stderr = io::stderr().lock();
    serde_json::to_writer_pretty(
        &mut stderr,
        &serde_json::json!({
            "approval": approval,
            "simulation": simulation,
        }),
    )?;
    stderr.write_all(b"\n")?;
    stderr.flush()?;
    Ok(())
}

async fn replace_policy(
    config: &ConfigStore,
    wallet_id: &str,
    policy: WalletPolicy,
    source: Option<&std::path::Path>,
) -> Result<()> {
    let wallet = config.wallet(wallet_id)?;
    require_interactive("policy changes")?;
    let mut policies = PolicyStore::production(config.data_dir())?;
    let current = policies.get(wallet_id)?;
    let policy_bytes = serde_json::to_vec(&policy)?;
    let digest = format!("0x{}", hex::encode(Keccak256::digest(&policy_bytes)));
    let mut request = ApprovalRequest::new(
        ApprovalKind::PolicyChange,
        "Replace wallet policy",
        "Replace the complete policy enforced before this wallet signs.",
    )
    .fact("Wallet", &wallet.id)
    .fact("Address", format!("{:#x}", wallet.address))
    .fact(
        "Current revision",
        current.as_ref().map_or_else(
            || "missing (fail-closed recovery)".into(),
            |value| value.revision.to_string(),
        ),
    )
    .fact("New policy digest", &digest)
    .digest(&digest)
    .warning(
        "A more permissive policy can authorize transactions without an exceptional approval.",
    );
    if let Some(source) = source {
        request = request.fact("Policy file", source.display().to_string());
    }
    if current.is_none() {
        request = request.warning(
            "This wallet currently has no policy, so server startup and signing fail closed. Approval will initialize revision 1.",
        );
    }
    require_approval(request).await?;
    PlatformHumanPresence
        .confirm(&PresenceRequest {
            action: PresenceAction::ChangePolicy,
            wallet_id: wallet_id.into(),
            operation_digest: Some(digest.clone()),
        })
        .await?;
    let stored = policies.put(
        wallet_id,
        &policy,
        current.as_ref().map(|value| value.revision),
    )?;
    print_json(&serde_json::json!({
        "wallet_id": wallet_id,
        "policy_version": stored.policy.version,
        "revision": stored.revision,
        "digest": digest,
    }))
}

async fn require_approval(request: ApprovalRequest) -> Result<()> {
    ensure!(
        TerminalApprovalUi.review(&request).await? == ApprovalDecision::Approved,
        "action rejected"
    );
    Ok(())
}

async fn run_network(config: &ConfigStore, command: NetworkCommand) -> Result<()> {
    match command {
        // The human CLI prints complete RPC URLs so the configuration can
        // actually be read back and edited. No MCP tool returns them.
        NetworkCommand::List => print_json(&describe_networks(&config.load()?.networks)),
        NetworkCommand::Presets => print_json(&serde_json::json!({
            "networks": describe_networks(&default_networks()),
        })),
        NetworkCommand::Reset => {
            let networks = default_networks();
            let digest = configuration_digest(&networks)?;
            authorize_network_change(
                "Reset network configuration",
                "Replace every configured RPC endpoint and network with the built-in public presets.",
                &digest,
                vec![("Networks", networks.len().to_string())],
            )
            .await?;
            config.update(|state| {
                state.networks.clone_from(&networks);
                Ok(())
            })?;
            print_json(&serde_json::json!({
                "reset": true,
                "networks": describe_networks(&networks),
            }))
        }
        NetworkCommand::Add(args) => {
            let candidate = network_candidate(*args)?;
            let mut prospective = config.load()?.networks;
            replace_configured_network(&mut prospective, candidate.clone())?;
            let digest = configuration_digest(&candidate)?;
            authorize_network_change(
                "Add or update network",
                "Trust this RPC to supply chain state and eth_simulateV1 execution for signing decisions.",
                &digest,
                vec![
                    ("Network", candidate.name.clone()),
                    ("Chain ID", candidate.chain_id.to_string()),
                    ("RPC origin", rpc_origin(&candidate.rpc_url)),
                ],
            )
            .await?;
            verify_chain_id(&candidate).await?;
            config.update(|state| {
                replace_configured_network(&mut state.networks, candidate.clone())
            })?;
            print_json(&serde_json::json!({
                "network": describe_network(&candidate),
                "rpc_verified": true,
            }))
        }
        NetworkCommand::Remove { name } => {
            let mut prospective = config.load()?.networks;
            let removed = remove_configured_network(&mut prospective, &name)?;
            let digest = configuration_digest(&serde_json::json!({
                "operation": "remove",
                "network": &removed,
            }))?;
            authorize_network_change(
                "Remove network",
                "Remove this network and RPC endpoint from the signing configuration.",
                &digest,
                vec![
                    ("Network", removed.name.clone()),
                    ("Chain ID", removed.chain_id.to_string()),
                ],
            )
            .await?;
            let removed =
                config.update(|state| remove_configured_network(&mut state.networks, &name))?;
            print_json(&serde_json::json!({
                "removed": removed.name,
                "chain_id": removed.chain_id.to_string(),
            }))
        }
    }
}

fn describe_networks(networks: &[NetworkConfig]) -> Vec<serde_json::Value> {
    networks.iter().map(describe_network).collect()
}

#[cfg(test)]
mod network_disclosure_tests {
    use super::*;

    #[test]
    fn cli_listing_round_trips_the_complete_configuration() {
        // The listing is how an operator reads back and edits configuration, so
        // it must reproduce the RPC URL exactly rather than an abbreviation.
        let mut network = default_networks().remove(0);
        network.rpc_url = "https://rpc.example.invalid:8545/v2/api-key-1234?token=abcd"
            .parse()
            .unwrap();
        let value = describe_network(&network);
        assert_eq!(value["rpc_url"].as_str(), Some(network.rpc_url.as_str()));
        assert_eq!(value["chain_id"].as_str(), Some("1"));
    }
}

fn describe_network(network: &NetworkConfig) -> serde_json::Value {
    serde_json::json!({
        "name": network.name,
        "display_name": network.display_name,
        "aliases": network.aliases,
        "chain_id": network.chain_id.to_string(),
        "rpc_url": network.rpc_url.as_str(),
        "max_gas_limit": network.max_gas_limit,
        "native_currency": network.native_currency,
        "block_explorer_url": network.block_explorer_url,
        "documentation_url": network.documentation_url,
    })
}

fn network_candidate(mut args: NetworkAddArgs) -> Result<NetworkConfig> {
    let preset = args
        .chain_id
        .is_none()
        .then(|| {
            default_networks().into_iter().find(|network| {
                network.name == args.name || network.aliases.iter().any(|alias| alias == &args.name)
            })
        })
        .flatten();
    ensure!(
        args.chain_id.is_some() || preset.is_some(),
        "unknown network preset {}; run `ekubo-wallet network presets` or provide a custom chain ID",
        args.name
    );

    if let Some(mut preset) = preset {
        if let Some(rpc_url) = args.rpc_url {
            preset.rpc_url = rpc_url;
        }
        if let Some(display_name) = args.display_name {
            preset.display_name = Some(display_name);
        }
        if !args.aliases.is_empty() {
            preset.aliases = normalize_aliases(args.aliases)?;
        }
        if let Some(maximum) = args.max_gas_limit {
            preset.max_gas_limit = Some(maximum);
        }
        if let Some(url) = args.block_explorer_url {
            preset.block_explorer_url = Some(url);
        }
        if let Some(url) = args.documentation_url {
            preset.documentation_url = Some(url);
        }
        if args.native_currency_name.is_some()
            || args.native_currency_symbol.is_some()
            || args.native_currency_decimals.is_some()
        {
            let mut currency = preset
                .native_currency
                .take()
                .context("preset has no native currency metadata")?;
            if let Some(name) = args.native_currency_name {
                currency.name = name;
            }
            if let Some(symbol) = args.native_currency_symbol {
                currency.symbol = symbol;
            }
            if let Some(decimals) = args.native_currency_decimals {
                currency.decimals = decimals;
            }
            preset.native_currency = Some(currency);
        }
        return Ok(preset);
    }

    let chain_id = args
        .chain_id
        .context("custom network requires a chain ID")?;
    ensure!(chain_id > 0, "network chain ID must be positive");
    let rpc_url = match args.rpc_url.take() {
        Some(url) => url,
        None => prompt_rpc_url()?,
    };
    let aliases = normalize_aliases(args.aliases)?;
    ensure!(
        !aliases.is_empty(),
        "custom network requires at least one --alias"
    );
    Ok(NetworkConfig {
        name: args.name,
        display_name: Some(
            args.display_name
                .context("custom network requires --display-name")?,
        ),
        aliases,
        chain_id,
        rpc_url,
        max_gas_limit: Some(
            args.max_gas_limit
                .context("custom network requires --max-gas-limit")?,
        ),
        native_currency: Some(NativeCurrency {
            name: args
                .native_currency_name
                .context("custom network requires --native-currency-name")?,
            symbol: args
                .native_currency_symbol
                .context("custom network requires --native-currency-symbol")?,
            decimals: args
                .native_currency_decimals
                .context("custom network requires --native-currency-decimals")?,
        }),
        block_explorer_url: Some(
            args.block_explorer_url
                .context("custom network requires --block-explorer-url")?,
        ),
        documentation_url: Some(
            args.documentation_url
                .context("custom network requires --documentation-url")?,
        ),
    })
}

fn normalize_aliases(aliases: Vec<String>) -> Result<Vec<String>> {
    let aliases = aliases
        .into_iter()
        .map(|alias| alias.trim().to_owned())
        .filter(|alias| !alias.is_empty())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    ensure!(
        aliases.iter().all(|alias| alias.len() <= 64),
        "network aliases must be at most 64 characters"
    );
    Ok(aliases)
}

fn prompt_rpc_url() -> Result<Url> {
    require_interactive("hidden RPC URL input")?;
    let mut input = cliclack::password("RPC URL")
        .mask('•')
        .interact()
        .context("failed to read RPC URL")?;
    let parsed = input.parse().context("RPC URL is invalid");
    input.zeroize();
    parsed
}

fn rpc_origin(url: &Url) -> String {
    let host = url.host_str().unwrap_or("<invalid-host>");
    url.port().map_or_else(
        || format!("{}://{host}", url.scheme()),
        |port| format!("{}://{host}:{port}", url.scheme()),
    )
}

fn configuration_digest(value: &impl serde::Serialize) -> Result<String> {
    Ok(format!(
        "0x{}",
        hex::encode(Keccak256::digest(serde_json::to_vec(value)?))
    ))
}

async fn authorize_network_change(
    title: &str,
    summary: &str,
    digest: &str,
    facts: Vec<(&str, String)>,
) -> Result<()> {
    require_interactive("network configuration changes")?;
    let mut request = ApprovalRequest::new(ApprovalKind::NetworkChange, title, summary)
        .digest(digest)
        .warning(
            "The configured RPC supplies state and eth_simulateV1 results used by automatic signing policy.",
        );
    for (label, value) in facts {
        request = request.fact(label, value);
    }
    require_approval(request).await?;
    PlatformHumanPresence
        .confirm(&PresenceRequest {
            action: PresenceAction::ChangeNetworkConfiguration,
            wallet_id: "network-configuration".into(),
            operation_digest: Some(digest.into()),
        })
        .await?;
    Ok(())
}

fn print_completion_values(config: &ConfigStore, requested: &str) -> Result<()> {
    let (kind, format) = requested.strip_suffix("-described").map_or_else(
        || {
            requested
                .strip_suffix("-fish")
                .map_or((requested, "plain"), |kind| (kind, "fish"))
        },
        |kind| (kind, "zsh"),
    );
    let candidates = match kind {
        "defaults" => default_networks()
            .into_iter()
            .map(|network| (network.name, format!("chain {}", network.chain_id)))
            .collect::<Vec<_>>(),
        "approvals" => {
            if config.data_dir().join("policies.db").exists() {
                let mut candidates = PendingStore::production(config.data_dir())?
                    .awaiting_approval(None)?
                    .into_iter()
                    .map(|request| {
                        (
                            request.request_id.to_string(),
                            format!("{} on chain {}", request.wallet_id, request.chain_id),
                        )
                    })
                    .collect::<Vec<_>>();
                candidates.extend(
                    TypedDataStore::production(config.data_dir())?
                        .awaiting_approval(None)?
                        .into_iter()
                        .map(|request| {
                            (
                                request.request_id.to_string(),
                                format!(
                                    "typed data for {} on chain {}",
                                    request.wallet_id, request.chain_id
                                ),
                            )
                        }),
                );
                candidates
            } else {
                Vec::new()
            }
        }
        "wallets" => config
            .load()?
            .wallets
            .into_iter()
            .map(|wallet| {
                (
                    wallet.id,
                    format!("{:#x} ({:?})", wallet.address, wallet.source),
                )
            })
            .collect(),
        "networks" => config
            .load()?
            .networks
            .into_iter()
            .map(|network| (network.name, format!("chain {}", network.chain_id)))
            .collect(),
        _ => anyhow::bail!("value kind must be wallets, networks, defaults, or approvals"),
    };
    let mut stdout = io::stdout().lock();
    for (value, description) in candidates {
        match format {
            "zsh" => writeln!(
                stdout,
                "{}:{}",
                completion_safe(&value),
                completion_safe(&description).replace(':', " ")
            )?,
            "fish" => writeln!(
                stdout,
                "{}\t{}",
                completion_safe(&value),
                completion_safe(&description)
            )?,
            _ => writeln!(stdout, "{}", completion_safe(&value))?,
        }
    }
    Ok(())
}

fn print_completion_script(shell: Shell) -> Result<()> {
    let packaged = match shell {
        Shell::Bash => Some(include_str!("../completions/ekubo-wallet.bash")),
        Shell::Zsh => Some(include_str!("../completions/_ekubo-wallet")),
        Shell::Fish => Some(include_str!("../completions/ekubo-wallet.fish")),
        _ => None,
    };
    let mut stdout = io::stdout().lock();
    if let Some(packaged) = packaged {
        stdout.write_all(packaged.as_bytes())?;
        return Ok(());
    }
    generate(shell, &mut Cli::command(), "ekubo-wallet", &mut stdout);
    Ok(())
}

fn completion_safe(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn run_configure_agent(command: ConfigureAgentCommand) -> Result<()> {
    match command {
        ConfigureAgentCommand::Cursor {
            server_command,
            server_args,
        } => {
            let file = configure_cursor_mcp(&server_command, &server_args)?;
            print_json(&serde_json::json!({
                "configured": "cursor",
                "file": file,
            }))
        }
    }
}

fn configure_cursor_mcp(server_command: &str, server_args: &[String]) -> Result<PathBuf> {
    ensure!(
        !server_command.trim().is_empty(),
        "server command cannot be empty"
    );
    let base = BaseDirs::new().context("could not determine the user home directory")?;
    configure_cursor_mcp_at(base.home_dir(), server_command, server_args)
}

fn configure_cursor_mcp_at(
    home: &Path,
    server_command: &str,
    server_args: &[String],
) -> Result<PathBuf> {
    let directory = home.join(".cursor");
    let file = directory.join("mcp.json");
    let mut document = if file.exists() {
        let value: serde_json::Value = serde_json::from_slice(
            &fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?,
        )
        .with_context(|| format!("failed to parse {}", file.display()))?;
        value
            .as_object()
            .cloned()
            .context("Cursor MCP configuration must be a JSON object")?
    } else {
        serde_json::Map::new()
    };
    let mut servers = match document.remove("mcpServers") {
        Some(value) => value
            .as_object()
            .cloned()
            .context("Cursor mcpServers must be a JSON object")?,
        None => serde_json::Map::new(),
    };
    servers.insert(
        "ekubo-wallet".into(),
        serde_json::json!({
            "command": server_command,
            "args": server_args,
        }),
    );
    document.insert("mcpServers".into(), servers.into());

    fs::create_dir_all(&directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;
    set_private_permissions(&directory, true)?;
    let mut temporary = NamedTempFile::new_in(&directory).with_context(|| {
        format!(
            "failed to create a temporary file in {}",
            directory.display()
        )
    })?;
    set_private_permissions(temporary.path(), false)?;
    serde_json::to_writer_pretty(&mut temporary, &document)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(&file)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to replace {}", file.display()))?;
    set_private_permissions(&file, false)?;
    sync_directory(&directory)?;
    Ok(file)
}

fn set_private_permissions(path: &Path, directory: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )?;
    }
    let _ = (path, directory);
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    let _ = path;
    Ok(())
}

fn require_interactive(operation: &str) -> Result<()> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal(),
        "{operation} requires an interactive terminal"
    );
    Ok(())
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    serde_json::to_writer_pretty(io::stdout().lock(), value)?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_transaction_network_and_completion_parity_commands() {
        let cli = Cli::try_parse_from([
            "ekubo-wallet",
            "transaction",
            "list",
            "primary",
            "--limit",
            "50",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Transaction(TransactionArgs {
                command: TransactionCommand::List {
                    wallet_id: Some(ref wallet_id),
                    limit: 50,
                },
            }) if wallet_id == "primary"
        ));
        let cli = Cli::try_parse_from(["ekubo-wallet", "completion", "zsh"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Completion { shell: Shell::Zsh }
        ));
        let cli = Cli::try_parse_from(["ekubo-wallet", "network", "presets"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Network(args) if matches!(args.command, NetworkCommand::Presets)
        ));
    }

    #[test]
    fn preset_network_add_uses_complete_catalog_metadata() {
        let candidate = network_candidate(NetworkAddArgs {
            name: "eth".into(),
            chain_id: None,
            rpc_url: None,
            display_name: None,
            aliases: Vec::new(),
            native_currency_name: None,
            native_currency_symbol: None,
            native_currency_decimals: None,
            max_gas_limit: None,
            block_explorer_url: None,
            documentation_url: None,
        })
        .unwrap();
        assert_eq!(candidate.name, "ethereum");
        assert_eq!(candidate.chain_id, 1);
        assert!(candidate.native_currency.is_some());
        assert!(candidate.max_gas_limit.is_some());
    }

    #[test]
    fn cursor_configuration_is_private_atomic_and_preserves_other_servers() {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join(".cursor");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("mcp.json"),
            br#"{"mcpServers":{"other":{"command":"other"}},"setting":true}"#,
        )
        .unwrap();
        let file = configure_cursor_mcp_at(
            home.path(),
            "/usr/local/bin/ekubo-wallet",
            &["server".into()],
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        assert_eq!(value["setting"], true);
        assert_eq!(value["mcpServers"]["other"]["command"], "other");
        assert_eq!(
            value["mcpServers"]["ekubo-wallet"]["args"],
            serde_json::json!(["server"])
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
