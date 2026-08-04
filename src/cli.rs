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
    message::{
        MessageStatus, MessageStore, PendingMessage, describe_message, message_digest, parse_siwe,
        siwe_warnings,
    },
    pending::{PendingStatus, PendingStore, PendingTransaction},
    policy_store::PolicyStore,
    render::{OutputMode, described_time, emit, explorer_transaction_url, relative_time},
    rpc::{ReceiptDetails, transaction_receipt_details, verify_chain_id},
    simulation::{SimulationResult, simulate_execution},
    typed_data::{
        PendingTypedData, TypedDataStatus, TypedDataStore, interpret_permit_approvals,
        parse_typed_data,
    },
};
use alloy::{
    primitives::{Address, B256, U256, b256},
    signers::SignerSync,
};
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use directories::BaseDirs;
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};
use std::{
    collections::BTreeMap,
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

    /// Print machine-readable JSON instead of the human-readable view.
    /// JSON is also the default whenever stdout is not a terminal.
    #[arg(long, global = true)]
    json: bool,

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
    /// Review the agent-proposed policy change as a permission diff and apply it.
    Review { wallet_id: String },
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
        let mode = OutputMode::resolve(self.json);
        match self.command {
            Command::Server => crate::mcp::serve(config).await,
            Command::Version => {
                println!("ekubo-wallet {VERSION}");
                Ok(())
            }
            Command::Wallet(args) => run_wallet(config, args.command, mode).await,
            Command::Network(args) => run_network(&config, args.command, mode).await,
            Command::Policy(args) => run_policy(config, args.command, mode).await,
            Command::Transaction(args) => run_transaction(&config, args.command, mode).await,
            Command::Token(args) => run_token(&config, &args.command, mode),
            Command::AddressBook(args) => run_address_book(&config, args.command, mode).await,
            Command::Legal(args) => run_legal(&config, &args.command, mode),
            Command::Approve {
                request_id,
                no_confirm,
            } => run_approve(&config, request_id, no_confirm, mode).await,
            Command::Reject { request_id } => run_reject(&config, request_id, mode),
            Command::Completion { shell } => print_completion_script(shell),
            Command::Complete { value_kind } => print_completion_values(&config, &value_kind),
            Command::ConfigureAgent(args) => run_configure_agent(args.command),
        }
    }
}

async fn run_wallet(config: ConfigStore, command: WalletCommand, mode: OutputMode) -> Result<()> {
    let custody = CustodyService::new(
        config.clone(),
        Arc::new(OsKeyStore),
        Arc::new(PlatformHumanPresence),
    );
    match command {
        WalletCommand::List => {
            let wallets = config.load()?.wallets;
            emit(mode, &wallets, || {
                if wallets.is_empty() {
                    return Ok(
                        "No wallets. Create one with `ekubo-wallet wallet create <id>`.".into(),
                    );
                }
                Ok(wallets
                    .iter()
                    .map(|wallet| {
                        format!(
                            "{}\n  address: {:#x}\n  source: {:?}, custody: {:?}\n  created: {}",
                            wallet.id,
                            wallet.address,
                            wallet.source,
                            wallet.custody,
                            described_time(wallet.created_at),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            })
        }
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
            emit(mode, &wallet, || {
                Ok(format!(
                    "Created wallet {} at {:#x} with the allow-all policy.\nReplace the policy before funding the address: `ekubo-wallet policy require-approval {}`.",
                    wallet.id, wallet.address, wallet.id
                ))
            })
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
                    emit(mode, &wallet, || {
                        Ok(format!(
                            "Imported wallet {} at {:#x}.",
                            wallet.id, wallet.address
                        ))
                    })
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
                    emit(mode, &wallet, || {
                        Ok(format!(
                            "Removed wallet {} ({:#x}) and its stored key.",
                            wallet.id, wallet.address
                        ))
                    })
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

fn run_token(config: &ConfigStore, command: &TokenCommand, mode: OutputMode) -> Result<()> {
    match command {
        TokenCommand::List {
            chain_id,
            limit,
            offset,
        } => {
            let (chain_id, limit, offset) = (*chain_id, *limit, *offset);
            let store = crate::token_store::TokenStore::production(config.data_dir())?;
            let total = store.count(chain_id)?;
            let tokens = store.list(chain_id, limit, offset)?;
            emit(
                mode,
                &serde_json::json!({ "total": total, "tokens": tokens }),
                || {
                    if tokens.is_empty() {
                        return Ok("The token database is empty.".into());
                    }
                    let mut lines = vec![format!(
                        "{total} token(s) stored, showing {}:",
                        tokens.len()
                    )];
                    for token in &tokens {
                        lines.push(format!(
                            "  chain {} · {} · {}{} · via {}",
                            token.chain_id,
                            token.address,
                            token.symbol.as_deref().unwrap_or("<no symbol>"),
                            token.decimals.map_or_else(String::new, |decimals| format!(
                                " ({decimals} decimals)"
                            )),
                            token.source,
                        ));
                    }
                    Ok(lines.join("\n"))
                },
            )
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

async fn run_address_book(
    config: &ConfigStore,
    command: AddressBookCommand,
    mode: OutputMode,
) -> Result<()> {
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
            let total = store.count(chain_id)?;
            let entries = store.list(chain_id, limit, offset)?;
            emit(
                mode,
                &serde_json::json!({ "total": total, "entries": entries }),
                || {
                    if entries.is_empty() {
                        return Ok(
                            "The address book is empty. Add an alias with `ekubo-wallet address-book add <network> <alias> <address>`.".into(),
                        );
                    }
                    let mut lines = vec![format!("{total} entrie(s), showing {}:", entries.len())];
                    for entry in &entries {
                        lines.push(format!(
                            "  {} → {} (chain {}){}",
                            entry.alias,
                            entry.address,
                            entry.chain_id,
                            entry
                                .note
                                .as_deref()
                                .map_or_else(String::new, |note| format!(" — {note}")),
                        ));
                    }
                    Ok(lines.join("\n"))
                },
            )
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
            emit(mode, &entry, || {
                Ok(format!(
                    "Stored {} → {} on chain {}.",
                    entry.alias, entry.address, entry.chain_id
                ))
            })
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
            emit(mode, &serde_json::json!({ "removed": removed }), || {
                Ok(format!(
                    "Removed {} → {} from chain {}.",
                    removed.alias, removed.address, removed.chain_id
                ))
            })
        }
    }
}

fn run_legal(config: &ConfigStore, command: &LegalCommand, mode: OutputMode) -> Result<()> {
    // `legal show` needs no store at all; keep it usable before any
    // credential-store or database access is possible.
    if let LegalCommand::Show { document } = command {
        let mut stdout = io::stdout().lock();
        stdout.write_all(document.document().text().as_bytes())?;
        stdout.flush()?;
        return Ok(());
    }
    let store = LegalStore::production(config.data_dir())?;
    let render_status = |status: &crate::legal::LegalStatus| {
        let describe = |name: &str, document: &crate::legal::DocumentStatus| {
            if document.accepted {
                format!(
                    "{name}: accepted{}",
                    document
                        .accepted_at
                        .map_or_else(String::new, |when| format!(" {}", relative_time(when)))
                )
            } else if document.superseded_digest.is_some() {
                format!("{name}: a previous revision was accepted; re-acceptance required")
            } else {
                format!("{name}: not accepted")
            }
        };
        format!(
            "{}\n{}\n{}",
            describe("Terms of Service", &status.terms_of_service),
            describe("Privacy Policy", &status.privacy_policy),
            if status.signing_allowed {
                "The wallet is fully enabled."
            } else {
                "The wallet is disabled until both documents are accepted: run `ekubo-wallet legal accept`."
            }
        )
    };
    match command {
        LegalCommand::Status => {
            let status = store.status()?;
            emit(mode, &status, || Ok(render_status(&status)))
        }
        LegalCommand::Show { .. } => unreachable!("handled before opening the store"),
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
            let status = store.status()?;
            emit(mode, &status, || Ok(render_status(&status)))
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

async fn run_policy(config: ConfigStore, command: PolicyCommand, mode: OutputMode) -> Result<()> {
    match command {
        PolicyCommand::Show { wallet_id } => {
            config.wallet(&wallet_id)?;
            let stored = PolicyStore::production(config.data_dir())?
                .get(&wallet_id)?
                .with_context(|| format!("wallet {wallet_id} has no local policy"))?;
            emit(
                mode,
                &serde_json::json!({
                    "wallet_id": stored.wallet_id,
                    "revision": stored.revision,
                    "updated_at": stored.updated_at,
                    "policy": stored.policy,
                }),
                || {
                    // The policy body stays pretty-printed JSON: it is the
                    // exact configuration document an operator would edit.
                    Ok(format!(
                        "Policy for {} — revision {}, updated {}:\n{}",
                        stored.wallet_id,
                        stored.revision,
                        described_time(stored.updated_at),
                        serde_json::to_string_pretty(&stored.policy)?,
                    ))
                },
            )
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
            replace_policy(&config, &wallet_id, policy, Some(&policy_file), mode).await
        }
        PolicyCommand::AllowAll { wallet_id } => {
            replace_policy(
                &config,
                &wallet_id,
                WalletPolicy::allow_all_with_approval(),
                None,
                mode,
            )
            .await
        }
        PolicyCommand::RequireApproval { wallet_id } => {
            replace_policy(
                &config,
                &wallet_id,
                WalletPolicy::require_approval_for_everything(),
                None,
                mode,
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
            let digest = format!("0x{}", hex::encode(Keccak256::digest(&canonical)));
            emit(
                mode,
                &serde_json::json!({
                    "valid": true,
                    "policy_file": policy_file.display().to_string(),
                    "digest": digest,
                    "version": policy.version,
                    "require_simulation": policy.require_simulation,
                    "approval_expiry_seconds": policy.approval_expiry_seconds,
                    "chains": policy.chains.keys().collect::<Vec<_>>(),
                    "policy": policy,
                }),
                || {
                    Ok(format!(
                        "{} is a valid policy.\n  digest: {digest}\n  chains: {}\n  require_simulation: {}\n  approval_expiry_seconds: {}",
                        policy_file.display(),
                        policy.chains.keys().cloned().collect::<Vec<_>>().join(", "),
                        policy.require_simulation,
                        policy.approval_expiry_seconds,
                    ))
                },
            )
        }
        // The schema is itself a JSON document; there is no human form.
        PolicyCommand::Schema => print_json(&policy_json_schema()),
        PolicyCommand::Review { wallet_id } => {
            review_policy_proposal(&config, &wallet_id, mode).await
        }
    }
}

/// Review and apply the single pending agent-proposed policy for a wallet.
/// The reviewer sees a minimized permission diff and the agent's rationale,
/// never a raw JSON comparison; application requires terminal approval plus
/// OS owner authentication and is revision-guarded end to end.
async fn review_policy_proposal(
    config: &ConfigStore,
    wallet_id: &str,
    mode: OutputMode,
) -> Result<()> {
    let wallet = config.wallet(wallet_id)?;
    require_interactive("policy changes")?;
    let mut policies = PolicyStore::production(config.data_dir())?;
    let Some(proposal) = policies.proposal(wallet_id)? else {
        eprintln!(
            "No policy proposal is pending for {wallet_id}. Agents create one with the \
             wallet_propose_policy tool."
        );
        return Ok(());
    };
    let current = policies
        .get(wallet_id)?
        .with_context(|| format!("wallet {wallet_id} has no local policy"))?;
    if current.revision != proposal.source_revision {
        policies.delete_proposal(wallet_id)?;
        anyhow::bail!(
            "the pending proposal referenced policy revision {} but the active policy is now \
             revision {}; the stale proposal was discarded. Ask the agent to read the current \
             policy and propose again.",
            proposal.source_revision,
            current.revision
        );
    }

    let diff = crate::core::policy::diff_policies(&current.policy, &proposal.policy);
    let policy_bytes = serde_json::to_vec(&proposal.policy)?;
    let digest = format!("0x{}", hex::encode(Keccak256::digest(&policy_bytes)));
    let mut request = ApprovalRequest::new(
        ApprovalKind::PolicyChange,
        "Apply proposed wallet policy",
        "An agent proposed this replacement policy. The permission diff below is authoritative; \
         the rationale is the agent's own explanation.",
    )
    .fact("Wallet", &wallet.id)
    .fact("Address", format!("{:#x}", wallet.address))
    .fact("Current revision", current.revision.to_string())
    .fact("Proposed", described_time(proposal.created_at))
    .fact("Proposed policy digest", &digest)
    .fact("Agent rationale (untrusted)", &proposal.rationale);
    for (index, line) in diff.iter().enumerate() {
        request = request.fact(format!("Change {}", index + 1), line);
    }
    request = request
        .digest(&digest)
        .warning(
            "A more permissive policy can authorize transactions without an exceptional approval.",
        )
        .warning(
            "The rationale is agent-authored text. Judge the change by the diff lines, not the \
             story.",
        );
    require_approval(request).await?;
    PlatformHumanPresence
        .confirm(&PresenceRequest {
            action: PresenceAction::ChangePolicy,
            wallet_id: wallet_id.into(),
            operation_digest: Some(digest.clone()),
        })
        .await?;

    // put() enforces the expected revision atomically, so a policy change
    // during the human review fails closed rather than applying stale rules.
    let stored = policies.put(wallet_id, &proposal.policy, Some(proposal.source_revision))?;
    policies.delete_proposal(wallet_id)?;
    eprintln!(
        "Applied. An agent can observe the new revision through wallet_get_policy; nothing \
         further is needed here."
    );
    emit(
        mode,
        &serde_json::json!({
            "wallet_id": wallet_id,
            "revision": stored.revision,
            "digest": digest,
            "applied_changes": diff,
        }),
        || {
            Ok(format!(
                "Applied policy revision {} for {wallet_id}:\n{}",
                stored.revision,
                diff.iter()
                    .map(|line| format!("  {line}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ))
        },
    )
}

/// The schema is derived from the same types the wallet enforces, so a document
/// that validates here cannot drift from what `policy set` will accept.
fn policy_json_schema() -> serde_json::Value {
    crate::core::policy::json_schema()
}

async fn run_transaction(
    config: &ConfigStore,
    command: TransactionCommand,
    mode: OutputMode,
) -> Result<()> {
    let pending = PendingStore::production(config.data_dir())?;
    match command {
        TransactionCommand::List { wallet_id, limit } => {
            if let Some(wallet_id) = wallet_id.as_deref() {
                config.wallet(wallet_id)?;
            }
            let transactions = pending.list(wallet_id.as_deref(), limit)?;
            if mode == OutputMode::Json {
                return print_json(&serde_json::json!({ "transactions": transactions }));
            }
            if transactions.is_empty() {
                println!("No recorded transactions.");
                return Ok(());
            }
            // The full interactive browser needs stdin; without it, print the
            // one-line summaries instead.
            if io::stdin().is_terminal() {
                browse_transactions(config, &transactions).await
            } else {
                for record in &transactions {
                    println!("{}", transaction_line(record));
                }
                Ok(())
            }
        }
        TransactionCommand::Show { identifier } => {
            let record = pending.get_by_identifier(&identifier)?;
            if mode == OutputMode::Json {
                return print_json(&record);
            }
            let detail = transaction_detail(config, &record).await;
            println!("{}", crate::render::terminal_safe_multiline(&detail));
            Ok(())
        }
    }
}

/// keccak256("Transfer(address,address,uint256)"), for receipt log decoding.
const TRANSFER_EVENT: B256 =
    b256!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

fn status_label(status: PendingStatus) -> &'static str {
    match status {
        PendingStatus::AwaitingApproval => "awaiting approval",
        PendingStatus::Rejected => "rejected",
        PendingStatus::Signed => "approved, not submitted",
        PendingStatus::Submitting => "submitting",
        PendingStatus::Broadcast => "broadcast, awaiting receipt",
        PendingStatus::Confirmed => "confirmed",
        PendingStatus::Reverted => "reverted",
        PendingStatus::Expired => "expired",
        PendingStatus::Cancelled => "cancelled",
    }
}

fn transaction_line(record: &PendingTransaction) -> String {
    let native_total = record
        .execution_plan
        .ordered_steps
        .iter()
        .filter_map(|step| BigUint::from_str(step.transaction.value.as_str()).ok())
        .sum::<BigUint>();
    format!(
        "{} · {} · {} on chain {} · {} call(s), {} wei native · {}",
        relative_time(record.created_at),
        status_label(record.status),
        record.wallet_id,
        record.chain_id,
        record.execution_plan.ordered_steps.len(),
        native_total,
        record.request_id,
    )
}

/// Interactive loop: pick a transaction, see its expanded details (including
/// live receipt lookups), return to the list.
async fn browse_transactions(config: &ConfigStore, records: &[PendingTransaction]) -> Result<()> {
    const DONE: usize = usize::MAX;
    loop {
        let mut select = cliclack::select(format!("{} recorded transaction(s)", records.len()));
        for (index, record) in records.iter().enumerate() {
            select = select.item(
                index,
                crate::render::terminal_safe_multiline(&transaction_line(record))
                    .replace('\n', " "),
                "",
            );
        }
        select = select.item(DONE, "Done", "quit");
        let choice = select.interact()?;
        if choice == DONE {
            return Ok(());
        }
        let detail = transaction_detail(config, &records[choice]).await;
        cliclack::note(
            format!("Request {}", records[choice].request_id),
            crate::render::terminal_safe_multiline(&detail),
        )?;
    }
}

/// The expanded human view of one lifecycle record. Chain lookups are
/// best-effort display work: an unreachable RPC degrades to the stored data.
async fn transaction_detail(config: &ConfigStore, record: &PendingTransaction) -> String {
    let network = config.network_by_chain_id(&record.chain_id).ok();
    let mut lines = Vec::new();
    lines.push(format!("Status: {}", status_label(record.status)));
    lines.push(format!("Wallet: {}", record.wallet_id));
    lines.push(format!(
        "Network: {} (chain {})",
        network
            .as_ref()
            .map_or(record.network_name.as_str(), |network| network
                .name
                .as_str()),
        record.chain_id,
    ));
    lines.push(format!("Created: {}", described_time(record.created_at)));
    if record.updated_at != record.created_at {
        lines.push(format!("Updated: {}", described_time(record.updated_at)));
    }
    if record.status == PendingStatus::AwaitingApproval {
        lines.push(format!("Expires: {}", described_time(record.expires_at)));
    }
    if let Some(approved_at) = record.approved_at {
        lines.push(format!("Approved: {}", described_time(approved_at)));
    }
    if let Some(rejected_at) = record.rejected_at {
        lines.push(format!("Rejected: {}", described_time(rejected_at)));
    }
    lines.push(format!("Plan digest: {}", record.digest));
    lines.push(format!(
        "Policy revision: {}; approval {}",
        record.policy_revision,
        if record.approval_required {
            "required"
        } else {
            "automatic"
        }
    ));

    for step in &record.execution_plan.ordered_steps {
        let calldata = step.transaction.data.as_ref();
        let selector = if calldata.is_empty() {
            "no calldata".into()
        } else {
            format!(
                "selector 0x{}, {} bytes",
                hex::encode(&calldata[..calldata.len().min(4)]),
                calldata.len()
            )
        };
        lines.push(format!(
            "Call {}: to {:#x}; value {} wei; {selector}",
            step.step, step.transaction.to, step.transaction.value,
        ));
    }

    let transaction_hash = record
        .broadcast_transaction_hash
        .as_deref()
        .or(record.signed_transaction_hash.as_deref());
    if let Some(hash) = transaction_hash {
        lines.push(format!("Transaction hash: {hash}"));
        if let Some(url) = network
            .as_ref()
            .and_then(|network| explorer_transaction_url(network, hash))
        {
            lines.push(format!("Explorer: {url}"));
        }
    }
    if let Some(block) = &record.block_number {
        lines.push(format!("Block: {block}"));
    }

    // Live receipt enrichment for anything that reached the chain.
    if let (Some(network), Some(hash)) = (network.as_ref(), transaction_hash)
        && matches!(
            record.status,
            PendingStatus::Broadcast | PendingStatus::Confirmed | PendingStatus::Reverted
        )
    {
        match transaction_receipt_details(network, hash).await {
            Ok(Some(receipt)) => {
                lines.extend(receipt_lines(network, record, &receipt).await);
            }
            Ok(None) => lines.push("Receipt: not yet available from the RPC".into()),
            Err(error) => lines.push(format!("Receipt: lookup failed ({error:#})")),
        }
    }
    lines.join("\n")
}

/// Receipt facts plus the wallet's decoded ERC-20 transfer balance changes.
async fn receipt_lines(
    network: &NetworkConfig,
    record: &PendingTransaction,
    receipt: &ReceiptDetails,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "Receipt: {} in block {}",
        if receipt.succeeded {
            "succeeded"
        } else {
            "reverted"
        },
        receipt.block_number,
    ));
    let fee_wei = u128::from(receipt.gas_used).saturating_mul(receipt.effective_gas_price);
    let currency_symbol = network
        .native_currency
        .as_ref()
        .map_or("native units", |currency| currency.symbol.as_str());
    let currency_decimals = network
        .native_currency
        .as_ref()
        .map_or(18, |currency| currency.decimals);
    lines.push(format!(
        "Fee paid: {} {currency_symbol} ({fee_wei} wei; {} gas)",
        crate::approval_summary::format_fixed_point(&fee_wei.to_string(), currency_decimals),
        receipt.gas_used,
    ));

    // Net standard Transfer activity for the sender, from the receipt logs.
    let wallet = record.execution_plan.sender;
    let mut activity: std::collections::BTreeMap<Address, (U256, U256)> =
        std::collections::BTreeMap::new();
    for log in &receipt.logs {
        if log.topics.len() != 3 || log.topics[0] != TRANSFER_EVENT || log.data.len() != 32 {
            continue;
        }
        let from = Address::from_slice(&log.topics[1].as_slice()[12..]);
        let to = Address::from_slice(&log.topics[2].as_slice()[12..]);
        let amount = U256::from_be_slice(&log.data);
        let entry = activity.entry(log.address).or_default();
        if to == wallet {
            entry.0 = entry.0.saturating_add(amount);
        }
        if from == wallet {
            entry.1 = entry.1.saturating_add(amount);
        }
    }
    let activity: Vec<(Address, (U256, U256))> = activity
        .into_iter()
        .filter(|(_, (incoming, outgoing))| !incoming.is_zero() || !outgoing.is_zero())
        .collect();
    if activity.is_empty() {
        lines.push("Token balance changes: none for this wallet in the receipt logs".into());
        return lines;
    }
    let tokens: Vec<Address> = activity.iter().map(|(token, _)| *token).collect();
    let metadata = crate::approval_summary::load_token_metadata(network, &tokens).await;
    lines.push("Token balance changes (from receipt Transfer logs):".into());
    for (token, (incoming, outgoing)) in activity {
        let display = metadata.get(&token).cloned().unwrap_or_default();
        let mut parts = Vec::new();
        if !incoming.is_zero() {
            parts.push(format!(
                "+{}",
                crate::approval_summary::format_token_amount(incoming, token, &display)
            ));
        }
        if !outgoing.is_zero() {
            parts.push(format!(
                "-{}",
                crate::approval_summary::format_token_amount(outgoing, token, &display)
            ));
        }
        lines.push(format!("  {}", parts.join(", ")));
    }
    lines
}

fn list_pending_approvals(config: &ConfigStore, mode: OutputMode) -> Result<()> {
    let pending = PendingStore::production(config.data_dir())?;
    let awaiting = pending.awaiting_approval(None)?;
    let awaiting_typed_data =
        TypedDataStore::production(config.data_dir())?.awaiting_approval(None)?;
    let awaiting_messages = MessageStore::production(config.data_dir())?.awaiting_approval(None)?;
    let proposals = PolicyStore::production(config.data_dir())?.list_proposals()?;
    if awaiting.is_empty()
        && awaiting_typed_data.is_empty()
        && awaiting_messages.is_empty()
        && proposals.is_empty()
    {
        eprintln!("No requests are awaiting approval.");
    } else {
        eprintln!(
            "{} request(s) awaiting approval. Review one with `ekubo-wallet approve <request-id>`; \
             unapproved requests expire at their listed expires_at.{}",
            awaiting.len() + awaiting_typed_data.len() + awaiting_messages.len(),
            if proposals.is_empty() {
                String::new()
            } else {
                format!(
                    " {} policy proposal(s) await `ekubo-wallet policy review <wallet-id>`.",
                    proposals.len()
                )
            },
        );
    }
    let proposal_summaries: Vec<serde_json::Value> = proposals
        .iter()
        .map(|proposal| {
            serde_json::json!({
                "wallet_id": proposal.wallet_id,
                "source_revision": proposal.source_revision,
                "created_at": proposal.created_at,
                "rationale": proposal.rationale,
            })
        })
        .collect();
    emit(
        mode,
        &serde_json::json!({
            "pending_approvals": awaiting,
            "pending_typed_data": awaiting_typed_data,
            "pending_messages": awaiting_messages,
            "pending_policy_proposals": proposal_summaries,
        }),
        || {
            let mut lines = Vec::new();
            for record in &awaiting {
                lines.push(format!(
                    "{}\n    expires {}",
                    transaction_line(record),
                    relative_time(record.expires_at),
                ));
            }
            for record in &awaiting_typed_data {
                lines.push(format!(
                    "{} · typed data for {} on chain {} · {}\n    expires {}",
                    relative_time(record.created_at),
                    record.wallet_id,
                    record.chain_id,
                    record.request_id,
                    relative_time(record.expires_at),
                ));
            }
            for record in &awaiting_messages {
                lines.push(format!(
                    "{} · message for {}{} · {}\n    expires {}",
                    relative_time(record.created_at),
                    record.wallet_id,
                    record
                        .chain_id
                        .as_deref()
                        .map_or_else(String::new, |chain| format!(" (chain {chain} claimed)")),
                    record.request_id,
                    relative_time(record.expires_at),
                ));
            }
            for proposal in &proposals {
                lines.push(format!(
                    "{} · policy proposal for {} (from revision {}) · review with `ekubo-wallet policy review {}`",
                    relative_time(proposal.created_at),
                    proposal.wallet_id,
                    proposal.source_revision,
                    proposal.wallet_id,
                ));
            }
            if lines.is_empty() {
                lines.push("Nothing is awaiting approval.".into());
            }
            Ok(lines.join("\n"))
        },
    )
}

fn run_reject(config: &ConfigStore, request_id: Option<Uuid>, mode: OutputMode) -> Result<()> {
    let Some(request_id) = request_id else {
        return list_pending_approvals(config, mode);
    };
    let request = match PendingStore::production(config.data_dir())?.reject(request_id) {
        Ok(request) => request,
        Err(transaction_error) => {
            let mut typed_data = TypedDataStore::production(config.data_dir())?;
            let Ok(request) = typed_data.reject(request_id) else {
                let mut messages = MessageStore::production(config.data_dir())?;
                let Ok(request) = messages.reject(request_id) else {
                    return Err(transaction_error);
                };
                eprintln!(
                    "Rejected. An MCP agent waiting on this message request sees the rejection \
                     automatically."
                );
                return emit(
                    mode,
                    &serde_json::json!({
                        "rejected": request.request_id,
                        "digest": request.digest,
                        "rejected_at": request.rejected_at,
                    }),
                    || Ok(format!("Rejected message request {}.", request.request_id)),
                );
            };
            eprintln!(
                "Rejected. An MCP agent waiting on this typed-data request sees the rejection \
                 automatically."
            );
            return emit(
                mode,
                &serde_json::json!({
                    "rejected": request.request_id,
                    "digest": request.digest,
                    "rejected_at": request.rejected_at,
                }),
                || {
                    Ok(format!(
                        "Rejected typed-data request {}.",
                        request.request_id
                    ))
                },
            );
        }
    };
    eprintln!("Rejected. An MCP agent waiting on this request sees the rejection automatically.");
    emit(
        mode,
        &serde_json::json!({
            "rejected": request.request_id,
            "digest": request.digest,
            "rejected_at": request.rejected_at,
        }),
        || Ok(format!("Rejected request {}.", request.request_id)),
    )
}

async fn run_approve(
    config: &ConfigStore,
    request_id: Option<Uuid>,
    no_confirm: bool,
    mode: OutputMode,
) -> Result<()> {
    let Some(request_id) = request_id else {
        return list_pending_approvals(config, mode);
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
                let messages = MessageStore::production(config.data_dir())?;
                let Ok(request) = messages.get(request_id) else {
                    return Err(transaction_error);
                };
                return approve_message(config, messages, request, no_confirm, mode).await;
            };
            return approve_typed_data(config, typed_data, request, no_confirm, mode).await;
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

    let simulation = simulate_execution(
        &wallet,
        &network,
        &request.execution_plan,
        &stored_policy,
        None,
    )
    .await?;
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
    emit(
        mode,
        &serde_json::json!({
            "approved": approved.request_id,
            "digest": approved.digest,
            "transaction_hash": approved.signed_transaction_hash,
            "approved_at": approved.approved_at,
        }),
        || {
            Ok(format!(
                "Approved request {} — signed transaction {}.",
                approved.request_id,
                approved
                    .signed_transaction_hash
                    .as_deref()
                    .unwrap_or("<missing>"),
            ))
        },
    )
}

async fn approve_typed_data(
    config: &ConfigStore,
    mut store: TypedDataStore,
    request: PendingTypedData,
    no_confirm: bool,
    mode: OutputMode,
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
    emit(
        mode,
        &serde_json::json!({
            "approved": stored.request_id,
            "digest": stored.digest,
            "signature": stored.signature,
            "approved_at": stored.approved_at,
        }),
        || {
            Ok(format!(
                "Approved typed-data request {}.\nSignature: {}",
                stored.request_id,
                stored.signature.as_deref().unwrap_or("<missing>"),
            ))
        },
    )
}

async fn approve_message(
    config: &ConfigStore,
    mut store: MessageStore,
    request: PendingMessage,
    no_confirm: bool,
    mode: OutputMode,
) -> Result<()> {
    ensure!(
        request.status == MessageStatus::AwaitingApproval,
        "message request is not awaiting approval"
    );
    let wallet = config.wallet(&request.wallet_id)?;
    if let Some(chain_id) = &request.chain_id {
        config.network_by_chain_id(chain_id)?;
    }
    let message = request.message_bytes()?;
    let digest = message_digest(&message);
    ensure!(
        format!("{digest:#x}") == request.digest,
        "message request no longer matches its stored bytes"
    );
    let display = describe_message(&message);
    let siwe = display.text.as_deref().and_then(parse_siwe);
    // Re-check the account the login names here too: the request was refused
    // at creation, and nothing may have changed the wallet under it since.
    if let Some(siwe) = &siwe {
        ensure!(
            siwe.address == wallet.address.to_checksum(None),
            "this sign-in message names account {}, but wallet {} is {}",
            siwe.address,
            wallet.id,
            wallet.address.to_checksum(None)
        );
    }

    let mut approval = ApprovalRequest::new(
        ApprovalKind::MessageSignature,
        "Approve message signature",
        "Sign these exact bytes with the wallet key, prefixed as an EIP-191 personal message. \
         The complete message is printed above this summary.",
    )
    .fact("Wallet", &request.wallet_id)
    .fact("Signer", wallet.address.to_checksum(None))
    .fact(
        "Chain",
        request.chain_id.as_ref().map_or_else(
            || "not stated; a message signature binds no chain".to_owned(),
            |chain_id| format!("{chain_id}, claimed by the requester"),
        ),
    )
    .fact(
        "Size",
        format!(
            "{} bytes, {} line(s), sent as {}",
            display.byte_length,
            display.line_count,
            match request.encoding {
                crate::message::MessageEncoding::Text => "text",
                crate::message::MessageEncoding::Hex => "raw bytes",
            }
        ),
    );

    if let Some(siwe) = &siwe {
        approval = approval
            .fact("Sign in to", &siwe.domain)
            .fact("Account", &siwe.address)
            .fact("URI", &siwe.uri)
            .fact("Chain ID in message", &siwe.chain_id)
            .fact("Nonce", &siwe.nonce)
            .fact("Issued at", &siwe.issued_at);
        if let Some(statement) = &siwe.statement {
            approval = approval.fact("Statement", terminal_safe_excerpt(statement));
        }
        for (label, value) in [
            ("Expires at", siwe.expiration_time.as_deref()),
            ("Not before", siwe.not_before.as_deref()),
            ("Request ID", siwe.request_id.as_deref()),
        ] {
            if let Some(value) = value {
                approval = approval.fact(label, value);
            }
        }
        for (index, resource) in siwe.resources.iter().enumerate() {
            approval = approval.fact(
                format!("Resource {}", index + 1),
                terminal_safe_excerpt(resource),
            );
        }
        for warning in siwe_warnings(
            siwe,
            request.chain_id.as_deref(),
            siwe.chain_id
                .parse::<u64>()
                .is_ok_and(|_| config.network_by_chain_id(&siwe.chain_id).is_ok()),
            chrono::Utc::now(),
        ) {
            approval = approval.warning(warning);
        }
    } else {
        approval = approval
            .fact(
                "Message",
                display
                    .escaped_text
                    .as_deref()
                    .map_or_else(|| request.message_hex.clone(), terminal_safe_excerpt),
            )
            .warning(
                "This is not a recognized sign-in message. A message signature can authorize an \
                 off-chain order, a delegation, or an account link; verify every byte printed \
                 above against whatever asked for it.",
            );
    }
    for warning in &display.warnings {
        approval = approval.warning(warning.clone());
    }
    approval = approval.fact("Signing hash", &request.digest);
    approval.digest = Some(request.digest.clone());
    approval.id = request.request_id;
    approval.expires_at = request.expires_at;

    let mut stderr = io::stderr().lock();
    serde_json::to_writer_pretty(
        &mut stderr,
        &serde_json::json!({
            "approval": approval,
            "message": {
                "hex": request.message_hex,
                "text": display.text,
                "escaped_text": display.escaped_text,
                "byte_length": display.byte_length,
                "encoding": request.encoding,
                "siwe": siwe,
            },
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
            action: PresenceAction::SignMessage,
            wallet_id: wallet.id.clone(),
            operation_digest: Some(request.digest.clone()),
        })
        .await?;

    // Re-read mutable local authority after the potentially long human
    // review; the final SQL write repeats the pending checks atomically.
    let current = store.get(request.request_id)?;
    ensure!(
        current.status == MessageStatus::AwaitingApproval
            && current.digest == request.digest
            && current.message_hex == request.message_hex,
        "message request changed during approval"
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
        .context("failed to sign the message")?;
    let stored = store.store_signature(
        request.request_id,
        &request.digest,
        &format!("0x{}", hex::encode(signature.as_bytes())),
    )?;
    eprintln!(
        "Approved and signed. An MCP agent waiting on this request reads the signature \
         automatically; nothing further is needed here."
    );
    emit(
        mode,
        &serde_json::json!({
            "approved": stored.request_id,
            "digest": stored.digest,
            "signature": stored.signature,
            "approved_at": stored.approved_at,
        }),
        || {
            Ok(format!(
                "Approved message request {}.\nSignature: {}",
                stored.request_id,
                stored.signature.as_deref().unwrap_or("<missing>"),
            ))
        },
    )
}

/// Keep one approval fact to a readable length; the exact bytes are always
/// printed in full above the summary.
fn terminal_safe_excerpt(value: &str) -> String {
    const MAX_FACT_CHARACTERS: usize = 200;
    if value.chars().count() <= MAX_FACT_CHARACTERS {
        return value.to_owned();
    }
    let head: String = value.chars().take(MAX_FACT_CHARACTERS).collect();
    format!("{head}… (full message printed above)")
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
    mode: OutputMode,
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
    emit(
        mode,
        &serde_json::json!({
            "wallet_id": wallet_id,
            "policy_version": stored.policy.version,
            "revision": stored.revision,
            "digest": digest,
        }),
        || {
            Ok(format!(
                "Installed policy revision {} for {wallet_id} (digest {digest}).",
                stored.revision
            ))
        },
    )
}

async fn require_approval(request: ApprovalRequest) -> Result<()> {
    ensure!(
        TerminalApprovalUi.review(&request).await? == ApprovalDecision::Approved,
        "action rejected"
    );
    Ok(())
}

async fn run_network(
    config: &ConfigStore,
    command: NetworkCommand,
    mode: OutputMode,
) -> Result<()> {
    match command {
        // The human CLI prints complete RPC URLs so the configuration can
        // actually be read back and edited. No MCP tool returns them.
        NetworkCommand::List => {
            let networks = config.load()?.networks;
            emit(mode, &describe_networks(&networks), || {
                Ok(networks_human(&networks))
            })
        }
        NetworkCommand::Presets => {
            let networks = default_networks();
            emit(
                mode,
                &serde_json::json!({ "networks": describe_networks(&networks) }),
                || Ok(networks_human(&networks)),
            )
        }
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
            emit(
                mode,
                &serde_json::json!({
                    "reset": true,
                    "networks": describe_networks(&networks),
                }),
                || {
                    Ok(format!(
                        "Reset to the {} built-in network presets.\n{}",
                        networks.len(),
                        networks_human(&networks)
                    ))
                },
            )
        }
        NetworkCommand::Add(args) => {
            let mut prospective = config.load()?.networks;
            let candidate = network_candidate(*args, &prospective)?;
            replace_configured_network(&mut prospective, candidate.clone())?;
            let digest = configuration_digest(&candidate)?;
            // The complete URL is shown, not just its origin. This is the
            // one moment the user can catch a typo or the wrong endpoint, and
            // `network list` already prints configured URLs in full; an RPC
            // URL is configuration this human owns, not a signing credential.
            authorize_network_change(
                "Add or update network",
                "Trust this RPC to supply chain state and eth_simulateV1 execution for signing decisions.",
                &digest,
                vec![
                    ("Network", candidate.name.clone()),
                    ("Chain ID", candidate.chain_id.to_string()),
                    ("RPC URL", candidate.rpc_url.to_string()),
                ],
            )
            .await?;
            verify_chain_id(&candidate).await?;
            config.update(|state| {
                replace_configured_network(&mut state.networks, candidate.clone())
            })?;
            emit(
                mode,
                &serde_json::json!({
                    "network": describe_network(&candidate),
                    "rpc_verified": true,
                }),
                || {
                    Ok(format!(
                        "Configured {} (chain {}) via {}; the RPC verified its chain ID.",
                        candidate.name, candidate.chain_id, candidate.rpc_url,
                    ))
                },
            )
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
            emit(
                mode,
                &serde_json::json!({
                    "removed": removed.name,
                    "chain_id": removed.chain_id.to_string(),
                }),
                || {
                    Ok(format!(
                        "Removed network {} (chain {}).",
                        removed.name, removed.chain_id
                    ))
                },
            )
        }
    }
}

fn describe_networks(networks: &[NetworkConfig]) -> Vec<serde_json::Value> {
    networks.iter().map(describe_network).collect()
}

/// Full RPC URLs are intentionally included: the CLI listing is how an
/// operator reads back the configuration.
fn networks_human(networks: &[NetworkConfig]) -> String {
    networks
        .iter()
        .map(|network| {
            format!(
                "{} (chain {}){}\n  rpc: {}{}",
                network.name,
                network.chain_id,
                if network.aliases.is_empty() {
                    String::new()
                } else {
                    format!(" — aliases: {}", network.aliases.join(", "))
                },
                network.rpc_url,
                network
                    .block_explorer_url
                    .as_ref()
                    .map_or_else(String::new, |url| format!("\n  explorer: {url}")),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
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

/// Resolve the network to write.
///
/// An already-configured network or a built-in preset with the same name or
/// alias becomes the base, so editing one field never means restating the
/// other eight. Only a genuinely new custom chain has to supply everything,
/// and that path collects what it needs interactively rather than rejecting
/// one missing flag per attempt.
fn network_candidate(args: NetworkAddArgs, configured: &[NetworkConfig]) -> Result<NetworkConfig> {
    if let Some(base) = network_base(&args, configured) {
        return apply_network_overrides(base, args);
    }
    ensure!(
        args.chain_id.is_some(),
        "unknown network {}; run `ekubo-wallet network presets` to see the built-in ones, `ekubo-wallet network list` to see the configured ones, or pass a chain ID to define a custom network",
        args.name
    );
    build_custom_network(args)
}

/// The configured network or built-in preset this add/update starts from.
///
/// A configured network wins over a preset with the same name, so editing a
/// customized network never silently reverts the rest of it to the preset. A
/// declared chain ID must match, because repointing a name at a different
/// chain is a redefinition rather than an edit.
fn network_base(args: &NetworkAddArgs, configured: &[NetworkConfig]) -> Option<NetworkConfig> {
    let matches = |network: &NetworkConfig| {
        (network.name == args.name || network.aliases.iter().any(|alias| alias == &args.name))
            && args
                .chain_id
                .is_none_or(|chain_id| chain_id == network.chain_id)
    };
    configured
        .iter()
        .find(|network| matches(network))
        .cloned()
        .or_else(|| default_networks().into_iter().find(matches))
}

/// Apply only the fields this invocation actually supplied.
fn apply_network_overrides(mut base: NetworkConfig, args: NetworkAddArgs) -> Result<NetworkConfig> {
    if let Some(rpc_url) = args.rpc_url {
        base.rpc_url = rpc_url;
    }
    if let Some(display_name) = args.display_name {
        base.display_name = Some(display_name);
    }
    if !args.aliases.is_empty() {
        base.aliases = normalize_aliases(args.aliases)?;
    }
    if let Some(maximum) = args.max_gas_limit {
        base.max_gas_limit = Some(maximum);
    }
    if let Some(url) = args.block_explorer_url {
        base.block_explorer_url = Some(url);
    }
    if let Some(url) = args.documentation_url {
        base.documentation_url = Some(url);
    }
    if args.native_currency_name.is_some()
        || args.native_currency_symbol.is_some()
        || args.native_currency_decimals.is_some()
    {
        let mut currency = base.native_currency.take().unwrap_or(NativeCurrency {
            name: "Ether".into(),
            symbol: "ETH".into(),
            decimals: 18,
        });
        if let Some(name) = args.native_currency_name {
            currency.name = name;
        }
        if let Some(symbol) = args.native_currency_symbol {
            currency.symbol = symbol;
        }
        if let Some(decimals) = args.native_currency_decimals {
            currency.decimals = decimals;
        }
        base.native_currency = Some(currency);
    }
    Ok(base)
}

/// One field a brand-new custom network needs, with everything required to
/// either ask for it or explain how to pass it.
struct RequiredField {
    flag: &'static str,
    prompt: &'static str,
    help: &'static str,
    example: &'static str,
    /// Offered as the prompt default and accepted on an empty answer.
    default: Option<&'static str>,
}

/// Asked in this order: the cheap descriptive metadata first, then the
/// endpoint that is actually being trusted, so the last thing on screen
/// before the authorization prompt is the RPC itself.
const CUSTOM_NETWORK_FIELDS: &[RequiredField] = &[
    RequiredField {
        flag: "--display-name",
        prompt: "Display name",
        help: "How this chain is named in human output",
        example: "Base",
        default: None,
    },
    RequiredField {
        flag: "--alias",
        prompt: "Aliases (comma-separated)",
        help: "Short names this chain can also be selected by",
        example: "base-mainnet, base8453",
        default: None,
    },
    RequiredField {
        flag: "--native-currency-name",
        prompt: "Native currency name",
        help: "The gas token's full name",
        example: "Ether",
        default: Some("Ether"),
    },
    RequiredField {
        flag: "--native-currency-symbol",
        prompt: "Native currency symbol",
        help: "The gas token's ticker",
        example: "ETH",
        default: Some("ETH"),
    },
    RequiredField {
        flag: "--native-currency-decimals",
        prompt: "Native currency decimals",
        help: "Smallest-unit exponent of the gas token",
        example: "18",
        default: Some("18"),
    },
    RequiredField {
        flag: "--max-gas-limit",
        prompt: "Maximum gas limit",
        help: "Largest gas limit this wallet may ever sign on this chain",
        example: "16777216",
        default: Some("16777216"),
    },
    RequiredField {
        flag: "--block-explorer-url",
        prompt: "Block explorer URL",
        help: "Where the CLI links transactions and addresses",
        example: "https://basescan.org",
        default: None,
    },
    RequiredField {
        flag: "--documentation-url",
        prompt: "Documentation URL",
        help: "Where this chain's connection details are published",
        example: "https://docs.base.org",
        default: None,
    },
    RequiredField {
        flag: "--rpc-url",
        prompt: "RPC URL",
        help: "JSON-RPC endpoint that supplies chain state and eth_simulateV1 execution",
        example: "https://rpc.example.com/v1/<key>",
        default: None,
    },
];

/// Build a network that matches no preset and no configured network.
///
/// Everything missing is worked out up front. In a terminal each gap is
/// prompted for in one session; otherwise a single error names every missing
/// flag, so a scripted invocation is fixed in one edit rather than one per
/// run.
fn build_custom_network(args: NetworkAddArgs) -> Result<NetworkConfig> {
    let chain_id = args
        .chain_id
        .context("custom network requires a chain ID")?;
    ensure!(chain_id > 0, "network chain ID must be positive");

    let supplied = BTreeMap::from([
        ("--display-name", args.display_name.clone()),
        (
            "--alias",
            (!args.aliases.is_empty()).then(|| args.aliases.join(",")),
        ),
        ("--native-currency-name", args.native_currency_name.clone()),
        (
            "--native-currency-symbol",
            args.native_currency_symbol.clone(),
        ),
        (
            "--native-currency-decimals",
            args.native_currency_decimals.map(|value| value.to_string()),
        ),
        ("--max-gas-limit", args.max_gas_limit.clone()),
        (
            "--block-explorer-url",
            args.block_explorer_url.as_ref().map(ToString::to_string),
        ),
        (
            "--documentation-url",
            args.documentation_url.as_ref().map(ToString::to_string),
        ),
        ("--rpc-url", args.rpc_url.as_ref().map(ToString::to_string)),
    ]);
    let answers = collect_custom_network_fields(&args.name, chain_id, &supplied)?;
    let field = |flag: &str| answers[flag].clone();

    let aliases = normalize_aliases(
        field("--alias")
            .split([',', ' '])
            .map(str::to_owned)
            .collect::<Vec<_>>(),
    )?;
    ensure!(
        !aliases.is_empty(),
        "custom network requires at least one alias"
    );
    Ok(NetworkConfig {
        name: args.name,
        display_name: Some(field("--display-name")),
        aliases,
        chain_id,
        rpc_url: field("--rpc-url").parse().context("RPC URL is invalid")?,
        max_gas_limit: Some(field("--max-gas-limit")),
        native_currency: Some(NativeCurrency {
            name: field("--native-currency-name"),
            symbol: field("--native-currency-symbol"),
            decimals: field("--native-currency-decimals")
                .parse()
                .context("native currency decimals must be 0-255")?,
        }),
        block_explorer_url: Some(
            field("--block-explorer-url")
                .parse()
                .context("block explorer URL is invalid")?,
        ),
        documentation_url: Some(
            field("--documentation-url")
                .parse()
                .context("documentation URL is invalid")?,
        ),
    })
}

/// Fill every gap in `supplied`: by prompting when a terminal is attached,
/// and by reporting all of them at once when one is not.
fn collect_custom_network_fields(
    name: &str,
    chain_id: u64,
    supplied: &BTreeMap<&'static str, Option<String>>,
) -> Result<BTreeMap<&'static str, String>> {
    let missing = CUSTOM_NETWORK_FIELDS
        .iter()
        .filter(|field| supplied.get(field.flag).is_none_or(Option::is_none))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(supplied
            .iter()
            .map(|(flag, value)| (*flag, value.clone().unwrap_or_default()))
            .collect());
    }
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
        let flags = missing
            .iter()
            .map(|field| format!("{} <value>", field.flag))
            .collect::<Vec<_>>();
        let width = flags.iter().map(String::len).max().unwrap_or_default();
        let lines = flags
            .iter()
            .zip(&missing)
            .map(|(flag, field)| {
                format!("  {flag:width$}  {} (e.g. {})", field.help, field.example)
            })
            .collect::<Vec<_>>()
            .join("\n");
        bail!(
            "{name} is neither a built-in preset nor an already-configured network, so defining \
it as chain {chain_id} needs its complete profile.\n\nAll {} missing values:\n{lines}\n\n\
Run the same command in a terminal to be prompted for them one at a time, or see \
`ekubo-wallet network presets` for complete examples.",
            missing.len(),
        );
    }

    cliclack::intro(format!("Configure network {name} (chain {chain_id})"))?;
    cliclack::log::info(format!(
        "{} value(s) still needed: {}",
        missing.len(),
        missing
            .iter()
            .map(|field| field.flag)
            .collect::<Vec<_>>()
            .join(", ")
    ))?;
    let mut answers = BTreeMap::new();
    for field in CUSTOM_NETWORK_FIELDS {
        if let Some(Some(value)) = supplied.get(field.flag) {
            cliclack::log::info(format!("{}: {value}", field.prompt))?;
            answers.insert(field.flag, value.clone());
            continue;
        }
        // The RPC URL is shown rather than masked. It is configuration, not a
        // signing credential, and masking it made a typo impossible to spot
        // and forced a full re-entry on the next attempt. Prompting for it at
        // all still keeps any embedded key out of shell history.
        let mut input = cliclack::input(field.prompt)
            .placeholder(field.example)
            .validate(validator(field));
        if let Some(default) = field.default {
            input = input.default_input(default);
        }
        let value: String = input
            .interact()
            .with_context(|| format!("failed to read {} ({})", field.prompt, field.flag))?;
        answers.insert(field.flag, value);
    }
    cliclack::outro(format!(
        "{name} is fully described. Authorize the change to start trusting this RPC."
    ))?;
    Ok(answers)
}

/// Reject a malformed answer while the prompt is still open, rather than
/// after the whole profile has been typed out.
fn validator(field: &RequiredField) -> impl Fn(&String) -> std::result::Result<(), String> {
    let flag = field.flag;
    move |input: &String| {
        let value = input.trim();
        match flag {
            _ if value.is_empty() => Err("a value is required".into()),
            "--rpc-url" | "--block-explorer-url" | "--documentation-url" => Url::parse(value)
                .map_err(|error| format!("not a URL: {error}"))
                .and_then(|url| {
                    matches!(url.scheme(), "http" | "https")
                        .then_some(())
                        .ok_or_else(|| "must be an http or https URL".into())
                }),
            "--native-currency-decimals" => value
                .parse::<u8>()
                .map(|_| ())
                .map_err(|_| "must be a whole number from 0 to 255".into()),
            "--max-gas-limit" => value
                .parse::<u64>()
                .map_err(|_| "must be a whole number of gas".to_owned())
                .and_then(|limit| {
                    (limit >= 21_000)
                        .then_some(())
                        .ok_or_else(|| "must be at least the 21000 intrinsic gas".into())
                }),
            _ => Ok(()),
        }
    }
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
                candidates.extend(
                    MessageStore::production(config.data_dir())?
                        .awaiting_approval(None)?
                        .into_iter()
                        .map(|request| {
                            (
                                request.request_id.to_string(),
                                format!("message for {}", request.wallet_id),
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

    #[tokio::test]
    async fn transaction_line_and_detail_render_offline() {
        let plan = crate::core::execution_plan::ExecutionPlan::parse(serde_json::json!({
            "schema_version": "1",
            "chain_id": "1",
            "caip2_chain_id": "eip155:1",
            "sender": "0x1111111111111111111111111111111111111111",
            "ordered_steps": [{
                "step": 1,
                "kind": "execution",
                "submit_condition": "always",
                "transaction": {
                    "chain_id": "1",
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0xa9059cbb",
                    "value": "5"
                }
            }]
        }))
        .unwrap();
        let now = chrono::Utc::now();
        let record = PendingTransaction {
            request_id: Uuid::nil(),
            wallet_id: "primary".into(),
            network_name: "ethereum".into(),
            chain_id: "1".into(),
            digest: format!("{:#x}", plan.digest()),
            execution_plan: plan,
            review_digest: None,
            policy_revision: 3,
            approval_required: true,
            status: PendingStatus::AwaitingApproval,
            created_at: now - chrono::TimeDelta::minutes(7),
            expires_at: now + chrono::TimeDelta::minutes(3),
            updated_at: now - chrono::TimeDelta::minutes(7),
            approved_at: None,
            rejected_at: None,
            serialized_transaction: None,
            signed_transaction_hash: None,
            broadcast_transaction_hash: None,
            block_number: None,
        };

        let line = transaction_line(&record);
        assert!(line.contains("7 minutes ago"));
        assert!(line.contains("awaiting approval"));
        assert!(line.contains("primary"));
        assert!(line.contains("1 call(s), 5 wei native"));

        // An awaiting record renders entirely from stored data: no RPC.
        let directory = tempfile::tempdir().unwrap();
        let config = ConfigStore::new(directory.path());
        let detail = transaction_detail(&config, &record).await;
        assert!(detail.contains("Status: awaiting approval"));
        assert!(detail.contains("Network: ethereum (chain 1)"));
        assert!(detail.contains("Expires: in 3 minutes"));
        assert!(detail.contains("Call 1: to 0x2222222222222222222222222222222222222222"));
        assert!(detail.contains("selector 0xa9059cbb"));
        assert!(detail.contains("Policy revision: 3; approval required"));

        // A broadcast hash yields an explorer link from the configured network.
        let mut broadcast = record;
        broadcast.status = PendingStatus::Signed;
        broadcast.serialized_transaction = Some("0x0102".into());
        broadcast.signed_transaction_hash = Some(format!("0x{}", "aa".repeat(32)));
        let detail = transaction_detail(&config, &broadcast).await;
        assert!(detail.contains(&format!("https://etherscan.io/tx/0x{}", "aa".repeat(32))));
    }

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

    fn add_args(name: &str, chain_id: Option<u64>) -> NetworkAddArgs {
        NetworkAddArgs {
            name: name.into(),
            chain_id,
            rpc_url: None,
            display_name: None,
            aliases: Vec::new(),
            native_currency_name: None,
            native_currency_symbol: None,
            native_currency_decimals: None,
            max_gas_limit: None,
            block_explorer_url: None,
            documentation_url: None,
        }
    }

    #[test]
    fn editing_a_configured_network_only_needs_the_field_that_changes() {
        let mut configured = default_networks();
        let base = configured
            .iter_mut()
            .find(|network| network.name == "base")
            .unwrap();
        base.display_name = Some("My Base".into());
        base.max_gas_limit = Some("1234567".into());
        let configured = configured;

        let mut args = add_args("base", None);
        args.rpc_url = Some("https://rpc.example.invalid/base".parse().unwrap());
        let candidate = network_candidate(args, &configured).unwrap();

        assert_eq!(
            candidate.rpc_url.as_str(),
            "https://rpc.example.invalid/base"
        );
        // Everything the user did not name survives, including their own
        // earlier customizations rather than the preset's values.
        assert_eq!(candidate.display_name.as_deref(), Some("My Base"));
        assert_eq!(candidate.max_gas_limit.as_deref(), Some("1234567"));
        assert_eq!(candidate.chain_id, 8453);
        assert!(!candidate.aliases.is_empty());
    }

    #[test]
    fn an_alias_and_a_matching_chain_id_both_resolve_the_same_base() {
        let configured = default_networks();
        for (name, chain_id) in [("base-mainnet", None), ("base", Some(8453))] {
            let candidate = network_candidate(add_args(name, chain_id), &configured).unwrap();
            assert_eq!(candidate.name, "base");
            assert_eq!(candidate.chain_id, 8453);
        }
    }

    #[test]
    fn preset_network_add_uses_complete_catalog_metadata() {
        let candidate = network_candidate(add_args("eth", None), &[]).unwrap();
        assert_eq!(candidate.name, "ethereum");
        assert_eq!(candidate.chain_id, 1);
        assert!(candidate.native_currency.is_some());
        assert!(candidate.max_gas_limit.is_some());
    }

    #[test]
    fn an_unknown_network_without_a_chain_id_says_where_to_look() {
        let error = network_candidate(add_args("nowhere", None), &default_networks())
            .expect_err("an unknown name is not a network");
        let message = error.to_string();
        assert!(message.contains("network presets"), "{message}");
        assert!(message.contains("network list"), "{message}");
        assert!(message.contains("chain ID"), "{message}");
    }

    #[test]
    fn a_new_custom_network_reports_every_missing_value_at_once() {
        // Non-interactive, so this is the scripted path: one error has to
        // name the complete set, or fixing it takes one run per flag.
        let error = network_candidate(add_args("custom", Some(987_654)), &default_networks())
            .expect_err("an incomplete custom network is rejected");
        let message = error.to_string();
        for flag in CUSTOM_NETWORK_FIELDS.iter().map(|field| field.flag) {
            assert!(message.contains(flag), "{flag} missing from:\n{message}");
        }
        assert!(message.contains("987654"), "{message}");
        // Every flag carries its own explanation and a usable example.
        assert!(message.contains("eth_simulateV1"), "{message}");
        assert!(message.contains("16777216"), "{message}");
    }

    #[test]
    fn a_complete_custom_network_needs_no_terminal_at_all() {
        let mut args = add_args("custom", Some(987_654));
        args.rpc_url = Some("https://rpc.example.invalid".parse().unwrap());
        args.display_name = Some("Custom Chain".into());
        args.aliases = vec!["custom-chain".into()];
        args.native_currency_name = Some("Ether".into());
        args.native_currency_symbol = Some("ETH".into());
        args.native_currency_decimals = Some(18);
        args.max_gas_limit = Some("16777216".into());
        args.block_explorer_url = Some("https://explorer.example.invalid".parse().unwrap());
        args.documentation_url = Some("https://docs.example.invalid".parse().unwrap());
        let candidate = network_candidate(args, &default_networks()).unwrap();
        assert_eq!(candidate.chain_id, 987_654);
        assert_eq!(candidate.aliases, vec!["custom-chain".to_owned()]);
        assert_eq!(candidate.native_currency.unwrap().decimals, 18);
    }

    #[test]
    fn prompt_validation_rejects_malformed_answers_before_the_next_question() {
        let field = |flag: &str| {
            CUSTOM_NETWORK_FIELDS
                .iter()
                .find(|field| field.flag == flag)
                .expect("declared field")
        };
        let rpc = validator(field("--rpc-url"));
        assert!(rpc(&"https://rpc.example.invalid".to_owned()).is_ok());
        assert!(rpc(&"rpc.example.invalid".to_owned()).is_err());
        assert!(rpc(&"ftp://rpc.example.invalid".to_owned()).is_err());
        assert!(rpc(&String::new()).is_err());

        let decimals = validator(field("--native-currency-decimals"));
        assert!(decimals(&"18".to_owned()).is_ok());
        assert!(decimals(&"18.5".to_owned()).is_err());

        let gas = validator(field("--max-gas-limit"));
        assert!(gas(&"16777216".to_owned()).is_ok());
        assert!(gas(&"1000".to_owned()).is_err());

        // Every declared default has to survive its own validator.
        for entry in CUSTOM_NETWORK_FIELDS {
            if let Some(default) = entry.default {
                assert!(
                    validator(entry)(&default.to_owned()).is_ok(),
                    "{} offers a default its validator rejects",
                    entry.flag
                );
            }
        }
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
