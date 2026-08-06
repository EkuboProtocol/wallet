use crate::approve_tui::TerminalApprovalUi;
use crate::{
    VERSION,
    address_book::AddressBookStore,
    approval::{ApprovalDecision, ApprovalKind, ApprovalRequest, ApprovalUi},
    config::{
        ConfigStore, NativeCurrency, NetworkConfig, default_networks, remove_configured_network,
        replace_configured_network,
    },
    core::policy::WalletPolicy,
    custody::{CustodyService, OsKeyStore, PrivateKeyMaterial, load_matching_signer},
    human_presence::{HumanPresence, PlatformHumanPresence, PresenceRequest},
    legal::{self, LegalDocument, LegalStore},
    message::{
        MessageStatus, MessageStore, PendingMessage, describe_message, message_digest, parse_siwe,
        siwe_warnings,
    },
    pending::{PendingStatus, PendingStore, PendingTransaction},
    policy_store::PolicyStore,
    render::{OutputMode, described_time, emit, print_json, relative_time},
    rpc::verify_chain_id,
    simulation::SimulationResult,
    tx_browser::status_label,
    typed_data::{
        PendingTypedData, TypedDataStatus, TypedDataStore, interpret_permit_approvals,
        parse_typed_data,
    },
};
use alloy::{primitives::Address, signers::SignerSync};
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use directories::BaseDirs;
use num_bigint::BigUint;
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
    /// Browse and edit per-chain address aliases used for agent lookups.
    /// Bare, on a terminal, this opens the full-screen editor.
    #[command(name = "address-book")]
    AddressBook(AddressBookArgs),
    /// Read legal documents and record their acceptance.
    Legal(LegalArgs),
    /// List exceptional requests, or review one locally and approve or reject it.
    Review {
        request_id: Option<Uuid>,
        /// Decide without the interactive prompt. Approving still requires
        /// platform owner authentication.
        #[arg(long, value_enum)]
        decision: Option<ReviewDecision>,
    },
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
    Create {
        wallet_id: String,
        /// Starting policy. Asked for in a terminal when omitted; anywhere
        /// else the safe choice is taken rather than guessed at.
        #[arg(long, value_enum)]
        policy: Option<StartingPolicy>,
    },
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
    /// Replace a wallet policy from a JSON file after terminal confirmation.
    Set {
        wallet_id: String,
        policy_file: PathBuf,
    },
    /// Install the wildcard automatic policy after terminal confirmation.
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
    /// Without arguments, every choice is prompted for interactively.
    Add(Box<NetworkAddArgs>),
    /// Interactively edit one configured network field by field.
    Edit { name: Option<String> },
    /// Remove a configured network by name or alias.
    #[command(alias = "delete")]
    Remove { name: String },
}

#[derive(Debug, Args)]
struct NetworkAddArgs {
    /// Preset or custom network name; taken from whatever already describes
    /// the chain ID when omitted.
    name: Option<String>,
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
    command: Option<AddressBookCommand>,
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
    /// Add or update one alias after terminal confirmation and owner
    /// authentication.
    Add {
        /// Network name, alias, or decimal chain ID.
        network: String,
        alias: String,
        address: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Remove one alias after terminal confirmation and owner
    /// authentication.
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

/// The policy a brand-new wallet starts under.
///
/// A generated key holds nothing until it is funded, which is why creation
/// used to install the permissive profile and print a line asking the user to
/// replace it before funding. Printed advice cannot tell whether it was
/// followed, and funding does not revisit the policy, so the window closed
/// only for users who remembered. Asking once, here, is the same decision
/// without the gap — and it lines up `create` with `import`, which has always
/// started locked down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum StartingPolicy {
    /// Nothing signs without an explicit CLI review.
    RequireApproval,
    /// Sign automatically; ask only when policy or simulation fails.
    AllowAll,
}

impl StartingPolicy {
    fn policy(self) -> WalletPolicy {
        match self {
            Self::RequireApproval => WalletPolicy::require_approval_for_everything(),
            Self::AllowAll => WalletPolicy::allow_all_with_approval(),
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::RequireApproval => "the require-approval policy: nothing signs automatically",
            Self::AllowAll => {
                "the allow-all policy: signing is automatic until policy or simulation fails"
            }
        }
    }
}

/// A decision supplied on the command line instead of at the prompt, so a
/// script or a remote session can resolve a request without a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ReviewDecision {
    /// Record the rejection. Nothing is signed; needs no terminal.
    Reject,
    /// Sign the request. Platform owner authentication still applies.
    Approve,
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
    /// Review tokens an agent suggested, and confirm the ones to trust.
    ///
    /// Confirming a token is what lets the wallet show its symbol when
    /// reviewing a transaction, so nothing an agent proposes is displayed as a
    /// name until it is accepted here.
    Review,
    /// Import a token list file, confirming what to trust in the terminal.
    ///
    /// Reads the standard token-list shape: a `tokens` array of entries with
    /// `chainId`, `address`, `symbol`, `name`, and `decimals`, or a bare array
    /// of the same.
    Import {
        /// Path to the token list JSON file.
        path: std::path::PathBuf,
        /// Name recorded as the source of these tokens; defaults to the
        /// list's own `name` field, then to the file name.
        #[arg(long)]
        list_name: Option<String>,
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
    /// Attempt to cancel a broadcast but unmined transaction by outbidding it
    /// with a 0-value self-send at the same nonce. Fails if it already mined.
    Cancel { identifier: String },
    /// Rebroadcast the exact already-signed bytes of a broadcast but unmined
    /// transaction, for example after it fell out of mempools.
    Rebroadcast { identifier: String },
    /// Discard a signed but never-broadcast transaction, freeing its
    /// wallet+chain in-flight slot. Anything that reached the network is
    /// refused; cancel that on chain instead.
    Discard { identifier: String },
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
            Command::Policy(args) => run_policy(&config, args.command, mode).await,
            Command::Transaction(args) => run_transaction(&config, args.command, mode).await,
            Command::Token(args) => run_token(&config, &args.command, mode).await,
            Command::AddressBook(args) => run_address_book(&config, args.command, mode).await,
            Command::Legal(args) => run_legal(&config, &args.command, mode),
            Command::Review {
                request_id,
                decision,
            } => run_review(&config, request_id, decision, mode).await,
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
                            "{}\n  address: {:#x}\n  source: {:?}\n  created: {}\n  key exported: {}",
                            wallet.id,
                            wallet.address,
                            wallet.source,
                            described_time(wallet.created_at),
                            // Only this tool's own exports are recorded; the OS
                            // credential store can hand the key out without
                            // telling us, so this is not a custody guarantee.
                            wallet
                                .exported_at
                                .map_or_else(|| "no".to_string(), described_time),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            })
        }
        WalletCommand::Create { wallet_id, policy } => {
            // Chosen before the key exists, so a wallet is never briefly
            // permissive while the user is still deciding, and a cancelled
            // prompt leaves nothing behind.
            let Some(starting) = resolve_starting_policy(policy)? else {
                crate::tui::outro_cancel("No wallet was created.");
                return Ok(());
            };
            let wallet = custody.create(&wallet_id)?;
            initialize_wallet_policy(&config, &wallet.id, &starting.policy()).with_context(|| {
                format!(
                    "wallet {} was created but policy initialization failed; signing will fail closed",
                    wallet.id
                )
            })?;
            emit(mode, &wallet, || {
                Ok(format!(
                    "Created wallet {} at {:#x} with {}.",
                    wallet.id,
                    wallet.address,
                    starting.description()
                ))
            })
        }
        WalletCommand::Import { wallet_id } => {
            require_interactive("wallet import")?;
            crate::tui::intro("Import an existing wallet");
            let mut input = crate::tui::text("Private key")
                .masked()
                .prompt_required()
                .context("failed to read private key")?;
            let key = PrivateKeyMaterial::from_hex(&input)?;
            input.zeroize();

            let progress =
                crate::tui::Progress::start("Saving the key in the platform credential store");
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
                    crate::tui::outro(
                        "Imported wallets start with the require-approval policy: nothing signs \
                         automatically until you install a more permissive policy.",
                    );
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
                    "Export reveals the raw key and cannot be undone. Anyone holding it signs directly, with no policy, simulation, or approval in the way.",
                ),
            )
            .await?;

            let progress = crate::tui::Progress::start("Waiting for owner authentication");
            let result = custody.export(&wallet_id).await;
            let key = match result {
                Ok(key) => {
                    progress.stop("Owner authenticated; export recorded");
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

            let progress = crate::tui::Progress::start("Waiting for owner authentication");
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

async fn run_token(config: &ConfigStore, command: &TokenCommand, mode: OutputMode) -> Result<()> {
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
        TokenCommand::Review => run_token_review(config, mode).await,
        TokenCommand::Import { path, list_name } => {
            run_token_import(config, path, list_name.as_deref(), mode).await
        }
    }
}

/// One entry of a standard token-list file. Field names follow the token-list
/// convention so a published list parses unmodified.
#[derive(Debug, serde::Deserialize)]
struct TokenListEntry {
    #[serde(rename = "chainId")]
    chain_id: u64,
    address: String,
    symbol: String,
    #[serde(default)]
    name: Option<String>,
    decimals: u8,
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum TokenListFile {
    Wrapped {
        #[serde(default)]
        name: Option<String>,
        tokens: Vec<TokenListEntry>,
    },
    Bare(Vec<TokenListEntry>),
}

/// Import a token list the owner points at, confirming entries in the
/// terminal. This is the trusted way names get into the database: the owner
/// chose the file, and sees exactly what it would name before anything is
/// written.
async fn run_token_import(
    config: &ConfigStore,
    path: &std::path::Path,
    list_name: Option<&str>,
    mode: OutputMode,
) -> Result<()> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read token list {}", path.display()))?;
    let parsed: TokenListFile = serde_json::from_str(&body)
        .with_context(|| format!("{} is not a token list", path.display()))?;
    let (declared_name, entries) = match parsed {
        TokenListFile::Wrapped { name, tokens } => (name, tokens),
        TokenListFile::Bare(tokens) => (None, tokens),
    };
    let source = list_name
        .map(str::to_owned)
        .or(declared_name)
        .unwrap_or_else(|| {
            path.file_name()
                .map_or_else(|| "token list".into(), |name| name.to_string_lossy().into())
        });
    ensure!(!entries.is_empty(), "{} lists no tokens", path.display());

    let mut listed = Vec::with_capacity(entries.len());
    for entry in entries {
        listed.push(crate::token_store::ListedToken {
            chain_id: entry.chain_id,
            address: Address::from_str(&entry.address)
                .with_context(|| format!("token address {} is not valid", entry.address))?,
            symbol: entry.symbol,
            name: entry.name,
            decimals: entry.decimals,
        });
    }
    confirm_and_store(config, vec![(source, listed)], mode, &[]).await
}

/// Review what agents have suggested. Accepting writes the names; rejecting
/// forgets the suggestion so the same screen does not reappear unchanged.
async fn run_token_review(config: &ConfigStore, mode: OutputMode) -> Result<()> {
    let store = crate::token_store::TokenStore::production(config.data_dir())?;
    let proposals = store.proposals()?;
    drop(store);
    if proposals.is_empty() {
        return emit(mode, &serde_json::json!({ "awaiting_review": 0 }), || {
            Ok("No tokens are waiting for review.".into())
        });
    }
    if mode == OutputMode::Json || !crate::tui::interactive() {
        return emit(
            mode,
            &serde_json::json!({
                "awaiting_review": proposals.len(),
                "tokens": proposals
                    .iter()
                    .map(|proposal| serde_json::json!({
                        "chain_id": proposal.token.chain_id,
                        "address": proposal.token.address.to_checksum(None),
                        "symbol": proposal.token.symbol,
                        "decimals": proposal.token.decimals,
                        "source": proposal.source,
                        "proposed_at": proposal.proposed_at,
                    }))
                    .collect::<Vec<_>>(),
            }),
            || {
                Ok(format!(
                    "{} token(s) await review. Run `ekubo-wallet token review` in a \
                     terminal to confirm them.",
                    proposals.len()
                ))
            },
        );
    }

    // Group by the list that vouched for them: that is the unit the owner
    // actually decides, and it keeps a hundred suggestions to a few choices.
    let mut grouped: std::collections::BTreeMap<String, Vec<crate::token_store::ListedToken>> =
        std::collections::BTreeMap::new();
    for proposal in proposals {
        grouped
            .entry(proposal.source)
            .or_default()
            .push(proposal.token);
    }
    let groups: Vec<(String, Vec<crate::token_store::ListedToken>)> = grouped.into_iter().collect();
    let proposed: Vec<(u64, Address)> = groups
        .iter()
        .flat_map(|(_, tokens)| tokens.iter().map(|token| (token.chain_id, token.address)))
        .collect();
    confirm_and_store(config, groups, mode, &proposed).await
}

/// Show the picker, verify what the owner accepted against the chain, and
/// write it. `clear_proposals` is the set to drop from the proposal queue once
/// a decision is made, so a reviewed suggestion is not asked about twice.
async fn confirm_and_store(
    config: &ConfigStore,
    groups: Vec<(String, Vec<crate::token_store::ListedToken>)>,
    mode: OutputMode,
    clear_proposals: &[(u64, Address)],
) -> Result<()> {
    let sources: std::collections::BTreeMap<(u64, Address), String> = groups
        .iter()
        .flat_map(|(source, tokens)| {
            tokens
                .iter()
                .map(move |token| ((token.chain_id, token.address), source.clone()))
        })
        .collect();
    let picker_groups = groups
        .into_iter()
        .map(|(source, tokens)| crate::token_picker::TokenGroup { source, tokens })
        .collect();
    let Some(decision) = crate::token_picker::review(picker_groups)? else {
        return emit(mode, &serde_json::json!({ "confirmed": 0 }), || {
            Ok("Nothing confirmed; the suggestions are still waiting.".into())
        });
    };

    // Rejection needs no chain access: the owner has said no, and the only
    // thing left is to stop asking.
    let mut store = crate::token_store::TokenStore::production(config.data_dir())?;
    if !decision.rejected.is_empty() {
        let keys: Vec<(u64, Address)> = decision
            .rejected
            .iter()
            .map(|token| (token.chain_id, token.address))
            .collect();
        let removed = store.discard_proposals(&keys)?;
        return emit(
            mode,
            &serde_json::json!({ "confirmed": 0, "rejected": removed }),
            || {
                Ok(format!(
                    "Rejected {removed} suggestion(s); nothing was named."
                ))
            },
        );
    }

    // Accepting is where the chain finally gets its veto: confirm a token
    // lives at each address and that decimals agree with what the owner just
    // read, one Multicall3 pass per chain.
    let mut by_chain: std::collections::BTreeMap<u64, Vec<crate::token_store::ListedToken>> =
        std::collections::BTreeMap::new();
    for token in decision.accepted {
        by_chain.entry(token.chain_id).or_default().push(token);
    }
    let mut confirmed = 0_u64;
    let mut refused: Vec<String> = Vec::new();
    let mut decided: Vec<(u64, Address)> = Vec::new();
    for (chain_id, tokens) in by_chain {
        let Ok(network) = config.network_by_chain_id(&chain_id.to_string()) else {
            refused.push(format!("chain {chain_id}: no configured network"));
            continue;
        };
        for (token, rejection) in crate::token_store::verify_listings(&network, &tokens).await? {
            let key = (token.chain_id, token.address);
            if let Some(rejection) = rejection {
                refused.push(format!(
                    "{} ({}): {rejection}",
                    token.symbol,
                    token.address.to_checksum(None)
                ));
                continue;
            }
            let source = sources.get(&key).cloned().unwrap_or_else(|| "list".into());
            if store.insert_if_absent(&token, &source)? {
                confirmed += 1;
            }
            decided.push(key);
        }
    }
    // Only forget suggestions that were actually decided. One refused by the
    // chain stays queued, because the owner's answer was yes and the reason it
    // did not land is worth showing again.
    if !clear_proposals.is_empty() {
        let clear: Vec<(u64, Address)> = decided
            .into_iter()
            .filter(|key| clear_proposals.contains(key))
            .collect();
        store.discard_proposals(&clear)?;
    }
    emit(
        mode,
        &serde_json::json!({ "confirmed": confirmed, "refused": refused }),
        || {
            let mut lines = vec![format!("Confirmed {confirmed} token name(s).")];
            for entry in &refused {
                lines.push(format!("  refused — {entry}"));
            }
            Ok(lines.join("\n"))
        },
    )
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
    command: Option<AddressBookCommand>,
    mode: OutputMode,
) -> Result<()> {
    match command {
        // The bare command opens the full-screen editor; without a terminal
        // (or under --json) it degrades to the plain listing.
        None => {
            if mode == OutputMode::Json || !crate::tui::interactive() {
                return list_address_book(config, None, 200, 0, mode);
            }
            crate::address_book_browser::browse(config, &PlatformHumanPresence).await
        }
        Some(AddressBookCommand::List {
            network,
            limit,
            offset,
        }) => list_address_book(config, network.as_deref(), limit, offset, mode),
        Some(AddressBookCommand::Add {
            network,
            alias,
            address,
            note,
        }) => {
            require_interactive("address book changes")?;
            crate::address_book::validate_alias(&alias)?;
            let network = resolve_network(config, &network)?;
            let address =
                Address::from_str(&address).context("address must be a 20-byte EVM address")?;
            let draft = crate::address_book_browser::EntryDraft {
                chain_id: network.chain_id,
                network_name: network.name,
                alias,
                address,
                note: note.filter(|note| !note.trim().is_empty()),
            };
            match crate::address_book_browser::confirm_and_save(
                config,
                &PlatformHumanPresence,
                &draft,
            )
            .await?
            {
                Some(entry) => emit(mode, &entry, || {
                    Ok(format!(
                        "Stored {} → {} on chain {}.",
                        entry.alias, entry.address, entry.chain_id
                    ))
                }),
                None => Ok(()),
            }
        }
        Some(AddressBookCommand::Remove { network, alias }) => {
            require_interactive("address book changes")?;
            let network = resolve_network(config, &network)?;
            match crate::address_book_browser::confirm_and_remove(
                config,
                &PlatformHumanPresence,
                &network.name,
                network.chain_id,
                &alias,
            )
            .await?
            {
                Some(removed) => emit(mode, &serde_json::json!({ "removed": removed }), || {
                    Ok(format!(
                        "Removed {} → {} from chain {}.",
                        removed.alias, removed.address, removed.chain_id
                    ))
                }),
                None => Ok(()),
            }
        }
    }
}

fn list_address_book(
    config: &ConfigStore,
    network: Option<&str>,
    limit: usize,
    offset: usize,
    mode: OutputMode,
) -> Result<()> {
    let chain_id = network
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
                    "The address book is empty. Run `ekubo-wallet address-book` to add aliases interactively, or `ekubo-wallet address-book add <network> <alias> <address>`.".into(),
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

fn run_legal(config: &ConfigStore, command: &LegalCommand, mode: OutputMode) -> Result<()> {
    // `legal show` needs no store at all; keep it usable before any
    // credential-store or database access is possible.
    if let LegalCommand::Show { document } = command {
        let document = document.document();
        // Reading it on screen and capturing it are different jobs. A
        // terminal gets the pager, so a long document is scrollable instead
        // of being dumped into the scrollback; a pipe or a file gets the
        // exact bytes the digest is taken over, unwrapped and unpaged.
        if io::stdout().is_terminal() && crate::tui::interactive() {
            crate::pager::read_fully(document.title(), &terminal_note_safe(&document.text()))?;
            return Ok(());
        }
        let mut stdout = io::stdout().lock();
        stdout.write_all(document.text().as_bytes())?;
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
            // The question is only asked once the document has actually been
            // read to the end: the pager owns the screen, so there is no
            // scrollback to fight, and it reports whether the reader ever got
            // there. Quitting early is a decline, not a re-prompt.
            let accept = |document: LegalDocument, prompt: &str| -> Result<bool> {
                let digest = document.digest();
                let body = format!(
                    "{}\n\nDocument digest: {digest}",
                    terminal_note_safe(&document.text())
                );
                if crate::pager::read_fully(document.title(), &body)?
                    != crate::pager::Outcome::ReadToEnd
                {
                    crate::tui::warning(format!(
                        "{} was closed before the end; nothing was accepted.",
                        document.title()
                    ));
                    return Ok(false);
                }
                crate::tui::info(format!("Document digest: {digest}"));
                let accepted = crate::tui::confirm(prompt)?;
                if accepted {
                    store.record_acceptance(document, &digest)?;
                }
                Ok(accepted)
            };
            crate::tui::intro("Ekubo Wallet legal acceptance");
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
            crate::tui::outro("Recorded. Signing is now enabled for this installation.");
            let status = store.status()?;
            emit(mode, &status, || Ok(render_status(&status)))
        }
    }
}

/// Legal texts are trusted compile-time strings, but they pass through the
/// same stripping as every other terminal output.
fn terminal_note_safe(text: &str) -> String {
    crate::render::terminal_safe_multiline(text)
}

async fn run_policy(config: &ConfigStore, command: PolicyCommand, mode: OutputMode) -> Result<()> {
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
            replace_policy(config, &wallet_id, &policy, Some(&policy_file), mode).await
        }
        PolicyCommand::AllowAll { wallet_id } => {
            replace_policy(
                config,
                &wallet_id,
                &WalletPolicy::allow_all_with_approval(),
                None,
                mode,
            )
            .await
        }
        PolicyCommand::RequireApproval { wallet_id } => {
            replace_policy(
                config,
                &wallet_id,
                &WalletPolicy::require_approval_for_everything(),
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
            let digest = policy.digest()?;
            emit(
                mode,
                &serde_json::json!({
                    "valid": true,
                    "policy_file": policy_file.display().to_string(),
                    "digest": digest,
                    "version": policy.version,
                    "chains": policy.chains.keys().collect::<Vec<_>>(),
                    "policy": policy,
                }),
                || {
                    Ok(format!(
                        "{} is a valid policy.\n  digest: {digest}\n  chains: {}",
                        policy_file.display(),
                        policy.chains.keys().cloned().collect::<Vec<_>>().join(", "),
                    ))
                },
            )
        }
        // The schema is itself a JSON document; there is no human form.
        PolicyCommand::Schema => print_json(&policy_json_schema()),
        PolicyCommand::Review { wallet_id } => {
            review_policy_proposal(config, &wallet_id, mode).await
        }
    }
}

/// Review and apply the single pending agent-proposed policy for a wallet.
/// The reviewer sees a minimized permission diff and the agent's rationale,
/// never a raw JSON comparison; application is confirmed in the terminal,
/// then authenticated against the OS — the policy decides what may be signed
/// with nobody watching, so replacing it requires the owner even though no
/// key material is read — and is revision-guarded end to end.
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
    let digest = proposal.policy.digest()?;
    let mut question = crate::tui::Confirmation::new(
        "Apply proposed wallet policy",
        "An agent proposed this replacement policy. The permission diff below is authoritative; \
         the rationale is the agent's own explanation.",
    )
    .fact("Wallet", &wallet.id)
    .fact("Address", format!("{:#x}", wallet.address))
    .fact("Current revision", current.revision.to_string())
    .fact("Proposed", described_time(proposal.created_at))
    .fact("Agent rationale (untrusted)", &proposal.rationale);
    for (index, line) in diff.iter().enumerate() {
        question = question.fact(format!("Change {}", index + 1), line);
    }
    question = question
        .warning(
            "A more permissive policy can authorize transactions without an exceptional approval.",
        )
        .warning(
            "The rationale is agent-authored text. Judge the change by the diff lines, not the \
             story.",
        );
    if !question.ask("Apply this policy?")? {
        crate::tui::outro_cancel("Policy unchanged. The proposal is still pending.");
        return Ok(());
    }

    PlatformHumanPresence
        .confirm(&PresenceRequest::ReplacePolicy {
            wallet: wallet.id.clone(),
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
            // Settle in-flight rows against the chain before display. The
            // in-flight unique index bounds this at one row per wallet and
            // chain, so a long listing still costs at most a couple of RPCs.
            let pending = std::sync::Mutex::new(pending);
            let transactions =
                crate::reconcile::reconcile_all(config, &pending, transactions).await;
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
                crate::tx_browser::browse(config, &pending, transactions).await
            } else {
                for record in &transactions {
                    println!("{}", transaction_line(record));
                }
                Ok(())
            }
        }
        TransactionCommand::Show { identifier } => {
            let record = pending.get_by_identifier(&identifier)?;
            let pending = std::sync::Mutex::new(pending);
            let record = crate::reconcile::reconcile_all(config, &pending, vec![record])
                .await
                .pop()
                .expect("reconciled listing keeps its single record");
            if mode == OutputMode::Json {
                return print_json(&record);
            }
            let detail = crate::tx_browser::load_detail(config, &record).await;
            println!(
                "{}",
                crate::fullscreen::lines_to_text(&detail, crate::tui::paint_stdout)
            );
            Ok(())
        }
        TransactionCommand::Cancel { identifier } => {
            let record = pending.get_by_identifier(&identifier)?;
            let wallet = config.wallet(&record.wallet_id)?;
            let network = config.network_by_chain_id(&record.chain_id)?;
            let pending = std::sync::Mutex::new(pending);
            let (record, broadcast) = crate::reconcile::attempt_cancellation(
                &pending,
                &wallet,
                &network,
                record,
                &OsKeyStore,
            )
            .await?;
            if mode == OutputMode::Json {
                return print_json(&serde_json::json!({
                    "transaction": record,
                    "broadcast": broadcast,
                }));
            }
            println!("{}", transaction_line(&record));
            match record.status {
                PendingStatus::Cancelled => println!(
                    "Cancellation mined in block {}; the original plan will never execute.",
                    record.block_number.as_deref().unwrap_or("unknown")
                ),
                PendingStatus::Cancelling => println!(
                    "Cancellation {} broadcast; it races the original at the same nonce. \
                     Run `ekubo-wallet transaction show {}` to watch the outcome.",
                    broadcast.transaction_hash, record.request_id
                ),
                // attempt_cancellation reconciled a rejection into what it
                // actually meant, for example the original mining first.
                _ => {}
            }
            if let Some(error) = &broadcast.broadcast_error {
                println!("Broadcast reported: {error}");
            }
            Ok(())
        }
        TransactionCommand::Rebroadcast { identifier } => {
            let record = pending.get_by_identifier(&identifier)?;
            let wallet = config.wallet(&record.wallet_id)?;
            let network = config.network_by_chain_id(&record.chain_id)?;
            let pending = std::sync::Mutex::new(pending);
            let record =
                crate::reconcile::reconcile_record(&pending, &network, record, true).await?;
            ensure!(
                record.status == PendingStatus::Broadcast,
                "nothing to rebroadcast: the transaction is {}",
                status_label(record.status)
            );
            let claimed = pending
                .lock()
                .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
                .claim_broadcast_retry(record.request_id)?;
            let (record, broadcast) =
                crate::reconcile::submit_claimed(&pending, &wallet, &network, claimed).await?;
            if mode == OutputMode::Json {
                return print_json(&serde_json::json!({
                    "transaction": record,
                    "broadcast": broadcast,
                }));
            }
            println!("{}", transaction_line(&record));
            if let Some(error) = &broadcast.broadcast_error {
                println!("Broadcast reported: {error}");
            }
            Ok(())
        }
        TransactionCommand::Discard { identifier } => {
            let mut pending = pending;
            let record = pending.get_by_identifier(&identifier)?;
            let record = pending.discard_unsent(record.request_id)?;
            if mode == OutputMode::Json {
                return print_json(&record);
            }
            println!(
                "Discarded {}: the signed bytes were never broadcast, so nothing can mine and \
                 the wallet's in-flight slot is free again.",
                record.request_id
            );
            Ok(())
        }
    }
}

fn transaction_line(record: &PendingTransaction) -> String {
    format!(
        "{} · {} · {} on chain {} · {} call(s), {} wei native · {}",
        relative_time(record.created_at),
        status_label(record.status),
        record.wallet_id,
        record.chain_id,
        record.execution_plan.ordered_steps.len(),
        plan_native_total(record),
        record.request_id,
    )
}

/// Native value the whole plan moves, in wei. Steps whose value does not
/// parse contribute nothing rather than poisoning the total: this is a
/// display summary, and every exact per-call value is in the expanded view.
fn plan_native_total(record: &PendingTransaction) -> BigUint {
    record
        .execution_plan
        .ordered_steps
        .iter()
        .filter_map(|step| BigUint::from_str(step.transaction.value.as_str()).ok())
        .sum()
}

/// The visible page size for an interactive list in this CLI.
///
/// The prompt draws a header, a footer, and a blank separator around the list,
/// and the shell prompt returns underneath it; leaving that many rows free
/// keeps the whole prompt on one screen.
fn interactive_list_rows() -> usize {
    const PROMPT_CHROME_ROWS: usize = 6;
    crate::render::interactive_list_rows(PROMPT_CHROME_ROWS)
}

/// Show what awaits review, and — on an interactive terminal — let the user
/// pick an entry to review right there.
///
/// The browser is only ever navigation: choosing an entry leaves the
/// alternate screen first and the review runs exactly as
/// `ekubo-wallet review <request-id>` would — its JSON record prints into
/// the terminal transcript, and signature reviews then take over the screen
/// again for the scrollable document. When that review finishes, the queues
/// are reloaded and the browser returns, minus whatever was just resolved.
async fn list_pending_approvals(config: &ConfigStore, mode: OutputMode) -> Result<()> {
    loop {
        let awaiting = PendingStore::production(config.data_dir())?.awaiting_approval(None)?;
        let awaiting_typed_data =
            TypedDataStore::production(config.data_dir())?.awaiting_approval(None)?;
        let awaiting_messages =
            MessageStore::production(config.data_dir())?.awaiting_approval(None)?;
        let proposals = PolicyStore::production(config.data_dir())?.list_proposals()?;
        if mode == OutputMode::Json || !crate::tui::interactive() {
            return print_pending_approvals(
                mode,
                &awaiting,
                &awaiting_typed_data,
                &awaiting_messages,
                &proposals,
            );
        }
        if awaiting.is_empty()
            && awaiting_typed_data.is_empty()
            && awaiting_messages.is_empty()
            && proposals.is_empty()
        {
            crate::tui::info("Nothing is awaiting approval.");
            return Ok(());
        }
        let (rows, choices) = pending_approval_rows(
            config,
            &awaiting,
            &awaiting_typed_data,
            &awaiting_messages,
            &proposals,
        );
        let Some(index) =
            crate::fullscreen::pick_table("Pending approvals", "review", approval_columns(), rows)?
        else {
            return Ok(());
        };
        let outcome = match &choices[index] {
            PendingChoice::Request(request_id) => {
                run_approve(config, *request_id, false, mode).await
            }
            PendingChoice::Proposal(wallet_id) => {
                review_policy_proposal(config, wallet_id, mode).await
            }
        };
        // A failed review (expired mid-browse, declined authentication)
        // should not tear down the whole browser; report it and return to
        // the refreshed list.
        if let Err(error) = outcome {
            crate::tui::warning(format!("Review did not complete: {error:#}"));
        }
    }
}

/// What Enter reviews for one row of the pending-approvals browser.
enum PendingChoice {
    /// A queued signing request, reviewable by request ID whichever queue
    /// holds it.
    Request(Uuid),
    /// A policy proposal, reviewed per wallet.
    Proposal(String),
}

fn approval_columns() -> Vec<crate::fullscreen::TableColumn> {
    use crate::fullscreen::TableColumn;
    use ratatui::layout::Constraint;
    vec![
        TableColumn::new("Id", Constraint::Length(8)),
        TableColumn::new("Kind", Constraint::Length(11)),
        TableColumn::new("Age", Constraint::Length(14)),
        TableColumn::new("Wallet", Constraint::Fill(1)),
        TableColumn::new("Network", Constraint::Fill(1)),
    ]
}

/// The four pending queues flattened into browser rows, with the action each
/// row's Enter takes alongside.
fn pending_approval_rows(
    config: &ConfigStore,
    awaiting: &[PendingTransaction],
    awaiting_typed_data: &[PendingTypedData],
    awaiting_messages: &[PendingMessage],
    proposals: &[crate::policy_store::PolicyProposal],
) -> (Vec<crate::fullscreen::TableRow>, Vec<PendingChoice>) {
    use crate::fullscreen::{Span, TableRow};
    use crate::tui::Tone;
    let networks: BTreeMap<String, String> = config
        .load()
        .map(|loaded| {
            loaded
                .networks
                .into_iter()
                .map(|network| (network.chain_id.to_string(), network.name))
                .collect()
        })
        .unwrap_or_default();
    let network_name = |chain: &str| {
        networks
            .get(chain)
            .cloned()
            .unwrap_or_else(|| format!("chain {chain}"))
    };
    let none = || Span::toned("—", Tone::Muted);
    let short = |request_id: Uuid| {
        Span::toned(
            request_id.to_string().split('-').next().unwrap_or_default(),
            Tone::Muted,
        )
    };

    let mut rows = Vec::new();
    let mut choices = Vec::new();
    for record in awaiting {
        let network = network_name(&record.chain_id);
        rows.push(TableRow::new(
            vec![
                short(record.request_id),
                Span::plain("transaction"),
                Span::plain(relative_time(record.created_at)),
                Span::plain(&record.wallet_id),
                Span::plain(&network),
            ],
            &[
                &record.request_id.to_string(),
                "transaction",
                &record.wallet_id,
                &network,
                &record.chain_id,
            ],
        ));
        choices.push(PendingChoice::Request(record.request_id));
    }
    for record in awaiting_typed_data {
        let network = network_name(&record.chain_id);
        rows.push(TableRow::new(
            vec![
                short(record.request_id),
                Span::plain("typed data"),
                Span::plain(relative_time(record.created_at)),
                Span::plain(&record.wallet_id),
                Span::plain(&network),
            ],
            &[
                &record.request_id.to_string(),
                "typed data",
                &record.wallet_id,
                &network,
                &record.chain_id,
                &record.digest,
            ],
        ));
        choices.push(PendingChoice::Request(record.request_id));
    }
    for record in awaiting_messages {
        let network = record
            .chain_id
            .as_deref()
            .map(|chain| format!("{} (claimed)", network_name(chain)));
        rows.push(TableRow::new(
            vec![
                short(record.request_id),
                Span::plain("message"),
                Span::plain(relative_time(record.created_at)),
                Span::plain(&record.wallet_id),
                network.as_deref().map_or_else(none, Span::plain),
            ],
            &[
                &record.request_id.to_string(),
                "message",
                &record.wallet_id,
                network.as_deref().unwrap_or(""),
                &record.digest,
            ],
        ));
        choices.push(PendingChoice::Request(record.request_id));
    }
    for proposal in proposals {
        rows.push(TableRow::new(
            vec![
                none(),
                Span::plain("policy"),
                Span::plain(relative_time(proposal.created_at)),
                Span::plain(&proposal.wallet_id),
                none(),
                none(),
            ],
            &["policy proposal", &proposal.wallet_id, &proposal.rationale],
        ));
        choices.push(PendingChoice::Proposal(proposal.wallet_id.clone()));
    }
    (rows, choices)
}

/// The non-interactive listing: a summary on stderr and the queues on
/// stdout, exact JSON when the mode calls for it.
fn print_pending_approvals(
    mode: OutputMode,
    awaiting: &[PendingTransaction],
    awaiting_typed_data: &[PendingTypedData],
    awaiting_messages: &[PendingMessage],
    proposals: &[crate::policy_store::PolicyProposal],
) -> Result<()> {
    if awaiting.is_empty()
        && awaiting_typed_data.is_empty()
        && awaiting_messages.is_empty()
        && proposals.is_empty()
    {
        eprintln!("No requests are awaiting approval.");
    } else {
        eprintln!(
            "{} request(s) awaiting approval. Review one with `ekubo-wallet review <request-id>`; \
             they wait indefinitely.{}",
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
            for record in awaiting {
                lines.push(transaction_line(record));
            }
            for record in awaiting_typed_data {
                lines.push(format!(
                    "{} · typed data for {} on chain {} · {}",
                    relative_time(record.created_at),
                    record.wallet_id,
                    record.chain_id,
                    record.request_id,
                ));
            }
            for record in awaiting_messages {
                lines.push(format!(
                    "{} · message for {}{} · {}",
                    relative_time(record.created_at),
                    record.wallet_id,
                    record
                        .chain_id
                        .as_deref()
                        .map_or_else(String::new, |chain| format!(" (chain {chain} claimed)")),
                    record.request_id,
                ));
            }
            for proposal in proposals {
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

/// Record a rejection without reviewing anything first.
///
/// A request ID does not say which queue it belongs to, so each store is
/// tried in turn and the transaction store's error is what surfaces when no
/// queue claims it — that is the one the caller almost certainly meant.
fn run_reject(config: &ConfigStore, request_id: Uuid, mode: OutputMode) -> Result<()> {
    let request = match PendingStore::production(config.data_dir())?.reject(request_id) {
        Ok(request) => request,
        Err(transaction_error) => {
            let mut typed_data = TypedDataStore::production(config.data_dir())?;
            let Ok(request) = typed_data.reject(request_id) else {
                let mut messages = MessageStore::production(config.data_dir())?;
                let Ok(request) = messages.reject(request_id) else {
                    return Err(transaction_error);
                };
                return emit_rejected(
                    mode,
                    "message request",
                    request.request_id,
                    &request.digest,
                    request.rejected_at,
                );
            };
            return emit_rejected(
                mode,
                "typed-data request",
                request.request_id,
                &request.digest,
                request.rejected_at,
            );
        }
    };
    emit_rejected(
        mode,
        "request",
        request.request_id,
        &request.digest,
        request.rejected_at,
    )
}

/// One rejection, reported identically wherever it was decided: at the review
/// prompt or through `--decision reject`.
fn emit_rejected(
    mode: OutputMode,
    noun: &str,
    request_id: Uuid,
    digest: &str,
    rejected_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<()> {
    eprintln!("Rejected. An MCP agent waiting on this {noun} sees the rejection automatically.");
    emit(
        mode,
        &serde_json::json!({
            "rejected": request_id,
            "digest": digest,
            "rejected_at": rejected_at,
        }),
        || Ok(format!("Rejected {noun} {request_id}.")),
    )
}

/// Review one exceptional request and resolve it, either way.
///
/// Approving and rejecting were separate commands, which meant declining at
/// the approval prompt left the request sitting in the queue until a second
/// command was run against it. One command that ends in a decision cannot
/// leave that gap: whichever outcome the reviewer picks is recorded before
/// this returns.
async fn run_review(
    config: &ConfigStore,
    request_id: Option<Uuid>,
    decision: Option<ReviewDecision>,
    mode: OutputMode,
) -> Result<()> {
    let Some(request_id) = request_id else {
        return list_pending_approvals(config, mode).await;
    };
    // Rejecting needs no review and no terminal: it signs nothing, and a
    // scripted or remote session must always be able to say no.
    if decision == Some(ReviewDecision::Reject) {
        return run_reject(config, request_id, mode);
    }
    run_approve(
        config,
        request_id,
        decision == Some(ReviewDecision::Approve),
        mode,
    )
    .await
}

async fn run_approve(
    config: &ConfigStore,
    request_id: Uuid,
    no_confirm: bool,
    mode: OutputMode,
) -> Result<()> {
    require_interactive("transaction approval")?;
    legal::require_current_acceptance(config.data_dir())?;
    let pending = PendingStore::production(config.data_dir())?;
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
    let data_dir = config.data_dir().to_path_buf();
    let wallet_id = request.wallet_id.clone();
    let read_policy = move || -> Result<crate::policy_store::StoredPolicy> {
        PolicyStore::production(&data_dir)?
            .get(&wallet_id)?
            .with_context(|| format!("wallet {wallet_id} has no local policy"))
    };
    let outcome = crate::orchestrator::approve_transaction(
        config,
        pending,
        &crate::token_store::TokenStore::production(config.data_dir())?,
        &read_policy,
        request,
        crate::approval::InteractiveProof::from_terminal()?,
        &CliTransactionPresenter { no_confirm },
        &PlatformHumanPresence,
        &OsKeyStore,
    )
    .await?;
    match outcome {
        crate::orchestrator::ApprovalOutcome::Rejected(rejected) => emit_rejected(
            mode,
            "request",
            rejected.request_id,
            &rejected.digest,
            rejected.rejected_at,
        ),
        crate::orchestrator::ApprovalOutcome::Signed(approved) => {
            eprintln!(
                "Approved and signed. An MCP agent waiting on this request detects the approval \
                 and submits automatically; nothing further is needed here."
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
    }
}

/// The terminal implementation of the review seam: print the full review to
/// stderr, then run the reject-default picker. `no_confirm` skips only the
/// picker — owner authentication still follows in the orchestrator.
struct CliTransactionPresenter {
    no_confirm: bool,
}

#[async_trait::async_trait]
impl crate::approval::ReviewPresenter for CliTransactionPresenter {
    async fn review_transaction(
        &self,
        request: &ApprovalRequest,
        simulation: &SimulationResult,
    ) -> Result<ApprovalDecision> {
        print_approval_review(request, simulation)?;
        if self.no_confirm {
            return Ok(ApprovalDecision::Approved);
        }
        TerminalApprovalUi.review(request).await
    }
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
         shown at the end of this review.",
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

    // A vendored ERC-7730 descriptor reading, when the domain matches one
    // exactly. Supplemental display only: the printed payload and the permit
    // decode below stay authoritative.
    if let Some(reading) = crate::clear_signing::interpret_typed_data(&request.typed_data).await {
        approval = approval.fact("Reads as", reading.intent);
        for line in reading.fields {
            approval = approval.fact("·", line);
        }
    }

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
            "Signing grants the token approvals listed above. No policy limits what a signature \
             authorizes, and nothing stops the holder collecting more of them, so approve this \
             only if you expected exactly these approvals now.",
        );
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
    if !no_confirm
        && !reviewer_approved(approval, typed_data_payload_lines(&request.typed_data)).await?
    {
        let rejected = store.reject(request.request_id)?;
        return emit_rejected(
            mode,
            "typed-data request",
            rejected.request_id,
            &rejected.digest,
            rejected.rejected_at,
        );
    }

    PlatformHumanPresence
        .confirm(&PresenceRequest::SignTypedData {
            wallet: wallet.id.clone(),
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
    let signer = load_matching_signer(&OsKeyStore, &wallet)?;
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
         The complete message is shown at the end of this review.",
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
            config.network_by_chain_id(&siwe.chain_id).is_ok(),
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
                 off-chain order, a delegation, or an account link; verify every byte of the \
                 complete message against whatever asked for it.",
            );
    }
    for warning in &display.warnings {
        approval = approval.warning(warning.clone());
    }
    approval = approval
        .fact("Signing hash", &request.digest)
        .digest(&request.digest);
    approval.id = request.request_id;

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
    if !no_confirm
        && !reviewer_approved(
            approval,
            message_payload_lines(&request.message_hex, &display),
        )
        .await?
    {
        let rejected = store.reject(request.request_id)?;
        return emit_rejected(
            mode,
            "message request",
            rejected.request_id,
            &rejected.digest,
            rejected.rejected_at,
        );
    }

    PlatformHumanPresence
        .confirm(&PresenceRequest::SignMessage {
            wallet: wallet.id.clone(),
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
    let signer = load_matching_signer(&OsKeyStore, &wallet)?;
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

/// Keep one approval fact to a readable length; the complete message always
/// follows at the end of the review document.
fn terminal_safe_excerpt(value: &str) -> String {
    const MAX_FACT_CHARACTERS: usize = 200;
    if value.chars().count() <= MAX_FACT_CHARACTERS {
        return value.to_owned();
    }
    let head: String = value.chars().take(MAX_FACT_CHARACTERS).collect();
    format!("{head}… (complete message below)")
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
    policy: &WalletPolicy,
    source: Option<&std::path::Path>,
    mode: OutputMode,
) -> Result<()> {
    let wallet = config.wallet(wallet_id)?;
    require_interactive("policy changes")?;
    let mut policies = PolicyStore::production(config.data_dir())?;
    let current = policies.get(wallet_id)?;
    let digest = policy.digest()?;
    let mut question = crate::tui::Confirmation::new(
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
    .warning(
        "A more permissive policy can authorize transactions without an exceptional approval.",
    );
    if let Some(source) = source {
        question = question.fact("Policy file", source.display().to_string());
    }
    if current.is_none() {
        question = question.warning(
            "This wallet currently has no policy, so server startup and signing fail closed. Saying yes will initialize revision 1.",
        );
    }
    if !question.ask("Replace the policy?")? {
        crate::tui::outro_cancel("Policy unchanged.");
        return Ok(());
    }
    PlatformHumanPresence
        .confirm(&PresenceRequest::ReplacePolicy {
            wallet: wallet.id.clone(),
        })
        .await?;
    let stored = policies.put(
        wallet_id,
        policy,
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

/// Settle which policy a new wallet starts under.
///
/// An explicit `--policy` wins. In a terminal the user is asked, with the
/// cursor on the locked-down choice so the permissive one takes a deliberate
/// move. Everywhere else — a pipe, a script, `--json` — the locked-down
/// choice is taken outright: a non-interactive run has nobody to ask, and
/// guessing wrong in that direction is the expensive mistake.
///
/// `Ok(None)` means the user backed out and no wallet should be created.
fn resolve_starting_policy(flag: Option<StartingPolicy>) -> Result<Option<StartingPolicy>> {
    if let Some(chosen) = flag {
        return Ok(Some(chosen));
    }
    if !crate::tui::interactive() {
        return Ok(Some(StartingPolicy::RequireApproval));
    }
    let choices = [StartingPolicy::RequireApproval, StartingPolicy::AllowAll];
    Ok(crate::tui::pick(
        "How should this wallet start?",
        vec![
            "Require approval — every transaction needs a CLI review".to_owned(),
            "Allow all — sign automatically, ask only when policy or simulation fails".to_owned(),
        ],
        choices.len(),
    )?
    .map(|index| choices[index]))
}

/// Ask for a decision and return it, for the queued signing requests where
/// declining has somewhere to be written. Everything else uses
/// [`require_approval`], which treats a decline as an abort because there is
/// no queue entry to resolve.
///
/// These reviews run full screen: the complete payload scrolls inside the
/// review itself rather than somewhere above the prompt, and the JSON record
/// printed to the transcript beforehand stays in the scrollback for after
/// the alternate screen closes.
async fn reviewer_approved(
    request: ApprovalRequest,
    payload: Vec<crate::fullscreen::Line>,
) -> Result<bool> {
    Ok(
        crate::approve_tui::review_signature_fullscreen(&request, payload).await?
            == ApprovalDecision::Approved,
    )
}

/// Payload text for the full-screen review: every control or bidirectional
/// character becomes a visible `\u{..}` escape rather than a silent space,
/// because in a payload being signed the tricky characters are exactly the
/// ones the reviewer needs to see.
fn escape_payload_line(line: &str) -> String {
    use std::fmt::Write as _;
    let mut escaped = String::with_capacity(line.len());
    for character in line.chars() {
        if crate::sanitize::is_disallowed(character) {
            let _ = write!(escaped, "\\u{{{:04x}}}", character as u32);
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// The complete message, line by line, for the scrollable review document.
fn message_payload_lines(
    message_hex: &str,
    display: &crate::message::MessageDisplay,
) -> Vec<crate::fullscreen::Line> {
    use crate::fullscreen::Span;
    use crate::tui::Tone;
    let mut lines = vec![
        Vec::new(),
        vec![Span::toned("Complete message", Tone::Emphasis)],
    ];
    if let Some(text) = &display.text {
        lines.extend(
            text.split('\n')
                .map(|line| vec![Span::plain(escape_payload_line(line))]),
        );
    } else {
        lines.push(vec![Span::toned(
            "Not valid UTF-8; the exact bytes as hex:",
            Tone::Muted,
        )]);
        lines.push(vec![Span::plain(message_hex)]);
    }
    lines
}

/// The complete EIP-712 payload, pretty-printed, for the scrollable review
/// document.
fn typed_data_payload_lines(typed_data: &serde_json::Value) -> Vec<crate::fullscreen::Line> {
    use crate::fullscreen::Span;
    use crate::tui::Tone;
    let pretty =
        serde_json::to_string_pretty(typed_data).unwrap_or_else(|_| typed_data.to_string());
    let mut lines = vec![
        Vec::new(),
        vec![Span::toned("Complete EIP-712 payload", Tone::Emphasis)],
    ];
    lines.extend(
        pretty
            .split('\n')
            .map(|line| vec![Span::plain(escape_payload_line(line))]),
    );
    lines
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
            require_interactive("network reset")?;
            let configured = config.load()?.networks;
            let discarded: Vec<&str> = configured
                .iter()
                .filter(|network| !networks.contains(network))
                .map(|network| network.name.as_str())
                .collect();
            let mut question = crate::tui::Confirmation::new(
                "Reset network configuration",
                format!(
                    "Replaces the configured networks with fresh copies of the {} built-in \
                     presets. Wallets, policies, and pending requests are untouched.",
                    networks.len()
                ),
            );
            if discarded.is_empty() {
                question = question.fact(
                    "Losing custom settings",
                    "nothing — every network matches its preset".to_owned(),
                );
            } else {
                question = question.warning(format!(
                    "Custom settings, including RPC URLs, are discarded for: {}",
                    discarded.join(", ")
                ));
            }
            if !question.ask("Reset every network?")? {
                crate::tui::outro_cancel("Networks unchanged.");
                return Ok(());
            }
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
        NetworkCommand::Add(mut args) => {
            let mut prospective = config.load()?.networks;
            let name = if let Some(name) = args.name.take() {
                name
            } else {
                let Some(name) = prompt_network_choice(&mut args, &prospective)? else {
                    crate::tui::outro_cancel("No network added.");
                    return Ok(());
                };
                name
            };
            let candidate = network_candidate(name, *args, &prospective)?;
            replace_configured_network(&mut prospective, candidate.clone())?;
            // The complete URL is shown, not just its origin. This is the
            // one moment the user can catch a typo or the wrong endpoint, and
            // `network list` already prints configured URLs in full; an RPC
            // URL is configuration this human owns, not a signing credential.
            if !confirm_network_change(
                "Add or update network",
                "The wallet will read chain state and run eth_simulateV1 through this endpoint.",
                "Use this network?",
                vec![
                    ("Network", candidate.name.clone()),
                    ("Chain ID", candidate.chain_id.to_string()),
                    ("RPC URL", candidate.rpc_url.to_string()),
                ],
            )? {
                crate::tui::outro_cancel("No network added.");
                return Ok(());
            }
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
        NetworkCommand::Edit { name } => run_network_edit(config, name, mode).await,
        NetworkCommand::Remove { name } => {
            let mut prospective = config.load()?.networks;
            let removed = remove_configured_network(&mut prospective, &name)?;
            if !confirm_network_change(
                "Remove network",
                "The wallet will forget this network and the endpoint it was reached through.",
                "Remove this network?",
                vec![
                    ("Network", removed.name.clone()),
                    ("Chain ID", removed.chain_id.to_string()),
                ],
            )? {
                crate::tui::outro_cancel("Networks unchanged.");
                return Ok(());
            }
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
fn network_candidate(
    name: String,
    args: NetworkAddArgs,
    configured: &[NetworkConfig],
) -> Result<NetworkConfig> {
    if let Some(base) = network_base(&name, args.chain_id, configured) {
        return apply_network_overrides(base, args);
    }
    ensure!(
        args.chain_id.is_some(),
        "unknown network {name}; run `ekubo-wallet network presets` to see the built-in ones, `ekubo-wallet network list` to see the configured ones, or pass a chain ID to define a custom network",
    );
    build_custom_network(name, &args)
}

/// Work out what `network add` should configure when no name was given.
///
/// The chain ID is the first question because it, rather than a name, is what
/// says which network this is. A chain that a preset or the configuration
/// already describes needs no naming at all: it keeps its own name and its own
/// settings, and the only question left is which endpoint to reach it through.
/// Only a chain nothing here has heard of has to be named and described.
///
/// `Ok(None)` means the user backed out.
fn prompt_network_choice(
    args: &mut NetworkAddArgs,
    configured: &[NetworkConfig],
) -> Result<Option<String>> {
    require_interactive("network add")?;
    crate::tui::intro("Add a network");
    let chain_id = if let Some(chain_id) = args.chain_id {
        chain_id
    } else {
        let answer = crate::tui::text("Chain ID")
            .placeholder("8453")
            .validate(|value| match value.trim().parse::<u64>() {
                Ok(chain_id) if chain_id > 0 => Ok(()),
                _ => Err("must be a positive whole number".into()),
            })
            .prompt()?;
        let Some(answer) = answer else {
            return Ok(None);
        };
        let chain_id = answer.trim().parse().expect("validated above");
        args.chain_id = Some(chain_id);
        chain_id
    };

    if let Some((known, origin)) = network_for_chain(chain_id, configured) {
        crate::tui::info(format!(
            "Chain {chain_id} is {origin} {}; its settings are the starting point.",
            known.name
        ));
        if args.rpc_url.is_none() {
            let answer = prompt_network_field(
                custom_network_field("--rpc-url"),
                Some(known.rpc_url.as_str()),
            )?;
            args.rpc_url = Some(answer.trim().parse().context("RPC URL is invalid")?);
        }
        return Ok(Some(known.name));
    }

    crate::tui::info(format!(
        "Nothing configured and no built-in preset uses chain {chain_id}, so it needs a name and a full profile."
    ));
    // Two different names are wanted here and only one of them is being
    // asked for. This is the identifier typed after `--network` and completed
    // by the shell, so it is one word; the readable name ("BNB Smart Chain")
    // is the separate display-name field further down the profile. Asking for
    // a "network name" and then rejecting a space is the prompt's mistake,
    // not the answer's.
    let name = crate::tui::text("Network identifier")
        .placeholder("base")
        .help("One word, used on the command line — the readable name is asked for next")
        .validate(|value| {
            if value.trim().is_empty() || value.trim().contains(char::is_whitespace) {
                Err("one word only — spaces belong in the display name".into())
            } else {
                Ok(())
            }
        })
        .prompt()?;
    let Some(name) = name else { return Ok(None) };
    Ok(Some(name.trim().to_owned()))
}

/// Whatever already describes this chain ID, and where it came from. A
/// configured network wins over the preset it started from, so an endpoint
/// someone already changed is not quietly described by the shipped default.
fn network_for_chain(
    chain_id: u64,
    configured: &[NetworkConfig],
) -> Option<(NetworkConfig, &'static str)> {
    configured
        .iter()
        .find(|network| network.chain_id == chain_id)
        .cloned()
        .map(|network| (network, "configured as"))
        .or_else(|| {
            default_networks()
                .into_iter()
                .find(|network| network.chain_id == chain_id)
                .map(|network| (network, "the built-in preset"))
        })
}

fn custom_network_field(flag: &str) -> &'static RequiredField {
    CUSTOM_NETWORK_FIELDS
        .iter()
        .find(|field| field.flag == flag)
        .expect("every custom network field is listed")
}

/// Full-screen pick of one configured network, searchable by everything the
/// wallet knows about it: name, display name, aliases, chain ID, RPC URL,
/// and explorer URL. `Ok(None)` means the user backed out.
fn pick_network(networks: &[NetworkConfig], action: &str) -> Result<Option<usize>> {
    use crate::fullscreen::{Span, TableColumn, TableRow, pick_table};
    use ratatui::layout::Constraint;
    let columns = vec![
        TableColumn::new("Network", Constraint::Fill(1)),
        TableColumn::new("Display name", Constraint::Fill(1)),
        TableColumn::new("Chain", Constraint::Length(10)).right_aligned(),
        TableColumn::new("RPC", Constraint::Fill(2)),
    ];
    let rows = networks
        .iter()
        .map(|network| {
            let display_name = network.display_name.clone().unwrap_or_default();
            let aliases = network.aliases.join(" ");
            let explorer = network
                .block_explorer_url
                .as_ref()
                .map(Url::to_string)
                .unwrap_or_default();
            TableRow::new(
                vec![
                    Span::plain(&network.name),
                    if display_name.is_empty() {
                        Span::toned("—", crate::tui::Tone::Muted)
                    } else {
                        Span::plain(&display_name)
                    },
                    Span::plain(network.chain_id.to_string()),
                    Span::toned(network.rpc_url.as_str(), crate::tui::Tone::Muted),
                ],
                &[
                    &network.name,
                    &display_name,
                    &aliases,
                    &network.chain_id.to_string(),
                    network.rpc_url.as_str(),
                    &explorer,
                ],
            )
        })
        .collect();
    pick_table("Networks", action, columns, rows)
}

/// Interactive field-by-field editing of one configured network. Every
/// change is drafted locally, shown in the menu, and only trusted after the
/// same authorization and live chain-ID verification as `network add`.
async fn run_network_edit(
    config: &ConfigStore,
    name: Option<String>,
    mode: OutputMode,
) -> Result<()> {
    require_interactive("network edit")?;
    let networks = config.load()?.networks;
    ensure!(!networks.is_empty(), "no networks are configured");
    let original = if let Some(name) = name {
        network_base(&name, None, &networks)
            .filter(|network| {
                networks
                    .iter()
                    .any(|configured| configured.name == network.name)
            })
            .with_context(|| format!("{name} is not a configured network"))?
    } else {
        let Some(index) = pick_network(&networks, "edit")? else {
            crate::tui::outro_cancel("Nothing edited.");
            return Ok(());
        };
        networks[index].clone()
    };

    crate::tui::intro(format!(
        "Edit network {} (chain {})",
        original.name, original.chain_id
    ));
    let mut draft = original.clone();
    loop {
        // Field rows are two aligned columns rather than "label: value": the
        // values here are URLs and comma-separated lists that read as prose
        // otherwise, so a name and its contents are told apart by position
        // instead of by punctuation buried mid-line. The `*` column marks a
        // field the draft has changed, which a suffix could not do without
        // hiding at the far end of a long value.
        let name_columns = CUSTOM_NETWORK_FIELDS
            .iter()
            .map(|field| field.prompt.chars().count())
            .max()
            .unwrap_or_default();
        let mut labels = vec!["Save and authorize".to_owned()];
        labels.extend(CUSTOM_NETWORK_FIELDS.iter().map(|field| {
            let value = network_field_value(&draft, field.flag);
            let marker = if value == network_field_value(&original, field.flag) {
                ' '
            } else {
                '*'
            };
            let shown = if value.is_empty() {
                "(not set)"
            } else {
                &value
            };
            format!(
                "{marker} {:<name_columns$} │ {shown}",
                field.prompt,
                name_columns = name_columns
            )
        }));
        labels.push("Discard changes".to_owned());
        let choice = crate::tui::pick(
            "Edit which field? (* = changed)",
            labels,
            interactive_list_rows(),
        )?;
        match choice {
            Some(0) => break,
            Some(index) if index <= CUSTOM_NETWORK_FIELDS.len() => {
                let field = &CUSTOM_NETWORK_FIELDS[index - 1];
                let current = network_field_value(&draft, field.flag);
                let value = prompt_network_field(field, Some(&current))?;
                set_network_field(&mut draft, field.flag, &value)?;
            }
            _ => {
                crate::tui::outro_cancel("Nothing edited.");
                return Ok(());
            }
        }
    }
    if draft == original {
        crate::tui::outro("No changes to save.");
        return Ok(());
    }

    if !confirm_network_change(
        "Save network changes",
        "The wallet will read chain state and run eth_simulateV1 through this endpoint.",
        "Save these changes?",
        vec![
            ("Network", draft.name.clone()),
            ("Chain ID", draft.chain_id.to_string()),
            ("RPC URL", draft.rpc_url.to_string()),
        ],
    )? {
        crate::tui::outro_cancel("Nothing saved.");
        return Ok(());
    }
    verify_chain_id(&draft).await?;
    config.update(|state| replace_configured_network(&mut state.networks, draft.clone()))?;
    emit(
        mode,
        &serde_json::json!({
            "network": describe_network(&draft),
            "rpc_verified": true,
        }),
        || {
            Ok(format!(
                "Updated {} (chain {}) via {}; the RPC verified its chain ID.",
                draft.name, draft.chain_id, draft.rpc_url,
            ))
        },
    )
}

/// The editable value of one `--flag` field on a network profile.
fn network_field_value(network: &NetworkConfig, flag: &str) -> String {
    let currency = network.native_currency.clone().unwrap_or(NativeCurrency {
        name: "Ether".into(),
        symbol: "ETH".into(),
        decimals: 18,
    });
    match flag {
        "--display-name" => network
            .display_name
            .clone()
            .unwrap_or_else(|| network.name.clone()),
        "--alias" => network.aliases.join(", "),
        "--native-currency-name" => currency.name,
        "--native-currency-symbol" => currency.symbol,
        "--native-currency-decimals" => currency.decimals.to_string(),
        "--max-gas-limit" => network.max_gas_limit.clone().unwrap_or_default(),
        "--block-explorer-url" => network
            .block_explorer_url
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        "--documentation-url" => network
            .documentation_url
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        "--rpc-url" => network.rpc_url.to_string(),
        _ => unreachable!("unknown network field {flag}"),
    }
}

/// Writes one validated `--flag` answer back onto the draft profile.
fn set_network_field(network: &mut NetworkConfig, flag: &str, value: &str) -> Result<()> {
    match flag {
        "--display-name" => network.display_name = Some(value.trim().to_owned()),
        "--alias" => {
            let aliases = normalize_aliases(
                value
                    .split([',', ' '])
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            )?;
            ensure!(!aliases.is_empty(), "at least one alias is required");
            network.aliases = aliases;
        }
        "--native-currency-name" | "--native-currency-symbol" | "--native-currency-decimals" => {
            let mut currency = network.native_currency.take().unwrap_or(NativeCurrency {
                name: "Ether".into(),
                symbol: "ETH".into(),
                decimals: 18,
            });
            match flag {
                "--native-currency-name" => value.trim().clone_into(&mut currency.name),
                "--native-currency-symbol" => value.trim().clone_into(&mut currency.symbol),
                _ => {
                    currency.decimals = value
                        .trim()
                        .parse()
                        .context("native currency decimals must be 0-255")?;
                }
            }
            network.native_currency = Some(currency);
        }
        "--max-gas-limit" => network.max_gas_limit = Some(value.trim().to_owned()),
        "--block-explorer-url" => {
            network.block_explorer_url = Some(
                value
                    .trim()
                    .parse()
                    .context("block explorer URL is invalid")?,
            );
        }
        "--documentation-url" => {
            network.documentation_url = Some(
                value
                    .trim()
                    .parse()
                    .context("documentation URL is invalid")?,
            );
        }
        "--rpc-url" => network.rpc_url = value.trim().parse().context("RPC URL is invalid")?,
        _ => unreachable!("unknown network field {flag}"),
    }
    Ok(())
}

/// The configured network or built-in preset this add/update starts from.
///
/// A configured network wins over a preset with the same name, so editing a
/// customized network never silently reverts the rest of it to the preset. A
/// declared chain ID must match, because repointing a name at a different
/// chain is a redefinition rather than an edit.
fn network_base(
    name: &str,
    chain_id: Option<u64>,
    configured: &[NetworkConfig],
) -> Option<NetworkConfig> {
    let matches = |network: &NetworkConfig| {
        (network.name == name || network.aliases.iter().any(|alias| alias == name))
            && chain_id.is_none_or(|chain_id| chain_id == network.chain_id)
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
fn build_custom_network(name: String, args: &NetworkAddArgs) -> Result<NetworkConfig> {
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
    let answers = collect_custom_network_fields(&name, chain_id, &supplied)?;
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
        name,
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

    crate::tui::intro(format!("Configure network {name} (chain {chain_id})"));
    crate::tui::info(format!(
        "{} value(s) still needed: {}",
        missing.len(),
        missing
            .iter()
            .map(|field| field.flag)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let mut answers = BTreeMap::new();
    for field in CUSTOM_NETWORK_FIELDS {
        if let Some(Some(value)) = supplied.get(field.flag) {
            crate::tui::info(format!("{}: {value}", field.prompt));
            answers.insert(field.flag, value.clone());
            continue;
        }
        answers.insert(field.flag, prompt_network_field(field, None)?);
    }
    crate::tui::outro(format!(
        "{name} is fully described. Authorize the change to start trusting this RPC."
    ));
    Ok(answers)
}

/// One text prompt for one network field, validated while the prompt is
/// still open rather than after the whole profile has been typed out.
/// `current` pre-fills the line when an existing value is being edited.
///
/// The RPC URL is shown rather than masked. It is configuration, not a
/// signing credential, and masking it made a typo impossible to spot and
/// forced a full re-entry on the next attempt. Prompting for it at all still
/// keeps any embedded key out of shell history.
fn prompt_network_field(field: &RequiredField, current: Option<&str>) -> Result<String> {
    let flag = field.flag;
    let mut input = crate::tui::text(field.prompt)
        .placeholder(field.example)
        .validate(move |value| validate_network_field(flag, value));
    if let Some(current) = current {
        input = input.initial(current);
    } else if let Some(default) = field.default {
        input = input.default_value(default);
    }
    input
        .prompt_required()
        .with_context(|| format!("failed to read {} ({})", field.prompt, field.flag))
}

/// Reject a malformed answer for the named `--flag`.
fn validate_network_field(flag: &str, input: &str) -> std::result::Result<(), String> {
    {
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

/// Ask before rewriting which networks the wallet knows and which endpoints
/// it reads them through.
///
/// This is configuration, not custody. No key is touched, nothing is signed,
/// and the change is undone by running the command again — so it is a yes or
/// no with the endpoint spelled out, not the signing review. `Ok(false)`
/// means leave the configuration alone.
fn confirm_network_change(
    title: &str,
    summary: &str,
    prompt: &str,
    facts: Vec<(&str, String)>,
) -> Result<bool> {
    require_interactive("network configuration changes")?;
    let mut question = crate::tui::Confirmation::new(title, summary).warning(
        "The configured RPC supplies the chain state and eth_simulateV1 results that automatic \
         signing decisions are made from.",
    );
    for (label, value) in facts {
        question = question.fact(label, value);
    }
    question.ask(prompt)
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
    crate::render::terminal_safe_line(value)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_wallet_never_starts_permissive_by_accident() {
        // The tests run without a terminal, which is exactly the case that
        // must not quietly enable automatic signing: with nobody to ask, the
        // locked-down policy is taken rather than the convenient one.
        assert_eq!(
            resolve_starting_policy(None).unwrap(),
            Some(StartingPolicy::RequireApproval)
        );
        // An explicit flag is obeyed either way, including the permissive one.
        for chosen in [StartingPolicy::RequireApproval, StartingPolicy::AllowAll] {
            assert_eq!(resolve_starting_policy(Some(chosen)).unwrap(), Some(chosen));
        }
    }

    #[test]
    fn the_two_starting_policies_are_the_profiles_they_name() {
        // A wallet that asked to require approval must not be able to sign
        // anything automatically, whatever the profile is called.
        let locked = StartingPolicy::RequireApproval.policy();
        assert_eq!(locked, WalletPolicy::require_approval_for_everything());
        assert_eq!(
            StartingPolicy::AllowAll.policy(),
            WalletPolicy::allow_all_with_approval()
        );
        assert_ne!(locked, StartingPolicy::AllowAll.policy());
    }

    #[test]
    fn interactive_lists_are_sized_to_the_terminal() {
        // The page is bounded and always leaves room for the prompt chrome.
        let rows = interactive_list_rows();
        assert!(rows >= 3);
        assert!(rows < 10_000);
    }

    #[test]
    fn transaction_lines_render_offline() {
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
            updated_at: now - chrono::TimeDelta::minutes(7),
            approved_at: None,
            rejected_at: None,
            serialized_transaction: None,
            signed_transaction_hash: None,
            broadcast_transaction_hash: None,
            block_number: None,
            mined_fee: None,
            cancel_serialized_transaction: None,
            cancel_transaction_hashes: Vec::new(),
        };

        let line = transaction_line(&record);
        assert!(line.contains("7 minutes ago"));
        assert!(line.contains("awaiting approval"));
        assert!(line.contains("primary"));
        assert!(line.contains("1 call(s), 5 wei native"));
        // The piped listing keeps the whole request ID, because that is what
        // `transaction show` takes as an identifier.
        assert!(line.contains(&Uuid::nil().to_string()));

        // The approvals browser flattens every queue into rows whose Enter
        // action carries the right identifier, and its network column names
        // the chain rather than numbering it.
        let now = chrono::Utc::now();
        let typed = PendingTypedData {
            request_id: Uuid::from_u128(2),
            wallet_id: "primary".into(),
            chain_id: "1".into(),
            typed_data: serde_json::json!({}),
            digest: format!("0x{}", "cd".repeat(32)),
            status: TypedDataStatus::AwaitingApproval,
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            signature: None,
        };
        let message = PendingMessage {
            request_id: Uuid::from_u128(3),
            wallet_id: "primary".into(),
            chain_id: None,
            message_hex: "0x68690a".into(),
            encoding: crate::message::MessageEncoding::Text,
            digest: format!("0x{}", "ef".repeat(32)),
            status: MessageStatus::AwaitingApproval,
            created_at: now,
            updated_at: now,
            approved_at: None,
            rejected_at: None,
            signature: None,
        };
        let proposal = crate::policy_store::PolicyProposal {
            wallet_id: "primary".into(),
            source_revision: 4,
            policy: WalletPolicy::require_approval_for_everything(),
            rationale: "allow the weekly compounding plan".into(),
            created_at: now,
        };
        let directory = tempfile::tempdir().unwrap();
        let config = ConfigStore::new(directory.path());
        let (rows, choices) = pending_approval_rows(
            &config,
            std::slice::from_ref(&record),
            std::slice::from_ref(&typed),
            std::slice::from_ref(&message),
            std::slice::from_ref(&proposal),
        );
        assert_eq!(rows.len(), 4);
        assert_eq!(choices.len(), 4);
        // The default configuration names chain 1, so the row says
        // "ethereum" — the chain ID lives in the haystack instead.
        assert!(rows[0].haystack.contains("ethereum"));
        assert!(rows[0].haystack.contains(&Uuid::nil().to_string()));
        assert!(matches!(choices[0], PendingChoice::Request(id) if id == Uuid::nil()));
        assert!(matches!(choices[1], PendingChoice::Request(id) if id == Uuid::from_u128(2)));
        // A typed-data row is searchable by its EIP-712 digest.
        assert!(rows[1].haystack.contains(&format!("0x{}", "cd".repeat(32))));
        assert!(matches!(choices[2], PendingChoice::Request(id) if id == Uuid::from_u128(3)));
        // A proposal reviews per wallet, and its rationale is searchable.
        assert!(matches!(&choices[3], PendingChoice::Proposal(wallet) if wallet == "primary"));
        assert!(rows[3].haystack.contains("weekly compounding"));
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
            name: Some(name.into()),
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

    /// Resolves the candidate exactly as the `network add` arm does: the
    /// name is taken out of the parsed arguments first.
    fn candidate_of(
        mut args: NetworkAddArgs,
        configured: &[NetworkConfig],
    ) -> Result<NetworkConfig> {
        let name = args
            .name
            .take()
            .expect("test arguments always carry a name");
        network_candidate(name, args, configured)
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
        let candidate = candidate_of(args, &configured).unwrap();

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
    fn a_chain_id_names_its_own_network_so_add_never_asks_for_one() {
        // What `network add` asks first is the chain ID, and the answer is
        // only turned back into a name when nothing already holds that chain.
        let mut configured = default_networks();
        let base = configured
            .iter_mut()
            .find(|network| network.name == "base")
            .unwrap();
        base.rpc_url = "https://rpc.example.invalid/base".parse().unwrap();
        let configured = configured;

        let (known, origin) = network_for_chain(8453, &configured).unwrap();
        assert_eq!(known.name, "base");
        assert_eq!(origin, "configured as");
        // The configured endpoint is what the RPC prompt offers back, not the
        // shipped default it was changed away from.
        assert_eq!(known.rpc_url.as_str(), "https://rpc.example.invalid/base");

        let (preset, origin) = network_for_chain(8453, &[]).unwrap();
        assert_eq!(preset.name, "base");
        assert_eq!(origin, "the built-in preset");

        assert!(network_for_chain(987_654, &configured).is_none());
    }

    #[test]
    fn an_alias_and_a_matching_chain_id_both_resolve_the_same_base() {
        let configured = default_networks();
        for (name, chain_id) in [("base-mainnet", None), ("base", Some(8453))] {
            let candidate = candidate_of(add_args(name, chain_id), &configured).unwrap();
            assert_eq!(candidate.name, "base");
            assert_eq!(candidate.chain_id, 8453);
        }
    }

    #[test]
    fn preset_network_add_uses_complete_catalog_metadata() {
        let candidate = candidate_of(add_args("eth", None), &[]).unwrap();
        assert_eq!(candidate.name, "ethereum");
        assert_eq!(candidate.chain_id, 1);
        assert!(candidate.native_currency.is_some());
        assert!(candidate.max_gas_limit.is_some());
    }

    #[test]
    fn an_unknown_network_without_a_chain_id_says_where_to_look() {
        let error = candidate_of(add_args("nowhere", None), &default_networks())
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
        let error = candidate_of(add_args("custom", Some(987_654)), &default_networks())
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
        let candidate = candidate_of(args, &default_networks()).unwrap();
        assert_eq!(candidate.chain_id, 987_654);
        assert_eq!(candidate.aliases, vec!["custom-chain".to_owned()]);
        assert_eq!(candidate.native_currency.unwrap().decimals, 18);
    }

    #[test]
    fn every_editable_field_round_trips_through_its_own_validator() {
        // The edit menu re-prompts with the current value pre-filled; that
        // value must satisfy the field's validator and write back unchanged,
        // or editing an untouched field would corrupt the profile.
        let preset = || {
            default_networks()
                .into_iter()
                .find(|network| network.name == "base")
                .expect("base preset exists")
        };
        let mut network = preset();
        for field in CUSTOM_NETWORK_FIELDS {
            let current = network_field_value(&network, field.flag);
            assert!(
                validate_network_field(field.flag, &current).is_ok(),
                "{} rejects its own current value {current:?}",
                field.flag
            );
            set_network_field(&mut network, field.flag, &current).unwrap();
        }
        let untouched = preset();
        assert_eq!(network.chain_id, untouched.chain_id);
        assert_eq!(network.rpc_url, untouched.rpc_url);
        assert_eq!(network.aliases, untouched.aliases);
        assert_eq!(network.native_currency, untouched.native_currency);
    }

    #[test]
    fn setting_network_fields_applies_each_typed_value() {
        let mut network = default_networks().remove(0);
        set_network_field(&mut network, "--rpc-url", "https://rpc.example.invalid").unwrap();
        assert_eq!(network.rpc_url.as_str(), "https://rpc.example.invalid/");
        set_network_field(&mut network, "--native-currency-decimals", "6").unwrap();
        assert_eq!(network.native_currency.clone().unwrap().decimals, 6);
        set_network_field(&mut network, "--alias", "one, two").unwrap();
        assert_eq!(network.aliases, vec!["one".to_owned(), "two".to_owned()]);
        set_network_field(&mut network, "--display-name", " Renamed ").unwrap();
        assert_eq!(network.display_name.as_deref(), Some("Renamed"));
        // A blank alias list cannot silently strand the network.
        assert!(set_network_field(&mut network, "--alias", "  ").is_err());
    }

    #[test]
    fn prompt_validation_rejects_malformed_answers_before_the_next_question() {
        let field = |flag: &str| {
            CUSTOM_NETWORK_FIELDS
                .iter()
                .find(|field| field.flag == flag)
                .expect("declared field")
        };
        let rpc = field("--rpc-url").flag;
        assert!(validate_network_field(rpc, "https://rpc.example.invalid").is_ok());
        assert!(validate_network_field(rpc, "rpc.example.invalid").is_err());
        assert!(validate_network_field(rpc, "ftp://rpc.example.invalid").is_err());
        assert!(validate_network_field(rpc, "").is_err());

        let decimals = field("--native-currency-decimals").flag;
        assert!(validate_network_field(decimals, "18").is_ok());
        assert!(validate_network_field(decimals, "18.5").is_err());

        let gas = field("--max-gas-limit").flag;
        assert!(validate_network_field(gas, "16777216").is_ok());
        assert!(validate_network_field(gas, "1000").is_err());

        // Every declared default has to survive its own validator.
        for entry in CUSTOM_NETWORK_FIELDS {
            if let Some(default) = entry.default {
                assert!(
                    validate_network_field(entry.flag, default).is_ok(),
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
