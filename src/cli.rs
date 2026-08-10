use crate::approve_tui::TerminalApprovalUi;
use crate::{
    BUILD_VERSION,
    address_book::AddressBookStore,
    approval::{ApprovalDecision, ApprovalKind, ApprovalRequest, ApprovalUi},
    config::{
        ConfigStore, NativeCurrency, NetworkConfig, RpcStrategy, add_configured_network,
        default_networks, remove_configured_network, replace_configured_network,
    },
    core::policy::WalletPolicy,
    custody::{CustodyService, OsKeyStore, PrivateKeyMaterial},
    human_presence::{HumanPresence, PlatformHumanPresence, PresenceRequest},
    legal::{self, LegalDocument, LegalStore},
    message::{MessageStore, PendingMessage},
    pending::{PendingStatus, PendingStore, PendingTransaction, is_unknown_request},
    policy_store::PolicyStore,
    render::{OutputMode, described_time, emit, print_json, relative_time},
    rpc::verify_chain_id,
    simulation::SimulationResult,
    tx_browser::status_label,
    typed_data::{PendingTypedData, TypedDataStore},
};
use alloy::primitives::Address;
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};
use directories::BaseDirs;
use num_bigint::BigUint;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, IsTerminal, Read, Write},
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
    version = BUILD_VERSION,
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

    /// Keep this session's database key in --data-dir instead of the platform
    /// credential store, for a scratch wallet that leaves nothing behind.
    ///
    /// Requires --data-dir. Refuses every account operation, since private
    /// keys live in the credential store and this session does not touch it.
    /// Absent from release builds.
    #[cfg(debug_assertions)]
    #[arg(long, global = true, requires = "data_dir")]
    ephemeral: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the stdio MCP server.
    Server,
    /// Print the server version.
    Version,
    /// What is set up, what is missing, and what is waiting for you.
    ///
    /// Reads only local state, so it never blocks on an endpoint and works
    /// before the legal documents are accepted — finding out that they are
    /// what is blocking signing is most of the point.
    Status,
    /// Read native and token balances for an account from a configured RPC.
    ///
    /// The one command here that talks to a chain. Balances come from the
    /// endpoint configured for the network, read at a single pinned block so
    /// the whole answer is one consistent view rather than a sequence of them.
    #[command(alias = "balance")]
    Portfolio(PortfolioArgs),
    /// Keys this wallet holds, and the addresses they control.
    ///
    /// Named `account` rather than `wallet` because the program is already
    /// called that: `ekubo-wallet wallet create` said it twice and the second
    /// one carried nothing.
    Account(AccountArgs),
    /// Configured EVM networks and the endpoints they are reached through.
    Network(Box<NetworkArgs>),
    /// What each account may sign without being asked.
    Policy(PolicyArgs),
    /// Transactions signed or broadcast by this wallet, and what to do about
    /// one that is stuck.
    #[command(alias = "tx")]
    Transaction(TransactionArgs),
    /// The local token database: what this wallet will display a name for.
    ///
    /// Under `meta-` because the first letter of a command is what tab
    /// completion has to work with, and `t` belongs to `transaction`.
    #[command(name = "meta-tokens")]
    Token(TokenArgs),
    /// Browse and edit per-chain address aliases used for agent lookups.
    /// Bare, on a terminal, this opens the full-screen editor.
    #[command(name = "meta-address-book")]
    AddressBook(AddressBookArgs),
    #[allow(clippy::doc_markdown)]
    /// Connect this wallet to a dapp with a pasted WalletConnect link.
    ///
    /// The dapp gets exactly what an MCP agent gets: it can propose, and
    /// nothing else. Every transaction it sends is simulated and put to this
    /// wallet's policy, and anything the policy does not already allow is shown
    /// to you here before it is signed. Every signature request is shown to you
    /// regardless, because no policy can evaluate what a signature authorizes.
    ///
    /// Runs until the dapp disconnects or you press Ctrl-C.
    ///
    ///   ekubo-wallet connect 'wc:a1b2…@2?relay-protocol=irn&symKey=…'
    Connect(ConnectArgs),
    /// Register this wallet as an MCP server with the agents on this machine.
    ///
    /// The installer does this once. This is how to redo it after moving the
    /// binary, and how to find out which agents currently point at it.
    ///
    /// Under `meta-` because `a` belongs to `account`.
    #[command(name = "meta-agent")]
    Agent(AgentArgs),
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
    // clap prints this doc comment as `--help` text, where the backticks the
    // lint wants would be shown literally. `artifact_reference` is the wire
    // spelling an agent has to type, so it is written as it is typed.
    #[allow(clippy::doc_markdown)]
    /// Print the artifact_reference envelope for a JSON body on this machine.
    ///
    /// Producers publish their own envelopes, so this is for bodies nobody
    /// published: an execution plan an agent assembled by splicing two
    /// prepared plans into one batch, a read-call bundle it merged, a token
    /// list it filtered. The file is checked to be the artifact it claims to
    /// be and then described — path, keccak256 digest, exact byte count — so
    /// the megabyte of calldata stays on disk and only the envelope is passed
    /// to the wallet's tools.
    ///
    /// Under `meta-` because `r` belongs to `review`.
    ///
    ///   ekubo-wallet meta-reference /tmp/combined-plan.json
    #[command(name = "meta-reference")]
    Reference {
        /// Path to the JSON body.
        path: PathBuf,
        /// What the file holds. Inferred from its top-level fields when
        /// omitted.
        #[arg(long = "type", value_enum)]
        artifact_type: Option<ReferenceType>,
    },
    /// Print a shell completion script, including local dynamic candidates.
    ///
    /// Spelled in full so `c` reaches `connect` alone.
    #[command(name = "shell-completion")]
    Completion { shell: Shell },
    /// Print the candidates for the cursor, given the words typed so far.
    ///
    /// The shipped completion scripts call this on every tab: they read the
    /// current line, pass it here, and print what comes back. Deciding *what*
    /// the cursor is on happens in `completion`, once, rather than three times
    /// in three dialects.
    #[command(name = "__complete", hide = true)]
    Complete {
        /// How to render each candidate: `plain` for bash, `zsh` for
        /// `value:description`, `fish` for a tab between the two.
        format: CompletionFormat,
        /// The words already on the line, program name included, without
        /// whatever is half-typed at the cursor.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        words: Vec<String>,
    },
}

/// How a shell wants a candidate and its description written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum CompletionFormat {
    /// One value per line. bash shows no descriptions.
    Plain,
    /// `value:description`, for `_describe`.
    Zsh,
    /// `value<tab>description`.
    Fish,
}

#[derive(Debug, Args)]
struct PortfolioArgs {
    /// Account id, or a 0x address to read one this wallet does not hold.
    ///
    /// Reading is not signing, so an address nobody here has a key for is a
    /// legitimate thing to ask about — checking where funds went before
    /// approving anything is exactly the moment this is useful.
    account: String,
    /// Network name, alias, or decimal chain ID.
    #[arg(long, short)]
    network: String,
    /// How many known tokens to check.
    ///
    /// Rarely worth setting. Every known token on a chain is read in one call
    /// through Ekubo's `TokenDataFetcher` lens, which returns only the nonzero
    /// balances, so the default already covers the whole database on every
    /// shipped network.
    ///
    /// The database has no notion of which tokens matter, so a lowered limit
    /// takes them in address order — an arbitrary slice, not the interesting
    /// ones. That is why a truncated read says so explicitly: a token missing
    /// from one says nothing about the balance.
    #[arg(long, default_value_t = crate::token_store::MAX_PORTFOLIO_TOKENS)]
    tokens: usize,
}

#[derive(Debug, Args)]
struct ConnectArgs {
    /// The `wc:` link copied from the dapp. Prompted for when omitted.
    ///
    /// Quote it: it contains `&`, which every shell reads as "run this in the
    /// background" long before the wallet ever sees it.
    uri: Option<String>,
    /// Which account to start the connection review on.
    ///
    /// A session exposes exactly one account, but you pick it on the review
    /// screen — press `a` there to cycle through the wallet's accounts and see
    /// what each one would expose. This only chooses where that starts.
    #[arg(long, short)]
    account: Option<String>,
    /// A relay other than the public one, for a self-hosted deployment.
    #[arg(long)]
    relay_url: Option<Url>,
}

#[derive(Debug, Args)]
struct AccountArgs {
    #[command(subcommand)]
    command: AccountCommand,
}

#[derive(Debug, Subcommand)]
enum AccountCommand {
    /// List account metadata. Never returns private keys.
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
    /// Remove an account and its key after terminal confirmation and owner
    /// authentication.
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
    Presets {
        /// Search the complete compiled-in registry instead of the defaults:
        /// every chain chainlist knows of that answered this wallet's probe.
        /// Matches a chain ID, a name, or part of a display name.
        #[arg(long)]
        search: Option<String>,
        /// List every chain in the registry. Long — hundreds of entries.
        #[arg(long, conflicts_with = "search")]
        all: bool,
    },
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
    /// Review network profiles an agent has suggested, and accept or discard
    /// each one. Nothing an agent proposes reaches the configuration until it
    /// is accepted here.
    Review,
}

#[derive(Debug, Args)]
struct NetworkAddArgs {
    /// Preset or custom network name; taken from whatever already describes
    /// the chain ID when omitted.
    name: Option<String>,
    chain_id: Option<u64>,
    /// RPC endpoint, repeatable. Each `--rpc-url` appends one fallback, tried
    /// in the order given, and supplying any replaces the whole list rather
    /// than adding to what is configured — so an edit says what the network
    /// should reach, not what to append to something already there.
    #[arg(long = "rpc-url")]
    rpc_urls: Vec<Url>,
    /// How the endpoints are used: `ordered` (first answer wins), `random`
    /// (fresh order per request), or `m_of_n(2)` (require 2 endpoints to
    /// return the same simulation before acting on it).
    #[arg(long)]
    rpc_strategy: Option<RpcStrategy>,
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
struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Show which supported agents are installed here and whether this server
    /// is registered with each.
    List,
    /// Register this server and the Ekubo protocol server. Without an agent,
    /// every one detected here.
    Add {
        agent: Option<AgentName>,
        /// Register only this wallet, leaving the Ekubo protocol server out.
        #[arg(long)]
        no_companion: bool,
    },
    /// Unregister this server and the Ekubo protocol server. Without an agent,
    /// every one detected here.
    #[command(alias = "delete")]
    Remove { agent: Option<AgentName> },
}

/// This wallet's own MCP server, as agents know it.
const LOCAL_SERVER_NAME: &str = "ekubo-wallet";

/// The Ekubo protocol server, registered alongside the wallet so a fresh
/// install can quote, swap, bridge, and provide liquidity rather than only
/// hold keys. It prepares unsigned plans and never sees a key: everything it
/// produces still arrives here as a reference the wallet fetches, verifies,
/// simulates, and policy-checks on its own. That is why registering it is a
/// convenience rather than a widening of what an agent can spend — the
/// security boundary is unchanged, and `--no-companion` opts out regardless.
const COMPANION_SERVER_NAME: &str = "ekubo";
const COMPANION_SERVER_URL: &str = "https://mcp.ekubo.org/mcp";

/// How an agent reaches one of the two servers.
enum ServerTransport {
    /// A subprocess: this executable, run as `<path> server`.
    Stdio(String),
    /// A remote streamable-HTTP endpoint.
    Http(&'static str),
}

/// The agents this wallet knows how to configure.
///
/// Three of them own their own MCP configuration and expose a CLI for it, so
/// registration shells out rather than editing their files: their format is
/// theirs to change. Cursor and opencode have no such command, which is why
/// they are the two whose configuration files this writes directly.
///
/// opencode is the near miss worth recording. It does have an `opencode mcp
/// add`, but its `mcp` command tree is `add`, `list`, `auth`, `logout`, and
/// `debug` — there is nothing that takes a server back out. Registering
/// through a CLI that cannot unregister would leave `meta-agent remove`
/// editing the file regardless, so both directions go through the file and
/// there is one mechanism to reason about rather than two that can disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum AgentName {
    Codex,
    #[value(name = "claude-code")]
    ClaudeCode,
    #[value(name = "gemini-cli")]
    Gemini,
    Cursor,
    Opencode,
}

impl AgentName {
    const ALL: [Self; 5] = [
        Self::Codex,
        Self::ClaudeCode,
        Self::Gemini,
        Self::Cursor,
        Self::Opencode,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::ClaudeCode => "Claude Code",
            Self::Gemini => "Gemini CLI",
            Self::Cursor => "Cursor",
            // Lowercase deliberately: it is how the project spells itself
            // everywhere, including its own binary and documentation.
            Self::Opencode => "opencode",
        }
    }

    const fn key(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::Gemini => "gemini-cli",
            Self::Cursor => "cursor",
            Self::Opencode => "opencode",
        }
    }

    /// The executable that owns this agent's MCP configuration, if any.
    const fn binary(self) -> Option<&'static str> {
        match self {
            Self::Codex => Some("codex"),
            Self::ClaudeCode => Some("claude"),
            Self::Gemini => Some("gemini"),
            Self::Cursor | Self::Opencode => None,
        }
    }
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
        #[arg(long)]
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
    /// Print stored tokens, optionally filtered to one network.
    List {
        /// Network name, alias, or decimal chain ID.
        #[arg(long)]
        chain: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Search confirmed tokens by symbol, name, or address.
    Search {
        /// A symbol, part of a name, or a full token address.
        query: String,
        /// Network name, alias, or decimal chain ID.
        #[arg(long)]
        chain: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Forget one confirmed token, so the wallet shows its bare address again.
    ///
    /// A new database ships with thousands of names already trusted; this is
    /// how to disagree with one of them.
    #[command(alias = "delete")]
    Remove {
        /// Network name, alias, or decimal chain ID.
        network: String,
        /// Token contract address.
        address: String,
    },
    /// Review tokens an agent suggested, and confirm the ones to trust.
    ///
    /// Confirming a token is what lets the wallet show its symbol when
    /// reviewing a transaction, so nothing an agent proposes is displayed as a
    /// name until it is accepted here.
    Review,
    /// Import a token list, confirming what to trust in the terminal.
    ///
    /// Reads the standard token-list shape: a `tokens` array of entries with
    /// `chainId`, `address`, `symbol`, `name`, and `decimals`, or a bare array
    /// of the same. `chain_id` is accepted for `chainId`, and a chain ID may
    /// be a number, a decimal string, or `0x`-hex, so a list can be piped
    /// straight from a curator's API without being rewritten on the way.
    ///
    /// Pass `-` to read the list from standard input:
    ///
    ///   curl -fsSL https://prod-api.ekubo.org/tokens | ekubo-wallet meta-tokens import -
    ///
    /// The review screen still opens, because piping in a list decides
    /// nothing: it only saves an agent from re-typing it.
    // clap prints this doc comment as `--help` text, where a URL in angle
    // brackets would be shown with the brackets. The example is meant to be
    // copied and run.
    #[allow(clippy::doc_markdown)]
    Import {
        /// Path to the token list JSON file, or `-` for standard input.
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
    ///
    /// There is no `--offset`: rows are reconciled against the chain as they
    /// are read and ordered by time, so a second page would be numbered
    /// against a list that has already moved. Narrow with `--account` and
    /// `--limit`, then read one row with `transaction show`.
    List {
        /// Only rows for this account.
        #[arg(long)]
        account: Option<String>,
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
        // Before anything opens a store, since this decides where the database
        // key is read from. `requires = "data_dir"` already guarantees the
        // directory was named by the caller rather than defaulted to the real
        // wallet's.
        #[cfg(debug_assertions)]
        if self.ephemeral {
            ekubo_wallet_core::ephemeral::enable();
            eprintln!(
                "ephemeral session: the database key is in --data-dir, not the credential store, \
and account operations are refused"
            );
        }
        let config = match self.data_dir {
            Some(path) => ConfigStore::new(path),
            None => ConfigStore::production()?,
        };
        let mode = OutputMode::resolve(self.json);
        match self.command {
            Command::Server => crate::mcp::serve(config).await,
            Command::Version => {
                println!("ekubo-wallet {BUILD_VERSION}");
                crate::release_check::print_notice(config.data_dir()).await;
                Ok(())
            }
            Command::Status => {
                let status = run_status(&config, mode);
                // Only after the command itself succeeded, and only on the two
                // commands someone runs to ask what they have. A wallet that
                // mentions a release during `account list` gets muted.
                if status.is_ok() {
                    crate::release_check::print_notice(config.data_dir()).await;
                }
                status
            }
            Command::Portfolio(args) => run_portfolio(&config, &args, mode).await,
            Command::Account(args) => run_account(config, args.command, mode).await,
            Command::Network(args) => run_network(&config, args.command, mode).await,
            Command::Policy(args) => run_policy(&config, args.command, mode).await,
            Command::Transaction(args) => run_transaction(&config, args.command, mode).await,
            Command::Token(args) => run_token(&config, &args.command, mode).await,
            Command::AddressBook(args) => run_address_book(&config, args.command, mode).await,
            Command::Connect(args) => {
                crate::connect::run(
                    &config,
                    crate::connect::ConnectOptions {
                        uri: args.uri,
                        account: args.account,
                        relay_url: args.relay_url,
                    },
                )
                .await
            }
            Command::Agent(args) => run_agent(&args.command, mode),
            Command::Legal(args) => run_legal(&config, &args.command, mode),
            Command::Review {
                request_id,
                decision,
            } => run_review(&config, request_id, decision, mode).await,
            Command::Reference {
                path,
                artifact_type,
            } => run_reference(&path, artifact_type),
            Command::Completion { shell } => print_completion_script(shell),
            Command::Complete { format, words } => {
                print_completion_candidates(&config, format, &words)
            }
        }
    }
}

/// Read balances for one account on one network.
///
/// The token side is bounded by what the database already names: a balance is
/// only shown for a token the owner's database knows, because a symbol read
/// from the chain would be a name chosen by the counterparty. That bound is
/// also why the reported skip matters — see `run_portfolio`'s note below.
async fn run_portfolio(config: &ConfigStore, args: &PortfolioArgs, mode: OutputMode) -> Result<()> {
    let network = config.network(&args.network)?;
    // An account id first, so a wallet named like an address still resolves to
    // the wallet. Falling back to a literal address is what makes reading a
    // counterparty possible at all.
    let address = match config.wallet(&args.account) {
        Ok(wallet) => wallet.address,
        Err(unknown) => Address::from_str(&args.account).map_err(|_| unknown)?,
    };

    let limit = args.tokens.min(crate::token_store::MAX_PORTFOLIO_TOKENS);
    let tokens = crate::token_store::TokenStore::production(config.data_dir())?;
    // The true total, not the page size. `read_portfolio` derives its own skip
    // from the slice it was handed, so a slice that is already truncated would
    // report nothing skipped and turn a partial read into a confident one.
    let total = tokens.count(Some(network.chain_id))?;
    let known = tokens.list(Some(network.chain_id), limit, 0)?;
    drop(tokens);
    let mut portfolio = crate::token_store::read_portfolio(&network, address, &known, None).await?;
    portfolio.tokens_skipped = match total.saturating_sub(portfolio.tokens_checked) {
        0 => None,
        skipped => Some(skipped),
    };

    emit(mode, &portfolio, || {
        let mut lines = vec![
            format!("{} on {}", portfolio.address, portfolio.network),
            format!("Block {}", portfolio.block_number),
            String::new(),
            format!(
                "{} {}",
                crate::approval_summary::format_fixed_point(
                    &portfolio.native_balance,
                    network
                        .native_currency
                        .as_ref()
                        .map_or(18, |currency| currency.decimals)
                ),
                network
                    .native_currency
                    .as_ref()
                    .map_or("native", |currency| currency.symbol.as_str())
            ),
        ];
        for token in &portfolio.tokens {
            lines.push(format!(
                "{} {}",
                token.decimals.map_or_else(
                    || format!("{} base units of", token.balance),
                    |decimals| crate::approval_summary::format_fixed_point(
                        &token.balance,
                        decimals
                    )
                ),
                token.symbol.as_deref().unwrap_or(&token.address),
            ));
        }
        if portfolio.tokens.is_empty() {
            lines.push("No known token has a balance here.".into());
        }
        lines.push(String::new());
        // Said plainly rather than as a footnote. A portfolio that checked a
        // subset is not a portfolio, and the seeded database is large enough
        // on a busy chain that this is the normal case rather than the edge
        // one: an owner who reads "no balance" without seeing this would
        // conclude something false about their own funds.
        match portfolio.tokens_skipped {
            Some(skipped) if skipped > 0 => lines.push(format!(
                "⚠ Checked {} of {} known tokens on this chain; {skipped} were not read. \
                 A token missing above may simply not have been checked.",
                portfolio.tokens_checked,
                portfolio.tokens_checked + skipped,
            )),
            _ => lines.push(format!(
                "Checked all {} known tokens on this chain.",
                portfolio.tokens_checked
            )),
        }
        Ok(lines.join("\n"))
    })
}

/// One place that answers "is this working, and does it need me?".
///
/// Deliberately local-only. Reaching an endpoint would make the one command
/// someone runs when something is wrong the command most likely to hang, and
/// the questions it answers — is a key present, were the documents accepted,
/// is anything queued — are all answered by files this process already owns.
/// `account list` and the balance reads are where the chain gets involved.
///
/// Nothing here requires legal acceptance, because "the documents are what is
/// blocking you" is one of the answers it exists to give.
fn run_status(config: &ConfigStore, mode: OutputMode) -> Result<()> {
    let state = config.load()?;
    let data_dir = config.data_dir().to_path_buf();

    let legal = crate::legal::LegalStore::production(&data_dir)?.status()?;
    let awaiting = PendingStore::production(&data_dir)?
        .awaiting_approval(None)?
        .len();
    let awaiting_typed_data = TypedDataStore::production(&data_dir)?
        .awaiting_approval(None)?
        .len();
    let awaiting_messages = MessageStore::production(&data_dir)?
        .awaiting_approval(None)?
        .len();
    let policies = PolicyStore::production(&data_dir)?;
    let policy_proposals = policies.list_proposals()?.len();
    let network_proposals = policies.network_proposals()?.len();
    drop(policies);
    let tokens = crate::token_store::TokenStore::production(&data_dir)?;
    let token_count = tokens.count(None)?;
    let token_proposals = tokens.count_proposals()?;
    drop(tokens);

    let waiting = awaiting + awaiting_typed_data + awaiting_messages;
    let report = serde_json::json!({
        "version": BUILD_VERSION,
        "data_dir": data_dir,
        "signing_allowed": legal.signing_allowed,
        "legal": legal,
        "accounts": state.wallets.iter().map(|wallet| serde_json::json!({
            "id": wallet.id,
            "address": format!("{:#x}", wallet.address),
        })).collect::<Vec<_>>(),
        "networks": state.networks.len(),
        "awaiting_approval": {
            "transactions": awaiting,
            "typed_data": awaiting_typed_data,
            "messages": awaiting_messages,
            "policy_proposals": policy_proposals,
            "network_proposals": network_proposals,
        },
        "tokens": { "confirmed": token_count, "suggested": token_proposals },
    });

    emit(mode, &report, || {
        Ok(status_lines(&StatusFacts {
            data_dir: &data_dir.display().to_string(),
            signing_allowed: legal.signing_allowed,
            terms_accepted: legal.terms_of_service.accepted,
            privacy_accepted: legal.privacy_policy.accepted,
            accounts: &state
                .wallets
                .iter()
                .map(|wallet| format!("{} ({:#x})", wallet.id, wallet.address))
                .collect::<Vec<_>>(),
            networks: state.networks.len(),
            token_count,
            token_proposals,
            waiting,
            policy_proposals,
            network_proposals,
        }))
    })
}

/// Everything the human view of `status` reports, gathered so the rendering
/// can be exercised without a database, a keyring, or a terminal.
struct StatusFacts<'a> {
    data_dir: &'a str,
    signing_allowed: bool,
    terms_accepted: bool,
    privacy_accepted: bool,
    accounts: &'a [String],
    networks: usize,
    token_count: u64,
    token_proposals: u64,
    waiting: usize,
    policy_proposals: usize,
    network_proposals: usize,
}

/// Render the human view.
///
/// Every line that reports a missing prerequisite also names the command that
/// supplies it. This is the command someone runs when the wallet is not doing
/// what they expected, and "terms of service not accepted" without the next
/// step just moves the search rather than ending it.
fn status_lines(facts: &StatusFacts<'_>) -> String {
    let mut lines = vec![
        format!("ekubo-wallet {BUILD_VERSION}"),
        format!("Data directory   {}", facts.data_dir),
        String::new(),
    ];
    lines.push(format!(
        "Legal            {}",
        if facts.signing_allowed {
            "terms and privacy policy accepted".to_string()
        } else {
            format!(
                "{} — signing is disabled until both are accepted \
                 (`ekubo-wallet legal accept`)",
                match (facts.terms_accepted, facts.privacy_accepted) {
                    (false, false) => "neither document accepted",
                    (true, false) => "privacy policy not accepted",
                    (false, true) => "terms of service not accepted",
                    // Both recorded yet signing still refused means a document
                    // changed since, and its digest no longer matches.
                    (true, true) => "a document changed and needs re-accepting",
                }
            )
        }
    ));
    lines.push(format!(
        "Accounts         {}",
        if facts.accounts.is_empty() {
            "none — create one with `ekubo-wallet account create <id>`".to_string()
        } else {
            facts.accounts.join(", ")
        }
    ));
    lines.push(format!("Networks         {} configured", facts.networks));
    lines.push(format!(
        "Tokens           {} confirmed{}",
        facts.token_count,
        if facts.token_proposals == 0 {
            String::new()
        } else {
            format!(
                " · {} suggested, waiting on `ekubo-wallet meta-tokens review`",
                facts.token_proposals
            )
        }
    ));

    // The line someone is actually looking for, so it goes last, where a
    // terminal leaves it closest to the prompt.
    let mut queued = Vec::new();
    if facts.waiting > 0 {
        queued.push(format!("{} signing request(s)", facts.waiting));
    }
    if facts.policy_proposals > 0 {
        queued.push(format!("{} policy proposal(s)", facts.policy_proposals));
    }
    if facts.network_proposals > 0 {
        queued.push(format!("{} network suggestion(s)", facts.network_proposals));
    }
    lines.push(format!(
        "Waiting for you  {}",
        if queued.is_empty() {
            "nothing".to_string()
        } else {
            format!("{} — `ekubo-wallet review`", queued.join(", "))
        }
    ));
    lines.join("\n")
}

async fn run_account(config: ConfigStore, command: AccountCommand, mode: OutputMode) -> Result<()> {
    let custody = CustodyService::new(
        config.clone(),
        Arc::new(OsKeyStore),
        Arc::new(PlatformHumanPresence),
    );
    match command {
        AccountCommand::List => {
            let wallets = config.load()?.wallets;
            emit(mode, &wallets, || {
                if wallets.is_empty() {
                    return Ok(
                        "No accounts. Create one with `ekubo-wallet account create <id>`.".into(),
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
        AccountCommand::Create { wallet_id, policy } => {
            // Chosen before the key exists, so a wallet is never briefly
            // permissive while the user is still deciding, and a cancelled
            // prompt leaves nothing behind.
            let Some(starting) = resolve_starting_policy(policy)? else {
                crate::tui::outro_cancel("No wallet was created.");
                return Ok(());
            };
            let wallet = custody.create(&wallet_id)?;
            initialize_wallet_policy(&config, &wallet.id, &starting.policy()).with_context(
                || {
                    format!(
                        "wallet {} was created but policy initialization failed. The wallet exists \
                     and its key is stored; it has no policy, so signing fails closed and the \
                     MCP server refuses to start until it has one. Give it one with \
                     `ekubo-wallet policy require-approval {}`, then choose a policy from there.",
                        wallet.id, wallet.id
                    )
                },
            )?;
            emit(mode, &wallet, || {
                Ok(format!(
                    "Created wallet {} at {:#x} with {}.",
                    wallet.id,
                    wallet.address,
                    starting.description()
                ))
            })
        }
        AccountCommand::Import { wallet_id } => {
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
                            "wallet {} was imported but policy initialization failed. The key is \
                             stored; the wallet has no policy, so signing fails closed and the \
                             MCP server refuses to start until it has one. Give it one with \
                             `ekubo-wallet policy require-approval {}`.",
                            wallet.id, wallet.id
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
        AccountCommand::Export { wallet_id } => {
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
        AccountCommand::Remove { wallet_id } => {
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
                    // The key is gone, so every row under this name describes
                    // a wallet that cannot exist again. Purging covers the
                    // queues and the proposal as well as the policy: the old
                    // revision-checked delete left all three behind.
                    let mut policies = PolicyStore::production(config.data_dir())?;
                    policies.purge(&wallet.id)?;
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
    // Anything already stored under this name belongs to a wallet that no
    // longer exists: `CustodyService::add` refuses an ID the configuration
    // already lists, so reaching here means the inventory has no entry for it.
    // Those rows are the remains of an earlier wallet, and inheriting them
    // would hand a brand-new key the policy — and the queued requests — of the
    // one it replaced. Erasing beats refusing: refusing would leave the name
    // permanently unusable with no way to clear it.
    policies.purge(wallet_id)?;
    policies.put(wallet_id, policy, None)?;
    Ok(())
}

async fn run_token(config: &ConfigStore, command: &TokenCommand, mode: OutputMode) -> Result<()> {
    match command {
        TokenCommand::List {
            chain,
            limit,
            offset,
        } => {
            let chain_id = chain
                .as_deref()
                .map(|chain| resolve_network(config, chain).map(|network| network.chain_id))
                .transpose()?;
            let (limit, offset) = (*limit, *offset);
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
        TokenCommand::Search {
            query,
            chain,
            limit,
        } => {
            let chain_id = chain
                .as_deref()
                .map(|chain| resolve_network(config, chain).map(|network| network.chain_id))
                .transpose()?;
            let store = crate::token_store::TokenStore::production(config.data_dir())?;
            let tokens = store.search(query, chain_id, *limit)?;
            emit(
                mode,
                &serde_json::json!({ "matches": tokens.len(), "tokens": tokens }),
                || {
                    if tokens.is_empty() {
                        return Ok(format!(
                            "No confirmed token matches {query:?}. The wallet shows \
                             unconfirmed tokens by address alone."
                        ));
                    }
                    let mut lines = vec![format!("{} match(es):", tokens.len())];
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
        TokenCommand::Remove { network, address } => {
            run_token_remove(config, network, address, mode)
        }
        TokenCommand::Review => run_token_review(config, mode).await,
        TokenCommand::Import { path, list_name } => {
            run_token_import(config, path, list_name.as_deref(), mode).await
        }
    }
}

/// Forget one confirmed token after the owner confirms it in the terminal.
///
/// Shows what is about to be forgotten before asking, because the address is
/// the only part of the row the owner supplied — confirming "remove USDC"
/// without seeing which address currently carries that name would be agreeing
/// to something they cannot check.
fn run_token_remove(
    config: &ConfigStore,
    network: &str,
    address: &str,
    mode: OutputMode,
) -> Result<()> {
    require_interactive("token database changes")?;
    let network = resolve_network(config, network)?;
    let address =
        Address::from_str(address).with_context(|| format!("{address} is not a token address"))?;
    let mut store = crate::token_store::TokenStore::production(config.data_dir())?;
    let existing = store
        .get(network.chain_id, address)
        .ok()
        .flatten()
        .with_context(|| {
            format!(
                "{} is not a confirmed token on {}",
                address.to_checksum(None),
                network.name
            )
        })?;

    let confirmed = crate::tui::confirm(&format!(
        "Forget {} ({}) on {}? The wallet will show its address instead of this name.",
        existing.symbol.as_deref().unwrap_or("this token"),
        address.to_checksum(None),
        network.name
    ))?;
    if !confirmed {
        crate::tui::outro_cancel("Nothing was removed.");
        return Ok(());
    }

    let removed = store.remove(network.chain_id, address)?;
    emit(
        mode,
        &serde_json::json!({
            "removed": removed,
            "chain_id": network.chain_id.to_string(),
            "address": address.to_checksum(None),
        }),
        || {
            Ok(format!(
                "Forgot {} on {}. Re-import a list naming it to get it back.",
                address.to_checksum(None),
                network.name
            ))
        },
    )
}

/// Import a token list the owner points at, confirming entries in the
/// terminal. This is the trusted way names get into the database: the owner
/// chose the source, and sees exactly what it would name before anything is
/// written.
///
/// Reading the bytes is the only thing that differs between a file and a
/// pipe. Both are equally untrusted, both are parsed by the one shared
/// [`crate::token_list`] parser, and both end at the same review screen — so
/// `-` is a way to spend fewer tokens getting a list here, never a way to
/// skip the owner.
async fn run_token_import(
    config: &ConfigStore,
    path: &std::path::Path,
    list_name: Option<&str>,
    mode: OutputMode,
) -> Result<()> {
    let from_stdin = path == std::path::Path::new("-");
    let body = if from_stdin {
        // Bounded at the parser's own cap plus one byte, so an endless pipe
        // is refused by the size check rather than by the allocator.
        let mut buffer = Vec::new();
        io::stdin()
            .take(crate::token_list::MAX_TOKEN_LIST_BYTES as u64 + 1)
            .read_to_end(&mut buffer)
            .context("failed to read the token list from standard input")?;
        // Every prompt reads the terminal rather than stdin, so spending
        // stdin on the list does not cost us the review screen.
        crate::tui::note_stdin_consumed();
        buffer
    } else {
        std::fs::read(path)
            .with_context(|| format!("failed to read token list {}", path.display()))?
    };
    let origin = if from_stdin {
        "standard input".to_owned()
    } else {
        path.display().to_string()
    };
    let parsed = crate::token_list::parse_token_list(&body)
        .with_context(|| format!("failed to import the token list from {origin}"))?;
    let source = list_name
        .map(str::to_owned)
        .or(parsed.declared_name)
        .unwrap_or_else(|| {
            if from_stdin {
                "standard input".into()
            } else {
                path.file_name()
                    .map_or_else(|| "token list".into(), |name| name.to_string_lossy().into())
            }
        });
    // Said before the screen opens, so a list that arrived shorter than the
    // owner expected explains itself rather than just looking incomplete.
    if parsed.skipped_non_evm > 0 {
        crate::tui::warning(format!(
            "Skipped {} entr{} without a 20-byte EVM address; this wallet cannot act on them.",
            parsed.skipped_non_evm,
            if parsed.skipped_non_evm == 1 {
                "y"
            } else {
                "ies"
            }
        ));
    }
    confirm_and_store(
        config,
        vec![(source, parsed.tokens)],
        mode,
        &std::collections::BTreeMap::new(),
    )
    .await
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
                    "{} token(s) await review. Run `ekubo-wallet meta-tokens review` in a \
                     terminal to confirm them.",
                    proposals.len()
                ))
            },
        );
    }

    // Which row each suggestion was read from, captured before the store is
    // released and the screen waits on a person. A decision reached about this
    // reading must not consume a different one made under the same key while
    // the owner was reading.
    let proposed_at: std::collections::BTreeMap<(u64, Address), chrono::DateTime<chrono::Utc>> =
        proposals
            .iter()
            .map(|proposal| {
                (
                    (proposal.token.chain_id, proposal.token.address),
                    proposal.proposed_at,
                )
            })
            .collect();

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
    confirm_and_store(config, groups, mode, &proposed_at).await
}

/// Show the picker, verify what the owner accepted against the chain, and
/// write it. `clear_proposals` maps each reviewed suggestion to the
/// `proposed_at` of the exact row it was read from, so a decision consumes
/// that row and not whatever has since taken its place under the same key.
async fn confirm_and_store(
    config: &ConfigStore,
    groups: Vec<(String, Vec<crate::token_store::ListedToken>)>,
    mode: OutputMode,
    clear_proposals: &std::collections::BTreeMap<(u64, Address), chrono::DateTime<chrono::Utc>>,
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
        let keys: Vec<(u64, Address, chrono::DateTime<chrono::Utc>)> = decision
            .rejected
            .iter()
            .filter_map(|token| {
                let key = (token.chain_id, token.address);
                clear_proposals
                    .get(&key)
                    .map(|proposed_at| (key.0, key.1, *proposed_at))
            })
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

    // Naming a token is the last step in a chain that started with an agent,
    // and every earlier link is untrusted: the list, the symbol, the decimals,
    // and the suggestion to look at them at all. What comes out of it decides
    // what the owner reads when they approve a transfer — `USDC` against an
    // address, and an amount scaled by decimals this row supplied. So the
    // terminal picker establishes intent and this establishes presence, the
    // same OS-backed check that guards replacing a policy.
    //
    // Only acceptance is gated. Rejecting deletes a suggestion, which can
    // mislead nobody, and asking for a fingerprint to say "no" would teach
    // people to authenticate their way through prompts.
    if !decision.accepted.is_empty() {
        PlatformHumanPresence
            .confirm(&PresenceRequest::ConfirmTokenNames {
                count: decision.accepted.len(),
            })
            .await?;
    }

    // The owner's yes is the whole decision. Nothing is asked of a chain
    // here: a contract cannot tell them whether the curator they are trusting
    // is trustworthy, and that is the only question a listing raises. An
    // address that answers nothing becomes a row that names nothing, which
    // costs a line in the database and misleads no one.
    //
    // This is also why accepting needs no network. A name for a chain the
    // owner has not configured is not a name they cannot have; it simply
    // waits for the chain.
    let decided: Vec<(u64, Address)> = decision
        .accepted
        .iter()
        .map(|token| (token.chain_id, token.address))
        .collect();
    let accepted: Vec<(crate::token_store::ListedToken, String)> = decision
        .accepted
        .into_iter()
        .map(|token| {
            let source = sources
                .get(&(token.chain_id, token.address))
                .cloned()
                .unwrap_or_else(|| "list".into());
            (token, source)
        })
        .collect();
    // One transaction for the whole decision. A row at a time meant a
    // filesystem sync each, and an accepted import can carry ten thousand of
    // them -- minutes of frozen terminal, and half of it applied if the owner
    // gave up waiting.
    let confirmed = store.insert_all_absent(&accepted)?;
    if !clear_proposals.is_empty() {
        let clear: Vec<(u64, Address, chrono::DateTime<chrono::Utc>)> = decided
            .into_iter()
            .filter_map(|key| {
                clear_proposals
                    .get(&key)
                    .map(|proposed_at| (key.0, key.1, *proposed_at))
            })
            .collect();
        store.discard_proposals(&clear)?;
    }
    emit(mode, &serde_json::json!({ "confirmed": confirmed }), || {
        Ok(format!("Confirmed {confirmed} token name(s)."))
    })
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
                    "The address book is empty. Run `ekubo-wallet meta-address-book` to add aliases interactively, or `ekubo-wallet meta-address-book add <network> <alias> <address>`.".into(),
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
            let accept =
                |document: LegalDocument, question: &str, accept_label: &str| -> Result<bool> {
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
                    // Asked in a screen of its own rather than an inline prompt.
                    // The pager has just held the terminal; dropping to the
                    // scrollback for the one question that matters put the digest
                    // and the answer in a different place from the document they
                    // are about.
                    let accepted = crate::fullscreen::confirm_review(
                        document.title(),
                        &[
                            vec![crate::fullscreen::Span::toned(
                                "You have read this document to the end.",
                                crate::tui::Tone::Muted,
                            )],
                            Vec::new(),
                            vec![
                                crate::fullscreen::Span::toned(
                                    "Document digest: ",
                                    crate::tui::Tone::Muted,
                                ),
                                crate::fullscreen::Span::plain(&digest),
                            ],
                        ],
                        question,
                        accept_label,
                        "Decline — signing stays disabled",
                    )?;
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
                    "Accept the Terms of Service",
                )?,
                "the Terms of Service were not accepted; signing stays disabled"
            );
            ensure!(
                accept(
                    LegalDocument::PrivacyPolicy,
                    "Do you separately acknowledge this Privacy Policy?",
                    "Acknowledge the Privacy Policy",
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
        // Discards the proposal that was actually read, not whatever occupies
        // the wallet's slot by now: the two reads above are separate, so a
        // replacement written in between could reference the current revision
        // and be perfectly applicable.
        let discarded = policies.delete_proposal(&proposal)?;
        anyhow::bail!(
            "the pending proposal referenced policy revision {} but the active policy is now \
             revision {}; {}. Ask the agent to read the current policy and propose again.",
            proposal.source_revision,
            current.revision,
            if discarded {
                "the stale proposal was discarded"
            } else {
                "it has already been replaced by a newer one, which was left in place"
            }
        );
    }

    let diff = crate::core::policy::diff_policies(&current.policy, &proposal.policy);
    let digest = proposal.policy.digest()?;
    // Full-screen rather than inline: the diff is exactly as long as the
    // change is, and the two warnings below are the ones a reviewer most needs
    // still on screen when they answer. This is also reached from the
    // pending-approvals browser, which is already a screen.
    let question = crate::fullscreen::Review::new(
        "Apply proposed wallet policy",
        "An agent proposed this replacement policy. The permission diff below is authoritative; \
         the rationale is the agent's own explanation.",
    )
    .fact("Wallet", &wallet.id)
    .fact("Address", format!("{:#x}", wallet.address))
    .fact("Current revision", current.revision.to_string())
    .fact("Proposed", described_time(proposal.created_at))
    .fact("Agent rationale (untrusted)", &proposal.rationale)
    .fact_lines("Changes", diff.iter().cloned())
    .warning("A more permissive policy can authorize transactions without an exceptional approval.")
    .warning(
        "The rationale is agent-authored text. Judge the change by the diff lines, not the story.",
    );
    if !question.ask("Apply this policy?", "Apply", "Cancel")? {
        crate::tui::outro_cancel("Policy unchanged. The proposal is still pending.");
        return Ok(());
    }

    PlatformHumanPresence
        .confirm(&PresenceRequest::ReplacePolicy {
            wallet: wallet.id.clone(),
        })
        .await?;

    // Applies and consumes the exact row that was reviewed, in one
    // transaction. The revision check inside it still makes a policy change
    // during the review fail closed; matching the proposal itself covers the
    // case that check cannot see, where a newer proposal arrived while the
    // active revision never moved.
    let stored = policies.consume_proposal(&proposal)?;
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
        TransactionCommand::List { account, limit } => {
            if let Some(account) = account.as_deref() {
                config.wallet(account)?;
            }
            let transactions = pending.list(account.as_deref(), limit)?;
            // Settle in-flight rows against the chain before display. The
            // in-flight unique index bounds this at one row per wallet and
            // chain, so a long listing still costs at most a couple of RPCs.
            let pending = std::sync::Mutex::new(pending);
            let transactions =
                crate::reconcile::reconcile_all(config, &pending, transactions).await;
            if mode.effective() == OutputMode::Json {
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
            if mode.effective() == OutputMode::Json {
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
            // Cancelling signs, so it takes the gate every other signing path
            // takes. `wallet_attempt_cancel` already does; these CLI paths did
            // not, which made acceptance depend on which door was used.
            legal::require_current_acceptance(config.data_dir())?;
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
            if mode.effective() == OutputMode::Json {
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
            if mode.effective() == OutputMode::Json {
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
            let record = pending.get_by_identifier(&identifier)?;
            let network = config.network_by_chain_id(&record.chain_id)?;
            // `signed` does not by itself mean "never sent". A submission whose
            // process died mid-send is recovered by returning the row to
            // `signed`, and that recovery turns on `transaction_known`, whose
            // negative answer is not authoritative: a node that has evicted or
            // never saw the envelope answers exactly as one that was never
            // offered it, while a peer may still hold it.
            //
            // So settle it against the chain first, and then ask the node
            // directly about the hash. Neither can prove the bytes are
            // unreachable — nothing can — but both catch the case where the
            // wallet is about to tell its owner something false.
            let pending = std::sync::Mutex::new(pending);
            let record =
                crate::reconcile::reconcile_record(&pending, &network, record, true).await?;
            if let Some(hash) = record.signed_transaction_hash.as_deref()
                && crate::rpc::transaction_known(&network, hash).await?
            {
                anyhow::bail!(
                    "{} is known to the configured node, so it can still mine; cancel it on \
                     chain with `ekubo-wallet transaction cancel` rather than discarding it \
                     locally",
                    record.request_id
                );
            }
            let record = pending
                .lock()
                .map_err(|_| anyhow::anyhow!("pending database lock was poisoned"))?
                .discard_unsent(record.request_id)?;
            if mode.effective() == OutputMode::Json {
                return print_json(&record);
            }
            println!(
                "Discarded {}: the wallet has stopped tracking it and its in-flight slot is \
                 free again. Nothing was found on chain or in the configured node's mempool, \
                 but a signed envelope that did reach the network can still mine at its nonce.",
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

/// Show what awaits review, and — on an interactive terminal — let the user
/// pick an entry to review right there.
///
/// The browser is only ever navigation: choosing an entry leaves the
/// alternate screen first and the review runs exactly as
/// `ekubo-wallet review <request-id>` would — its JSON record prints into
/// the terminal transcript, and the review then takes over the screen again
/// for the scrollable document. When that review finishes, the queues are
/// reloaded and the browser returns, minus whatever was just resolved.
async fn list_pending_approvals(config: &ConfigStore, mode: OutputMode) -> Result<()> {
    loop {
        let awaiting = PendingStore::production(config.data_dir())?.awaiting_approval(None)?;
        let awaiting_typed_data =
            TypedDataStore::production(config.data_dir())?.awaiting_approval(None)?;
        let awaiting_messages =
            MessageStore::production(config.data_dir())?.awaiting_approval(None)?;
        let policies = PolicyStore::production(config.data_dir())?;
        let proposals = policies.list_proposals()?;
        let network_proposals = policies.network_proposals()?;
        drop(policies);
        if mode == OutputMode::Json || !crate::tui::interactive() {
            return print_pending_approvals(
                mode,
                &awaiting,
                &awaiting_typed_data,
                &awaiting_messages,
                &proposals,
                &network_proposals,
            );
        }
        if awaiting.is_empty()
            && awaiting_typed_data.is_empty()
            && awaiting_messages.is_empty()
            && proposals.is_empty()
            && network_proposals.is_empty()
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
            &network_proposals,
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
            PendingChoice::Network(chain_id) => {
                review_network_proposal_by_chain(config, *chain_id).await
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
    /// A proposed network profile, reviewed per chain.
    Network(u64),
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

/// The five pending queues flattened into browser rows, with the action each
/// row's Enter takes alongside.
///
/// Token suggestions are deliberately absent. One accepted list can propose
/// hundreds of rows at once, and a queue that arrives by the hundred would
/// bury the handful of things that actually block signing; `meta-tokens review`
/// stays its own screen, where the suggestions can be grouped by the list
/// that carried them.
fn pending_approval_rows(
    config: &ConfigStore,
    awaiting: &[PendingTransaction],
    awaiting_typed_data: &[PendingTypedData],
    awaiting_messages: &[PendingMessage],
    proposals: &[crate::policy_store::PolicyProposal],
    network_proposals: &[crate::config::NetworkConfig],
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
    for proposal in network_proposals {
        rows.push(TableRow::new(
            vec![
                none(),
                Span::plain("network"),
                none(),
                none(),
                Span::plain(&proposal.name),
            ],
            &[
                "network proposal",
                &proposal.name,
                &proposal.chain_id.to_string(),
                proposal.primary_rpc_url().as_str(),
            ],
        ));
        choices.push(PendingChoice::Network(proposal.chain_id));
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
    network_proposals: &[crate::config::NetworkConfig],
) -> Result<()> {
    if awaiting.is_empty()
        && awaiting_typed_data.is_empty()
        && awaiting_messages.is_empty()
        && proposals.is_empty()
        && network_proposals.is_empty()
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
        if !network_proposals.is_empty() {
            eprintln!(
                "{} network suggestion(s) await `ekubo-wallet network review`.",
                network_proposals.len()
            );
        }
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
            "pending_network_proposals": network_proposals,
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
        // Only an absent row sends the search on. Anything else -- a row that
        // has already been decided, an envelope that no longer parses, a
        // database that cannot be read -- is this queue's answer about this
        // request, and carrying on past it rejected whatever the next queue
        // happened to hold under that id while the request the owner meant
        // stayed awaiting a decision.
        Err(transaction_error) if !is_unknown_request(&transaction_error) => {
            return Err(transaction_error);
        }
        Err(transaction_error) => {
            let mut typed_data = TypedDataStore::production(config.data_dir())?;
            let request = match typed_data.reject(request_id) {
                Ok(request) => Some(request),
                Err(typed_data_error) if !is_unknown_request(&typed_data_error) => {
                    return Err(typed_data_error);
                }
                Err(_) => None,
            };
            let Some(request) = request else {
                let mut messages = MessageStore::production(config.data_dir())?;
                let request = match messages.reject(request_id) {
                    Ok(request) => Some(request),
                    Err(message_error) if !is_unknown_request(&message_error) => {
                        return Err(message_error);
                    }
                    Err(_) => None,
                };
                let Some(request) = request else {
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
        // As in `run_reject`: only a missing row means "try the next queue".
        // A stored row this queue cannot read is a failure the owner has to
        // see, not permission to review something else under the same id.
        Err(transaction_error) if !is_unknown_request(&transaction_error) => {
            return Err(transaction_error);
        }
        Err(transaction_error) => {
            drop(pending);
            let typed_data = TypedDataStore::production(config.data_dir())?;
            let found = match typed_data.get(request_id) {
                Ok(request) => Some(request),
                Err(typed_data_error) if !is_unknown_request(&typed_data_error) => {
                    return Err(typed_data_error);
                }
                Err(_) => None,
            };
            let Some(request) = found else {
                let messages = MessageStore::production(config.data_dir())?;
                let found = match messages.get(request_id) {
                    Ok(request) => Some(request),
                    Err(message_error) if !is_unknown_request(&message_error) => {
                        return Err(message_error);
                    }
                    Err(_) => None,
                };
                let Some(request) = found else {
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

/// The terminal implementation of the review seam: draw the
/// orchestrator-authored document in the same full-screen scrollable review
/// the signing requests use — Approve stays unreachable until the end of the
/// document has been on screen. `no_confirm` skips only the review — owner
/// authentication still follows in the orchestrator.
///
/// Nothing is printed before that screen opens. This used to dump the approval
/// and its simulation as JSON first, which restated what the document already
/// renders and scrolled the terminal immediately before a full-screen surface
/// covered it, so the dump was never read where it was written and survived
/// only as scrollback the reviewer paged past once the screen was released.
/// The typed-data and message paths still print their transcripts: those
/// review the payload itself, which has no document of its own.
struct CliTransactionPresenter {
    no_confirm: bool,
}

#[async_trait::async_trait]
impl crate::approval::ReviewPresenter for CliTransactionPresenter {
    async fn review_transaction(
        &self,
        request: &ApprovalRequest,
        _simulation: &SimulationResult,
        refresh: &dyn crate::approval::ReviewRefresh,
    ) -> Result<ApprovalDecision> {
        if self.no_confirm {
            // The flag answers the question without being asked it. What it
            // must not also skip is the subject: a transaction is queued here
            // precisely because its policy asked something or its simulation
            // failed, so this is the path with the most to see and it was
            // showing nothing at all — no target, no value, no calldata, no
            // fees, no finding, no digest. The typed-data and message paths
            // print their transcripts under the same flag; this restores the
            // parity, and the document still reaches the terminal before the
            // owner authentication that follows in the orchestrator.
            print_review_document(request)?;
            return Ok(ApprovalDecision::Approved);
        }
        // The plan's calldata already lives in the document's call sections,
        // so there is no separate payload to append.
        //
        // This is the one review that can be re-simulated, and the one that
        // needs to be: a transaction is queued here precisely when its
        // simulation failed or its policy asked a question, and the first of
        // those is often about the moment rather than the plan.
        crate::approve_tui::review_fullscreen_refreshable(request, Vec::new(), Some(refresh)).await
    }
}

async fn approve_typed_data(
    config: &ConfigStore,
    store: TypedDataStore,
    request: PendingTypedData,
    no_confirm: bool,
    mode: OutputMode,
) -> Result<()> {
    match crate::signing_review::decide_typed_data(config, store, request, no_confirm).await? {
        crate::signing_review::TypedDataDecision::Rejected(rejected) => emit_rejected(
            mode,
            "typed-data request",
            rejected.request_id,
            &rejected.digest,
            rejected.rejected_at,
        ),
        crate::signing_review::TypedDataDecision::Signed(stored) => {
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
    }
}

async fn approve_message(
    config: &ConfigStore,
    store: MessageStore,
    request: PendingMessage,
    no_confirm: bool,
    mode: OutputMode,
) -> Result<()> {
    match crate::signing_review::decide_message(config, store, request, no_confirm).await? {
        crate::signing_review::MessageDecision::Rejected(rejected) => emit_rejected(
            mode,
            "message request",
            rejected.request_id,
            &rejected.digest,
            rejected.rejected_at,
        ),
        crate::signing_review::MessageDecision::Signed(stored) => {
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
    }
}

/// Write the orchestrator-authored review document to the terminal, for the
/// path that takes the decision without opening the screen that would have
/// drawn it.
fn print_review_document(request: &ApprovalRequest) -> Result<()> {
    let mut stderr = io::stderr().lock();
    stderr.write_all(crate::approve_tui::review_document_text(request, Vec::new()).as_bytes())?;
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
    .fact("New policy digest", &digest)
    // The change itself, which this prompt did not show. The proposal review
    // has always rendered `diff_policies` and called it authoritative; the
    // direct route asked the same authority question -- `policy set`,
    // `allow-all`, `require-approval` all land here -- and answered it with a
    // wallet name, a revision number, and a generic warning. An owner could
    // approve a materially more permissive policy without being shown a single
    // chain, call, or value that was gaining unattended signing authority.
    //
    // Against the fail-closed baseline when there is no current policy, since
    // that is what "no policy" means to every signing path: nothing is
    // permitted. A diff against it reads as what this policy grants.
    .fact_lines(
        if current.is_some() {
            "Changes"
        } else {
            "Grants (this wallet has no policy today)"
        },
        {
            let baseline = current
                .as_ref()
                .map_or_else(WalletPolicy::require_approval_for_everything, |stored| {
                    stored.policy.clone()
                });
            let lines = crate::core::policy::diff_policies(&baseline, policy);
            if lines.is_empty() {
                vec!["no change to what this wallet may sign".to_owned()]
            } else {
                lines
            }
        },
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
        NetworkCommand::Presets { search, all } => {
            let networks = match (search, all) {
                (None, false) => default_networks(),
                (None, true) => registry_networks(None),
                (Some(query), _) => {
                    let networks = registry_networks(Some(&query));
                    ensure!(
                        !networks.is_empty(),
                        "nothing in the built-in registry matches {query}"
                    );
                    networks
                }
            };
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
            // Full-screen: what this discards is one entry per configured
            // network, so the list is as long as the user's configuration and
            // naming them is the whole point of asking.
            let mut question = crate::fullscreen::Review::new(
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
                    "nothing — every network matches its preset",
                );
            } else {
                question = question
                    .fact_lines(
                        "Losing custom settings, including RPC URLs",
                        discarded.iter().map(|name| (*name).to_owned()),
                    )
                    .warning(
                        "Custom settings for the networks listed above are discarded and cannot \
                         be recovered from here.",
                    );
            }
            if !question.ask("Reset every network?", "Reset", "Cancel")? {
                crate::tui::outro_cancel("Networks unchanged.");
                return Ok(());
            }
            // A configuration mutation, so it takes owner authentication like
            // every other one — and binds to what was actually reviewed: the
            // discarded-settings warning above was computed from a snapshot,
            // so committing over a configuration that has moved since would
            // discard custom endpoints the owner was never shown.
            PlatformHumanPresence
                .confirm(&PresenceRequest::ConfirmNetwork {
                    network: "the built-in presets".into(),
                })
                .await?;
            config.update(|state| {
                ensure!(
                    state.networks == configured,
                    "the configured networks changed while the reset was being confirmed; \
                     nothing was reset"
                );
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
            // Captured before `prospective` is mutated: this is the profile the
            // human is about to be shown replacing, and the write below refuses
            // if the configuration no longer holds it.
            let reviewed = prospective
                .iter()
                .find(|network| network.chain_id == candidate.chain_id)
                .cloned();
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
                    ("Network", vec![candidate.name.clone()]),
                    ("Chain ID", vec![candidate.chain_id.to_string()]),
                    ("RPC URLs", endpoint_list(&candidate)),
                    ("RPC strategy", vec![candidate.rpc_strategy.to_string()]),
                ],
            )? {
                crate::tui::outro_cancel("No network added.");
                return Ok(());
            }
            verify_chain_id(&candidate).await?;
            PlatformHumanPresence
                .confirm(&PresenceRequest::ConfirmNetwork {
                    network: candidate.name.clone(),
                })
                .await?;
            config.update(|state| {
                ensure_reviewed_network(&state.networks, candidate.chain_id, reviewed.as_ref())?;
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
                        "Configured {} (chain {}) via {} endpoint(s), starting with {}; the RPC verified its chain ID.",
                        candidate.name,
                        candidate.chain_id,
                        candidate.rpc_urls.len(),
                        candidate.primary_rpc_url(),
                    ))
                },
            )
        }
        NetworkCommand::Edit { name } => run_network_edit(config, name, mode).await,
        NetworkCommand::Review => run_network_review(config, mode).await,
        NetworkCommand::Remove { name } => {
            let mut prospective = config.load()?.networks;
            let removed = remove_configured_network(&mut prospective, &name)?;
            if !confirm_network_change(
                "Remove network",
                "The wallet will forget this network and the endpoint it was reached through.",
                "Remove this network?",
                vec![
                    ("Network", vec![removed.name.clone()]),
                    ("Chain ID", vec![removed.chain_id.to_string()]),
                ],
            )? {
                crate::tui::outro_cancel("Networks unchanged.");
                return Ok(());
            }
            PlatformHumanPresence
                .confirm(&PresenceRequest::ConfirmNetwork {
                    network: removed.name.clone(),
                })
                .await?;
            // `remove_configured_network` resolves whatever currently answers
            // to `name`, and a name or alias can move between the confirmation
            // and the write. Remove the entry that was shown or nothing.
            let reviewed = removed.clone();
            let removed = config.update(|state| {
                let removed = remove_configured_network(&mut state.networks, &name)?;
                ensure!(
                    removed == reviewed,
                    "network {name} no longer describes the profile that was confirmed; \
                     nothing was removed"
                );
                Ok(removed)
            })?;
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

/// Every configured endpoint, one per line, for a review or listing screen.
///
/// All of them, always. Failover reaches any endpoint in the list, so a
/// display that showed only the first would be describing a different wallet
/// than the one that runs.
fn endpoint_lines(network: &NetworkConfig, indent: &str) -> String {
    network
        .rpc_urls
        .iter()
        .map(|url| format!("{indent}{url}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The same endpoints as separate values, for a confirmation that renders one
/// fact per line. Joining them first and letting the renderer split again
/// cannot work: both renderings clamp a fact to one line, so the newlines are
/// gone by the time anything could split on them.
fn endpoint_list(network: &NetworkConfig) -> Vec<String> {
    network.rpc_urls.iter().map(ToString::to_string).collect()
}

/// Registry entries, optionally narrowed to a query.
///
/// A chain ID matches exactly and nothing else, because someone who typed a
/// number knows which chain they mean; anything else is matched loosely
/// against the name, aliases, and display name.
fn registry_networks(query: Option<&str>) -> Vec<NetworkConfig> {
    let query = query.map(str::trim);
    ekubo_wallet_core::networks::known_networks()
        .iter()
        .filter(|profile| match query {
            None => true,
            Some(query) => {
                if let Ok(chain_id) = query.parse::<u64>() {
                    return profile.config.chain_id == chain_id;
                }
                let needle = query.to_lowercase();
                profile.config.name.contains(&needle)
                    || profile
                        .config
                        .aliases
                        .iter()
                        .any(|alias| alias.contains(&needle))
                    || profile
                        .config
                        .display_name
                        .as_deref()
                        .is_some_and(|name| name.to_lowercase().contains(&needle))
            }
        })
        .map(|profile| profile.config.clone())
        .collect()
}

/// One line for a table cell that cannot hold the whole list: the endpoint
/// that will actually be tried first, and how many stand behind it.
fn endpoint_summary(network: &NetworkConfig) -> String {
    match network.rpc_urls.len() {
        1 => network.primary_rpc_url().to_string(),
        count => format!("{} (+{} fallback)", network.primary_rpc_url(), count - 1),
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
            let aliases = if network.aliases.is_empty() {
                String::new()
            } else {
                format!(" — aliases: {}", network.aliases.join(", "))
            };
            let explorer = network
                .block_explorer_url
                .as_ref()
                .map_or_else(String::new, |url| format!("\n  explorer: {url}"));
            format!(
                "{} (chain {}){aliases}\n  rpc:\n{}\n  strategy: {}{explorer}",
                network.name,
                network.chain_id,
                endpoint_lines(network, "       "),
                network.rpc_strategy,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
#[path = "cli_network_disclosure_test.rs"]
mod network_disclosure_tests;
fn describe_network(network: &NetworkConfig) -> serde_json::Value {
    serde_json::json!({
        "name": network.name,
        "display_name": network.display_name,
        "aliases": network.aliases,
        "chain_id": network.chain_id.to_string(),
        "rpc_urls": network
            .rpc_urls
            .iter()
            .map(url::Url::as_str)
            .collect::<Vec<_>>(),
        "rpc_strategy": network.rpc_strategy.to_string(),
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
    let candidate = if let Some(base) = network_base(&name, args.chain_id, configured) {
        apply_network_overrides(base, args)?
    } else {
        ensure!(
            args.chain_id.is_some(),
            "unknown network {name}; run `ekubo-wallet network presets` to see the built-in ones, `ekubo-wallet network list` to see the configured ones, or pass a chain ID to define a custom network",
        );
        build_custom_network(name, &args)?
    };
    // Checked here rather than only at the write. The same rules run again
    // inside `add_configured_network`, so nothing invalid can be stored
    // either way — but a profile that will be refused should be refused
    // before the owner is walked through a confirmation screen, a live
    // chain-ID probe, and an operating-system authentication prompt, all to
    // be told at the end that a number they typed was out of range.
    ekubo_wallet_core::config::validate_network(&candidate)?;
    Ok(candidate)
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
        if args.rpc_urls.is_empty() {
            let answer = prompt_network_field(
                custom_network_field("--rpc-url"),
                Some(
                    &known
                        .rpc_urls
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            )?;
            args.rpc_urls = parse_endpoint_list(&answer)?;
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
/// What already describes a chain: the owner's own configuration first, then
/// the compiled-in registry.
///
/// The registry is every chain chainlist knows of that answered this wallet's
/// probe, not merely the ones configured by default, so adding a chain the
/// wallet did not default to is a chain ID and a confirmation rather than a
/// hunt for a working endpoint.
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
            ekubo_wallet_core::networks::known_network(chain_id).map(|profile| {
                (
                    profile.config.clone(),
                    if profile.is_default {
                        "the built-in preset"
                    } else {
                        "known to the built-in registry"
                    },
                )
            })
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
                    Span::toned(endpoint_summary(network), crate::tui::Tone::Muted),
                ],
                &[
                    &network.name,
                    &display_name,
                    &aliases,
                    &network.chain_id.to_string(),
                    // Every endpoint is searchable even though one row cannot
                    // show them all: someone looking for which network uses a
                    // given provider is asking about the whole list.
                    &endpoint_lines(network, ""),
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

    // One full-screen form, opened straight from the full-screen picker above.
    // This used to be an inline menu of fields with an inline prompt behind
    // each one, so editing four values flipped the terminal between the
    // alternate screen and the scrollback nine times and left the answered
    // line of every prompt behind.
    let fields = CUSTOM_NETWORK_FIELDS
        .iter()
        .map(|field| crate::fullscreen::FormField {
            label: field.prompt.to_owned(),
            help: format!("{} · example: {}", field.help, field.example),
            value: network_field_value(&original, field.flag),
        })
        .collect();
    // Validated against the same per-flag rules the inline prompt used, but on
    // save and for the whole form, so the reason names the field it belongs to
    // and the cursor lands there instead of the value being refused after the
    // screen is gone.
    let Some(values) = crate::fullscreen::edit_form(
        &format!(
            "Edit network {} (chain {})",
            original.name, original.chain_id
        ),
        fields,
        |values| {
            for (index, (field, value)) in CUSTOM_NETWORK_FIELDS.iter().zip(values).enumerate() {
                validate_network_field(field.flag, value).map_err(|reason| (index, reason))?;
            }
            Ok(())
        },
    )?
    else {
        crate::tui::outro_cancel("Nothing edited.");
        return Ok(());
    };
    let mut draft = original.clone();
    for (field, value) in CUSTOM_NETWORK_FIELDS.iter().zip(&values) {
        set_network_field(&mut draft, field.flag, value)?;
    }
    if draft == original {
        crate::tui::outro("No changes to save.");
        return Ok(());
    }

    // Asked in a full-screen document, like the form it follows. The inline
    // confirmation this replaced was the last step that dropped to the
    // scrollback mid-command.
    if !network_review(
        "Save network changes",
        "The wallet will read chain state and run eth_simulateV1 through this endpoint.",
        vec![
            ("Network", vec![draft.name.clone()]),
            ("Chain ID", vec![draft.chain_id.to_string()]),
            ("RPC URLs", endpoint_list(&draft)),
            ("RPC strategy", vec![draft.rpc_strategy.to_string()]),
        ],
    )
    .ask(
        "Save these changes to this network?",
        "Save these changes",
        "Cancel — nothing is written",
    )? {
        crate::tui::outro_cancel("Nothing saved.");
        return Ok(());
    }
    verify_chain_id(&draft).await?;
    PlatformHumanPresence
        .confirm(&PresenceRequest::ConfirmNetwork {
            network: draft.name.clone(),
        })
        .await?;
    config.update(|state| {
        ensure_reviewed_network(&state.networks, draft.chain_id, Some(&original))?;
        replace_configured_network(&mut state.networks, draft.clone())
    })?;
    emit(
        mode,
        &serde_json::json!({
            "network": describe_network(&draft),
            "rpc_verified": true,
        }),
        || {
            Ok(format!(
                "Updated {} (chain {}) via {}; the RPC verified its chain ID.",
                draft.name,
                draft.chain_id,
                draft.primary_rpc_url(),
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
        "--rpc-url" => network
            .rpc_urls
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        "--rpc-strategy" => network.rpc_strategy.to_string(),
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
        "--rpc-url" => network.rpc_urls = parse_endpoint_list(value)?,
        "--rpc-strategy" => {
            network.rpc_strategy = value.parse().context("RPC strategy is invalid")?;
        }
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
        .or_else(|| {
            ekubo_wallet_core::networks::known_networks()
                .iter()
                .map(|profile| &profile.config)
                .find(|network| matches(network))
                .cloned()
        })
}

/// Refuse a network write whose reviewed premise no longer holds.
///
/// Every confirmed network change reads the configuration, shows a human what
/// it is about to replace, and waits — for a prompt, an RPC probe, and an OS
/// presence check. All three take as long as the person does. A write that
/// then trusts the reading it took before the pause overwrites whatever landed
/// during it, and `replace_configured_network` is unconditional, so a chain
/// removed while the screen was up comes back.
///
/// Checked inside the `update` closure, which is the only place the lock is
/// held and therefore the only place the answer stays true long enough to act
/// on. Nothing is written on a mismatch; re-running the command re-reads and
/// re-asks against what is actually configured.
fn ensure_reviewed_network(
    networks: &[NetworkConfig],
    chain_id: u64,
    reviewed: Option<&NetworkConfig>,
) -> Result<()> {
    let current = networks.iter().find(|network| network.chain_id == chain_id);
    ensure!(
        current == reviewed,
        "chain {chain_id} changed while this was being reviewed; nothing was written. Run the command again to decide against the current configuration."
    );
    Ok(())
}

/// One or more RPC endpoints, however a human typed them: separated by
/// commas, spaces, or newlines.
///
/// Duplicates are refused rather than dropped. A list naming one endpoint
/// twice has fewer fallbacks than it looks like it has — the second attempt
/// reaches the service that just failed — and silently collapsing it would
/// leave the owner believing in a redundancy they do not have.
fn parse_endpoint_list(value: &str) -> Result<Vec<Url>> {
    let endpoints = value
        .split([',', ' ', '\n', '\t'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.parse::<Url>().context("RPC URL is invalid"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(!endpoints.is_empty(), "at least one RPC URL is required");
    let mut seen = std::collections::BTreeSet::new();
    for endpoint in &endpoints {
        ensure!(
            seen.insert(endpoint.as_str()),
            "{endpoint} is listed twice; each fallback must be a different endpoint"
        );
    }
    Ok(endpoints)
}

/// Apply only the fields this invocation actually supplied.
fn apply_network_overrides(mut base: NetworkConfig, args: NetworkAddArgs) -> Result<NetworkConfig> {
    if !args.rpc_urls.is_empty() {
        base.rpc_urls = args.rpc_urls;
    }
    if let Some(strategy) = args.rpc_strategy {
        base.rpc_strategy = strategy;
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
    /// Whether a scripted `network add` may leave this out and take the
    /// default.
    ///
    /// Every descriptive field is required, because a network nobody named is
    /// a network nobody can read back. A setting that is a *choice* between
    /// safe alternatives is not: demanding it would break every existing
    /// scripted install to ask a question whose answer was already fine.
    /// It still appears in the edit form, so it is no less editable for being
    /// optional.
    optional: bool,
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
        optional: false,
    },
    RequiredField {
        flag: "--alias",
        prompt: "Aliases (comma-separated)",
        help: "Short names this chain can also be selected by",
        example: "base-mainnet, base8453",
        default: None,
        optional: false,
    },
    RequiredField {
        flag: "--native-currency-name",
        prompt: "Native currency name",
        help: "The gas token's full name",
        example: "Ether",
        default: Some("Ether"),
        optional: false,
    },
    RequiredField {
        flag: "--native-currency-symbol",
        prompt: "Native currency symbol",
        help: "The gas token's ticker",
        example: "ETH",
        default: Some("ETH"),
        optional: false,
    },
    RequiredField {
        flag: "--native-currency-decimals",
        prompt: "Native currency decimals",
        help: "Smallest-unit exponent of the gas token",
        example: "18",
        default: Some("18"),
        optional: false,
    },
    RequiredField {
        flag: "--max-gas-limit",
        prompt: "Maximum gas limit",
        help: "Largest gas limit this wallet may ever sign on this chain",
        example: "16777216",
        default: Some("16777216"),
        optional: false,
    },
    RequiredField {
        flag: "--block-explorer-url",
        prompt: "Block explorer URL",
        help: "Where the CLI links transactions and addresses",
        example: "https://basescan.org",
        default: None,
        optional: false,
    },
    RequiredField {
        flag: "--documentation-url",
        prompt: "Documentation URL",
        help: "Where this chain's connection details are published",
        example: "https://docs.base.org",
        default: None,
        optional: false,
    },
    RequiredField {
        flag: "--rpc-url",
        prompt: "RPC URL",
        help: "JSON-RPC endpoint that supplies chain state and eth_simulateV1 execution",
        example: "https://rpc.example.com/v1/<key>",
        default: None,
        optional: false,
    },
    RequiredField {
        flag: "--rpc-strategy",
        prompt: "RPC strategy",
        help: "How the endpoints above are used: ordered, random, or m_of_n(N) to require N of them to return the same simulation",
        example: "m_of_n(2)",
        default: Some("ordered"),
        optional: true,
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
        (
            "--rpc-strategy",
            args.rpc_strategy.map(|strategy| strategy.to_string()),
        ),
        (
            "--rpc-url",
            (!args.rpc_urls.is_empty()).then(|| {
                args.rpc_urls
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            }),
        ),
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
        rpc_urls: parse_endpoint_list(&field("--rpc-url"))?,
        rpc_strategy: field("--rpc-strategy")
            .parse()
            .context("RPC strategy is invalid")?,
        max_gas_limit: Some(field("--max-gas-limit")),
        // Not asked for here. A fee ceiling is a judgement about what the
        // owner's transactions are worth rather than a property of the chain,
        // like `rpc_strategy`, and the form asks only for the latter.
        max_fee_per_gas: None,
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
    // An optional field that was not supplied is simply its default; only the
    // fields a profile cannot be written without are demanded.
    let defaults = CUSTOM_NETWORK_FIELDS
        .iter()
        .filter(|field| field.optional && supplied.get(field.flag).is_none_or(Option::is_none))
        .filter_map(|field| field.default.map(|value| (field.flag, value.to_owned())));
    let missing = CUSTOM_NETWORK_FIELDS
        .iter()
        .filter(|field| !field.optional)
        .filter(|field| supplied.get(field.flag).is_none_or(Option::is_none))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        return Ok(supplied
            .iter()
            .map(|(flag, value)| (*flag, value.clone().unwrap_or_default()))
            .chain(defaults)
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
/// Decide each network an agent has suggested.
///
/// The endpoint in a network profile is the wallet's entire view of its chain:
/// balances, gas, receipts, and the `eth_simulateV1` result every automatic
/// signing decision is scored against. An agent can assemble a profile — that
/// is tedious work it is good at — but pointing the wallet at an endpoint is a
/// statement about who is trusted to describe reality, and only the owner
/// makes it.
async fn run_network_review(config: &ConfigStore, mode: OutputMode) -> Result<()> {
    let proposals = PolicyStore::production(config.data_dir())?.network_proposals()?;
    if proposals.is_empty() {
        return emit(mode, &serde_json::json!({ "reviewed": 0 }), || {
            Ok("No network suggestions are waiting.".into())
        });
    }

    let mut accepted = Vec::new();
    let mut discarded = Vec::new();
    for proposal in proposals {
        match review_one_network_proposal(config, &proposal).await? {
            NetworkReviewOutcome::Accepted => accepted.push(proposal.name.clone()),
            NetworkReviewOutcome::Discarded => discarded.push(proposal.chain_id.to_string()),
        }
    }

    emit(
        mode,
        &serde_json::json!({ "accepted": accepted, "discarded": discarded }),
        || {
            Ok(format!(
                "Accepted {} network(s); discarded {}.",
                accepted.len(),
                discarded.len()
            ))
        },
    )
}

/// Review the network proposal for one chain, named by chain ID.
///
/// The browser holds a chain ID rather than the profile it drew, so the row
/// is re-read here immediately before it is shown. A proposal can be replaced
/// or withdrawn while the list is open, and reviewing the copy that was on
/// screen a minute ago would ask about an endpoint that is no longer the one
/// being proposed.
async fn review_network_proposal_by_chain(config: &ConfigStore, chain_id: u64) -> Result<()> {
    let proposal = PolicyStore::production(config.data_dir())?
        .network_proposals()?
        .into_iter()
        .find(|proposal| proposal.chain_id == chain_id)
        .with_context(|| {
            format!("the suggestion for chain {chain_id} is no longer waiting for review")
        })?;
    review_one_network_proposal(config, &proposal).await?;
    Ok(())
}

/// What one network proposal's review settled.
enum NetworkReviewOutcome {
    Accepted,
    Discarded,
}

/// Review exactly one proposed network profile and apply the answer.
///
/// Split out from the `network review` loop so the pending-approvals browser
/// can reach the same review for one row. Both paths must ask identically:
/// this is where an agent's claim about how to reach a chain becomes the
/// wallet's, and a second copy of that screen would eventually disagree with
/// this one about what it shows before writing.
async fn review_one_network_proposal(
    config: &ConfigStore,
    proposal: &crate::config::NetworkConfig,
) -> Result<NetworkReviewOutcome> {
    {
        // Held here now that the question is asked full-screen: a screen
        // answers `false` when there is nobody to show it to, and `false`
        // discards the proposal.
        require_interactive("network configuration changes")?;
        let existing = config
            .load()?
            .networks
            .into_iter()
            .find(|network| network.chain_id == proposal.chain_id);
        let mut facts = vec![
            ("Network", vec![proposal.name.clone()]),
            ("Chain ID", vec![proposal.chain_id.to_string()]),
            ("RPC endpoints", endpoint_list(proposal)),
            ("RPC strategy", vec![proposal.rpc_strategy.to_string()]),
        ];
        // Shown because it is the one field here that becomes an argument to
        // another program: pressing `o` on a transaction hands this base, plus
        // the hash, to whatever the desktop has registered for `http`. The
        // reviewer was accepting that destination without being told it.
        if let Some(explorer) = &proposal.block_explorer_url {
            facts.push(("Block explorer", vec![explorer.to_string()]));
        }
        // An edit is the dangerous shape: the chain keeps working and its
        // narrator changes. Say which endpoint is being replaced, because the
        // difference between the two URLs is the entire decision.
        let (title, summary) = if let Some(existing) = &existing {
            facts.push(("Replaces endpoints", endpoint_list(existing)));
            facts.push(("Configured name", vec![existing.name.clone()]));
            // The one setting on this screen that bounds what an automatic
            // transaction can spend, and it was not on it. A proposal never
            // names a ceiling — an agent does not choose one — so a reviewer
            // seeing only endpoints could not tell whether the profile they
            // were about to accept still had theirs. It does: the replacement
            // inherits it. Saying so is what makes that checkable rather than
            // something the reviewer has to know.
            facts.push((
                "Fee ceiling",
                vec![match existing.max_fee_per_gas.as_deref() {
                    Some(ceiling) => format!("{ceiling} wei per gas, unchanged by this edit"),
                    None => {
                        "none — automatic transactions accept whatever fee the RPC names".to_owned()
                    }
                }],
            ));
            (
                "Accept an edited network",
                "An agent suggested changing how this wallet reaches a chain it already uses.",
            )
        } else {
            (
                "Accept a new network",
                "An agent suggested a chain this wallet does not yet know how to reach.",
            )
        };

        // Full-screen on both paths that reach here: the pending-approvals
        // browser is already a screen, and `network review` walks every
        // proposal in a row, so an inline prompt would stack answered
        // exchanges behind the next one. Two endpoint lists side by side is
        // also the network fact most likely to outgrow a terminal.
        if !network_review(title, summary, facts).ask(
            "Accept this network?",
            "Accept this network",
            "Discard the suggestion",
        )? {
            let mut store = PolicyStore::production(config.data_dir())?;
            store.discard_network_proposal(proposal)?;
            return Ok(NetworkReviewOutcome::Discarded);
        }

        // Verified here rather than when it was proposed. What matters is that
        // the endpoint being written answers for the chain it claims, checked
        // immediately before writing it — a probe at proposal time would prove
        // something about a moment that has since passed.
        verify_chain_id(proposal).await.map_err(|_| {
            anyhow::anyhow!(
                "none of the {} RPC endpoints for {} answered eth_chainId with chain {}; nothing was written",
                proposal.rpc_urls.len(),
                proposal.name,
                proposal.chain_id
            )
        })?;
        PlatformHumanPresence
            .confirm(&PresenceRequest::ConfirmNetwork {
                network: proposal.name.clone(),
            })
            .await?;
        config.update(|state| {
            ensure_reviewed_network(&state.networks, proposal.chain_id, existing.as_ref())?;
            if existing.is_some() {
                replace_configured_network(&mut state.networks, proposal.clone())
            } else {
                add_configured_network(&mut state.networks, proposal.clone())
            }
        })?;
        PolicyStore::production(config.data_dir())?.discard_network_proposal(proposal)?;
        Ok(NetworkReviewOutcome::Accepted)
    }
}

/// The facts and the standing warning behind every network change, built once
/// so the inline and full-screen renderings cannot drift into describing the
/// same write differently.
///
/// Endpoints arrive as a list rather than one newline-joined string because a
/// fact is clamped to a single line in both renderings: a joined list used to
/// collapse into a run of URLs separated by spaces, which is the one fact
/// nobody can afford to misread.
fn network_review(
    title: &str,
    summary: &str,
    facts: Vec<(&str, Vec<String>)>,
) -> crate::fullscreen::Review {
    let mut review = crate::fullscreen::Review::new(title, summary);
    for (label, values) in facts {
        review = review.fact_lines(label, values);
    }
    review.warning(NETWORK_TRUST_WARNING)
}

/// What a configured RPC decides, said the same way everywhere it is asked
/// about.
const NETWORK_TRUST_WARNING: &str = "The configured RPC supplies the chain state and eth_simulateV1 results that automatic \
     signing decisions are made from.";

/// The scrollback rendering, for the network commands that never open a
/// screen. A command that has already shown one asks with
/// [`crate::fullscreen::Review::ask`] instead.
fn confirm_network_change(
    title: &str,
    summary: &str,
    prompt: &str,
    facts: Vec<(&str, Vec<String>)>,
) -> Result<bool> {
    require_interactive("network configuration changes")?;
    let mut question = crate::tui::Confirmation::new(title, summary).warning(NETWORK_TRUST_WARNING);
    for (label, values) in facts {
        // Repeated rather than blanked for the second and later values: a
        // `Confirmation` fact is one line, so a list has to arrive as separate
        // facts, and an unlabelled continuation line reads as a different
        // fact whose label went missing.
        for value in values {
            question = question.fact(label, value);
        }
    }
    question.ask(prompt)
}

/// Print what the shell should offer at the cursor.
///
/// The candidate set is decided in `completion` against the live clap tree;
/// what happens here is only the writing of it, in the one shape each shell
/// can read. Every value passes `terminal_safe_line` on the way out: these are
/// stored strings — an alias, a token symbol, a wallet id — being printed onto
/// the line the owner is typing on.
fn print_completion_candidates(
    config: &ConfigStore,
    format: CompletionFormat,
    words: &[String],
) -> Result<()> {
    // The words arrive with the program name at the front, as every shell
    // reports them; the resolver walks subcommands, so it never sees it.
    let words = words.split_first().map_or(&[][..], |(_, rest)| rest);
    let mut stdout = io::stdout().lock();
    match crate::completion::offer(config, words)? {
        // The shells complete paths themselves. Saying so rather than listing
        // a directory keeps their own filename handling — trailing slashes,
        // spaces, `~` — which no list of candidates would reproduce.
        crate::completion::Offer::Files => writeln!(stdout, "{FILE_COMPLETION_DIRECTIVE}")?,
        crate::completion::Offer::Values(candidates) => {
            for candidate in candidates {
                let value = completion_safe(&candidate.value);
                let description = completion_safe(&candidate.description);
                match format {
                    // `_describe` splits on the first colon, so a description
                    // carrying one would cut the entry short.
                    CompletionFormat::Zsh => {
                        writeln!(stdout, "{value}:{}", description.replace(':', " "))?;
                    }
                    CompletionFormat::Fish => writeln!(stdout, "{value}\t{description}")?,
                    CompletionFormat::Plain => writeln!(stdout, "{value}")?,
                }
            }
        }
    }
    Ok(())
}

/// What `__complete` prints instead of candidates when the cursor is on a
/// path. Chosen to be something no value could be: a shell that does not
/// recognise it offers one impossible word rather than the wrong list.
pub const FILE_COMPLETION_DIRECTIVE: &str = "__ekubo_wallet_complete_files__";

/// The artifact kinds a `file:` reference can name, spelled as the wire
/// values that go into the envelope's `artifact_type`.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum ReferenceType {
    #[value(name = "execution_plan", alias = "execution-plan", alias = "plan")]
    ExecutionPlan,
    #[value(name = "read_calls", alias = "read-calls", alias = "calls")]
    ReadCalls,
    #[value(name = "token_list", alias = "token-list", alias = "tokens")]
    TokenList,
}

impl ReferenceType {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::ExecutionPlan => "execution_plan",
            Self::ReadCalls => "read_calls",
            Self::TokenList => "token_list",
        }
    }

    /// What the file has to be for the envelope to be worth printing.
    ///
    /// The wallet runs exactly these parses again after it reads the file, so
    /// checking here changes no decision — it only moves the diagnosis to the
    /// terminal of whoever wrote the file, where the mistake was made, rather
    /// than leaving it to surface as a tool error a step later.
    fn validate(self, bytes: &[u8], value: serde_json::Value) -> Result<()> {
        match self {
            Self::ExecutionPlan => {
                crate::core::execution_plan::ExecutionPlan::parse(value)?;
            }
            Self::ReadCalls => {
                serde_json::from_value::<crate::batch_read::ReadCallsBody>(value).context(
                    "not a valid wallet_batch_eth_call argument object; a bundle carries \
                     chain_id and calls, and nothing this tool does not take inline",
                )?;
            }
            Self::TokenList => {
                crate::token_list::parse_token_list(bytes)?;
            }
        }
        Ok(())
    }
}

/// Describe a local JSON body as an `artifact_reference` envelope.
fn run_reference(path: &Path, declared: Option<ReferenceType>) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    ensure!(
        bytes.len() <= crate::core::execution_plan::MAX_SERIALIZED_PLAN_BYTES,
        "{} is larger than the {} bytes the wallet will read",
        path.display(),
        crate::core::execution_plan::MAX_SERIALIZED_PLAN_BYTES
    );
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not valid JSON", path.display()))?;
    let artifact_type = match declared {
        Some(declared) => declared,
        None => infer_reference_type(&value)?,
    };
    artifact_type.validate(&bytes, value)?;

    // Canonical, so the envelope names one path through symlinks and relative
    // segments: the file this command read is the file the wallet opens.
    let canonical =
        fs::canonicalize(path).with_context(|| format!("could not resolve {}", path.display()))?;
    let url = Url::from_file_path(&canonical)
        .map_err(|()| anyhow::anyhow!("{} has no file URL", canonical.display()))?;
    // A Windows UNC path is reachable from here and gets a file URL, but it
    // names a file server rather than this machine, and the wallet reads no
    // file server. Say so now instead of printing an envelope it will refuse.
    ensure!(
        url.host().is_none(),
        "{} is on the file server {}, and the wallet opens only this machine's own disk; \
         copy the file here and describe the copy",
        canonical.display(),
        url.host_str().unwrap_or_default()
    );
    print_json(&serde_json::json!({
        "kind": "artifact_reference",
        "artifact_type": artifact_type.wire_name(),
        "url": url.as_str(),
        "integrity": {
            "algorithm": "keccak256",
            "value": format!("{:#x}", alloy::primitives::keccak256(&bytes)),
        },
        "bytes": bytes.len(),
    }))
}

/// Which artifact a body is, from the field each kind requires.
///
/// Guessing is safe here in a way it would not be inside the wallet: a wrong
/// guess produces an envelope whose `artifact_type` the tool it is handed to
/// rejects outright, and the parse below has already refused a body that is
/// not the kind it was named. `--type` settles it for anything ambiguous.
fn infer_reference_type(value: &serde_json::Value) -> Result<ReferenceType> {
    // A bare array of token entries is the one shape with no object at all.
    if value.is_array() {
        return Ok(ReferenceType::TokenList);
    }
    let object = value
        .as_object()
        .context("a referenced body is a JSON object, or an array for a bare token list")?;
    if object.contains_key("ordered_steps") {
        Ok(ReferenceType::ExecutionPlan)
    } else if object.contains_key("calls") {
        Ok(ReferenceType::ReadCalls)
    } else if object.contains_key("tokens") {
        Ok(ReferenceType::TokenList)
    } else {
        bail!(
            "could not tell what this file holds from its fields; \
             pass --type execution_plan, read_calls, or token_list"
        )
    }
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

/// Where this executable actually is, so a registration records the path an
/// agent can still launch tomorrow.
///
/// `current_exe` rather than argv[0]: an agent config that recorded a shell
/// alias or a relative path would work only from the shell that wrote it.
fn server_command() -> Result<String> {
    let path = std::env::current_exe().context("could not determine this executable's path")?;
    path.to_str()
        .map(ToOwned::to_owned)
        .context("this executable's path is not valid UTF-8")
}

fn agent_binary(agent: AgentName) -> Option<PathBuf> {
    binary_on_path(agent.binary()?)
}

/// The first `name` on `PATH`, if it is there.
///
/// `which` is not available everywhere this runs, so PATH is walked here.
fn binary_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

/// Whether this agent is present on this machine at all.
fn agent_installed(agent: AgentName) -> bool {
    match agent {
        // Cursor is an editor rather than a CLI, so its configuration
        // directory is the evidence that it is here.
        AgentName::Cursor => {
            BaseDirs::new().is_some_and(|base| base.home_dir().join(".cursor").is_dir())
        }
        // opencode ships a CLI *and* a desktop app, and either one creates the
        // config directory on first run — it is `mkdir`ed unconditionally at
        // startup. So the directory answers for both, where looking only for
        // the binary would report the desktop-only install as absent.
        AgentName::Opencode => {
            binary_on_path("opencode").is_some()
                || opencode_config_dir().is_ok_and(|directory| directory.is_dir())
        }
        _ => agent_binary(agent).is_some(),
    }
}

/// Whether this server is currently registered with an agent.
///
/// `None` means the question could not be answered rather than answered no —
/// an agent's `mcp list` may fail or change its wording, and reporting that as
/// "not registered" would send someone to re-register something that is fine.
fn agent_registered(agent: AgentName) -> Option<Registration> {
    if agent == AgentName::Cursor {
        let file = BaseDirs::new()?.home_dir().join(".cursor").join("mcp.json");
        let document: serde_json::Value = serde_json::from_slice(&fs::read(file).ok()?).ok()?;
        let servers = document.get("mcpServers")?;
        return Some(Registration {
            wallet: servers.get(LOCAL_SERVER_NAME).is_some(),
            companion: servers.get(COMPANION_SERVER_NAME).is_some(),
        });
    }
    if agent == AgentName::Opencode {
        return opencode_registration_at(&opencode_config_dir().ok()?);
    }
    let output = std::process::Command::new(agent_binary(agent)?)
        .args(["mcp", "list"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(read_registration(&String::from_utf8_lossy(&output.stdout)))
}

/// What an agent's `mcp list` output says about the two servers.
///
/// Every CLI here prints its own layout and is free to change it, so this
/// stays a substring search rather than a parse. The one trap is that `ekubo`
/// is a prefix of `ekubo-wallet`: a plain search would report the companion
/// registered whenever the wallet is, and then `meta-agent list` would tell people
/// they have swaps and bridging when they have neither. Blanking the longer
/// name out first leaves only genuine mentions of the shorter one.
fn read_registration(listing: &str) -> Registration {
    Registration {
        wallet: listing.contains(LOCAL_SERVER_NAME),
        companion: listing
            .replace(LOCAL_SERVER_NAME, "")
            .contains(COMPANION_SERVER_NAME),
    }
}

/// Which of the two servers an agent currently has.
#[derive(Debug, Clone, Copy)]
struct Registration {
    wallet: bool,
    companion: bool,
}

/// Register both servers with one agent.
///
/// The wallet is the point of the command and its failure is the command's
/// failure. The companion is an extra, and it can fail on its own for reasons
/// that say nothing about the wallet — an agent CLI too old to add a remote
/// server by URL, most of all. So its error is returned beside a successful
/// wallet registration rather than replacing it, and the caller reports it as
/// a warning.
fn register_agent(agent: AgentName, companion: bool) -> Result<Option<String>> {
    let command = server_command()?;
    register_server(agent, LOCAL_SERVER_NAME, &ServerTransport::Stdio(command))?;
    if !companion {
        return Ok(None);
    }
    let outcome = register_server(
        agent,
        COMPANION_SERVER_NAME,
        &ServerTransport::Http(COMPANION_SERVER_URL),
    );
    Ok(outcome.err().map(|error| format!("{error:#}")))
}

fn register_server(agent: AgentName, name: &str, transport: &ServerTransport) -> Result<()> {
    if agent == AgentName::Cursor {
        configure_cursor_mcp(name, transport)?;
        return Ok(());
    }
    if agent == AgentName::Opencode {
        configure_opencode_mcp(name, transport)?;
        return Ok(());
    }
    let binary =
        agent_binary(agent).with_context(|| format!("{} is not installed here", agent.label()))?;
    // Removed first so re-registering after moving the binary replaces the old
    // path instead of failing on a name that already exists.
    let _ = unregister_server(agent, name);
    let mut arguments: Vec<String> = vec!["mcp".into(), "add".into()];
    match transport {
        ServerTransport::Stdio(command) => match agent {
            // Gemini takes the command inline and the scope after it; the
            // other two separate the command with `--`.
            AgentName::Gemini => arguments.extend([
                name.to_string(),
                command.clone(),
                "server".into(),
                "--scope".into(),
                "user".into(),
            ]),
            AgentName::ClaudeCode => arguments.extend([
                name.to_string(),
                "--scope".into(),
                "user".into(),
                "--".into(),
                command.clone(),
                "server".into(),
            ]),
            _ => arguments.extend([
                name.to_string(),
                "--".into(),
                command.clone(),
                "server".into(),
            ]),
        },
        ServerTransport::Http(url) => match agent {
            // Each CLI spells a remote server differently: Codex takes it as
            // a `--url` option, the other two as the positional that would
            // otherwise be a command, distinguished by `--transport http`.
            AgentName::Codex => {
                arguments.extend([name.to_string(), "--url".into(), (*url).to_string()]);
            }
            AgentName::ClaudeCode => arguments.extend([
                "--transport".into(),
                "http".into(),
                "--scope".into(),
                "user".into(),
                name.to_string(),
                (*url).to_string(),
            ]),
            AgentName::Gemini => arguments.extend([
                name.to_string(),
                (*url).to_string(),
                "--transport".into(),
                "http".into(),
                "--scope".into(),
                "user".into(),
            ]),
            AgentName::Cursor | AgentName::Opencode => {
                unreachable!("Cursor and opencode are configured by file above")
            }
        },
    }
    let status = std::process::Command::new(&binary)
        .args(&arguments)
        .status()
        .with_context(|| format!("failed to run {}", binary.display()))?;
    ensure!(
        status.success(),
        "{} rejected the registration of {name}; run it yourself to see why: {} {}",
        agent.label(),
        binary.display(),
        arguments.join(" ")
    );
    Ok(())
}

fn unregister_agent(agent: AgentName) -> Result<()> {
    // The companion may never have been registered — `--no-companion`, or an
    // install that predates it — and every CLI here treats removing an absent
    // name as an error. Removing the wallet is what `meta-agent remove` promises,
    // so only that failure is one.
    let _ = unregister_server(agent, COMPANION_SERVER_NAME);
    unregister_server(agent, LOCAL_SERVER_NAME)
}

fn unregister_server(agent: AgentName, name: &str) -> Result<()> {
    if agent == AgentName::Cursor {
        return remove_cursor_mcp(name);
    }
    if agent == AgentName::Opencode {
        return remove_opencode_mcp(name);
    }
    let binary =
        agent_binary(agent).with_context(|| format!("{} is not installed here", agent.label()))?;
    let mut arguments: Vec<String> = vec!["mcp".into(), "remove".into(), name.to_string()];
    if matches!(agent, AgentName::ClaudeCode | AgentName::Gemini) {
        arguments.extend(["--scope".into(), "user".into()]);
    }
    let status = std::process::Command::new(&binary)
        .args(&arguments)
        .status()
        .with_context(|| format!("failed to run {}", binary.display()))?;
    ensure!(status.success(), "{} rejected the removal", agent.label());
    Ok(())
}

/// Drop one server from Cursor's `mcp.json`, leaving every other entry and
/// every unrelated key exactly as they were.
fn remove_cursor_mcp(name: &str) -> Result<()> {
    let base = BaseDirs::new().context("could not determine the user home directory")?;
    remove_cursor_mcp_at(base.home_dir(), name)
}

fn remove_cursor_mcp_at(home: &Path, name: &str) -> Result<()> {
    let file = home.join(".cursor").join("mcp.json");
    if !file.exists() {
        return Ok(());
    }
    let mut document: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?,
        )
        .with_context(|| format!("failed to parse {}", file.display()))?
        .as_object()
        .cloned()
        .context("Cursor MCP configuration must be a JSON object")?;
    let Some(mut servers) = document
        .remove("mcpServers")
        .and_then(|value| value.as_object().cloned())
    else {
        return Ok(());
    };
    servers.remove(name);
    document.insert("mcpServers".into(), servers.into());
    write_private_json(&file, &document)
}

fn run_agent(command: &AgentCommand, mode: OutputMode) -> Result<()> {
    match command {
        AgentCommand::List => {
            let rows: Vec<serde_json::Value> = AgentName::ALL
                .into_iter()
                .map(|agent| {
                    let installed = agent_installed(agent);
                    let state = installed.then(|| agent_registered(agent)).flatten();
                    serde_json::json!({
                        "agent": agent.key(),
                        "installed": installed,
                        "registered": state.map(|state| state.wallet),
                        "companion_registered": state.map(|state| state.companion),
                    })
                })
                .collect();
            emit(mode, &serde_json::json!({ "agents": rows }), || {
                let mut lines = vec![
                    format!("Server command: {}", server_command()?),
                    format!("Companion server: {COMPANION_SERVER_URL}"),
                    String::new(),
                ];
                for agent in AgentName::ALL {
                    let state = if agent_installed(agent) {
                        match agent_registered(agent) {
                            // The companion is reported only when it is the
                            // thing missing. Naming both on every line would
                            // bury the answer the command is asked for.
                            Some(Registration {
                                wallet: true,
                                companion: true,
                            }) => "registered".to_string(),
                            Some(Registration { wallet: true, .. }) => format!(
                                "registered, without {COMPANION_SERVER_NAME} — \
                                 `ekubo-wallet meta-agent add {}`",
                                agent.key()
                            ),
                            Some(Registration { wallet: false, .. }) => format!(
                                "installed, not registered — `ekubo-wallet meta-agent add {}`",
                                agent.key()
                            ),
                            None => "installed; could not read its MCP configuration".to_string(),
                        }
                    } else {
                        "not installed".to_string()
                    };
                    lines.push(format!("{:<12} {state}", agent.label()));
                }
                Ok(lines.join("\n"))
            })
        }
        AgentCommand::Add { agent, .. } | AgentCommand::Remove { agent } => {
            let adding = matches!(command, AgentCommand::Add { .. });
            // `remove` takes both servers back regardless, so the flag is only
            // ever read on the way in.
            let companion = !matches!(
                command,
                AgentCommand::Add {
                    no_companion: true,
                    ..
                }
            );
            // A bare `add` configures what is actually here rather than
            // failing on the agents that are not, which is what the installer
            // does and the only behaviour that makes it re-runnable.
            let targets: Vec<AgentName> = agent.map_or_else(
                || {
                    AgentName::ALL
                        .into_iter()
                        .filter(|agent| agent_installed(*agent))
                        .collect()
                },
                |agent| vec![agent],
            );
            ensure!(
                !targets.is_empty(),
                "no supported agent was detected here; name one explicitly to configure it anyway"
            );
            let mut changed = Vec::new();
            let mut failed = Vec::new();
            let mut partial = Vec::new();
            for agent in targets {
                let outcome = if adding {
                    register_agent(agent, companion)
                } else {
                    unregister_agent(agent).map(|()| None)
                };
                match outcome {
                    Ok(warning) => {
                        changed.push(agent.key());
                        if let Some(warning) = warning {
                            partial.push(format!("{}: {warning}", agent.label()));
                        }
                    }
                    Err(error) => failed.push(format!("{}: {error:#}", agent.label())),
                }
            }
            let verb = if adding { "registered" } else { "unregistered" };
            emit(
                mode,
                &serde_json::json!({
                    verb: changed,
                    "failed": failed,
                    "companion_failed": partial,
                }),
                || {
                    let mut lines = Vec::new();
                    if changed.is_empty() {
                        lines.push(format!("Nothing was {verb}."));
                    } else {
                        lines.push(format!("{verb} with {}.", changed.join(", ")));
                    }
                    for failure in &failed {
                        lines.push(format!("Failed — {failure}"));
                    }
                    for failure in &partial {
                        lines.push(format!(
                            "This wallet registered, but {COMPANION_SERVER_NAME} did not — \
                             {failure}"
                        ));
                    }
                    if adding && !changed.is_empty() {
                        lines.push("Restart the agent to pick up the change.".into());
                    }
                    Ok(lines.join("\n"))
                },
            )
        }
    }
}

fn configure_cursor_mcp(name: &str, transport: &ServerTransport) -> Result<PathBuf> {
    if let ServerTransport::Stdio(command) = transport {
        ensure!(!command.trim().is_empty(), "server command cannot be empty");
    }
    let base = BaseDirs::new().context("could not determine the user home directory")?;
    configure_cursor_mcp_at(base.home_dir(), name, transport)
}

fn configure_cursor_mcp_at(
    home: &Path,
    name: &str,
    transport: &ServerTransport,
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
    // Cursor tells the two apart by which key is present: `command` for a
    // subprocess, `url` for a remote endpoint. There is no transport field.
    servers.insert(
        name.into(),
        match transport {
            ServerTransport::Stdio(command) => serde_json::json!({
                "command": command,
                "args": ["server"],
            }),
            ServerTransport::Http(url) => serde_json::json!({ "url": url }),
        },
    );
    document.insert("mcpServers".into(), servers.into());
    write_private_json(&file, &document)?;
    Ok(file)
}

/// The global configuration files opencode reads, in the order it merges them.
///
/// All three are loaded and merged rather than the first one found winning, so
/// a name defined in a later file shadows the same name in an earlier one.
/// That ordering is why removal has to consider every one of them and why
/// detection reads them all.
const OPENCODE_CONFIG_FILES: [&str; 3] = ["config.json", "opencode.json", "opencode.jsonc"];

/// The one this wallet writes.
///
/// opencode's own `mcp add` prefers whichever of `opencode.json` and
/// `opencode.jsonc` already exists; this always writes the `.json`. The
/// difference matters for one person — whoever keeps their settings in a
/// commented `.jsonc` — and for them it is the difference between an entry
/// added to a file this wallet owns outright and their own file rewritten
/// through a serializer that would delete every comment in it. opencode merges
/// all three of these files, so an entry written here is read either way.
const OPENCODE_WRITTEN_CONFIG: &str = "opencode.json";

/// Where opencode keeps its global configuration.
///
/// Deliberately not `BaseDirs::config_dir`. opencode resolves this path with
/// the `xdg-basedir` package rather than any platform convention, and that
/// package answers `$XDG_CONFIG_HOME`, or `~/.config` when it is unset, on
/// every operating system — including macOS and Windows, where the native
/// config directory is somewhere else entirely and a file written there would
/// be read by nothing.
fn opencode_config_dir() -> Result<PathBuf> {
    if let Some(base) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(base).join("opencode"));
    }
    let base = BaseDirs::new().context("could not determine the user home directory")?;
    Ok(base.home_dir().join(".config").join("opencode"))
}

/// One server in the shape opencode's `mcp` map expects.
///
/// The two forms are a tagged union rather than Cursor's "whichever key is
/// present", and `command` is an argv array rather than a string: a local
/// server written as `"command": "/path/to/ekubo-wallet server"` is rejected
/// by opencode's schema, and one written with Cursor's `args` key is silently
/// launched with no arguments at all.
fn opencode_server_entry(transport: &ServerTransport) -> serde_json::Value {
    match transport {
        ServerTransport::Stdio(command) => serde_json::json!({
            "type": "local",
            "command": [command, "server"],
            "enabled": true,
        }),
        ServerTransport::Http(url) => serde_json::json!({
            "type": "remote",
            "url": url,
            "enabled": true,
        }),
    }
}

fn configure_opencode_mcp(name: &str, transport: &ServerTransport) -> Result<PathBuf> {
    if let ServerTransport::Stdio(command) = transport {
        ensure!(!command.trim().is_empty(), "server command cannot be empty");
    }
    configure_opencode_mcp_at(&opencode_config_dir()?, name, transport)
}

fn configure_opencode_mcp_at(
    directory: &Path,
    name: &str,
    transport: &ServerTransport,
) -> Result<PathBuf> {
    let file = directory.join(OPENCODE_WRITTEN_CONFIG);
    // opencode parses every one of its configuration files as JSONC, the
    // `.json` included, so an existing file may hold comments this wallet
    // cannot round-trip. Failing here rather than starting from an empty
    // document is what keeps a hand-written configuration from being replaced
    // by one entry; the message has to say what to do instead, because there
    // is no automatic path out of it.
    let mut document = read_opencode_config(&file)
        .with_context(|| {
            format!(
                "this wallet writes plain JSON and will not rewrite {}. Add the entry by hand — \
                 `ekubo-wallet meta-agent list` prints the command and URL it would have used",
                file.display()
            )
        })?
        .unwrap_or_default();
    let mut servers = match document.remove("mcp") {
        Some(value) => value
            .as_object()
            .cloned()
            .context("opencode `mcp` must be a JSON object")?,
        None => serde_json::Map::new(),
    };
    servers.insert(name.into(), opencode_server_entry(transport));
    document.insert("mcp".into(), servers.into());
    write_private_json(&file, &document)?;
    Ok(file)
}

/// Drop one server from opencode's global configuration, leaving every other
/// entry and every unrelated key exactly as they were.
///
/// Every file opencode merges is considered rather than only the one this
/// wallet writes: an entry someone added by hand to `opencode.jsonc` shadows
/// the one in `opencode.json`, so removing only what was written here would
/// leave the server registered while reporting it removed.
fn remove_opencode_mcp(name: &str) -> Result<()> {
    remove_opencode_mcp_at(&opencode_config_dir()?, name)
}

fn remove_opencode_mcp_at(directory: &Path, name: &str) -> Result<()> {
    for candidate in OPENCODE_CONFIG_FILES {
        let file = directory.join(candidate);
        if !file.exists() {
            continue;
        }
        let mut document = match read_opencode_config(&file) {
            Ok(Some(document)) => document,
            Ok(None) => continue,
            // A `.jsonc` may hold comments and trailing commas that
            // `serde_json` refuses, and rewriting such a file is not on offer.
            // One that never mentions the server cannot be registering it, so
            // it is passed over; one that does is reported, because silently
            // leaving it would make `meta-agent remove` a lie.
            Err(error) => {
                ensure!(
                    !file_mentions_server(&file, name),
                    "{} registers `{name}` and this wallet cannot rewrite it — remove that entry \
                     by hand: {error:#}",
                    file.display()
                );
                continue;
            }
        };
        let Some(mut servers) = document
            .remove("mcp")
            .and_then(|value| value.as_object().cloned())
        else {
            continue;
        };
        if servers.remove(name).is_none() {
            continue;
        }
        document.insert("mcp".into(), servers.into());
        write_private_json(&file, &document)?;
    }
    Ok(())
}

/// What opencode's merged global configuration says about the two servers.
///
/// `None` means the question could not be answered, which is what a file this
/// wallet cannot parse leaves behind when it might be the file holding the
/// registration.
fn opencode_registration_at(directory: &Path) -> Option<Registration> {
    let mut found = Registration {
        wallet: false,
        companion: false,
    };
    for candidate in OPENCODE_CONFIG_FILES {
        let file = directory.join(candidate);
        if !file.exists() {
            continue;
        }
        let document = match read_opencode_config(&file) {
            Ok(Some(document)) => document,
            Ok(None) => continue,
            Err(_) => {
                if file_mentions_server(&file, LOCAL_SERVER_NAME)
                    || file_mentions_server(&file, COMPANION_SERVER_NAME)
                {
                    return None;
                }
                continue;
            }
        };
        let Some(servers) = document.get("mcp").and_then(serde_json::Value::as_object) else {
            continue;
        };
        found.wallet |= servers.contains_key(LOCAL_SERVER_NAME);
        found.companion |= servers.contains_key(COMPANION_SERVER_NAME);
    }
    Some(found)
}

/// Read one of opencode's configuration files.
///
/// `Ok(None)` is a file that is not there. A file that is there and will not
/// parse is an error rather than an absence, because treating it as an absence
/// would let a registration this wallet cannot see be reported as missing.
fn read_opencode_config(file: &Path) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
    if !file.exists() {
        return Ok(None);
    }
    let bytes = fs::read(file).with_context(|| format!("failed to read {}", file.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", file.display()))?;
    Ok(Some(value.as_object().cloned().with_context(|| {
        format!("{} must hold a JSON object", file.display())
    })?))
}

/// Whether a file this wallet could not parse names one of the two servers.
///
/// The name is quoted before the search because `ekubo` is a prefix of
/// `ekubo-wallet`: a bare substring test would find the companion in every
/// file that holds only the wallet. An unreadable file answers yes, because
/// the point of the question is whether it is safe to pass over.
fn file_mentions_server(file: &Path, name: &str) -> bool {
    fs::read_to_string(file).is_ok_and(|text| text.contains(&format!("\"{name}\"")))
}

/// Replace a configuration file with `document`, atomically and privately.
///
/// Shared by every agent whose file this wallet writes itself, so that one of
/// them cannot quietly stop being durable or stop being private: the temporary
/// file is created in the destination directory, given the final permissions
/// before it holds anything, flushed, and renamed over the target.
fn write_private_json(
    file: &Path,
    document: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let directory = file
        .parent()
        .with_context(|| format!("{} has no parent directory", file.display()))?;
    fs::create_dir_all(directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;
    set_private_permissions(directory, true)?;
    let mut temporary = NamedTempFile::new_in(directory).with_context(|| {
        format!(
            "failed to create a temporary file in {}",
            directory.display()
        )
    })?;
    set_private_permissions(temporary.path(), false)?;
    serde_json::to_writer_pretty(&mut temporary, document)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(file)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to replace {}", file.display()))?;
    set_private_permissions(file, false)?;
    sync_directory(directory)?;
    Ok(())
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
#[path = "cli_test.rs"]
mod tests;
