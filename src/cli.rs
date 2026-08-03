use crate::{
    VERSION,
    approval::{ApprovalDecision, ApprovalKind, ApprovalRequest, ApprovalUi, TerminalApprovalUi},
    config::ConfigStore,
    custody::{CustodyService, OsKeyStore, PrivateKeyMaterial},
    human_presence::PlatformHumanPresence,
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
    sync::Arc,
};
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
    Network(NetworkArgs),
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

#[derive(Debug, Subcommand)]
enum NetworkCommand {
    /// List configured networks without exposing credential-bearing RPC URLs.
    List,
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        let config = match self.data_dir {
            Some(path) => ConfigStore::new(path),
            None => ConfigStore::production()?,
        };
        match self.command {
            Command::Server => crate::mcp::serve(config),
            Command::Version => {
                println!("{VERSION}");
                Ok(())
            }
            Command::Wallet(args) => run_wallet(config, args.command).await,
            Command::Network(args) => run_network(&config, &args.command),
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
        WalletCommand::Create { wallet_id } => print_json(&custody.create(&wallet_id)?),
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
                    progress.stop("Wallet imported");
                    cliclack::outro("Imported wallets are marked as externally known.")?;
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

async fn require_approval(request: ApprovalRequest) -> Result<()> {
    ensure!(
        TerminalApprovalUi.review(&request).await? == ApprovalDecision::Approved,
        "action rejected"
    );
    Ok(())
}

fn run_network(config: &ConfigStore, command: &NetworkCommand) -> Result<()> {
    match command {
        NetworkCommand::List => {
            let public = config
                .load()?
                .networks
                .into_iter()
                .map(|network| {
                    serde_json::json!({
                        "name": network.name,
                        "display_name": network.display_name,
                        "aliases": network.aliases,
                        "chain_id": network.chain_id.to_string(),
                        "max_gas_limit": network.max_gas_limit,
                        "native_currency": network.native_currency,
                        "block_explorer_url": network.block_explorer_url,
                        "documentation_url": network.documentation_url,
                    })
                })
                .collect::<Vec<_>>();
            print_json(&public)
        }
    }
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
