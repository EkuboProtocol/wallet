//! What a shell should offer at one position of an `ekubo-wallet` command line.
//!
//! Tab is how this CLI is actually driven, and almost every argument it takes
//! names something that already exists on this machine: a configured network,
//! an account, a queued request, a confirmed token, an alias in the address
//! book. A completion that offers subcommand names and then stops at
//! `--network ` is the shape that makes a person open a second terminal to run
//! `network list` and copy a word back. So the candidates come from the same
//! stores the command itself will read.
//!
//! The three shipped scripts used to answer this question themselves, each in
//! its own dialect, by counting words and matching on positions. Three
//! transcriptions of one table is three chances to disagree with the CLI and
//! with each other, and they did: `--network` looked up networks in fish and
//! nothing at all in bash and zsh, and `transaction show` offered account ids
//! for an argument that takes a request ID.
//!
//! So the question is answered once, here, against the live clap tree. A shell
//! script now passes the words typed so far and prints what comes back. What
//! stays in the scripts is the part that is genuinely per-shell: how to read
//! the current line, and how to render a value with a description beside it.
//!
//! Two kinds of candidate come out of clap itself and need no table below:
//! subcommand names (with their `about` as the description) and the values of
//! a `ValueEnum` argument. The table is only for arguments whose values live
//! in a store — and it is written per command rather than per argument name,
//! because `address-book add`'s `address` is one the owner is about to invent
//! while `token remove`'s is one they must already have.

use crate::{
    address_book::AddressBookStore,
    config::{ConfigStore, default_networks},
    message::MessageStore,
    pending::PendingStore,
    typed_data::TypedDataStore,
};
use anyhow::Result;

/// One thing a shell may offer, and what to say about it where the shell can
/// show a description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub value: String,
    pub description: String,
}

impl Candidate {
    fn new(value: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            description: description.into(),
        }
    }
}

/// What to offer at the cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Offer {
    /// These words, filtered by the shell against whatever is half-typed.
    Values(Vec<Candidate>),
    /// A path: the shell's own file completion knows the filesystem better
    /// than a list of candidates could.
    Files,
}

/// Where an argument's values come from when clap does not already know them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    Networks,
    /// The built-in presets, which is what `network add` is choosing among —
    /// the configured list is what it would be adding *to*.
    Presets,
    Wallets,
    /// Requests waiting for a decision, across all three signing queues.
    Approvals,
    /// Recorded transactions, by request ID.
    Transactions,
    /// Address-book aliases on the network named earlier in the same command.
    Aliases,
    /// Confirmed tokens on the network named earlier in the same command.
    Tokens,
    /// The endpoint-agreement strategies, which are parsed from a string
    /// rather than a `ValueEnum` because `m_of_n(2)` carries a number.
    RpcStrategies,
    Files,
}

/// Which store an argument's values come from, keyed by the command that takes
/// it. Per command rather than per argument name: two commands can take an
/// `address` and mean opposite things by it, and only one of them is asking
/// for something that already exists.
fn source_of(command_path: &str, argument: &str) -> Option<Source> {
    Some(match (command_path, argument) {
        ("portfolio" | "transaction list", "account")
        | (
            "account export"
            | "account remove"
            | "policy show"
            | "policy set"
            | "policy allow-all"
            | "policy require-approval"
            | "policy review",
            "wallet_id",
        ) => Source::Wallets,
        ("network add", "name") => Source::Presets,
        ("network add", "rpc_strategy") => Source::RpcStrategies,
        ("network edit" | "network remove", "name")
        | (
            "portfolio"
            | "token list"
            | "token search"
            | "token remove"
            | "address-book list"
            | "address-book add"
            | "address-book remove",
            "network" | "chain",
        ) => Source::Networks,
        ("address-book add" | "address-book remove", "alias") => Source::Aliases,
        ("token remove", "address") => Source::Tokens,
        ("review", "request_id") => Source::Approvals,
        (
            "transaction show"
            | "transaction cancel"
            | "transaction rebroadcast"
            | "transaction discard",
            "identifier",
        ) => Source::Transactions,
        ("policy set" | "policy validate", "policy_file")
        | ("reference" | "token import", "path") => Source::Files,
        _ => return None,
    })
}

/// Whether a flag is followed by a value, so that a line ending in it is a line
/// waiting for one.
fn takes_a_value(argument: &clap::Arg) -> bool {
    !matches!(
        argument.get_action(),
        clap::ArgAction::SetTrue
            | clap::ArgAction::SetFalse
            | clap::ArgAction::Count
            | clap::ArgAction::Help
            | clap::ArgAction::HelpShort
            | clap::ArgAction::HelpLong
            | clap::ArgAction::Version
    )
}

/// Every argument reachable at this point, the root's global ones included.
///
/// Which is to say: exactly what the command carries, provided the tree was
/// built first. Building is what copies `--data-dir` and `--json` down into
/// every subcommand and what assigns the positional indices this module looks
/// arguments up by, and an unbuilt tree answers both questions with nothing
/// rather than with an error — `policy validate` offered flags where it should
/// have offered a file, and said so no more loudly than that.
fn arguments(command: &clap::Command) -> impl Iterator<Item = &clap::Arg> {
    command.get_arguments()
}

/// The flag a line ending in `--flag` is waiting for, if it is waiting for one.
fn pending_flag<'a>(command: &'a clap::Command, word: &str) -> Option<&'a clap::Arg> {
    // `--flag=value` is already answered, and a bare `--` is not a flag.
    let name = word.strip_prefix("--").filter(|name| !name.contains('='))?;
    arguments(command)
        .filter(|argument| takes_a_value(argument))
        .find(|argument| {
            argument.get_long() == Some(name)
                || argument
                    .get_all_aliases()
                    .is_some_and(|aliases| aliases.contains(&name))
        })
}

/// The short form of the same, so `-n ` reaches networks the way `--network `
/// does.
fn pending_short<'a>(command: &'a clap::Command, word: &str) -> Option<&'a clap::Arg> {
    let rest = word
        .strip_prefix('-')
        .filter(|rest| !rest.starts_with('-'))?;
    let mut characters = rest.chars();
    let short = characters.next().filter(|_| characters.next().is_none())?;
    arguments(command)
        .filter(|argument| takes_a_value(argument))
        .find(|argument| argument.get_short() == Some(short))
}

/// Where the words typed so far leave the cursor.
struct Position<'a> {
    command: &'a clap::Command,
    /// Space-joined subcommand names, as `source_of` keys them.
    path: String,
    /// Positional values already given to `command`, in order. They are what
    /// scopes a later positional: the network in `address-book remove` decides
    /// which aliases the alias argument can mean.
    positionals: Vec<String>,
    /// Set when the line ends in a flag that is still waiting for its value.
    awaiting: Option<&'a clap::Arg>,
}

/// Walk the words against the clap tree. `words` are the ones already
/// completed, without the program name and without whatever is half-typed at
/// the cursor.
fn locate<'a>(root: &'a clap::Command, words: &[String]) -> Position<'a> {
    let mut command = root;
    let mut names: Vec<&str> = Vec::new();
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < words.len() {
        let word = words[index].as_str();
        if let Some(argument) = pending_flag(command, word).or_else(|| pending_short(command, word))
        {
            // The last word being a flag is the whole question: the cursor sits
            // where its value goes.
            if index + 1 == words.len() {
                return Position {
                    command,
                    path: names.join(" "),
                    positionals,
                    awaiting: Some(argument),
                };
            }
            index += 2;
            continue;
        }
        if word.starts_with('-') {
            index += 1;
            continue;
        }
        if let Some(sub) = command
            .get_subcommands()
            .filter(|sub| !sub.is_hide_set())
            .find(|sub| sub.get_name() == word || sub.get_all_aliases().any(|alias| alias == word))
        {
            command = sub;
            names.push(sub.get_name());
            positionals.clear();
            index += 1;
            continue;
        }
        positionals.push(word.to_owned());
        index += 1;
    }
    Position {
        command,
        path: names.join(" "),
        positionals,
        awaiting: None,
    }
}

/// Every long flag the command accepts, offered alongside whatever else is at
/// the cursor. The shell filters them out until a `-` is typed.
fn flags(command: &clap::Command) -> Vec<Candidate> {
    arguments(command)
        .filter(|argument| !argument.is_hide_set())
        .filter_map(|argument| {
            let long = argument.get_long()?;
            Some(Candidate::new(
                format!("--{long}"),
                argument
                    .get_help()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
            ))
        })
        .collect()
}

/// The values clap itself knows an argument accepts.
fn enumerated(argument: &clap::Arg) -> Option<Vec<Candidate>> {
    let values = argument.get_possible_values();
    if values.is_empty() {
        return None;
    }
    Some(
        values
            .iter()
            .filter(|value| !value.is_hide_set())
            .map(|value| {
                Candidate::new(
                    value.get_name(),
                    value
                        .get_help()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                )
            })
            .collect(),
    )
}

/// What to offer after the given words.
pub fn offer(config: &ConfigStore, words: &[String]) -> Result<Offer> {
    let mut root = <crate::cli::Cli as clap::CommandFactory>::command();
    root.build();
    let position = locate(&root, words);

    // A flag waiting for its value asks nothing else.
    if let Some(argument) = position.awaiting {
        return argument_offer(config, &position, argument);
    }

    // Before any positional, a command with subcommands is choosing one.
    if position.positionals.is_empty() && position.command.get_subcommands().next().is_some() {
        let mut candidates: Vec<Candidate> = position
            .command
            .get_subcommands()
            .filter(|sub| !sub.is_hide_set())
            .map(|sub| {
                Candidate::new(
                    sub.get_name(),
                    sub.get_about().map(ToString::to_string).unwrap_or_default(),
                )
            })
            .collect();
        candidates.extend(flags(position.command));
        return Ok(Offer::Values(candidates));
    }

    // Otherwise the cursor is on the next positional this command takes.
    let wanted = position.positionals.len() + 1;
    let Some(argument) = position
        .command
        .get_arguments()
        .find(|argument| argument.get_index() == Some(wanted))
    else {
        return Ok(Offer::Values(flags(position.command)));
    };
    argument_offer(config, &position, argument)
}

fn argument_offer(
    config: &ConfigStore,
    position: &Position<'_>,
    argument: &clap::Arg,
) -> Result<Offer> {
    if let Some(values) = enumerated(argument) {
        return Ok(Offer::Values(values));
    }
    let Some(source) = source_of(&position.path, argument.get_id().as_str()) else {
        return Ok(Offer::Values(Vec::new()));
    };
    if source == Source::Files {
        return Ok(Offer::Files);
    }
    Ok(Offer::Values(lookup(config, source, position)?))
}

/// The chain a scoped lookup applies to: the network already named earlier in
/// this command. Without one there is nothing to scope by, and offering every
/// alias on every chain would offer names that do not resolve where they would
/// be used.
fn scoped_chain(config: &ConfigStore, position: &Position<'_>) -> Option<u64> {
    let named = position.positionals.first()?;
    config.network(named).ok().map(|network| network.chain_id)
}

fn lookup(config: &ConfigStore, source: Source, position: &Position<'_>) -> Result<Vec<Candidate>> {
    // The plain configuration file answers the first three without opening
    // anything that can wait on something else.
    match source {
        Source::Files => return Ok(Vec::new()),
        Source::RpcStrategies => {
            return Ok(vec![
                Candidate::new("ordered", "first endpoint that answers"),
                Candidate::new("random", "fresh endpoint order per request"),
                Candidate::new("m_of_n(2)", "two endpoints must return the same answer"),
                Candidate::new("m_of_n(3)", "three endpoints must return the same answer"),
            ]);
        }
        Source::Presets => {
            return Ok(default_networks()
                .into_iter()
                .map(|network| Candidate::new(network.name, format!("chain {}", network.chain_id)))
                .collect());
        }
        Source::Networks => {
            return Ok(config
                .load()?
                .networks
                .into_iter()
                .map(|network| Candidate::new(network.name, format!("chain {}", network.chain_id)))
                .collect());
        }
        Source::Wallets => {
            return Ok(config
                .load()?
                .wallets
                .into_iter()
                .map(|wallet| {
                    Candidate::new(
                        wallet.id,
                        format!("{:#x} ({:?})", wallet.address, wallet.source),
                    )
                })
                .collect());
        }
        Source::Approvals | Source::Transactions | Source::Aliases | Source::Tokens => {}
    }

    // The rest live in the encrypted database. A machine that has never run
    // the wallet does not have one, and completion stays silent there rather
    // than failing: a shell prints whatever a completion writes to stderr over
    // the line being typed.
    let data_dir = config.data_dir().to_path_buf();
    if !data_dir.join("policies.db").exists() {
        return Ok(Vec::new());
    }
    let chain = scoped_chain(config, position);
    Ok(within_budget(move || match source {
        Source::Approvals => {
            let mut candidates: Vec<Candidate> = PendingStore::production(&data_dir)?
                .awaiting_approval(None)?
                .into_iter()
                .map(|request| {
                    Candidate::new(
                        request.request_id.to_string(),
                        format!("{} on chain {}", request.wallet_id, request.chain_id),
                    )
                })
                .collect();
            candidates.extend(
                TypedDataStore::production(&data_dir)?
                    .awaiting_approval(None)?
                    .into_iter()
                    .map(|request| {
                        Candidate::new(
                            request.request_id.to_string(),
                            format!(
                                "typed data for {} on chain {}",
                                request.wallet_id, request.chain_id
                            ),
                        )
                    }),
            );
            candidates.extend(
                MessageStore::production(&data_dir)?
                    .awaiting_approval(None)?
                    .into_iter()
                    .map(|request| {
                        Candidate::new(
                            request.request_id.to_string(),
                            format!("message for {}", request.wallet_id),
                        )
                    }),
            );
            Ok(candidates)
        }
        Source::Transactions => Ok(PendingStore::production(&data_dir)?
            .list(None, COMPLETION_ROWS)?
            .into_iter()
            .map(|record| {
                Candidate::new(
                    record.request_id.to_string(),
                    format!(
                        "{} on {} ({})",
                        record.wallet_id,
                        record.network_name,
                        crate::tx_browser::status_label(record.status)
                    ),
                )
            })
            .collect()),
        Source::Aliases => Ok(AddressBookStore::production(&data_dir)?
            .list(chain, COMPLETION_ROWS as usize, 0)?
            .into_iter()
            .map(|entry| Candidate::new(entry.alias, entry.address))
            .collect()),
        Source::Tokens => Ok(crate::token_store::TokenStore::production(&data_dir)?
            .list(chain, COMPLETION_ROWS as usize, 0)?
            .into_iter()
            .map(|token| {
                Candidate::new(
                    token.address,
                    token.symbol.unwrap_or_else(|| "unnamed".to_owned()),
                )
            })
            .collect()),
        Source::Files
        | Source::RpcStrategies
        | Source::Presets
        | Source::Networks
        | Source::Wallets => Ok(Vec::new()),
    }))
}

/// How long a store-backed lookup may take before the answer is "nothing".
///
/// Opening the encrypted database needs its key from the OS credential store,
/// and asking for one can wait: on a locked keychain it waits for a dialog the
/// owner may not even be looking at, and behind another process holding the
/// file it waits for the lock. A completion runs on a keystroke and owns the
/// terminal while it does, so `review ` followed by tab hung the shell outright
/// — for as long as the prompt went unanswered, with no way to tell what was
/// happening. Offering nothing is a worse completion and a far better shell.
const LOOKUP_BUDGET: std::time::Duration = std::time::Duration::from_millis(300);

/// Run a store lookup with that budget, answering with nothing if it runs out.
///
/// The worker is left running rather than cancelled: it is blocked inside the
/// platform credential store, which has no cancellation to offer, and the
/// process exits as soon as the candidates are printed.
fn within_budget(work: impl FnOnce() -> Result<Vec<Candidate>> + Send + 'static) -> Vec<Candidate> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(work());
    });
    receiver
        .recv_timeout(LOOKUP_BUDGET)
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
}

/// How many rows a completion reads from a store.
///
/// A completion runs on a keystroke, and a shell that pauses on tab is worse
/// than one that offers a short list: the owner is choosing among things they
/// recognise, and the hundredth token on a chain is not one of them. Typing
/// more characters is the way to reach the rest, and it is the way a person
/// reaches it anyway.
const COMPLETION_ROWS: u16 = 200;

#[cfg(test)]
#[path = "completion_test.rs"]
mod tests;
