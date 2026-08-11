//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;

/// A configuration directory with nothing in it, which is the default
/// networks and no accounts. Enough for every question here: what is being
/// checked is which store a position reaches, not what happens to be in it.
fn config() -> (tempfile::TempDir, ConfigStore) {
    let directory = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(directory.path());
    (directory, store)
}

fn values(config: &ConfigStore, line: &str) -> Vec<String> {
    let words: Vec<String> = line.split_whitespace().map(ToOwned::to_owned).collect();
    match offer(config, &words, "").unwrap() {
        Offer::Values(candidates) => candidates
            .into_iter()
            .map(|candidate| candidate.value)
            .collect(),
        Offer::Files => panic!("`{line}` asked for file completion"),
    }
}

#[test]
fn root_completion_prioritizes_status_without_hiding_settings() {
    let (_directory, config) = config();
    let empty: Vec<String> = Vec::new();
    let Offer::Values(prioritized) = offer(&config, &empty, "s").unwrap() else {
        panic!("root completion must offer command names");
    };
    let prioritized: Vec<_> = prioritized
        .into_iter()
        .map(|candidate| candidate.value)
        .filter(|value| !value.starts_with('-'))
        .collect();
    assert_eq!(prioritized, ["status"]);

    let Offer::Values(all) = offer(&config, &empty, "").unwrap() else {
        panic!("root completion must offer command names");
    };
    let all: Vec<_> = all.into_iter().map(|candidate| candidate.value).collect();
    assert!(all.contains(&"settings".to_owned()));
    assert!(all.contains(&"review".to_owned()));
    assert!(all.contains(&"inbox".to_owned()));
}

#[test]
fn a_network_argument_reaches_the_configured_networks() {
    // The case that started this: an argument naming a network offers the
    // networks, whether it is written as a flag or as a positional, and
    // whether the flag is spelled long or short.
    let (_directory, config) = config();
    for line in [
        "portfolio main --network",
        "portfolio main -n",
        "settings tokens list --chain",
        "settings tokens search usdc --chain",
        "settings address-book list --network",
        "settings address-book add",
        "settings tokens remove",
        "settings network edit",
        "settings network remove",
    ] {
        let offered = values(&config, line);
        assert!(
            offered.contains(&"ethereum".to_owned()),
            "`{line}` offered {offered:?} rather than the configured networks"
        );
    }

    // `settings network add` is the one that means the presets instead: the configured
    // list is what it would be adding to.
    let presets = values(&config, "settings network add");
    assert!(presets.contains(&"ethereum".to_owned()));
}

#[test]
fn an_identifier_is_not_an_account() {
    // The packaged scripts used to offer account ids for `transaction show`,
    // whose argument is a request ID or a transaction hash. Nothing an account
    // is called can be typed here, so offering one is worse than offering
    // nothing: it completes to a word the command will reject.
    let (_directory, config) = config();
    for line in [
        "transaction show",
        "transaction cancel",
        "transaction rebroadcast",
        "transaction discard",
    ] {
        // With no database there is nothing to offer, which is the point: the
        // answer comes from the transaction store or not at all.
        assert!(values(&config, line).is_empty(), "`{line}`");
    }
    assert!(
        source_of("transaction show", "identifier") == Some(Source::Transactions),
        "the identifier argument must read the transaction store"
    );
}

#[test]
fn a_path_argument_hands_the_shell_its_own_file_completion() {
    // A candidate list cannot reproduce what a shell already does with paths:
    // trailing slashes, `~`, spaces, hidden files. So these positions say so
    // and get out of the way.
    let (_directory, config) = config();
    for line in [
        "account policy validate",
        "account policy set primary",
        "mcp reference",
        "settings tokens import",
    ] {
        let words: Vec<String> = line.split_whitespace().map(ToOwned::to_owned).collect();
        assert_eq!(
            offer(&config, &words, "").unwrap(),
            Offer::Files,
            "`{line}` should complete paths"
        );
    }
}

#[test]
fn clap_answers_for_every_argument_that_names_its_own_values() {
    // A `ValueEnum` argument needs no table: clap already knows what it takes,
    // so a new one is completable the day it is added.
    let (_directory, config) = config();
    assert!(values(&config, "legal show").contains(&"privacy".to_owned()));
    assert!(values(&config, "mcp register").contains(&"claude-code".to_owned()));
    assert!(values(&config, "settings completion").contains(&"fish".to_owned()));
    assert!(values(&config, "review --decision").contains(&"reject".to_owned()));
    assert!(
        values(&config, "mcp reference /tmp/plan.json --type")
            .contains(&"execution_plan".to_owned())
    );
    assert!(values(&config, "account create main --policy").contains(&"allow-all".to_owned()));
}

#[test]
fn every_command_offers_the_subcommands_it_has() {
    // The packaged scripts used to carry their own copy of this list, and the
    // only thing that noticed a new subcommand was a test comparing three
    // transcriptions against clap. Now there is one answer, so the test asks
    // whether it is the right one.
    let (_directory, config) = config();
    let mut root = <crate::cli::Cli as clap::CommandFactory>::command();
    root.build();

    let mut checked = 0;
    let mut walk = vec![(String::new(), &root)];
    while let Some((path, command)) = walk.pop() {
        let visible: Vec<&clap::Command> = command
            .get_subcommands()
            .filter(|sub| !sub.is_hide_set() && sub.get_name() != "help")
            .collect();
        if visible.is_empty() {
            continue;
        }
        let offered = values(&config, &path);
        for sub in visible {
            assert!(
                offered.contains(&sub.get_name().to_owned()),
                "`{path}` never offers `{}`",
                sub.get_name()
            );
            walk.push((format!("{path} {}", sub.get_name()), sub));
            checked += 1;
        }
        // A hidden subcommand is hidden from completion too: `__complete`
        // calling itself is not something a person ever means to type.
        assert!(!offered.contains(&"__complete".to_owned()), "`{path}`");
    }
    assert!(
        checked > 20,
        "walked implausibly few subcommands: {checked}"
    );
}

#[test]
fn a_flag_still_waiting_for_its_value_asks_nothing_else() {
    // `--network ` is a position with one question. Offering the sibling flags
    // beside the networks would complete `--json` into the slot where a
    // network goes.
    let (_directory, config) = config();
    let offered = values(&config, "portfolio main --network");
    assert!(
        !offered.iter().any(|value| value.starts_with('-')),
        "{offered:?}"
    );

    // Once it has one, the flags are back.
    let after = values(&config, "portfolio main --network ethereum");
    assert!(after.contains(&"--tokens".to_owned()), "{after:?}");

    // And a flag that was given its value inline is not still waiting.
    let inline = values(&config, "portfolio main --network=ethereum");
    assert!(inline.contains(&"--tokens".to_owned()), "{inline:?}");
}

#[test]
fn an_alias_is_offered_for_the_network_already_named() {
    // The alias argument of `settings address-book remove` means an alias *on that
    // chain*, so the network typed a word earlier is what scopes it. Without a
    // database there is nothing to list; what is checked here is that the
    // scope is read from the line rather than ignored.
    let (_directory, config) = config();
    let words = ["settings", "address-book", "remove", "ethereum"].map(ToOwned::to_owned);
    let mut root = <crate::cli::Cli as clap::CommandFactory>::command();
    root.build();
    let position = locate(&root, &words);
    assert_eq!(position.path, "settings address-book remove");
    assert_eq!(position.positionals, vec!["ethereum".to_owned()]);
    assert_eq!(scoped_chain(&config, &position), Some(1));
}

#[test]
fn a_store_that_does_not_answer_costs_a_keystroke_and_not_the_shell() {
    // Opening the encrypted database waits on the OS credential store, which
    // on a locked keychain waits for a dialog. A completion runs on tab and
    // owns the terminal while it runs, so it may not wait for one.
    let started = std::time::Instant::now();
    let candidates = within_budget(|| {
        std::thread::sleep(std::time::Duration::from_secs(30));
        Ok(vec![Candidate::new("late", "")])
    });
    assert!(candidates.is_empty());
    assert!(
        started.elapsed() < LOOKUP_BUDGET * 4,
        "waited {:?} on a store that never answered",
        started.elapsed()
    );
}

#[test]
fn every_source_rule_names_a_real_command_and_argument() {
    // `SOURCE_RULES` is keyed by strings the compiler never compares against
    // the command tree. A key that matches nothing is not an error: `source_of`
    // returns `None` and the argument silently loses its candidates, which is
    // precisely what moving commands between namespaces can do. So
    // the keys are resolved here, and a stale one fails the build instead.
    let root = <crate::cli::Cli as clap::CommandFactory>::command();
    for rule in SOURCE_RULES {
        for path in rule.paths {
            let mut command = &root;
            for word in path.split(' ') {
                command = command
                    .get_subcommands()
                    .find(|sub| sub.get_name() == word)
                    .unwrap_or_else(|| {
                        panic!("`{path}` names `{word}`, which is not a command here")
                    });
            }
            let known: Vec<&str> = command
                .get_arguments()
                .map(clap::Arg::get_id)
                .map(clap::Id::as_str)
                .collect();
            assert!(
                rule.arguments.iter().any(|wanted| known.contains(wanted)),
                "`{path}` takes {known:?}, none of which is {:?}",
                rule.arguments
            );
        }
    }
}
