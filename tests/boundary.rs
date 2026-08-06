//! Tripwires on the audit boundary.
//!
//! The security kernel lives in `crates/ekubo-wallet-core`; the binary crate
//! supplies presentation. These tests fail the build when a change crosses
//! the lines an auditor relies on, so the boundary cannot erode silently.

use std::{fs, path::PathBuf};

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The MCP server must never gain an approval capability: no reference to
/// the terminal presenter, the TUI, or the interactive-proof constructor.
#[test]
fn mcp_server_cannot_reach_an_approval_surface() {
    let mcp = fs::read_to_string(repository_root().join("src/mcp.rs")).unwrap();
    for forbidden in [
        "TerminalApprovalUi",
        "approve_tui",
        "crate::tui",
        "from_terminal",
        "InteractiveProof",
        "ReviewPresenter",
    ] {
        assert!(
            !mcp.contains(forbidden),
            "src/mcp.rs references {forbidden}; the MCP server must never reach an approval \
             surface"
        );
    }
}

/// Exactly one production call site can mint an interactive-terminal proof —
/// the CLI review command. Every human override in the process descends from
/// it, so an auditor enumerates override origins by reading one line.
#[test]
fn interactive_proof_has_exactly_one_production_origin() {
    let mut call_sites = Vec::new();
    let mut directories = vec![
        repository_root().join("src"),
        repository_root().join("crates/ekubo-wallet-core/src"),
    ];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directories.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            for (number, line) in source.lines().enumerate() {
                if line.contains("from_terminal()")
                    && !line.trim_start().starts_with("//")
                    && !line.contains("pub fn from_terminal")
                {
                    // Forward slashes on every platform, so the assertions
                    // below hold on Windows too.
                    let display = path.display().to_string().replace('\\', "/");
                    call_sites.push(format!("{display}:{}", number + 1));
                }
            }
        }
    }
    assert_eq!(
        call_sites.len(),
        1,
        "expected exactly one InteractiveProof::from_terminal call site, found: {call_sites:?}"
    );
    assert!(
        call_sites[0].contains("src/cli.rs"),
        "the one proof origin must be the CLI review command: {call_sites:?}"
    );
}

/// The security kernel carries no presentation or MCP dependencies: nothing
/// in the audited crate can draw a terminal or serve a tool.
#[test]
fn core_crate_has_no_presentation_dependencies() {
    let manifest =
        fs::read_to_string(repository_root().join("crates/ekubo-wallet-core/Cargo.toml")).unwrap();
    for forbidden in ["ratatui", "inquire", "crossterm", "rmcp", "clap"] {
        assert!(
            !manifest.contains(forbidden),
            "ekubo-wallet-core depends on {forbidden}; presentation stays outside the audit \
             boundary"
        );
    }
}

/// A token contract is never asked what it is called or how it scales.
///
/// The wallet displays a token's symbol at approval time and its decimals
/// scale every amount shown, so both must come from a list the owner
/// confirmed. Every value a contract returns is chosen by whoever deployed
/// it — `decimals` no less than `symbol` — which makes reading one back a
/// way for the counterparty to overrule the curator the owner picked.
///
/// `symbol()` and `name()` survive as a liveness probe: whether an address
/// answers is evidence a token lives there, and that answer is never decoded.
/// A `decimals()` call has no such innocent form, so its absence is the
/// invariant worth pinning.
#[test]
fn no_token_contract_is_asked_for_its_decimals() {
    let store =
        fs::read_to_string(repository_root().join("crates/ekubo-wallet-core/src/token_store.rs"))
            .unwrap();
    for forbidden in ["decimalsCall", "function decimals()"] {
        assert!(
            !store.contains(forbidden),
            "token_store.rs references {forbidden}; the list decides a token's decimals, \
             never the contract"
        );
    }

    // And nothing in the review path may read metadata off the chain either.
    let summary = fs::read_to_string(
        repository_root().join("crates/ekubo-wallet-core/src/approval_summary.rs"),
    )
    .unwrap();
    for forbidden in ["symbolCall", "decimalsCall", "ProviderBuilder"] {
        assert!(
            !summary.contains(forbidden),
            "approval_summary.rs references {forbidden}; names shown at approval time come \
             from the owner's token database, not from the chain"
        );
    }
}

/// The MCP server proposes metadata and never writes it.
///
/// Token names, address-book aliases, and network profiles are all supplied by
/// an untrusted client and all decide what the owner reads when they approve a
/// transaction — a name against an address, an amount's scale, and, for a
/// network, which endpoint describes the chain at all. Each one reaches the
/// database only through a terminal confirmation and an OS presence check, and
/// the way that erodes is a write helper called from a tool body because it was
/// right there. These are the names of those helpers.
#[test]
fn the_mcp_server_cannot_write_stored_metadata() {
    // The whole file is production code: the tests that legitimately write
    // through the stores — standing in for the CLI while read-only tools are
    // checked against the state — live in `mcp_test.rs` and `pipeline_test.rs`,
    // which this never reads. That is what the `_test.rs` split bought here.
    let mcp = fs::read_to_string(repository_root().join("src/mcp.rs")).unwrap();
    for forbidden in [
        "add_configured_network",
        "replace_configured_network",
        "remove_configured_network",
        "insert_if_absent",
        "upsert",
    ] {
        assert!(
            !mcp.contains(forbidden),
            "src/mcp.rs references {forbidden}; an agent proposes metadata and the owner \
             confirms it, so no tool body writes it"
        );
    }
}

/// No policy decision may consult what the RPC reported.
///
/// The configured endpoint is the only witness to a simulation, so any
/// predicate scored against observed balances or transfer logs is a rule a
/// dishonest endpoint can relax by misreporting what a transaction did — while
/// still reading, to whoever wrote the policy, like a limit that binds. The
/// policy therefore decides everything from the execution plan's own bytes.
///
/// `evaluate_policy` taking exactly the plan and the policy is what enforces
/// that: with no channel for an observation to arrive through, the property is
/// structural rather than a rule someone has to remember. This pins the
/// signature so restoring such a channel has to be a deliberate act.
#[test]
fn no_policy_predicate_can_consult_a_simulation() {
    let policy =
        fs::read_to_string(repository_root().join("crates/ekubo-wallet-core/src/core/policy.rs"))
            .unwrap();

    let signature = policy
        .lines()
        .find(|line| line.starts_with("pub fn evaluate_policy"))
        .expect("evaluate_policy must remain a single-line signature in policy.rs");
    assert_eq!(
        signature,
        "pub fn evaluate_policy(plan: &ExecutionPlan, policy: &WalletPolicy) -> Vec<PolicyFinding> {",
        "evaluate_policy grew a parameter; a policy decision takes the plan and the policy and \
         nothing the RPC reported"
    );

    for forbidden in ["TokenSpends", "token_spends", "crate::simulation"] {
        assert!(
            !policy.contains(forbidden),
            "policy.rs references {forbidden}; simulation observations must not reach a policy \
             predicate"
        );
    }
}

/// One implementation redacts RPC credentials, and it lives in `rpc.rs`.
///
/// An endpoint URL can carry a key in its userinfo, its path, or its query,
/// and getting all three right is fiddly enough that a second copy will drift
/// from the first. One did: `token_store.rs` grew a hand-rolled
/// `replace(rpc_url.as_str(), …)` that reproduced only the whole-URL case and
/// leaked every credential form the shared helper had learned to strip. The
/// tripwire is the literal that opens such a copy.
#[test]
fn rpc_credentials_are_redacted_in_exactly_one_place() {
    let core = repository_root().join("crates/ekubo-wallet-core/src");
    for entry in fs::read_dir(&core).unwrap() {
        let path = entry.unwrap().path();
        // `rpc.rs` is the one implementation, and `*_test.rs` files are not
        // production code — `rpc_test.rs` asserts on the redacted form, which
        // is the helper being tested rather than a second copy of it.
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        if path.extension().is_none_or(|extension| extension != "rs")
            || name == "rpc.rs"
            || name.ends_with("_test.rs")
        {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        assert!(
            !source.contains("\"<rpc-url>\""),
            "{} redacts an RPC URL itself; every module surfaces RPC errors through \
             rpc::sanitized_rpc_error so the credential forms are stripped in one place",
            path.display()
        );
    }
}
