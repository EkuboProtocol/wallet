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

/// Every file that may mint an interactive-terminal proof, and nothing else.
///
/// Each entry is a command a person is sitting in front of, reviewing a
/// specific request: `cli.rs` is `ekubo-wallet review`, and `connect.rs` is the
/// `WalletConnect` session, which reviews a dapp's transaction on the same
/// terminal through the same orchestrator. A proof is a non-cloneable
/// capability minted where it is used, so a second interactive command cannot
/// borrow the first one's — it has to appear here.
///
/// Adding to this list is a deliberate act. It widens the set of places a
/// human override can originate, which is exactly what an auditor reads this
/// test to enumerate.
///
/// `src/cli.rs` mints two, and they are different capabilities. One is
/// `ekubo-wallet review`. The other is `owner_at_terminal`, the single origin
/// of the `InteractiveOwner` that lets `network add` and `network edit`
/// configure a plaintext endpoint to a node the operator runs -- a decision the
/// confirmation screen puts to them by name, and one an agent's network
/// proposal has no way to reach, because it cannot mint the witness.
const PROOF_ORIGINS: &[(&str, usize)] = &[("src/cli.rs", 2), ("src/connect.rs", 1)];

/// Only the listed production call sites can mint an interactive-terminal
/// proof, one each. Every human override in the process descends from one of
/// them, so an auditor enumerates override origins by reading this list.
#[test]
fn interactive_proof_has_exactly_one_production_origin_per_listed_command() {
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
    call_sites.sort();
    for (origin, expected) in PROOF_ORIGINS {
        let found = call_sites
            .iter()
            .filter(|site| site.contains(origin))
            .count();
        assert_eq!(
            found, *expected,
            "expected exactly {expected} InteractiveProof::from_terminal call site(s) in \
             {origin}, found {found}: {call_sites:?}"
        );
    }
    // Nothing outside the list, so the count is the whole check: a new call
    // site anywhere else fails here rather than quietly becoming a third way
    // for a human override to originate.
    assert_eq!(
        call_sites.len(),
        PROOF_ORIGINS.iter().map(|(_, count)| count).sum::<usize>(),
        "InteractiveProof::from_terminal is called outside {PROOF_ORIGINS:?}: {call_sites:?}"
    );
}

/// Every custody symbol banned in presentation code, and the reason it is.
///
/// A `PrivateKeySigner` signs any 32 bytes with no policy, no simulation, and
/// no owner authentication, so a caller holding one holds the wallet. That
/// makes "who can obtain a signer" the question deciding whether the crate
/// split protects keys at all, and these are the answers.
///
/// `address` is deliberately absent: it is derived from the public key and
/// appears in every transaction the wallet sends, so exposing one discloses
/// nothing.
const CUSTODY_BANS: &[&str] = &[
    "ekubo_wallet_core::custody::load_matching_signer",
    "ekubo_wallet_core::custody::PrivateKeyMaterial::signer",
    "ekubo_wallet_core::custody::PrivateKeyMaterial::expose_hex",
    "ekubo_wallet_core::custody::KeyStore::load",
    "alloy::signers::local::PrivateKeySigner",
];

/// No key material, and nothing that can use it, leaves the kernel crate.
///
/// Three mechanisms stack here, and this test guards the two the compiler
/// cannot guard itself.
///
/// The compiler is the enforcement: `signer`, `expose_hex`, and
/// `load_matching_signer` are `pub(crate)`, so presentation code cannot write
/// the call at all. Clippy's `disallowed_methods` is the second line, denied
/// rather than warned in `Cargo.toml`, so that widening one of those to `pub`
/// — a one-word diff that reads as tidying up — fails at the first *use*
/// rather than silently restoring the bypass.
///
/// What neither can see is a widening that nobody has used yet, or the quiet
/// deletion of the `clippy.toml` that carries the bans. So this pins the
/// declarations and pins the config, and the assertions are text matching
/// because both targets *are* text: a declaration's spelling and a config
/// file's contents, not a claim about what the code does.
#[test]
fn no_signer_or_key_material_escapes_the_kernel() {
    let custody =
        fs::read_to_string(repository_root().join("crates/ekubo-wallet-core/src/custody.rs"))
            .unwrap();
    for declaration in [
        "pub(crate) fn signer(",
        "pub(crate) fn expose_hex(",
        "pub(crate) fn load_matching_signer",
    ] {
        assert!(
            custody.contains(declaration),
            "custody.rs no longer declares `{declaration}`; a signer or raw key that presentation \
             code can obtain is a signature nobody had to authenticate for"
        );
    }

    // The signature is one half of a signed decision; the row that says a
    // request was answered is the other, and it is the half every reader and
    // waiter actually reports. `store_signature` and `store_signed` check the
    // row -- right wallet, right digest, still awaiting -- and nothing about
    // whether a person reviewed the payload, authenticated as the owner, or
    // held the key that produced those bytes. Reachable from presentation
    // code, they are a durable signed decision with an attacker-chosen
    // signature in it and no signature ever made.
    for (module, declaration) in [
        ("message.rs", "pub(crate) fn store_signature("),
        ("typed_data.rs", "pub(crate) fn store_signature("),
        ("pending.rs", "pub(crate) fn store_signed("),
    ] {
        let source = fs::read_to_string(
            repository_root()
                .join("crates/ekubo-wallet-core/src")
                .join(module),
        )
        .unwrap();
        assert!(
            source.contains(declaration),
            "{module} no longer declares `{declaration}`; a terminal signed state presentation \
             code can write is an approval nobody gave"
        );
    }

    let clippy = fs::read_to_string(repository_root().join("clippy.toml")).unwrap();
    for ban in CUSTODY_BANS {
        assert!(
            clippy.contains(ban),
            "clippy.toml no longer bans `{ban}` in the presentation crate; the ban is what catches \
             a widened `pub(crate)` at its first use"
        );
    }

    // A ban that only warns is a ban you scroll past: the gate prints warnings
    // and still exits zero.
    let manifest = fs::read_to_string(repository_root().join("Cargo.toml")).unwrap();
    for level in [
        "disallowed_methods = \"deny\"",
        "disallowed_types = \"deny\"",
    ] {
        assert!(
            manifest.contains(level),
            "Cargo.toml no longer sets `{level}`; reaching for a private key must fail the build, \
             not warn in it"
        );
    }
}

/// The two capability traits stay closed to outside implementation.
///
/// `HumanPresence` is the one that matters. Every owner authentication in the
/// process is a single `confirm` call, so an implementation returning `Ok(())`
/// is not a weak check but the absence of all of them — and presentation code
/// hands a `HumanPresence` to the kernel by design, so it would be supplying
/// the very thing that is supposed to constrain it. `KeyStore` is sealed
/// alongside it: a store decides whether `insert_new` really persisted a key
/// and whether `delete` really removed one.
///
/// Dropping a supertrait bound is a one-line diff that compiles and breaks
/// nothing, which is exactly the kind of erosion no other check here sees.
#[test]
fn the_capability_traits_stay_sealed() {
    for (file, bound) in [
        (
            "crates/ekubo-wallet-core/src/custody.rs",
            "pub trait KeyStore: crate::sealed::SealedKeyStore",
        ),
        (
            "crates/ekubo-wallet-core/src/human_presence.rs",
            "pub trait HumanPresence: crate::sealed::SealedHumanPresence",
        ),
    ] {
        let source = fs::read_to_string(repository_root().join(file)).unwrap();
        assert!(
            source.contains(bound),
            "{file} no longer declares `{bound}`; an unsealed capability trait can be implemented \
             by the presentation crate, which is where it would be used to answer its own \
             security question"
        );
    }

    // And the seal is only a seal while its module is unreachable from outside
    // the kernel: `pub mod sealed` would let presentation code implement the
    // marker directly and satisfy the bound after all.
    let lib =
        fs::read_to_string(repository_root().join("crates/ekubo-wallet-core/src/lib.rs")).unwrap();
    assert!(
        lib.contains("\nmod sealed;"),
        "the kernel no longer declares `mod sealed;`"
    );
    assert!(
        !lib.contains("pub mod sealed;"),
        "`sealed` is published; the marker traits must be unnameable outside the kernel or the \
         seal means nothing"
    );
}

/// The kernel's clippy exemption covers the custody bans and nothing else.
///
/// Clippy reads the `clippy.toml` beside a crate's own `Cargo.toml` in
/// preference to the workspace root's, and the chosen file *replaces* the
/// other rather than merging. That is what scopes the custody bans to
/// presentation code — and it means any future ban added to the root file and
/// meant to apply everywhere silently skips the security kernel, the code that
/// most wants linting.
///
/// Nothing about that failure is visible: the kernel just stops being linted
/// for the new rule. So the two files are compared here instead. Add a ban to
/// the root that is not a custody ban, and this fails until it is mirrored
/// into the kernel's file.
#[test]
fn the_kernel_mirrors_every_lint_ban_that_is_not_about_custody() {
    fn banned_paths(file: &str) -> Vec<String> {
        fs::read_to_string(repository_root().join(file))
            .unwrap()
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .filter_map(|line| {
                let (_, rest) = line.split_once("path = \"")?;
                let (path, _) = rest.split_once('"')?;
                Some(path.to_owned())
            })
            .collect()
    }

    let mut expected: Vec<String> = banned_paths("clippy.toml")
        .into_iter()
        .filter(|path| !CUSTODY_BANS.contains(&path.as_str()))
        .collect();
    let mut found = banned_paths("crates/ekubo-wallet-core/clippy.toml");
    expected.sort();
    found.sort();
    assert_eq!(
        found, expected,
        "the kernel's clippy.toml does not mirror the root's non-custody bans; a rule meant for \
         the whole workspace is not being applied to the security kernel"
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
///
/// Display is the whole of why this matters, and it is reason enough. These
/// rows no longer decide policy — `is_token` and `is_address_book` were removed
/// from the predicate language precisely so a row could not have that second
/// job — but an agent that could name an address would still choose the
/// sentence the owner reads while deciding, which is the same outcome by a
/// different route.
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
/// `evaluate_policy` taking exactly the plan, the policy, and a
/// [`PolicyContext`] is what enforces that. The context is one address — the
/// signing wallet — so the evaluator holds no store handle, no lock, and no way
/// to reach the RPC. With no channel for an observation to arrive through, the
/// property is structural rather than a rule someone has to remember. This pins
/// the signature so restoring such a channel has to be a deliberate act.
#[test]
fn no_policy_predicate_can_consult_a_simulation() {
    let policy =
        fs::read_to_string(repository_root().join("crates/ekubo-wallet-core/src/core/policy.rs"))
            .unwrap();

    let declaration = policy
        .split_once("pub fn evaluate_policy(")
        .and_then(|(_, rest)| rest.split_once(" {"))
        .map(|(head, _)| head.split_whitespace().collect::<Vec<_>>().join(" "))
        .expect("evaluate_policy must remain declared in policy.rs");
    assert_eq!(
        declaration,
        "plan: &ExecutionPlan, policy: &WalletPolicy, context: &PolicyContext, ) -> Vec<PolicyFinding>",
        "evaluate_policy grew a parameter; a policy decision takes the plan, the policy, and the \
         resolved local metadata, and nothing the RPC reported"
    );

    for forbidden in ["TokenSpends", "token_spends", "crate::simulation"] {
        assert!(
            !policy.contains(forbidden),
            "policy.rs references {forbidden}; simulation observations must not reach a policy \
             predicate"
        );
    }

    // The evaluator is handed resolved sets, never a store, so it cannot read
    // anything that was not settled before the decision began.
    let predicate = fs::read_to_string(
        repository_root().join("crates/ekubo-wallet-core/src/core/predicate.rs"),
    )
    .unwrap();
    for forbidden in [
        "TokenStore",
        "AddressBookStore",
        "rusqlite",
        "crate::simulation",
    ] {
        assert!(
            !predicate.contains(forbidden),
            "predicate.rs references {forbidden}; the predicate language reads resolved data only"
        );
    }
}

/// A contract never gets a say in whether a token may be named.
///
/// The token database once asked each address whether it answered `symbol()`
/// or `name()` before the owner's acceptance could become a row, as a check
/// against typos and dead entries. That is gone, and must not come back by
/// habit: a contract cannot tell an owner whether the curator they are
/// trusting is trustworthy, which is the only question a listing raises, and
/// an address that answers nothing yields a row naming nothing rather than a
/// dangerous one. Approval is the check.
///
/// `decimals()` is named here too. It was never called in this design, and
/// calling it would be worse than the existence check ever was: it would let
/// whoever deployed the contract restate the scale of every amount the owner
/// is shown for that token.
#[test]
fn naming_a_token_asks_no_contract_for_permission() {
    let store =
        fs::read_to_string(repository_root().join("crates/ekubo-wallet-core/src/token_store.rs"))
            .unwrap();
    for forbidden in [
        "verify_listings",
        "responds_as_token",
        "ListingRejection",
        "symbolCall",
        "nameCall",
        "decimalsCall",
    ] {
        assert!(
            !store.contains(forbidden),
            "token_store.rs references {forbidden}; a listing is the owner's decision about a \
             curator, and no contract may veto or supply it"
        );
    }

    // The acceptance path is where the check used to run, so it is pinned
    // too: confirming names must reach no chain at all.
    let cli = fs::read_to_string(repository_root().join("src/cli.rs")).unwrap();
    let confirm = cli
        .split("async fn confirm_and_store(")
        .nth(1)
        .expect("confirm_and_store must remain declared in cli.rs")
        .split("\n/// ")
        .next()
        .unwrap();
    for forbidden in ["verify_listings", "network_by_chain_id", "ProviderBuilder"] {
        assert!(
            !confirm.contains(forbidden),
            "confirm_and_store references {forbidden}; accepting a token name must not depend on \
             a chain being reachable, or configured at all"
        );
    }
}

/// The profile people actually install keeps its arithmetic checked.
///
/// Cargo's defaults put `overflow-checks` on in `dev` and off in `release`, so
/// the setting decides whether the tested binary and the shipped binary compute
/// the same thing. Without it, every test in this repository — and every
/// property test in the kernel — runs against arithmetic that traps, while the
/// build a user installs runs against arithmetic that silently wraps. An
/// overflow there is not a crash to be diagnosed: it is a fee cap, an amount, a
/// deadline, or an index that came out wrong and that nothing downstream can
/// tell apart from a right one.
///
/// This is pinned rather than left to the manifest because deleting it is a
/// one-line diff that makes the binary marginally smaller and faster, arrives
/// with a plausible rationale, and changes nothing any other test can see: the
/// gate builds `dev`, so the release profile has no other tripwire on it.
#[test]
fn the_shipped_profile_keeps_overflow_checks_on() {
    let manifest = fs::read_to_string(repository_root().join("Cargo.toml")).unwrap();
    // One `key = value` out of a manifest line, with the comment dropped
    // first. Dropping it is the point: the setting is worth a sentence
    // explaining it, and a test matching the raw text would be satisfied by
    // the explanation that survives commenting the setting out.
    let setting = |line: &str| -> Option<(String, String)> {
        let (key, value) = line.split('#').next()?.split_once('=')?;
        Some((
            key.trim().trim_matches('"').to_owned(),
            value.trim().to_owned(),
        ))
    };

    let release = manifest
        .split("[profile.release]")
        .nth(1)
        .expect("Cargo.toml must declare a [profile.release] section");
    assert!(
        release
            .split("\n[")
            .next()
            .unwrap()
            .lines()
            .filter_map(setting)
            .any(|(key, value)| key == "overflow-checks" && value == "true"),
        "[profile.release] no longer sets `overflow-checks = true`; the shipped binary would wrap \
         where every test in this repository traps, and a wrapped amount is a wrong number rather \
         than a failure"
    );

    // And nothing anywhere takes it back. A per-package override, or a profile
    // inheriting from `release` for a distribution build, would ship wrapping
    // arithmetic with the section above still reading correctly.
    for (key, value) in manifest.lines().filter_map(setting) {
        assert!(
            key != "overflow-checks" || value == "true",
            "Cargo.toml sets `overflow-checks = {value}` somewhere; whichever profile or package \
             that covers, it ships arithmetic that wraps where the tests trap"
        );
    }
}
