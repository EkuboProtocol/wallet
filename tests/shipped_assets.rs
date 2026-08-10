//! The schema, policy templates, and decode examples shipped in this repository
//! are executable documentation. These tests fail if any of them drifts away
//! from what the wallet actually parses and enforces.

use assert_cmd::Command;
use ekubo_wallet::{abi_decoder::AbiDecodePlan, core::policy::WalletPolicy};
use serde_json::Value;
use std::{fs, path::Path};

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(relative: &str) -> Value {
    let path = repository_root().join(relative);
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("read {relative}: {error}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("parse {relative}: {error}"))
}

fn cli() -> Command {
    Command::cargo_bin("ekubo-wallet").expect("ekubo-wallet binary builds")
}

#[test]
fn committed_policy_schema_matches_the_enforced_types() {
    let output = cli().arg("policy").arg("schema").output().unwrap();
    assert!(output.status.success(), "policy schema exited non-zero");
    let generated: Value = serde_json::from_slice(&output.stdout).expect("schema is valid JSON");
    assert_eq!(
        generated,
        read_json("schemas/policy.schema.json"),
        "schemas/policy.schema.json is stale; regenerate it with `ekubo-wallet policy schema`"
    );
}

#[test]
fn every_shipped_policy_example_parses() {
    let mut checked = 0;
    for relative in [
        "examples/policy.json",
        "examples/policies/allow-all-with-approval.template.json",
        "examples/policies/approval-wildcards.template.json",
        "examples/policies/deny-all.json",
        "examples/policies/token-budget.template.json",
        "examples/policies/transfers-to-named-addresses.json",
        "examples/policies/revoke-approvals-only.json",
        "examples/policies/swap-proceeds-to-self.json",
        "examples/policies/deny-blanket-operators.json",
        "examples/policies/native-sends-only.json",
        "examples/policies/batched-calls.json",
        "examples/policies/predicate-edge-cases.json",
    ] {
        let policy = WalletPolicy::parse(read_json(relative))
            .unwrap_or_else(|error| panic!("{relative} is not a valid policy: {error:#}"));
        assert_eq!(
            policy.version, 1,
            "{relative} declares an unexpected version"
        );
        assert!(!policy.chains.is_empty(), "{relative} configures no chains");
        checked += 1;
    }
    assert_eq!(checked, 12);
}

#[test]
fn allow_all_template_matches_the_built_in_profile() {
    // `policy allow-all` and the shipped template must install the same rules,
    // so a reader can inspect the template to learn exactly what that command
    // does.
    let template = WalletPolicy::parse(read_json(
        "examples/policies/allow-all-with-approval.template.json",
    ))
    .expect("template parses");
    let built_in = WalletPolicy::allow_all_with_approval();
    assert_eq!(template.chains, built_in.chains);
    assert_eq!(template.version, built_in.version);
}

#[test]
fn require_approval_profile_matches_the_shipped_deny_all_example() {
    // `policy require-approval` and the shipped example must install the same
    // rules, so a reader can inspect the file to learn exactly what that
    // command does.
    let example =
        WalletPolicy::parse(read_json("examples/policies/deny-all.json")).expect("example parses");
    let built_in = WalletPolicy::require_approval_for_everything();
    assert_eq!(example.chains, built_in.chains);
    assert_eq!(example.version, built_in.version);
}

#[test]
fn deny_all_example_permits_nothing_automatically() {
    let policy =
        WalletPolicy::parse(read_json("examples/policies/deny-all.json")).expect("policy parses");
    let chain = policy
        .chain("1")
        .expect("wildcard chain applies to any chain");
    assert!(
        chain.rules.is_empty(),
        "no rule means every call falls to the default deny"
    );
    assert_eq!(chain.native_value.describe(), "exactly 0");
}

#[test]
fn every_documented_decode_plan_parses() {
    let examples = read_json("examples/abi-decoding.json");
    let object = examples.as_object().expect("examples are a JSON object");
    let mut checked = 0;
    for (name, example) in object {
        let Some(calls) = example.get("calls").and_then(Value::as_array) else {
            continue;
        };
        for call in calls {
            let plan = call.get("decode").unwrap_or_else(|| {
                panic!("example {name} has a call without a decode plan");
            });
            let parsed = serde_json::from_value::<AbiDecodePlan>(plan.clone())
                .unwrap_or_else(|error| panic!("example {name} decode plan is invalid: {error}"));
            // Parsing is not enough: a codec path that addresses nothing fails
            // at decode time, which is how this example shipped asking for
            // `sqrt_ratio` on a lone parameter that the decoder unwraps to a
            // bare value.
            if let AbiDecodePlan::AbiParameters {
                parameters,
                semantic_codecs,
                ..
            } = &parsed
            {
                for codec in semantic_codecs {
                    let root = codec.path.split('.').next().unwrap_or_default();
                    let addressable = if parameters.len() == 1 {
                        codec.path == "$"
                    } else {
                        parameters
                            .iter()
                            .any(|parameter| parameter.name.as_deref() == Some(root))
                    };
                    assert!(
                        addressable,
                        "example {name} addresses {}, which its parameters do not declare",
                        codec.path
                    );
                }
            }
            checked += 1;
        }
    }
    assert_eq!(
        checked, 6,
        "expected one decode plan per documented example kind"
    );
}

#[test]
fn policy_validate_accepts_examples_and_rejects_malformed_documents() {
    let valid = cli()
        .arg("policy")
        .arg("validate")
        .arg(repository_root().join("examples/policy.json"))
        .output()
        .unwrap();
    assert!(valid.status.success());
    let report: Value = serde_json::from_slice(&valid.stdout).expect("report is JSON");
    assert_eq!(report["valid"], Value::Bool(true));
    assert!(
        report["digest"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("0x")),
        "validation reports the digest a reviewer would see when applying the file"
    );

    let unknown_field = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        unknown_field.path(),
        br#"{"chains":{"*":{"unexpected_field":true}}}"#,
    )
    .unwrap();
    cli()
        .arg("policy")
        .arg("validate")
        .arg(unknown_field.path())
        .assert()
        .failure();
}

#[test]
fn every_packaged_completion_asks_the_binary_and_reads_its_answer() {
    // The scripts used to carry their own copy of the command tree, and this
    // test used to compare three transcriptions of it against clap. They now
    // pass the line to `__complete` and print what comes back, so the tree can
    // no longer go stale in them — and what is left to get wrong is the
    // handoff: asking in a format the binary does not print, or ignoring the
    // one answer that is a directive rather than a candidate.
    for (shell, format) in [("bash", "plain"), ("zsh", "zsh"), ("fish", "fish")] {
        let output = cli().arg("shell-completion").arg(shell).output().unwrap();
        assert!(
            output.status.success(),
            "shell-completion {shell} exited non-zero"
        );
        let script = String::from_utf8(output.stdout).expect("completion script is UTF-8");
        assert!(
            script.contains(&format!("__complete {format}")),
            "{shell} completion does not ask for candidates in the {format} format"
        );
        assert!(
            script.contains(ekubo_wallet::cli::FILE_COMPLETION_DIRECTIVE),
            "{shell} completion would offer the file directive as a candidate"
        );
        // A script that still names a subcommand is a script that has started
        // keeping its own list again.
        for stale in ["meta-address-book", "rebroadcast", "require-approval"] {
            assert!(
                !script.contains(stale),
                "{shell} completion hardcodes `{stale}` rather than asking"
            );
        }
    }
}

#[test]
fn the_completion_endpoint_answers_what_the_scripts_ask_it() {
    // The other half of the handoff, against the real binary: the words a
    // script passes come back as candidates, and a path argument comes back as
    // the directive the scripts check for.
    let root = cli()
        .args(["__complete", "plain", "ekubo-wallet"])
        .output()
        .unwrap();
    assert!(root.status.success());
    let offered = String::from_utf8(root.stdout).unwrap();
    let mut expected = Vec::new();
    declared_subcommands(
        &<ekubo_wallet::cli::Cli as clap::CommandFactory>::command(),
        &mut expected,
    );
    assert!(
        expected.len() > 20,
        "clap reported implausibly few subcommands: {expected:?}"
    );
    for name in ["portfolio", "meta-address-book", "review", "--json"] {
        assert!(
            offered.lines().any(|line| line == name),
            "the root completion never offers `{name}`: {offered}"
        );
    }
    assert!(
        !offered.lines().any(|line| line == "__complete"),
        "the root completion offers the hidden subcommand: {offered}"
    );

    let file = cli()
        .args(["__complete", "plain", "ekubo-wallet", "policy", "validate"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(file.stdout).unwrap().trim(),
        ekubo_wallet::cli::FILE_COMPLETION_DIRECTIVE
    );
}

/// Every visible subcommand name clap knows about, at any depth.
fn declared_subcommands(command: &clap::Command, into: &mut Vec<String>) {
    for subcommand in command.get_subcommands() {
        if subcommand.is_hide_set() {
            continue;
        }
        into.push(subcommand.get_name().to_owned());
        declared_subcommands(subcommand, into);
    }
}

#[test]
fn third_party_licenses_cover_every_locked_dependency() {
    // THIRD_PARTY_LICENSES.md ships in the binary via wallet_get_legal, so a
    // dependency change without regeneration must fail the build, keeping the
    // attribution document current with each release.
    let lock = fs::read_to_string(repository_root().join("Cargo.lock")).unwrap();
    let document = fs::read_to_string(repository_root().join("THIRD_PARTY_LICENSES.md")).unwrap();
    let mut checked = 0;
    let mut missing = Vec::new();
    let mut lines = lock.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim() != "[[package]]" {
            continue;
        }
        let field = |line: Option<&str>, key: &str| -> Option<String> {
            line?
                .trim()
                .strip_prefix(key)?
                .trim()
                .strip_prefix("= \"")?
                .strip_suffix('"')
                .map(str::to_owned)
        };
        let name = field(lines.next(), "name").expect("lockfile package has a name");
        let version = field(lines.next(), "version").expect("lockfile package has a version");
        // Workspace-local crates are first-party, not attributions.
        if name.starts_with("ekubo-wallet") {
            continue;
        }
        checked += 1;
        if !document.contains(&format!("- {name} {version}")) {
            missing.push(format!("{name} {version}"));
        }
    }
    assert!(checked > 100, "lockfile parse found too few packages");
    assert!(
        missing.is_empty(),
        "THIRD_PARTY_LICENSES.md is stale; regenerate it with \
         contrib/generate-third-party-licenses.py. Missing: {missing:?}"
    );
}

#[test]
fn policy_validate_never_touches_wallet_state() {
    // Validation must work before any wallet exists, so drafting a policy needs
    // neither the encrypted database nor owner authentication.
    let empty_home = tempfile::tempdir().unwrap();
    cli()
        .arg("--data-dir")
        .arg(empty_home.path())
        .arg("policy")
        .arg("validate")
        .arg(repository_root().join("examples/policies/deny-all.json"))
        .assert()
        .success();
    assert_eq!(
        fs::read_dir(empty_home.path()).unwrap().count(),
        0,
        "validation wrote to the data directory"
    );
}

/// No document tells a reader to pipe an unverified script into a shell.
///
/// `01d13cb` signed `install.sh`, made the agent-facing `upgrade_command`
/// verify it, and updated the release notes -- and left `README.md` and
/// `docs/installation.md` saying
/// `curl … raw.githubusercontent.com/…/main/install.sh | sh`. That is the
/// construction the fix exists to remove, and worse than what it replaced,
/// because it tracks a branch rather than a tag: no signature covers "whatever
/// `main` says today".
///
/// The inconsistency was the real defect. The project paid the cost of a
/// cosign-mandatory install in its documentation while keeping the unverified
/// path as the one most people would follow.
#[test]
fn no_shipped_document_pipes_an_unverified_installer() {
    for document in ["README.md", "docs/installation.md", "docs/releasing.md"] {
        let text = fs::read_to_string(repository_root().join(document))
            .unwrap_or_else(|error| panic!("{document} is readable: {error}"));
        for (number, line) in text.lines().enumerate() {
            let piped = line.contains("install.sh") && line.contains("| sh");
            assert!(
                !piped,
                "{document}:{} pipes an installer into a shell: {line}",
                number + 1
            );
            assert!(
                !line.contains("raw.githubusercontent.com"),
                "{document}:{} fetches from a branch, which no signature covers: {line}",
                number + 1
            );
        }
        assert!(
            !text.contains("install.sh") || text.contains("cosign verify-blob"),
            "{document} names the installer without showing how to verify it"
        );
    }
}
