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
    ] {
        let policy = WalletPolicy::parse(read_json(relative))
            .unwrap_or_else(|error| panic!("{relative} is not a valid policy: {error:#}"));
        assert_eq!(
            policy.version, 2,
            "{relative} declares an unexpected version"
        );
        assert!(!policy.chains.is_empty(), "{relative} configures no chains");
        checked += 1;
    }
    assert_eq!(checked, 5);
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
    assert_eq!(
        template.approval_expiry_seconds,
        built_in.approval_expiry_seconds
    );
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
    assert_eq!(
        example.approval_expiry_seconds,
        built_in.approval_expiry_seconds
    );
}

#[test]
fn deny_all_example_permits_nothing_automatically() {
    let policy =
        WalletPolicy::parse(read_json("examples/policies/deny-all.json")).expect("policy parses");
    let chain = policy
        .chain("1")
        .expect("wildcard chain applies to any chain");
    assert!(chain.targets.is_empty());
    assert!(chain.tokens.is_empty());
    assert!(chain.approval_spenders.is_empty());
    assert_eq!(chain.native.max_value_per_transaction, "0");
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
            serde_json::from_value::<AbiDecodePlan>(plan.clone())
                .unwrap_or_else(|error| panic!("example {name} decode plan is invalid: {error}"));
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
fn packaged_completions_offer_every_subcommand() {
    // The completion scripts are hand-written, because the candidates they
    // offer are looked up at completion time from the live configuration.
    // Nothing regenerates them when a subcommand is added, so this test is the
    // only thing that notices — which is why the list it checks is read out of
    // clap rather than kept by hand here. A hand-kept list goes stale in
    // exactly the same way, and just as quietly, as the scripts do.
    let mut expected = Vec::new();
    declared_subcommands(
        &<ekubo_wallet::cli::Cli as clap::CommandFactory>::command(),
        &mut expected,
    );
    assert!(
        expected.len() > 20,
        "clap reported implausibly few subcommands: {expected:?}"
    );
    for shell in ["bash", "zsh", "fish"] {
        let output = cli().arg("completion").arg(shell).output().unwrap();
        assert!(
            output.status.success(),
            "completion {shell} exited non-zero"
        );
        let script = String::from_utf8(output.stdout).expect("completion script is UTF-8");
        for subcommand in &expected {
            assert!(
                script.contains(subcommand.as_str()),
                "{shell} completion never offers `{subcommand}`"
            );
        }
        // The scripts call `ekubo-wallet __complete <kind>` to look candidates
        // up, so the name appears legitimately. What must never happen is the
        // hidden subcommand being offered as a candidate itself, which shows
        // up as an occurrence that is not part of that invocation.
        assert_eq!(
            script.matches("__complete").count(),
            script.matches("ekubo-wallet __complete").count(),
            "{shell} completion offers the hidden __complete subcommand"
        );
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
        if name == "ekubo-wallet" {
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
