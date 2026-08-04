//! Legal documents and their acceptance state.
//!
//! The terms of service and privacy policy are readable anywhere (MCP tools,
//! resources, and the CLI), but acceptance is recorded only by the interactive
//! CLI. Nothing signs — transactions or typed data — until the user has
//! separately accepted the current revision of both documents. Acceptance
//! binds the exact document text by digest, so shipping a materially changed
//! document automatically requires re-acceptance.
//!
//! The privacy policy's list of default network endpoints is generated from
//! the same [`crate::config::default_networks`] catalog the wallet actually
//! uses, so the disclosed endpoints cannot drift from a release's real
//! defaults; changing a default RPC changes the document digest and forces
//! re-acceptance.

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    fmt::Write as _,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

const ACCEPTANCE_FILE: &str = "legal.json";

/// Shipped attribution document for third-party dependencies. Regenerate with
/// `contrib/generate-third-party-licenses.py`; `tests/shipped_assets.rs`
/// fails when it no longer covers every locked dependency.
pub const THIRD_PARTY_LICENSES: &str = include_str!("../THIRD_PARTY_LICENSES.md");

pub const TERMS_OF_SERVICE: &str = "\
# Ekubo Wallet Terms of Service

Version 1 — 2026-08-04

By accepting these terms you agree to all of the following before this
software signs anything on your behalf.

## 1. What this software is

Ekubo Wallet is a local-first EVM wallet, command-line tool, and MCP server.
Private keys are generated or imported on your machine and stay in your
operating system's credential store. The developer operates no servers for
this software and never has access to your keys or funds.

## 2. You direct all signing, including through agents

This software is designed to be driven by AI agents and other automated
tooling through the Model Context Protocol. Policies, simulations, and
approval prompts are safety aids, not guarantees. You are solely responsible
for every transaction and signature this software produces, including those
requested by an agent on your behalf.

## 3. Assumption of risk

Blockchain transactions are irreversible. Agents can misunderstand
instructions, be manipulated by malicious content (including prompt
injection), or submit plans whose effects differ from what you intended.
Policy configuration, simulation results, and third-party RPC responses can
be incomplete or wrong. You accept all of these risks by using this software.

## 4. No liability for agent-directed signing

TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE DEVELOPER AND COPYRIGHT HOLDERS
ARE NOT RESPONSIBLE OR LIABLE FOR ANY LOSSES INCURRED DUE TO USING AN AGENT
OR OTHER AUTOMATED TOOLING TO SIGN TRANSACTIONS OR TYPED DATA WITH THIS
SOFTWARE. THIS INCLUDES, WITHOUT LIMITATION, LOSS OF FUNDS, TOKENS, OR
ACCESS RESULTING FROM AGENT ERROR, PROMPT INJECTION, MALICIOUS OR DEFECTIVE
EXECUTION PLANS, POLICY MISCONFIGURATION, SIMULATION INACCURACY, OR RPC
MISBEHAVIOR.

## 5. No warranty

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY ARISING FROM THE SOFTWARE OR ITS USE.

## 6. Acceptance

Acceptance is recorded locally against the exact text of this document. If a
future release materially changes these terms, you will be asked to accept
them again before signing resumes.
";

const PRIVACY_POLICY_PREAMBLE: &str = "\
# Ekubo Wallet Privacy Policy

Version 1 — 2026-08-04

This policy must be acknowledged separately from the terms of service.

## 1. The developer collects nothing

This software is local-first. It contains no telemetry, no analytics, no
crash reporting, and no developer-operated services. The developer receives
no data from your use of this software.

## 2. Requests to RPC endpoints

To read chain state and to simulate and broadcast transactions, the wallet
sends network requests to the RPC endpoint configured for each network. Those
requests can include your wallet addresses, transaction calldata, balances
queries, and signed transactions. RPC operators are independent third
parties: they can observe your IP address and the contents of every request,
may log or retain them under their own policies, and are outside the
developer's control. The developer is not responsible for data those
endpoints collect.

Other than the configured RPC endpoints, this software makes no network
requests by default. If you add or replace a network, requests for that
network go to the endpoint you configure. Each release keeps the following
list current with its built-in defaults.

## 3. Default RPC endpoints in this release
";

const PRIVACY_POLICY_CLOSING: &str = "
## 4. Data exposed through agents and tooling

Any MCP client, agent, or other tooling you connect to this wallet can read
what its tools return: wallet addresses, balances, token holdings,
transaction history, policy contents, and execution status. Where that data
travels after the agent reads it — model providers, logs, other tools — is
determined by your agent stack, not by this software. THE DEVELOPER IS NOT
RESPONSIBLE FOR ANY DATA DISCLOSED OR LEAKED THROUGH THE AGENT OR ASSOCIATED
TOOLING.

## 5. Local data

Keys stay in the operating system credential store. Policies and transaction
lifecycle records are stored in an encrypted local database. Token metadata,
the address book, and legal acceptance records are stored unencrypted in the
wallet data directory. Nothing in this section leaves your machine except as
described in sections 2 and 4.

## 6. Acknowledgment

Acknowledgment is recorded locally against the exact text of this document,
including the endpoint list above. A release that changes the default
endpoints changes this document and requires a fresh acknowledgment before
signing resumes.
";

/// The complete privacy policy, with the default endpoint list generated from
/// the same catalog the wallet configures by default.
#[must_use]
pub fn privacy_policy() -> String {
    let mut text = String::from(PRIVACY_POLICY_PREAMBLE);
    for network in crate::config::default_networks() {
        let _ = writeln!(
            text,
            "- {} (chain {}): {}",
            network.name,
            network.chain_id,
            crate::mcp::rpc_origin(&network.rpc_url)
        );
    }
    text.push_str(PRIVACY_POLICY_CLOSING);
    text
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LegalDocument {
    TermsOfService,
    PrivacyPolicy,
    ThirdPartyLicenses,
}

impl LegalDocument {
    #[must_use]
    pub fn text(self) -> String {
        match self {
            Self::TermsOfService => TERMS_OF_SERVICE.into(),
            Self::PrivacyPolicy => privacy_policy(),
            Self::ThirdPartyLicenses => THIRD_PARTY_LICENSES.into(),
        }
    }

    /// Keccak-256 digest of the exact document text.
    #[must_use]
    pub fn digest(self) -> String {
        format!("0x{}", hex::encode(Keccak256::digest(self.text())))
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::TermsOfService => "Terms of Service",
            Self::PrivacyPolicy => "Privacy Policy",
            Self::ThirdPartyLicenses => "Third-Party Licenses",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AcceptanceRecord {
    pub digest: String,
    pub accepted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AcceptanceFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terms_of_service: Option<AcceptanceRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    privacy_policy: Option<AcceptanceRecord>,
}

/// Acceptance state of one document, as reported to the CLI and MCP.
#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct DocumentStatus {
    /// Whether the current revision of the document has been accepted.
    pub accepted: bool,
    pub current_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<DateTime<Utc>>,
    /// Set when a previous revision was accepted but the text has changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema, PartialEq, Eq)]
pub struct LegalStatus {
    /// Whether signing is currently allowed by legal acceptance state.
    pub signing_allowed: bool,
    pub terms_of_service: DocumentStatus,
    pub privacy_policy: DocumentStatus,
}

#[derive(Clone, Debug)]
pub struct LegalStore {
    file: PathBuf,
}

impl LegalStore {
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        Self {
            file: data_dir.join(ACCEPTANCE_FILE),
        }
    }

    fn load(&self) -> Result<AcceptanceFile> {
        if !self.file.exists() {
            return Ok(AcceptanceFile::default());
        }
        let bytes = fs::read(&self.file)
            .with_context(|| format!("failed to read {}", self.file.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", self.file.display()))
    }

    fn save(&self, state: &AcceptanceFile) -> Result<()> {
        let directory = self
            .file
            .parent()
            .context("legal acceptance file has no parent directory")?;
        fs::create_dir_all(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let mut temporary = NamedTempFile::new_in(directory)
            .context("failed to create temporary acceptance file")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o600))?;
        }
        serde_json::to_writer_pretty(&mut temporary, state)?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.file)
            .map_err(|error| error.error)
            .with_context(|| format!("failed to replace {}", self.file.display()))?;
        Ok(())
    }

    /// Record acceptance of the current revision of one document. The digest
    /// argument must match the current text, so a caller can only record what
    /// it actually displayed.
    pub fn record_acceptance(&self, document: LegalDocument, reviewed_digest: &str) -> Result<()> {
        ensure!(
            document != LegalDocument::ThirdPartyLicenses,
            "third-party licenses are informational and are not accepted"
        );
        ensure!(
            reviewed_digest == document.digest(),
            "the reviewed {} text is not the current revision; read it again before accepting",
            document.title()
        );
        let record = AcceptanceRecord {
            digest: document.digest(),
            accepted_at: Utc::now(),
        };
        let mut state = self.load()?;
        match document {
            LegalDocument::TermsOfService => state.terms_of_service = Some(record),
            LegalDocument::PrivacyPolicy => state.privacy_policy = Some(record),
            LegalDocument::ThirdPartyLicenses => unreachable!("rejected above"),
        }
        self.save(&state)
    }

    pub fn status(&self) -> Result<LegalStatus> {
        let state = self.load()?;
        let terms_of_service = document_status(
            LegalDocument::TermsOfService,
            state.terms_of_service.as_ref(),
        );
        let privacy_policy =
            document_status(LegalDocument::PrivacyPolicy, state.privacy_policy.as_ref());
        Ok(LegalStatus {
            signing_allowed: terms_of_service.accepted && privacy_policy.accepted,
            terms_of_service,
            privacy_policy,
        })
    }
}

fn document_status(document: LegalDocument, record: Option<&AcceptanceRecord>) -> DocumentStatus {
    let current_digest = document.digest();
    let accepted = record.is_some_and(|record| record.digest == current_digest);
    DocumentStatus {
        accepted,
        accepted_at: record.filter(|_| accepted).map(|record| record.accepted_at),
        superseded_digest: record
            .filter(|record| record.digest != current_digest)
            .map(|record| record.digest.clone()),
        current_digest,
    }
}

/// Fails closed unless the current terms of service and privacy policy have
/// both been accepted. The MCP dispatch calls this before every tool except
/// `wallet_get_legal` (the privacy policy governs even read-only RPC and
/// agent data exposure), and the signing paths repeat it as defense in depth.
pub fn require_current_acceptance(data_dir: &Path) -> Result<()> {
    let status = LegalStore::new(data_dir).status()?;
    ensure!(
        status.signing_allowed,
        "this wallet is disabled until the user accepts the current Terms of Service and Privacy \
         Policy. The user must run `ekubo-wallet legal accept` in their own terminal (never run \
         it for them). The documents can be read first with the wallet_get_legal tool or \
         `ekubo-wallet legal show`."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents_have_stable_nonempty_digests() {
        for document in [
            LegalDocument::TermsOfService,
            LegalDocument::PrivacyPolicy,
            LegalDocument::ThirdPartyLicenses,
        ] {
            assert!(!document.text().is_empty());
            assert_eq!(document.digest(), document.digest());
            assert!(document.digest().starts_with("0x"));
        }
    }

    #[test]
    fn privacy_policy_discloses_every_default_endpoint() {
        let policy = privacy_policy();
        for network in crate::config::default_networks() {
            let origin = crate::mcp::rpc_origin(&network.rpc_url);
            assert!(
                policy.contains(&origin),
                "privacy policy does not disclose default endpoint {origin}"
            );
        }
        assert!(policy.contains("Other than the configured RPC endpoints"));
    }

    #[test]
    fn terms_disclaim_agent_signing_losses() {
        assert!(TERMS_OF_SERVICE.contains("NOT RESPONSIBLE OR LIABLE FOR ANY LOSSES"));
        assert!(TERMS_OF_SERVICE.contains("USING AN AGENT"));
    }

    #[test]
    fn signing_requires_both_current_documents() {
        let directory = tempfile::tempdir().unwrap();
        let store = LegalStore::new(directory.path());
        assert!(!store.status().unwrap().signing_allowed);
        assert!(require_current_acceptance(directory.path()).is_err());

        store
            .record_acceptance(
                LegalDocument::TermsOfService,
                &LegalDocument::TermsOfService.digest(),
            )
            .unwrap();
        assert!(!store.status().unwrap().signing_allowed);
        assert!(require_current_acceptance(directory.path()).is_err());

        store
            .record_acceptance(
                LegalDocument::PrivacyPolicy,
                &LegalDocument::PrivacyPolicy.digest(),
            )
            .unwrap();
        let status = store.status().unwrap();
        assert!(status.signing_allowed);
        assert!(status.terms_of_service.accepted_at.is_some());
        require_current_acceptance(directory.path()).unwrap();
    }

    #[test]
    fn stale_digests_cannot_be_recorded_and_stale_acceptance_is_superseded() {
        let directory = tempfile::tempdir().unwrap();
        let store = LegalStore::new(directory.path());
        assert!(
            store
                .record_acceptance(LegalDocument::TermsOfService, "0xdeadbeef")
                .is_err()
        );
        assert!(
            store
                .record_acceptance(
                    LegalDocument::ThirdPartyLicenses,
                    &LegalDocument::ThirdPartyLicenses.digest(),
                )
                .is_err()
        );

        // Simulate acceptance of a previous revision by writing it directly.
        store
            .save(&AcceptanceFile {
                terms_of_service: Some(AcceptanceRecord {
                    digest: "0xoutdated".into(),
                    accepted_at: Utc::now(),
                }),
                privacy_policy: None,
            })
            .unwrap();
        let status = store.status().unwrap();
        assert!(!status.terms_of_service.accepted);
        assert_eq!(
            status.terms_of_service.superseded_digest.as_deref(),
            Some("0xoutdated")
        );
        assert!(status.terms_of_service.accepted_at.is_none());
    }
}
