//! Legal documents and their acceptance state.
//!
//! The terms of service and privacy policy are readable anywhere (MCP tools,
//! resources, and the desktop application), but acceptance is recorded only
//! by the owner-only native UI. Nothing signs — transactions or typed data — until the user has
//! separately accepted the current revision of both documents. Acceptance
//! binds the exact document text by digest, so shipping a materially changed
//! document automatically requires re-acceptance.
//!
//! The privacy policy describes owner-controlled RPC configuration without
//! embedding a volatile endpoint catalog in the legal document.
//!
//! Acceptance records live in the authenticated encrypted database, not in a
//! plain file, so an agent with filesystem access cannot forge acceptance.

use crate::{
    policy_store::PolicyStore,
    sql::{self, Blob, Millis, RowExt},
};
use alloy::primitives::{B256, keccak256};
use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use rusqlite::OptionalExtension;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Shipped attribution document for third-party dependencies. Regenerate with
/// `contrib/generate-third-party-licenses.py`; CI fails when it is stale or a
/// resolved dependency only offers a forbidden strong-copyleft license.
pub const THIRD_PARTY_LICENSES: &str = include_str!("../../../THIRD_PARTY_LICENSES.md");
/// Exact application license bundled with this build. Keeping it beside the
/// other legal documents makes every viewer work offline and avoids an
/// unexpected jump to a source-hosting website.
pub const APPLICATION_LICENSE: &str = include_str!("../../../LICENSE");

pub const TERMS_OF_SERVICE: &str = "\
# Ekubo Wallet Terms of Service

Version 3 — Effective 2026-08-10

These terms are an agreement between you and Ekubo, Inc. (the
\"developer\"). By accepting them you agree to all of the following before
this software signs anything on your behalf.

## 1. What this software is

Ekubo Wallet is a local-first native EVM desktop wallet and authenticated MCP server
developed by Ekubo, Inc. Private keys are generated or imported on your
machine and stay in your operating system's credential store. The developer
operates no servers for this software and never has access to your keys or
funds.

The Connections → WalletConnect screen additionally speaks the WalletConnect
protocol to a dapp you choose, through a relay operated by a third party — by default
`wss://relay.walletconnect.org`. Neither the relay nor the dapp is operated
by, endorsed by, or under the control of the developer, and this software's
use of the WalletConnect protocol implies no relationship with, or approval
by, its operators or any dapp you connect to.

## 2. There are no backups, and backing up your keys is out of scope

This software keeps no backup of any private key, and neither does the
developer. A key exists in your operating system's credential store on one
machine and nowhere else. There is no recovery phrase, no seed, no hosted
copy, and no account to recover. Nobody — including the developer — can
restore a key that is lost, and no support request can recover one.

If the credential store entry is deleted, if the machine is lost, wiped, or
destroyed, or if the operating system account holding the entry becomes
inaccessible, THE FUNDS CONTROLLED BY THAT KEY ARE PERMANENTLY LOST. Copying
the wallet's data directory does not copy any key, and restoring that
directory onto another machine does not restore one.

Keeping a durable copy of any key you care about is entirely your
responsibility, and doing so is out of the scope of this software. You can
obtain a timed copy through the account's Export Private Key action, and the key is
also readable through the tooling your operating system provides for its own
credential store. Storing, protecting, and securely destroying every copy you
make is your responsibility alone, and the developer is not responsible or
liable for any loss of funds arising from a key you did not back up, from a
backup you cannot find or read, or from a copy that was exposed, stolen, or
misused.

## 3. You direct all signing, including through agents and connected dapps

This software is designed to be driven by AI agents and other automated
tooling through the Model Context Protocol, and to serve requests from a dapp
you connect to over WalletConnect. Policies, simulations, and approval
prompts are safety aids, not guarantees. You are solely responsible for every
transaction and signature this software produces, including those requested
by an agent on your behalf and those requested by a dapp you paired with.

## 4. Assumption of risk

Blockchain transactions are irreversible. Agents can misunderstand
instructions, be manipulated by malicious content (including prompt
injection), or submit plans whose effects differ from what you intended.
Policy configuration, simulation results, and third-party RPC responses can
be incomplete or wrong. You accept all of these risks by using this software.

A dapp you connect to is an untrusted counterparty for the whole life of the
session: it chooses what to propose, its site may be compromised or
impersonated, and a pairing link you did not just generate yourself may
belong to someone else. The relay carrying that session can delay, drop, or
refuse messages, and may be unavailable. Nothing this software shows about a
dapp is a verification of who it is. You accept these risks too.

## 5. No liability for agent-directed or dapp-directed signing

TO THE MAXIMUM EXTENT PERMITTED BY LAW, EKUBO, INC. AND ALL COPYRIGHT
HOLDERS ARE NOT RESPONSIBLE OR LIABLE FOR ANY LOSSES INCURRED DUE TO USING AN AGENT
OR OTHER AUTOMATED TOOLING TO SIGN TRANSACTIONS OR TYPED DATA WITH THIS
SOFTWARE. THIS INCLUDES, WITHOUT LIMITATION, LOSS OF FUNDS, TOKENS, OR
ACCESS RESULTING FROM AGENT ERROR, PROMPT INJECTION, MALICIOUS OR DEFECTIVE
EXECUTION PLANS, POLICY MISCONFIGURATION, SIMULATION INACCURACY, OR RPC
MISBEHAVIOR.

THE SAME APPLIES TO EVERY TRANSACTION OR SIGNATURE PRODUCED FOR A DAPP
CONNECTED OVER WALLETCONNECT. THE DEVELOPER IS NOT RESPONSIBLE OR LIABLE FOR
ANY LOSSES ARISING FROM A CONNECTED DAPP, A PAIRING LINK OBTAINED FROM ANY
SOURCE, OR THE CONDUCT, FAILURE, DOWNTIME, OR UNAVAILABILITY OF ANY RELAY
OPERATOR, INCLUDING WITHOUT LIMITATION LOSSES FROM A MALICIOUS, COMPROMISED,
OR IMPERSONATED DAPP AND FROM MESSAGES DELAYED, DROPPED, OR NEVER DELIVERED.

## 6. No warranty

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY ARISING FROM THE SOFTWARE OR ITS USE.

## 7. Acceptance

Acceptance is recorded locally against the exact text of this document. If a
future release materially changes these terms, you will be asked to accept
them again before signing resumes.
";

const PRIVACY_POLICY_PREAMBLE: &str = "\
# Ekubo Wallet Privacy Policy

Version 4 — Effective 2026-08-11

This policy of Ekubo, Inc. (the \"developer\") must be acknowledged
separately from the terms of service.

## 1. The developer collects nothing

This software is local-first. It contains no telemetry, no analytics, no
crash reporting, and no developer-operated services. Ekubo, Inc. receives
no data from your use of this software.

## 2. Requests to RPC endpoints

To read chain state and to simulate and broadcast transactions, the wallet
sends network requests to the RPC endpoints configured for each network. Those
requests can include your wallet addresses, transaction calldata, balances
queries, and signed transactions. RPC operators are independent third
parties: they can observe your IP address and the contents of every request,
may log or retain them under their own policies, and are outside the
developer's control. The developer is not responsible for data those
endpoints collect.

Apart from these RPC endpoints, the referenced-artifact fetches described in
section 4, the WalletConnect relay described in section 5, and the release
check described in section 6, this software makes no network requests. If you
add or replace a network, requests for that network go to the endpoints you
configure. The complete network configuration, including RPC URLs, is
owner-controlled and stored in the encrypted local database. A fresh
installation starts with bundled settings that you can inspect and replace in
Networks. A disabled network sends no RPC requests until you enable it.

Enabled networks can list several endpoints run by unrelated operators. The
wallet uses the configured strategy and can move to another endpoint when one
fails, so over time your requests for a network may reach any configured
endpoint. Ordered strategy tries endpoints from top to bottom. Random strategy
shuffles them for each request before trying them. To send your traffic to one
operator only, keep one endpoint in the Networks screen.

## 3. Owner-controlled network configuration

The wallet does not treat a bundled or owner-configured RPC response as a
security policy. RPC configuration can nevertheless affect balances and
simulation results shown for review, so only owner-authorized core operations
can add, edit, enable, disable, restore, or remove a network. Agents cannot
change these settings through the MCP interface.

## 4. Execution plans fetched by reference

The transactions this wallet simulates and signs are built elsewhere. A
producer — the Ekubo MCP server, another protocol server, a dapp, or any
other tool — hands the wallet an execution plan, or a bundle of read-only
calls, as a reference rather than as inline text: a URL where the exact body
is stored, plus a digest of those bytes. When you or your agent passes such a
reference to a wallet tool, this process fetches the body from that URL
itself. Apart from the WalletConnect relay in section 5 and the release check
in section 6, these fetches are the only network requests this software makes
that do not go to a configured RPC endpoint.

The request is an unauthenticated HTTPS GET for exactly the URL given. It
carries no wallet address, key, credential, cookie, policy, or other data of
yours, and the wallet sends nothing back to the host; only public https hosts
on the default port are accepted, redirects and credentials in the URL are
refused, and the response is size-capped. The operator of the host named by
the URL is an independent third party outside the developer's control. It can
observe your IP address, the time of the fetch, and which reference you
fetched — and because a plan is prepared for a specific sender and action, a
fetch tells that operator the machine at that address is about to simulate or
sign that particular plan. Hosts may log or retain this under their own
policies. Usually the host is the same producer that prepared the plan and
therefore already knows its contents, but the URL comes from whatever
produced the reference, so it can name any public host: fetching resolves a
plan you are being asked to sign, and you should treat the reference with the
same scrutiny as its source. The developer is not responsible for data those
hosts collect.

A plan or call bundle you hold inline travels instead as a
`data:application/json` URI, which the wallet decodes locally and never
fetches over the network.

## 5. The WalletConnect relay

The Connections → WalletConnect screen pairs this wallet with a dapp over the
WalletConnect protocol. While a session is connected — and only then — this software holds
an open websocket to a WalletConnect relay, by default
`wss://relay.walletconnect.org`, operated by an independent third party
outside the developer's control.

The connection carries a project id that identifies this application, not
you. It is a fixed value compiled into this release, shared by every copy of
it, and cannot be changed by configuration; it is not derived from anything of
yours and is not a secret. Under it, the relay operator can observe your IP
address, when you are connected and for how long, the pairing and session
topics your wallet subscribes to, and the size and timing of every message.
Topics are derived from the pairing link the dapp gave you and are not your
wallet address, but they do link the messages of one session to each other and
to your IP address. The operator may log or retain this under its own policy.

Message contents are end-to-end encrypted between this wallet and the dapp
with a key established from the pairing link, so the relay routes ciphertext
it cannot read and cannot forge a message that opens: what you sign, what a
dapp proposes, and which account you exposed are not visible to it. What the
relay sees is the metadata above.

The dapp on the other end is a separate third party. When you approve a
connection it learns the single account address you chose to expose and the
chains you allowed, and thereafter whatever it asks for and you approve. The
developer is not responsible for data the relay operator or the dapp collects.
Having no connected session means this software opens no relay connection at
all.

## 6. The release check

To tell you when the copy you are running is out of date, this software asks
GitHub which release is newest. It sends an unauthenticated HTTPS GET to
`https://api.github.com/repos/EkuboProtocol/wallet/releases/latest`,
which is the same listing the installer reads, and uses only the version tag
in the answer. Nothing of yours is sent: no wallet address, key, credential,
cookie, balance, policy, or transaction, and no identifier of your machine or
your installation. The request carries a user agent naming this software and
its version, which every copy of a given release shares.

The check runs when you open or refresh the Updates screen and when an agent
calls the `wallet_check_for_updates` tool. The release-listing answer used by the
read-only MCP tool is cached in your wallet data directory for a day.
Setting `EKUBO_WALLET_SKIP_UPDATE_CHECK=1` disables the check entirely, and
nothing else about the software changes when you do.

GitHub is an independent third party outside the developer's control. It can
observe your IP address and the time of the request, and may log or retain
that under its own policy. The developer receives nothing from this check and
operates no service involved in it.

The application has no self-update capability. The Updates screen reports the
latest published version and opens the wallet's GitHub Releases page in your
browser; downloading and installing a release is outside this application.

## 7. Data exposed through agents and tooling

Any MCP client, agent, or other tooling you connect to this wallet can read
what its tools return: wallet addresses, balances, token holdings,
transaction history, policy contents, and execution status. Where that data
travels after the agent reads it — model providers, logs, other tools — is
determined by your agent stack, not by this software. THE DEVELOPER IS NOT
RESPONSIBLE FOR ANY DATA DISCLOSED OR LEAKED THROUGH THE AGENT OR ASSOCIATED
TOOLING.

## 8. Local data

Keys stay in the operating system credential store. Policies, transaction
lifecycle records, token metadata, legal acceptance
records, and pending policy proposals are stored in an encrypted local
database. A resolved execution plan is stored in that database as part of the
record of the request it becomes; the URL it was fetched from is not retained.
Wallet metadata and network configuration, including the RPC URLs you
configure, are stored in that encrypted database. A dapp session
is not recorded: the pairing keys live only in memory and are gone when the
application restarts, though the transactions and signatures it produced are kept
like any others. Nothing in this section leaves your machine except as
described in sections 2, 4, 5, 6, and 7. The release check in section 6 reads
a cache in this directory and writes the version tag it learned; that file
holds nothing about you and is never sent anywhere.

## 9. Acknowledgment

Acknowledgment is recorded locally against the exact text of this document. A
release that materially changes these privacy disclosures requires a fresh
acknowledgment before signing resumes. Ordinary changes to bundled or
owner-configured RPC endpoints do not rewrite this policy.
";

/// The complete privacy policy.
#[must_use]
pub fn privacy_policy() -> String {
    PRIVACY_POLICY_PREAMBLE.to_owned()
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LegalDocument {
    TermsOfService,
    PrivacyPolicy,
    ApplicationLicense,
    ThirdPartyLicenses,
}

impl LegalDocument {
    #[must_use]
    pub fn text(self) -> String {
        match self {
            Self::TermsOfService => TERMS_OF_SERVICE.into(),
            Self::PrivacyPolicy => privacy_policy(),
            Self::ApplicationLicense => APPLICATION_LICENSE.into(),
            Self::ThirdPartyLicenses => THIRD_PARTY_LICENSES.into(),
        }
    }

    /// Keccak-256 digest of the exact document text.
    #[must_use]
    pub fn digest_bytes(self) -> B256 {
        keccak256(self.text())
    }

    /// The same digest as the hex the desktop and MCP surfaces display.
    #[must_use]
    pub fn digest(self) -> String {
        format!("{:#x}", self.digest_bytes())
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::TermsOfService => "Terms of Service",
            Self::PrivacyPolicy => "Privacy Policy",
            Self::ApplicationLicense => "Application License",
            Self::ThirdPartyLicenses => "Third-Party Licenses",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AcceptanceRecord {
    pub digest: String,
    pub accepted_at: DateTime<Utc>,
}

/// Acceptance state of one document, as reported to the desktop and MCP.
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

/// Acceptance state, stored in the authenticated encrypted database so that
/// nothing outside this process — in particular an agent with file access —
/// can forge acceptance by writing a file.
pub struct LegalStore {
    database: PolicyStore,
}

impl LegalStore {
    pub fn production(data_dir: &Path) -> Result<Self> {
        Ok(Self {
            database: PolicyStore::production(data_dir)?,
        })
    }

    #[must_use]
    pub const fn new(database: PolicyStore) -> Self {
        Self { database }
    }

    fn record(&self, document: LegalDocument) -> Result<Option<AcceptanceRecord>> {
        let key = match document {
            LegalDocument::TermsOfService => "terms_of_service",
            LegalDocument::PrivacyPolicy => "privacy_policy",
            LegalDocument::ApplicationLicense | LegalDocument::ThirdPartyLicenses => {
                return Ok(None);
            }
        };
        Ok(self
            .database
            .connection
            .query_row(
                "SELECT digest, accepted_at FROM legal_acceptance WHERE document = ?1",
                [key],
                |row| Ok((row.blob::<B256>(0)?, row.time(1)?)),
            )
            .optional()?
            .map(|(digest, accepted_at)| AcceptanceRecord {
                digest: format!("{digest:#x}"),
                accepted_at,
            }))
    }

    /// Record acceptance of the current revision of one document. The digest
    /// argument must match the current text, so a caller can only record what
    /// it actually displayed.
    pub fn record_acceptance(&self, document: LegalDocument, reviewed_digest: &str) -> Result<()> {
        ensure!(
            matches!(
                document,
                LegalDocument::TermsOfService | LegalDocument::PrivacyPolicy
            ),
            "informational legal documents are not accepted"
        );
        ensure!(
            reviewed_digest == document.digest(),
            "the reviewed {} text is not the current revision; read it again before accepting",
            document.title()
        );
        let key = match document {
            LegalDocument::TermsOfService => "terms_of_service",
            LegalDocument::PrivacyPolicy => "privacy_policy",
            LegalDocument::ApplicationLicense | LegalDocument::ThirdPartyLicenses => {
                unreachable!("rejected above")
            }
        };
        self.database.connection.execute(
            "INSERT INTO legal_acceptance(document, digest, accepted_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(document) DO UPDATE SET
                 digest = excluded.digest,
                 accepted_at = excluded.accepted_at",
            rusqlite::params![key, Blob(document.digest_bytes()), Millis(sql::now())],
        )?;
        Ok(())
    }

    pub fn status(&self) -> Result<LegalStatus> {
        let terms_of_service = document_status(
            LegalDocument::TermsOfService,
            self.record(LegalDocument::TermsOfService)?.as_ref(),
        );
        let privacy_policy = document_status(
            LegalDocument::PrivacyPolicy,
            self.record(LegalDocument::PrivacyPolicy)?.as_ref(),
        );
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
/// both been accepted.
///
/// Called once per request by the two dispatchers — the MCP server before
/// every tool except `wallet_get_legal` (the privacy policy governs even
/// read-only RPC and agent data exposure), and the `WalletConnect` session
/// before every dapp method — and on entry by each owner operation that can reach
/// a signature.
///
/// It is **not** called by the signing paths themselves. The sentence here
/// used to claim they repeated it as defense in depth, and that was wrong:
/// none of them calls it. Acceptance is live state: it goes stale when a document changes,
/// which can happen while a review waits for a person or a reconciliation loop
/// runs. Per-request dispatch bounds that window to one request; it does not
/// close it. Closing it means checking at [`crate::custody::load_matching_signer`],
/// the one point every signature in this process passes through, which means
/// threading a store into the signing kernel and deciding whether a
/// *cancellation* — protective rather than new authority — should be refused
/// when terms have lapsed. Both are maintainer calls.
pub fn require_current_acceptance(data_dir: &Path) -> Result<()> {
    require_status_allows_use(&LegalStore::production(data_dir)?.status()?)
}

/// The shared refusal for unaccepted documents, usable with an already-open
/// store (the MCP server holds one rather than reopening per tool call).
pub fn require_status_allows_use(status: &LegalStatus) -> Result<()> {
    ensure!(
        status.signing_allowed,
        "this wallet is disabled until the user accepts the current Terms of Service and Privacy \
         Policy. The user must run the Legal screen in the desktop application (never run \
         it for them). The documents can be read first with the wallet_get_legal tool or the \
         Legal & Version screen."
    );
    Ok(())
}

#[cfg(test)]
#[path = "legal_test.rs"]
mod tests;
